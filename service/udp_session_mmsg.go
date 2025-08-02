//go:build linux || netbsd

package service

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// sessionUplinkMmsg is used for passing information about relay uplink to the relay goroutine.
type sessionUplinkMmsg struct {
	csid           uint64
	clientName     string
	natConn        *conn.MmsgWConn
	natConnSendCh  <-chan *sessionQueuedPacket
	natConnPacker  zerocopy.ClientPacker
	natTimeout     time.Duration
	username       string
	relayBatchSize int
	logger         *zap.Logger
}

// sessionDownlinkMmsg is used for passing information about relay downlink to the relay goroutine.
type sessionDownlinkMmsg struct {
	csid               uint64
	clientName         string
	clientAddrInfop    *sessionClientAddrInfo
	clientAddrInfo     *atomic.Pointer[sessionClientAddrInfo]
	natConn            *conn.MmsgRConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConn         *conn.MmsgWConn
	serverConnPacker   zerocopy.ServerPacker
	username           string
	relayBatchSize     int
	logger             *zap.Logger
}

func (s *UDPSessionRelay) start(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	switch lnc.batchMode {
	case "sendmmsg", "":
		return s.startMmsg(ctx, index, lnc)
	default:
		return s.startGeneric(ctx, index, lnc)
	}
}

func (s *UDPSessionRelay) startMmsg(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	serverConn, _, err := lnc.listenConfig.ListenUDPMmsgConn(ctx, lnc.network, lnc.address)
	if err != nil {
		return err
	}
	lnc.serverConn = serverConn.UDPConn
	lnc.address = serverConn.LocalAddr().String()
	lnc.logger = s.logger.With(
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
	)

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnRecvmmsg(ctx, lnc, serverConn.NewRConn())
		s.mwg.Done()
	}()

	lnc.logger.Info("Started UDP session relay service listener")
	return nil
}

func (s *UDPSessionRelay) recvFromServerConnRecvmmsg(ctx context.Context, lnc *udpRelayServerConn, serverConn *conn.MmsgRConn) {
	n := lnc.serverRecvBatchSize
	qpvec := make([]*sessionQueuedPacket, n)
	namevec := make([]unix.RawSockaddrInet6, n)
	iovec := make([]unix.Iovec, n)
	cmsgvec := make([][]byte, n)
	msgvec := make([]conn.Mmsghdr, n)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = unsafe.SliceData(cmsgBuf)
	}

	var (
		err                  error
		recvmmsgCount        uint64
		packetsReceived      uint64
		payloadBytesReceived uint64
		burstBatchSize       int
	)

	for {
		for i := range iovec[:n] {
			queuedPacket := s.getQueuedPacket()
			qpvec[i] = queuedPacket
			iovec[i].Base = &queuedPacket.buf[s.packetBufFrontHeadroom]
			iovec[i].SetLen(s.packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = serverConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			lnc.logger.Warn("Failed to batch read packets from serverConn", zap.Error(err))

			n = 1
			s.putQueuedPacket(qpvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		burstBatchSize = max(burstBatchSize, n)

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			queuedPacket := qpvec[i]

			if msg.Msghdr.Controllen == 0 {
				lnc.logger.Error("Skipping packet with no control message from serverConn")
				s.putQueuedPacket(queuedPacket)
				continue
			}

			queuedPacket.clientAddrPort, err = conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				lnc.logger.Error("Failed to parse sockaddr of packet from serverConn", zap.Error(err))
				s.putQueuedPacket(queuedPacket)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				lnc.logger.Warn("Packet from serverConn discarded",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			packet := queuedPacket.buf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+int(msg.Msglen)]

			csid, err := s.server.SessionInfo(packet)
			if err != nil {
				lnc.logger.Warn("Failed to extract session info from packet",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			entry, ok := s.table[csid]
			if !ok {
				entry = &session{
					serverConn: lnc.serverConn,
					logger:     lnc.logger,
				}

				entry.serverConnUnpacker, entry.username, err = s.server.NewUnpacker(packet, csid)
				if err != nil {
					lnc.logger.Warn("Failed to create unpacker for client session",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Uint64("clientSessionID", csid),
						zap.Uint32("packetLength", msg.Msglen),
						zap.Error(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}
			}

			queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, queuedPacket.clientAddrPort, s.packetBufFrontHeadroom, int(msg.Msglen))
			if err != nil {
				lnc.logger.Warn("Failed to unpack packet from serverConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			payloadBytesReceived += uint64(queuedPacket.length)

			var clientAddrInfop *sessionClientAddrInfo
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			updateClientAddrPort := entry.clientAddrPortCache != queuedPacket.clientAddrPort
			updateClientPktinfo := !bytes.Equal(entry.clientPktinfoCache, cmsg)

			if updateClientAddrPort {
				entry.clientAddrPortCache = queuedPacket.clientAddrPort
			}

			if updateClientPktinfo {
				entry.clientPktinfoCache = make([]byte, len(cmsg))
				copy(entry.clientPktinfoCache, cmsg)
			}

			if updateClientAddrPort || updateClientPktinfo {
				m, err := conn.ParseSocketControlMessage(cmsg)
				if err != nil {
					lnc.logger.Error("Failed to parse pktinfo control message from serverConn",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Error(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}

				clientAddrInfop = &sessionClientAddrInfo{entry.clientAddrPortCache, entry.clientPktinfoCache}
				entry.clientAddrInfo.Store(clientAddrInfop)

				if ce := lnc.logger.Check(zap.DebugLevel, "Updated client address info"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Stringer("clientPktinfoAddr", m.PktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", m.PktinfoIfindex),
					)
				}
			}

			if !ok {
				natConnSendCh := make(chan *sessionQueuedPacket, lnc.sendChannelCapacity)
				entry.natConnSendCh = natConnSendCh
				s.table[csid] = entry
				s.wg.Add(1)

				go func() {
					var sendChClean bool

					defer func() {
						s.mu.Lock()
						close(natConnSendCh)
						delete(s.table, csid)
						s.mu.Unlock()

						if !sendChClean {
							for queuedPacket := range natConnSendCh {
								s.putQueuedPacket(queuedPacket)
							}
						}

						s.wg.Done()
					}()

					c, err := s.router.GetUDPClient(ctx, router.RequestInfo{
						ServerIndex:    s.serverIndex,
						Username:       entry.username,
						SourceAddrPort: queuedPacket.clientAddrPort,
						TargetAddr:     queuedPacket.targetAddr,
					})
					if err != nil {
						lnc.logger.Warn("Failed to get UDP client for new NAT session",
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.Error(err),
						)
						return
					}

					clientInfo, clientSession, err := c.NewSession(ctx)
					if err != nil {
						lnc.logger.Warn("Failed to create new UDP client session",
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("client", clientInfo.Name),
							zap.Error(err),
						)
						return
					}

					natConn, _, err := clientInfo.ListenConfig.ListenUDPMmsgConn(ctx, "udp", "")
					if err != nil {
						lnc.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("client", clientInfo.Name),
							zap.Error(err),
						)
						clientSession.Close()
						return
					}

					err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout))
					if err != nil {
						lnc.logger.Error("Failed to set read deadline on natConn",
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("client", clientInfo.Name),
							zap.Duration("natTimeout", lnc.natTimeout),
							zap.Error(err),
						)
						natConn.Close()
						clientSession.Close()
						return
					}

					serverConnPacker, err := entry.serverConnUnpacker.NewPacker()
					if err != nil {
						lnc.logger.Warn("Failed to create packer for client session",
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.Error(err),
						)
						natConn.Close()
						clientSession.Close()
						return
					}

					oldState := entry.state.Swap(natConn.UDPConn)
					if oldState != nil {
						natConn.Close()
						clientSession.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					lnc.logger.Info("UDP session relay started",
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(ctx, sessionUplinkMmsg{
							csid:           csid,
							clientName:     clientInfo.Name,
							natConn:        natConn.NewWConn(),
							natConnSendCh:  natConnSendCh,
							natConnPacker:  clientSession.Packer,
							natTimeout:     lnc.natTimeout,
							username:       entry.username,
							relayBatchSize: lnc.relayBatchSize,
							logger:         lnc.logger,
						})
						natConn.Close()
						clientSession.Close()
						s.wg.Done()
					}()

					s.relayNatConnToServerConnSendmmsg(sessionDownlinkMmsg{
						csid:               csid,
						clientName:         clientInfo.Name,
						clientAddrInfop:    clientAddrInfop,
						clientAddrInfo:     &entry.clientAddrInfo,
						natConn:            natConn.NewRConn(),
						natConnRecvBufSize: clientSession.MaxPacketSize,
						natConnUnpacker:    clientSession.Unpacker,
						serverConn:         serverConn.NewWConn(),
						serverConnPacker:   serverConnPacker,
						username:           entry.username,
						relayBatchSize:     lnc.relayBatchSize,
						logger:             lnc.logger,
					})
				}()

				if ce := lnc.logger.Check(zap.DebugLevel, "New UDP session"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					)
				}
			}

			select {
			case entry.natConnSendCh <- queuedPacket:
			default:
				if ce := lnc.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					)
				}

				s.putQueuedPacket(queuedPacket)
			}
		}

		s.mu.Unlock()
	}

	for i := range qpvec {
		s.putQueuedPacket(qpvec[i])
	}

	lnc.logger.Info("Finished receiving from serverConn",
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnSendmmsg(ctx context.Context, uplink sessionUplinkMmsg) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	qpvec := make([]*sessionQueuedPacket, uplink.relayBatchSize)
	dapvec := make([]netip.AddrPort, uplink.relayBatchSize)
	namevec := make([]unix.RawSockaddrInet6, uplink.relayBatchSize)
	iovec := make([]unix.Iovec, uplink.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, uplink.relayBatchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

main:
	for {
		var count int

		// Block on first dequeue op.
		queuedPacket, ok := <-uplink.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(ctx, queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
			if err != nil {
				uplink.logger.Warn("Failed to pack packet for natConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", uplink.username),
					zap.Uint64("clientSessionID", uplink.csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("client", uplink.clientName),
					zap.Int("payloadLength", queuedPacket.length),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)

				if count == 0 {
					continue main
				}
				goto next
			}

			qpvec[count] = queuedPacket
			dapvec[count] = destAddrPort
			conn.SockaddrInet6PutAddrPort(&namevec[count], destAddrPort)
			iovec[count].Base = &queuedPacket.buf[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.length)

			if count == uplink.relayBatchSize {
				break
			}

		next:
			select {
			case queuedPacket, ok = <-uplink.natConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		for start := 0; start < count; {
			n, err := uplink.natConn.WriteMsgs(msgvec[start:count], 0)
			start += n
			if err != nil {
				uplink.logger.Warn("Failed to batch write packets to natConn",
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", uplink.username),
					zap.Uint64("clientSessionID", uplink.csid),
					zap.Stringer("targetAddress", &qpvec[start].targetAddr),
					zap.String("client", uplink.clientName),
					zap.Stringer("writeDestAddress", &dapvec[start]),
					zap.Uint("packetLength", uint(iovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			packetsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if err := uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout)); err != nil {
			uplink.logger.Error("Failed to set read deadline on natConn",
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.String("client", uplink.clientName),
				zap.Duration("natTimeout", uplink.natTimeout),
				zap.Error(err),
			)
		}

		qpvecn := qpvec[:count]

		for i := range qpvecn {
			s.putQueuedPacket(qpvecn[i])
		}

		if !ok {
			break
		}
	}

	uplink.logger.Info("Finished relay serverConn -> natConn",
		zap.String("username", uplink.username),
		zap.Uint64("clientSessionID", uplink.csid),
		zap.String("client", uplink.clientName),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionUplink(uplink.username, packetsSent, payloadBytesSent)
}

func (s *UDPSessionRelay) relayNatConnToServerConnSendmmsg(downlink sessionDownlinkMmsg) {
	clientAddrInfop := downlink.clientAddrInfop
	clientAddrPort := downlink.clientAddrInfop.addrPort
	clientPktinfo := downlink.clientAddrInfop.pktinfo
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	var (
		name    unix.RawSockaddrInet6
		namelen uint32
	)
	conn.SockaddrPutAddrPort(&name, &namelen, clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, downlink.relayBatchSize)
	bufvec := make([][]byte, downlink.relayBatchSize)
	riovec := make([]unix.Iovec, downlink.relayBatchSize)
	siovec := make([]unix.Iovec, downlink.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, downlink.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, downlink.relayBatchSize)

	for i := range downlink.relayBatchSize {
		packetBuf := make([]byte, headroom.Front+downlink.natConnRecvBufSize+headroom.Rear)
		bufvec[i] = packetBuf

		riovec[i].Base = &packetBuf[headroom.Front]
		riovec[i].SetLen(downlink.natConnRecvBufSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&name))
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = unsafe.SliceData(clientPktinfo)
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	for {
		nr, err := downlink.natConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			downlink.logger.Warn("Failed to batch read packets from natConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.String("client", downlink.clientName),
				zap.Error(err),
			)
			continue
		}

		if caip := downlink.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
			conn.SockaddrPutAddrPort(&name, &namelen, clientAddrPort) // namelen won't change

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = unsafe.SliceData(clientPktinfo)
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		var ns int
		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				downlink.logger.Error("Failed to parse sockaddr of packet from natConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.String("client", downlink.clientName),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				downlink.logger.Warn("Failed to read packet from natConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, int(msg.Msglen))
			if err != nil {
				downlink.logger.Warn("Failed to unpack packet from natConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
			if err != nil {
				downlink.logger.Warn("Failed to pack packet for serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Int("payloadLength", payloadLength),
					zap.Int("maxClientPacketSize", maxClientPacketSize),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[packetStart]
			siovec[ns].SetLen(packetLength)
			ns++
			payloadBytesSent += uint64(payloadLength)
		}

		if ns == 0 {
			continue
		}

		for start := 0; start < ns; {
			n, err := downlink.serverConn.WriteMsgs(smsgvec[start:ns], 0)
			start += n
			if err != nil {
				downlink.logger.Warn("Failed to batch write packets to serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", downlink.username),
					zap.Uint64("clientSessionID", downlink.csid),
					zap.String("client", downlink.clientName),
					zap.Uint("packetLength", uint(siovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			packetsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}
	}

	downlink.logger.Info("Finished relay serverConn <- natConn",
		zap.Stringer("clientAddress", clientAddrPort),
		zap.String("username", downlink.username),
		zap.Uint64("clientSessionID", downlink.csid),
		zap.String("client", downlink.clientName),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink(downlink.username, packetsSent, payloadBytesSent)
}
