//go:build linux || netbsd

package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/zerocopy"
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
	logger         *tslog.Logger
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
	logger             *tslog.Logger
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
	serverConn, err := conn.ListenUDPMmsgConn(ctx, lnc.network, lnc.address, nil, lnc.socketConfig)
	if err != nil {
		return err
	}
	lnc.serverConn = serverConn.UDPConn
	lnc.address = serverConn.LocalAddr().String()
	lnc.logger = s.logger.WithAttrs(
		slog.String("server", s.serverName),
		slog.Int("listener", index),
		slog.String("listenAddress", lnc.address),
	)

	s.mwg.Go(func() {
		s.recvFromServerConnRecvmmsg(ctx, lnc, serverConn.NewRConn())
	})

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

			lnc.logger.Warn("Failed to batch read packets from serverConn", tslog.Err(err))

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
				lnc.logger.Error("Failed to parse sockaddr of packet from serverConn", tslog.Err(err))
				s.putQueuedPacket(queuedPacket)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				lnc.logger.Warn("Packet from serverConn discarded",
					tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			packet := queuedPacket.buf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+int(msg.Msglen)]

			csid, err := s.server.SessionInfo(packet)
			if err != nil {
				lnc.logger.Warn("Failed to extract session info from packet",
					tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
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
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						tslog.Uint("clientSessionID", csid),
						tslog.Uint("packetLength", msg.Msglen),
						tslog.Err(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}
			}

			queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, queuedPacket.clientAddrPort, s.packetBufFrontHeadroom, int(msg.Msglen))
			if err != nil {
				lnc.logger.Warn("Failed to unpack packet from serverConn",
					tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
					slog.String("username", entry.username),
					slog.Uint64("clientSessionID", csid),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
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
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						slog.String("username", entry.username),
						slog.Uint64("clientSessionID", csid),
						tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
						tslog.Err(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}

				clientAddrInfop = &sessionClientAddrInfo{entry.clientAddrPortCache, entry.clientPktinfoCache}
				entry.clientAddrInfo.Store(clientAddrInfop)

				if lnc.logger.Enabled(slog.LevelDebug) {
					lnc.logger.Debug("Updated client address info",
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						slog.String("username", entry.username),
						slog.Uint64("clientSessionID", csid),
						tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
						tslog.Addr("clientPktinfoAddr", m.PktinfoAddr),
						tslog.Uint("clientPktinfoIfindex", m.PktinfoIfindex),
					)
				}
			}

			if !ok {
				natConnSendCh := make(chan *sessionQueuedPacket, lnc.sendChannelCapacity)
				entry.natConnSendCh = natConnSendCh
				s.table[csid] = entry

				s.wg.Go(func() {
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
					}()

					c, err := s.router.GetUDPClient(ctx, router.RequestInfo{
						ServerIndex:    s.serverIndex,
						Username:       entry.username,
						SourceAddrPort: queuedPacket.clientAddrPort,
						TargetAddr:     queuedPacket.targetAddr,
					})
					if err != nil {
						lnc.logger.Warn("Failed to get UDP client for new NAT session",
							tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
							slog.String("username", entry.username),
							slog.Uint64("clientSessionID", csid),
							tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
							tslog.Err(err),
						)
						return
					}

					clientInfo, clientSession, err := c.NewSession(ctx)
					if err != nil {
						lnc.logger.Warn("Failed to create new UDP client session",
							tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
							slog.String("username", entry.username),
							slog.Uint64("clientSessionID", csid),
							tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
							slog.String("client", clientInfo.Name),
							tslog.Err(err),
						)
						return
					}

					natConn, err := conn.ListenUDPMmsgConn(ctx, "udp", "", nil, clientInfo.SocketConfig)
					if err != nil {
						lnc.logger.Warn("Failed to create UDP socket for new NAT session",
							tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
							slog.String("username", entry.username),
							slog.Uint64("clientSessionID", csid),
							tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
							slog.String("client", clientInfo.Name),
							tslog.Err(err),
						)
						clientSession.Close()
						return
					}

					err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout))
					if err != nil {
						lnc.logger.Error("Failed to set read deadline on natConn",
							tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
							slog.String("username", entry.username),
							slog.Uint64("clientSessionID", csid),
							tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
							slog.String("client", clientInfo.Name),
							slog.Duration("natTimeout", lnc.natTimeout),
							tslog.Err(err),
						)
						natConn.Close()
						clientSession.Close()
						return
					}

					serverConnPacker, err := entry.serverConnUnpacker.NewPacker()
					if err != nil {
						lnc.logger.Warn("Failed to create packer for client session",
							tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
							slog.String("username", entry.username),
							slog.Uint64("clientSessionID", csid),
							tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
							tslog.Err(err),
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
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						slog.String("username", entry.username),
						slog.Uint64("clientSessionID", csid),
						tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
						slog.String("client", clientInfo.Name),
					)

					s.wg.Go(func() {
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
					})

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
				})

				if lnc.logger.Enabled(slog.LevelDebug) {
					lnc.logger.Debug("New UDP session",
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						slog.String("username", entry.username),
						slog.Uint64("clientSessionID", csid),
						tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
					)
				}
			}

			select {
			case entry.natConnSendCh <- queuedPacket:
			default:
				if lnc.logger.Enabled(slog.LevelDebug) {
					lnc.logger.Debug("Dropping packet due to full send channel",
						tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
						slog.String("username", entry.username),
						slog.Uint64("clientSessionID", csid),
						tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
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
		slog.Uint64("recvmmsgCount", recvmmsgCount),
		slog.Uint64("packetsReceived", packetsReceived),
		slog.Uint64("payloadBytesReceived", payloadBytesReceived),
		slog.Int("burstBatchSize", burstBatchSize),
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
					tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
					slog.String("username", uplink.username),
					slog.Uint64("clientSessionID", uplink.csid),
					tslog.ConnAddrp("targetAddress", &queuedPacket.targetAddr),
					slog.String("client", uplink.clientName),
					slog.Int("payloadLength", queuedPacket.length),
					tslog.Err(err),
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
					tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
					slog.String("username", uplink.username),
					slog.Uint64("clientSessionID", uplink.csid),
					tslog.ConnAddrp("targetAddress", &qpvec[start].targetAddr),
					slog.String("client", uplink.clientName),
					tslog.AddrPortp("writeDestAddress", &dapvec[start]),
					tslog.Uint("packetLength", iovec[start].Len),
					tslog.Err(err),
				)
				start++
			}

			sendmmsgCount++
			packetsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if err := uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout)); err != nil {
			uplink.logger.Error("Failed to set read deadline on natConn",
				tslog.AddrPortp("clientAddress", &queuedPacket.clientAddrPort),
				slog.String("username", uplink.username),
				slog.Uint64("clientSessionID", uplink.csid),
				slog.String("client", uplink.clientName),
				slog.Duration("natTimeout", uplink.natTimeout),
				tslog.Err(err),
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
		slog.String("username", uplink.username),
		slog.Uint64("clientSessionID", uplink.csid),
		slog.String("client", uplink.clientName),
		tslog.AddrPort("lastWriteDestAddress", destAddrPort),
		slog.Uint64("sendmmsgCount", sendmmsgCount),
		slog.Uint64("packetsSent", packetsSent),
		slog.Uint64("payloadBytesSent", payloadBytesSent),
		slog.Int("burstBatchSize", burstBatchSize),
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
				tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
				slog.String("username", downlink.username),
				slog.Uint64("clientSessionID", downlink.csid),
				slog.String("client", downlink.clientName),
				tslog.Err(err),
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
					tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
					slog.String("username", downlink.username),
					slog.Uint64("clientSessionID", downlink.csid),
					slog.String("client", downlink.clientName),
					tslog.Err(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				downlink.logger.Warn("Failed to read packet from natConn",
					tslog.AddrPort("clientAddress", clientAddrPort),
					slog.String("username", downlink.username),
					slog.Uint64("clientSessionID", downlink.csid),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					slog.String("client", downlink.clientName),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, int(msg.Msglen))
			if err != nil {
				downlink.logger.Warn("Failed to unpack packet from natConn",
					tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
					slog.String("username", downlink.username),
					slog.Uint64("clientSessionID", downlink.csid),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					slog.String("client", downlink.clientName),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
				)
				continue
			}

			packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
			if err != nil {
				downlink.logger.Warn("Failed to pack packet for serverConn",
					tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
					slog.String("username", downlink.username),
					slog.Uint64("clientSessionID", downlink.csid),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					slog.String("client", downlink.clientName),
					tslog.AddrPort("payloadSourceAddress", payloadSourceAddrPort),
					slog.Int("payloadLength", payloadLength),
					slog.Int("maxClientPacketSize", maxClientPacketSize),
					tslog.Err(err),
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
					tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
					slog.String("username", downlink.username),
					slog.Uint64("clientSessionID", downlink.csid),
					slog.String("client", downlink.clientName),
					tslog.Uint("packetLength", siovec[start].Len),
					tslog.Err(err),
				)
				start++
			}

			sendmmsgCount++
			packetsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}
	}

	downlink.logger.Info("Finished relay serverConn <- natConn",
		tslog.AddrPortp("clientAddress", &clientAddrInfop.addrPort),
		slog.String("username", downlink.username),
		slog.Uint64("clientSessionID", downlink.csid),
		slog.String("client", downlink.clientName),
		slog.Uint64("sendmmsgCount", sendmmsgCount),
		slog.Uint64("packetsSent", packetsSent),
		slog.Uint64("payloadBytesSent", payloadBytesSent),
		slog.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink(downlink.username, packetsSent, payloadBytesSent)
}
