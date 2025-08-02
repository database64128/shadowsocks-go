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

// natUplinkMmsg is used for passing information about relay uplink to the relay goroutine.
type natUplinkMmsg struct {
	clientName     string
	clientAddrPort netip.AddrPort
	natConn        *conn.MmsgWConn
	natConnSendCh  <-chan *natQueuedPacket
	natConnPacker  zerocopy.ClientPacker
	natTimeout     time.Duration
	relayBatchSize int
	logger         *zap.Logger
}

// natDownlinkMmsg is used for passing information about relay downlink to the relay goroutine.
type natDownlinkMmsg struct {
	clientName         string
	clientAddrPort     netip.AddrPort
	clientPktinfop     *[]byte
	clientPktinfo      *atomic.Pointer[[]byte]
	natConn            *conn.MmsgRConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConn         *conn.MmsgWConn
	serverConnPacker   zerocopy.ServerPacker
	relayBatchSize     int
	logger             *zap.Logger
}

func (s *UDPNATRelay) start(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	switch lnc.batchMode {
	case "sendmmsg", "":
		return s.startMmsg(ctx, index, lnc)
	default:
		return s.startGeneric(ctx, index, lnc)
	}
}

func (s *UDPNATRelay) startMmsg(ctx context.Context, index int, lnc *udpRelayServerConn) error {
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

	lnc.logger.Info("Started UDP NAT relay service listener")
	return nil
}

func (s *UDPNATRelay) recvFromServerConnRecvmmsg(ctx context.Context, lnc *udpRelayServerConn, serverConn *conn.MmsgRConn) {
	n := lnc.serverRecvBatchSize
	qpvec := make([]*natQueuedPacket, n)
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

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				lnc.logger.Error("Failed to parse sockaddr of packet from serverConn", zap.Error(err))
				s.putQueuedPacket(queuedPacket)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				lnc.logger.Warn("Packet from serverConn discarded",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			entry, ok := s.table[clientAddrPort]
			if !ok {
				entry = &natEntry{
					serverConn: lnc.serverConn,
					logger:     lnc.logger,
				}

				entry.serverConnUnpacker, err = s.server.NewUnpacker()
				if err != nil {
					lnc.logger.Warn("Failed to create unpacker for serverConn",
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					s.putQueuedPacket(queuedPacket)
					continue
				}
			}

			queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, clientAddrPort, s.packetBufFrontHeadroom, int(msg.Msglen))
			if err != nil {
				lnc.logger.Warn("Failed to unpack packet from serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				s.putQueuedPacket(queuedPacket)
				continue
			}

			payloadBytesReceived += uint64(queuedPacket.length)

			var clientPktinfop *[]byte
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if !bytes.Equal(entry.clientPktinfoCache, cmsg) {
				m, err := conn.ParseSocketControlMessage(cmsg)
				if err != nil {
					lnc.logger.Error("Failed to parse pktinfo control message from serverConn",
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Error(err),
					)
					s.putQueuedPacket(queuedPacket)
					continue
				}

				clientPktinfoCache := make([]byte, len(cmsg))
				copy(clientPktinfoCache, cmsg)
				clientPktinfop = &clientPktinfoCache
				entry.clientPktinfo.Store(clientPktinfop)
				entry.clientPktinfoCache = clientPktinfoCache

				if ce := lnc.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Stringer("clientPktinfoAddr", m.PktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", m.PktinfoIfindex),
					)
				}
			}

			if !ok {
				natConnSendCh := make(chan *natQueuedPacket, lnc.sendChannelCapacity)
				entry.natConnSendCh = natConnSendCh
				s.table[clientAddrPort] = entry
				s.wg.Add(1)

				go func() {
					var sendChClean bool

					defer func() {
						s.mu.Lock()
						close(natConnSendCh)
						delete(s.table, clientAddrPort)
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
						SourceAddrPort: clientAddrPort,
						TargetAddr:     queuedPacket.targetAddr,
					})
					if err != nil {
						lnc.logger.Warn("Failed to get UDP client for new NAT session",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.Error(err),
						)
						return
					}

					clientInfo, clientSession, err := c.NewSession(ctx)
					if err != nil {
						lnc.logger.Warn("Failed to create new UDP client session",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("client", clientInfo.Name),
							zap.Error(err),
						)
						return
					}

					natConn, _, err := clientInfo.ListenConfig.ListenUDPMmsgConn(ctx, "udp", "")
					if err != nil {
						lnc.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.Stringer("clientAddress", clientAddrPort),
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
							zap.Stringer("clientAddress", clientAddrPort),
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
						lnc.logger.Warn("Failed to create packer for serverConn",
							zap.Stringer("clientAddress", clientAddrPort),
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

					lnc.logger.Info("UDP NAT relay started",
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(ctx, natUplinkMmsg{
							clientName:     clientInfo.Name,
							clientAddrPort: clientAddrPort,
							natConn:        natConn.NewWConn(),
							natConnSendCh:  natConnSendCh,
							natConnPacker:  clientSession.Packer,
							natTimeout:     lnc.natTimeout,
							relayBatchSize: lnc.relayBatchSize,
							logger:         lnc.logger,
						})
						natConn.Close()
						clientSession.Close()
						s.wg.Done()
					}()

					s.relayNatConnToServerConnSendmmsg(natDownlinkMmsg{
						clientName:         clientInfo.Name,
						clientAddrPort:     clientAddrPort,
						clientPktinfop:     clientPktinfop,
						clientPktinfo:      &entry.clientPktinfo,
						natConn:            natConn.NewRConn(),
						natConnRecvBufSize: clientSession.MaxPacketSize,
						natConnUnpacker:    clientSession.Unpacker,
						serverConn:         serverConn.NewWConn(),
						serverConnPacker:   serverConnPacker,
						relayBatchSize:     lnc.relayBatchSize,
						logger:             lnc.logger,
					})
				}()

				if ce := lnc.logger.Check(zap.DebugLevel, "New UDP NAT session"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					)
				}
			}

			select {
			case entry.natConnSendCh <- queuedPacket:
			default:
				if ce := lnc.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", clientAddrPort),
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

func (s *UDPNATRelay) relayServerConnToNatConnSendmmsg(ctx context.Context, uplink natUplinkMmsg) {
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

	qpvec := make([]*natQueuedPacket, uplink.relayBatchSize)
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
					zap.Stringer("clientAddress", uplink.clientAddrPort),
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
					zap.Stringer("clientAddress", uplink.clientAddrPort),
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
				zap.Stringer("clientAddress", uplink.clientAddrPort),
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
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.String("client", uplink.clientName),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionUplink("", packetsSent, payloadBytesSent)
}

func (s *UDPNATRelay) relayNatConnToServerConnSendmmsg(downlink natDownlinkMmsg) {
	clientPktinfop := downlink.clientPktinfop
	clientPktinfo := *clientPktinfop
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, downlink.clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
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

		smsgvec[i].Msghdr.Name = name
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
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.String("client", downlink.clientName),
				zap.Error(err),
			)
			continue
		}

		var ns int
		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				downlink.logger.Error("Failed to parse sockaddr of packet from natConn",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.String("client", downlink.clientName),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				downlink.logger.Warn("Packet from natConn discarded",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
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
					zap.Stringer("clientAddress", downlink.clientAddrPort),
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
					zap.Stringer("clientAddress", downlink.clientAddrPort),
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

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = unsafe.SliceData(clientPktinfo)
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		for start := 0; start < ns; {
			n, err := downlink.serverConn.WriteMsgs(smsgvec[start:ns], 0)
			start += n
			if err != nil {
				downlink.logger.Warn("Failed to batch write packets to serverConn",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
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
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.String("client", downlink.clientName),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink("", packetsSent, payloadBytesSent)
}
