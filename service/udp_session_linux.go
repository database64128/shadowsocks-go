package service

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (s *UDPSessionRelay) setRelayFunc(batchMode string) {
	switch batchMode {
	case "sendmmsg", "":
		s.recvFromServerConn = s.recvFromServerConnRecvmmsg
	default:
		s.recvFromServerConn = s.recvFromServerConnGeneric
	}
}

func (s *UDPSessionRelay) recvFromServerConnRecvmmsg() {
	qpvec := make([]*sessionQueuedPacket, s.serverRecvBatchSize)
	namevec := make([]unix.RawSockaddrInet6, s.serverRecvBatchSize)
	iovec := make([]unix.Iovec, s.serverRecvBatchSize)
	cmsgvec := make([][]byte, s.serverRecvBatchSize)
	msgvec := make([]conn.Mmsghdr, s.serverRecvBatchSize)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	n := s.serverRecvBatchSize

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

		n, err = conn.Recvmmsg(s.serverConn, msgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Error(err),
			)

			n = 1
			s.putQueuedPacket(qpvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		if burstBatchSize < n {
			burstBatchSize = n
		}

		s.server.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			queuedPacket := qpvec[i]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			queuedPacket.clientAddrPort, err = conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from serverConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
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
				s.logger.Warn("Failed to extract session info from packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			entry, ok := s.table[csid]
			if !ok {
				entry = &session{}

				entry.serverConnUnpacker, entry.username, err = s.server.NewUnpacker(packet, csid)
				if err != nil {
					s.logger.Warn("Failed to create unpacker for client session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
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
				s.logger.Warn("Failed to unpack packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
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
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					s.logger.Warn("Failed to parse pktinfo control message from serverConn",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Error(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}

				clientAddrInfop = &sessionClientAddrInfo{entry.clientAddrPortCache, entry.clientPktinfoCache}
				entry.clientAddrInfo.Store(clientAddrInfop)

				if ce := s.logger.Check(zap.DebugLevel, "Updated client address info"); ce != nil {
					ce.Write(
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
					)
				}
			}

			if !ok {
				entry.natConnSendCh = make(chan *sessionQueuedPacket, s.sendChannelCapacity)
				s.table[csid] = entry

				go func() {
					var sendChClean bool

					defer func() {
						s.server.Lock()
						close(entry.natConnSendCh)
						delete(s.table, csid)
						s.server.Unlock()

						if !sendChClean {
							for queuedPacket := range entry.natConnSendCh {
								s.putQueuedPacket(queuedPacket)
							}
						}
					}()

					c, err := s.router.GetUDPClient(s.serverName, queuedPacket.clientAddrPort, queuedPacket.targetAddr)
					if err != nil {
						s.logger.Warn("Failed to get UDP client for new NAT session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					clientName := c.String()

					// Only add for the current goroutine here, since we don't want the router to block exiting.
					s.wg.Add(1)
					defer s.wg.Done()

					natConnMaxPacketSize, natConnFwmark := c.LinkInfo()
					natConnPacker, natConnUnpacker, err := c.NewSession()
					if err != nil {
						s.logger.Warn("Failed to create new UDP client session",
							zap.String("server", s.serverName),
							zap.String("client", clientName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					serverConnPacker, err := s.server.NewPacker(csid)
					if err != nil {
						s.logger.Warn("Failed to create packer for client session",
							zap.String("server", s.serverName),
							zap.String("client", clientName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					natConn, err := conn.ListenUDP("udp", "", false, natConnFwmark)
					if err != nil {
						s.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.String("server", s.serverName),
							zap.String("client", clientName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Int("natConnFwmark", natConnFwmark),
							zap.Error(err),
						)
						return
					}

					err = natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
					if err != nil {
						s.logger.Warn("Failed to set read deadline on natConn",
							zap.String("server", s.serverName),
							zap.String("client", clientName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddr),
							zap.Duration("natTimeout", s.natTimeout),
							zap.String("username", entry.username),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						natConn.Close()
						return
					}

					oldState := entry.state.Swap(natConn)
					if oldState != nil {
						natConn.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					entry.natConn = natConn
					entry.natConnRecvBufSize = natConnMaxPacketSize
					entry.natConnPacker = natConnPacker
					entry.natConnUnpacker = natConnUnpacker
					entry.serverConnPacker = serverConnPacker

					s.logger.Info("UDP session relay started",
						zap.String("server", s.serverName),
						zap.String("client", clientName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(csid, entry)
						entry.natConn.Close()
						s.wg.Done()
					}()

					s.relayNatConnToServerConnSendmmsg(csid, entry, clientAddrInfop)
				}()

				if ce := s.logger.Check(zap.DebugLevel, "New UDP session"); ce != nil {
					ce.Write(
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
					)
				}
			}

			select {
			case entry.natConnSendCh <- queuedPacket:
			default:
				if ce := s.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
					ce.Write(
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
					)
				}

				s.putQueuedPacket(queuedPacket)
			}
		}

		s.server.Unlock()
	}

	for i := range qpvec {
		s.putQueuedPacket(qpvec[i])
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnSendmmsg(csid uint64, entry *session) {
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

	qpvec := make([]*sessionQueuedPacket, s.relayBatchSize)
	namevec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	iovec := make([]unix.Iovec, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, s.relayBatchSize)

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
		queuedPacket, ok := <-entry.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			destAddrPort, packetStart, packetLength, err = entry.natConnPacker.PackInPlace(queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
			if err != nil {
				s.logger.Warn("Failed to pack packet for natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
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
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &queuedPacket.buf[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.length)

			if count == s.relayBatchSize {
				break
			}

		next:
			select {
			case queuedPacket, ok = <-entry.natConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		if err := conn.WriteMsgvec(entry.natConn, msgvec[:count]); err != nil {
			s.logger.Warn("Failed to batch write packets to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Stringer("lastTargetAddress", &qpvec[count-1].targetAddr),
				zap.Stringer("lastWriteDestAddress", destAddrPort),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		if err := entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)
		if burstBatchSize < count {
			burstBatchSize = count
		}

		qpvecn := qpvec[:count]

		for i := range qpvecn {
			s.putQueuedPacket(qpvecn[i])
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.String("username", entry.username),
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionUplink(entry.username, packetsSent, payloadBytesSent)
}

func (s *UDPSessionRelay) relayNatConnToServerConnSendmmsg(csid uint64, entry *session, clientAddrInfop *sessionClientAddrInfo) {
	clientAddrPort := clientAddrInfop.addrPort
	clientPktinfo := clientAddrInfop.pktinfo
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())

	frontHeadroom := entry.serverConnPacker.FrontHeadroom() - entry.natConnUnpacker.FrontHeadroom()
	if frontHeadroom < 0 {
		frontHeadroom = 0
	}
	rearHeadroom := entry.serverConnPacker.RearHeadroom() - entry.natConnUnpacker.RearHeadroom()
	if rearHeadroom < 0 {
		rearHeadroom = 0
	}

	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	rsa6, namelen := conn.AddrPortToSockaddrValue(clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	bufvec := make([][]byte, s.relayBatchSize)
	riovec := make([]unix.Iovec, s.relayBatchSize)
	siovec := make([]unix.Iovec, s.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, s.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, s.relayBatchSize)

	for i := 0; i < s.relayBatchSize; i++ {
		packetBuf := make([]byte, frontHeadroom+entry.natConnRecvBufSize+rearHeadroom)
		bufvec[i] = packetBuf

		riovec[i].Base = &packetBuf[frontHeadroom]
		riovec[i].SetLen(entry.natConnRecvBufSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	for {
		nr, err := conn.Recvmmsg(entry.natConn, rmsgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
			continue
		}

		if caip := entry.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
			rsa6, _ = conn.AddrPortToSockaddrValue(clientAddrPort) // namelen won't change

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		var ns int
		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Failed to read packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, frontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetStart, packetLength, err := entry.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
			if err != nil {
				s.logger.Warn("Failed to pack packet for serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
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

		err = conn.WriteMsgvec(s.serverConn, smsgvec[:ns])
		if err != nil {
			s.logger.Warn("Failed to batch write packets to serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
		if burstBatchSize < ns {
			burstBatchSize = ns
		}
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.String("username", entry.username),
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink(entry.username, packetsSent, payloadBytesSent)
}
