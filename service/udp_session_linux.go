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
	bufvec := make([]*[]byte, conn.UIO_MAXIOV)
	namevec := make([]unix.RawSockaddrInet6, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	cmsgvec := make([][]byte, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	n := conn.UIO_MAXIOV

	var (
		err                  error
		recvmmsgCount        uint64
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		for i := range iovec[:n] {
			packetBufp := s.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			bufvec[i] = packetBufp
			iovec[i].Base = &packetBuf[s.packetBufFrontHeadroom]
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
			s.packetBufPool.Put(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)

		s.mu.Lock()

		for i, msg := range msgvec[:n] {
			packetBufp := bufvec[i]
			packetBuf := *packetBufp
			packet := packetBuf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+int(msg.Msglen)]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from serverConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			csid, err := s.server.SessionInfo(packet)
			if err != nil {
				s.logger.Warn("Failed to extract session info from packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			entry, ok := s.table[csid]
			if !ok {
				entry = &session{}

				entry.serverConnUnpacker, err = s.server.NewUnpacker(packet, csid)
				if err != nil {
					s.logger.Warn("Failed to create unpacker for client session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Uint64("clientSessionID", csid),
						zap.Uint32("packetLength", msg.Msglen),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					continue
				}
			}

			targetAddr, payloadStart, payloadLength, err := entry.serverConnUnpacker.UnpackInPlace(packetBuf, clientAddrPort, s.packetBufFrontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint64("clientSessionID", csid),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			payloadBytesReceived += uint64(payloadLength)

			var clientAddrInfop *sessionClientAddrInfo

			updateClientAddrPort := entry.clientAddrPortCache != clientAddrPort
			updateClientPktinfo := !bytes.Equal(entry.clientPktinfoCache, cmsg)

			if updateClientAddrPort {
				entry.clientAddrPortCache = clientAddrPort
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Uint64("clientSessionID", csid),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					continue
				}

				clientAddrInfop = &sessionClientAddrInfo{clientAddrPort, entry.clientPktinfoCache}
				entry.clientAddrInfo.Store(clientAddrInfop)

				s.logger.Debug("Updated client address info",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
					zap.Uint64("clientSessionID", csid),
				)
			}

			if !ok {
				entry.natConnSendCh = make(chan sessionQueuedPacket, sendChannelCapacity)
				s.table[csid] = entry

				go func() {
					var sendChClean bool

					defer func() {
						s.mu.Lock()
						close(entry.natConnSendCh)
						delete(s.table, csid)
						s.mu.Unlock()

						if !sendChClean {
							for queuedPacket := range entry.natConnSendCh {
								s.packetBufPool.Put(queuedPacket.bufp)
							}
						}
					}()

					c, err := s.router.GetUDPClient(s.serverName, clientAddrPort, targetAddr)
					if err != nil {
						s.logger.Warn("Failed to get UDP client for new NAT session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddr),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					// Only add for the current goroutine here, since we don't want the router to block exiting.
					s.wg.Add(1)
					defer s.wg.Done()

					natConnMaxPacketSize, natConnFwmark := c.LinkInfo()
					natConnPacker, natConnUnpacker, err := c.NewSession()
					if err != nil {
						s.logger.Warn("Failed to create new UDP client session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddr),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					serverConnPacker, err := s.server.NewPacker(csid)
					if err != nil {
						s.logger.Warn("Failed to create packer for client session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Uint64("clientSessionID", csid),
							zap.Error(err),
						)
						return
					}

					natConn, err, serr := conn.ListenUDP("udp", "", false, natConnFwmark)
					if err != nil {
						s.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddr),
							zap.Uint64("clientSessionID", csid),
							zap.Int("natConnFwmark", natConnFwmark),
							zap.Error(err),
						)
						return
					}
					if serr != nil {
						s.logger.Warn("An error occurred while setting socket options on natConn",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddr),
							zap.Uint64("clientSessionID", csid),
							zap.Int("natConnFwmark", natConnFwmark),
							zap.Error(serr),
						)
					}

					err = natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
					if err != nil {
						s.logger.Warn("Failed to set read deadline on natConn",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddr),
							zap.Duration("natTimeout", s.natTimeout),
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

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(csid, entry)
						entry.natConn.Close()
						s.wg.Done()
					}()

					s.relayNatConnToServerConnSendmmsg(csid, entry, clientAddrInfop)
				}()

				s.logger.Info("New UDP session",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Uint64("clientSessionID", csid),
				)
			}

			select {
			case entry.natConnSendCh <- sessionQueuedPacket{packetBufp, payloadStart, payloadLength, targetAddr, clientAddrPort}:
			default:
				s.logger.Debug("Dropping packet due to full send channel",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Uint64("clientSessionID", csid),
				)

				s.packetBufPool.Put(packetBufp)
			}
		}

		s.mu.Unlock()
	}

	for _, packetBufp := range bufvec {
		s.packetBufPool.Put(packetBufp)
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
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
	)

	dequeuedPackets := make([]sessionQueuedPacket, s.batchSize)
	namevec := make([]unix.RawSockaddrInet6, s.batchSize)
	iovec := make([]unix.Iovec, s.batchSize)
	msgvec := make([]conn.Mmsghdr, s.batchSize)

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
			destAddrPort, packetStart, packetLength, err = entry.natConnPacker.PackInPlace(*queuedPacket.bufp, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
			if err != nil {
				s.logger.Warn("Failed to pack packet for natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
					zap.Stringer("targetAddress", queuedPacket.targetAddr),
					zap.Uint64("clientSessionID", csid),
					zap.Error(err),
				)

				s.packetBufPool.Put(queuedPacket.bufp)

				if count == 0 {
					continue main
				}
				goto next
			}

			dequeuedPackets[count] = queuedPacket
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &(*queuedPacket.bufp)[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.length)

			if count == s.batchSize {
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
				zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
				zap.Stringer("lastTargetAddress", dequeuedPackets[count-1].targetAddr),
				zap.Stringer("lastWriteDestAddress", destAddrPort),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		if err := entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

		for _, packet := range dequeuedPackets[:count] {
			s.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
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
	)

	rsa6, namelen := conn.AddrPortToSockaddrValue(clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, s.batchSize)
	bufvec := make([][]byte, s.batchSize)
	riovec := make([]unix.Iovec, s.batchSize)
	siovec := make([]unix.Iovec, s.batchSize)
	rmsgvec := make([]conn.Mmsghdr, s.batchSize)
	smsgvec := make([]conn.Mmsghdr, s.batchSize)

	for i := 0; i < s.batchSize; i++ {
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

		for i, msg := range rmsgvec[:nr] {
			packetBuf := bufvec[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
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
					zap.Uint64("clientSessionID", csid),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, frontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
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
					zap.Uint64("clientSessionID", csid),
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
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}
