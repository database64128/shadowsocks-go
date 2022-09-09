package service

import (
	"errors"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (s *UDPNATRelay) setRelayServerConnToNatConnFunc(batchMode string) {
	switch batchMode {
	case "", "sendmmsg":
		s.relayServerConnToNatConn = s.relayServerConnToNatConnSendmmsg
	default:
		s.relayServerConnToNatConn = s.relayServerConnToNatConnGeneric
	}
}

func (s *UDPNATRelay) setRelayNatConnToServerConnFunc(batchMode string) {
	switch batchMode {
	case "", "sendmmsg":
		s.relayNatConnToServerConn = s.relayNatConnToServerConnSendmmsg
	default:
		s.relayNatConnToServerConn = s.relayNatConnToServerConnGeneric
	}
}

func (s *UDPNATRelay) relayServerConnToNatConnSendmmsg(clientAddrPort netip.AddrPort, entry *natEntry) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
	)

	dequeuedPackets := make([]queuedPacket, s.batchSize)
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
				s.logger.Warn("Failed to pack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", queuedPacket.targetAddr),
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
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("lastTargetAddress", dequeuedPackets[count-1].targetAddr),
				zap.Stringer("lastWriteDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		if err := entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
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
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

func (s *UDPNATRelay) relayNatConnToServerConnSendmmsg(clientAddrPort netip.AddrPort, entry *natEntry) {
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

	name, namelen := conn.AddrPortToSockaddr(clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, s.batchSize)
	bufvec := make([][]byte, s.batchSize)
	riovec := make([]unix.Iovec, s.batchSize)
	siovec := make([]unix.Iovec, s.batchSize)
	rmsgvec := make([]conn.Mmsghdr, s.batchSize)
	smsgvec := make([]conn.Mmsghdr, s.batchSize)

	for i := 0; i < s.batchSize; i++ {
		bufvec[i] = make([]byte, frontHeadroom+entry.natConnRecvBufSize+rearHeadroom)

		riovec[i].Base = &bufvec[i][frontHeadroom]
		riovec[i].SetLen(entry.natConnRecvBufSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
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
				zap.Error(err),
			)
			continue
		}

		smsgControl := entry.clientPktinfoCache
		smsgControlLen := len(smsgControl)
		var ns int

		for i, msg := range rmsgvec[:nr] {
			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from natConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(bufvec[i], packetSourceAddrPort, frontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetStart, packetLength, err := entry.serverConnPacker.PackInPlace(bufvec[i], payloadSourceAddrPort, payloadStart, payloadLength, entry.maxClientPacketSize)
			if err != nil {
				s.logger.Warn("Failed to pack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &bufvec[i][packetStart]
			siovec[ns].SetLen(packetLength)
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
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
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}
