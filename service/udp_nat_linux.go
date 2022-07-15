package service

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
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
	// Cache the last used target address.
	//
	// When the target address is a domain, it is very likely that the target address won't change
	// throughout the lifetime of the session. In this case, caching the target address can eliminate
	// the per-packet DNS lookup overhead.
	var (
		cachedTargetAddr          socks5.Addr
		name                      *byte
		namelen                   uint32
		cachedTargetMaxPacketSize int
		sendmmsgCount             uint64
		packetsSent               uint64
		payloadBytesSent          uint64
	)

	if entry.natConnUseFixedTargetAddrPort {
		name, namelen = conn.AddrPortToSockaddr(entry.natConnFixedTargetAddrPort)
		cachedTargetMaxPacketSize = zerocopy.MaxPacketSizeForAddr(entry.natConnMTU, entry.natConnFixedTargetAddrPort.Addr())
	}

	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	// Initialize msgvec.
	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	// Main relay loop.
	for {
		var count int

		// Block on first dequeue op.
		queuedPacket, ok := <-entry.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			if !entry.natConnUseFixedTargetAddrPort {
				if !bytes.Equal(cachedTargetAddr, queuedPacket.targetAddr) {
					targetAddrPort, err := queuedPacket.targetAddr.AddrPort(s.preferIPv6)
					if err != nil {
						s.logger.Warn("Failed to get target address port",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", queuedPacket.targetAddr),
							zap.Error(err),
						)

						s.packetBufPool.Put(queuedPacket.bufp)
						continue
					}

					// Workaround for https://github.com/golang/go/issues/52264
					targetAddrPort = conn.Tov4Mappedv6(targetAddrPort)

					cachedTargetAddr = append(cachedTargetAddr[:0], queuedPacket.targetAddr...)
					name, namelen = conn.AddrPortToSockaddr(targetAddrPort)
					cachedTargetMaxPacketSize = zerocopy.MaxPacketSizeForAddr(entry.natConnMTU, targetAddrPort.Addr())
				}

				msgvec[count].Msghdr.Name = name
				msgvec[count].Msghdr.Namelen = namelen
			}

			packetStart, packetLength, err := entry.natConnPacker.PackInPlace(*queuedPacket.bufp, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, cachedTargetMaxPacketSize)
			if err != nil {
				s.logger.Warn("Failed to pack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", queuedPacket.targetAddr),
					zap.Error(err),
				)

				s.packetBufPool.Put(queuedPacket.bufp)
				continue
			}

			dequeuedPackets[count] = queuedPacket
			iovec[count].Base = &(*queuedPacket.bufp)[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.length)

			if count == vecSize {
				break
			}

			select {
			case queuedPacket, ok = <-entry.natConnSendCh:
				if !ok {
					goto cleanup
				}
			default:
				break dequeue
			}
		}

		// Batch write.
		if err := conn.WriteMsgvec(entry.natConn, msgvec[:count]); err != nil {
			s.logger.Warn("Failed to batch write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("lastTargetAddress", queuedPacket.targetAddr),
				zap.Stringer("lastWriteTargetAddress", cachedTargetAddr),
				zap.Error(err),
			)
		}

		if err := entry.natConn.SetReadDeadline(time.Now().Add(natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

	cleanup:
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
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

func (s *UDPNATRelay) relayNatConnToServerConnSendmmsg(clientAddrPort netip.AddrPort, entry *natEntry) {
	frontHeadroom := s.serverPacker.FrontHeadroom() - entry.natConnUnpacker.FrontHeadroom()
	if frontHeadroom < 0 {
		frontHeadroom = 0
	}
	rearHeadroom := s.serverPacker.RearHeadroom() - entry.natConnUnpacker.RearHeadroom()
	if rearHeadroom < 0 {
		rearHeadroom = 0
	}

	var (
		cachedTargetAddr         socks5.Addr
		cachedPacketFromAddrPort netip.AddrPort
		sendmmsgCount            uint64
		packetsSent              uint64
		payloadBytesSent         uint64
	)

	name, namelen := conn.AddrPortToSockaddr(clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	// Initialize riovec, rmsgvec and smsgvec.
	for i := 0; i < vecSize; i++ {
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

	// Main relay loop.
	for {
		nr, err := conn.Recvmmsg(entry.natConn, rmsgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
			continue
		}

		smsgControl := entry.clientOobCache
		smsgControlLen := len(smsgControl)
		var ns int

		for i, msg := range rmsgvec[:nr] {
			packetFromAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
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
					zap.Stringer("packetFromAddress", packetFromAddrPort),
					zap.Error(err),
				)
				continue
			}

			targetAddr, hasTargetAddr, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(bufvec[i], frontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetFromAddress", packetFromAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}
			if !hasTargetAddr {
				if packetFromAddrPort != cachedPacketFromAddrPort {
					cachedPacketFromAddrPort = packetFromAddrPort
					cachedTargetAddr = socks5.AppendFromAddrPort(cachedTargetAddr[:0], packetFromAddrPort)
				}

				targetAddr = cachedTargetAddr
			}

			packetStart, packetLength, err := s.serverPacker.PackInPlace(bufvec[i], targetAddr, payloadStart, payloadLength, entry.maxClientPacketSize)
			if err != nil {
				s.logger.Warn("Failed to pack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Stringer("packetFromAddress", packetFromAddrPort),
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
			if errors.Is(err, net.ErrClosed) {
				break
			}

			s.logger.Warn("Failed to batch write packet to serverConn",
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
