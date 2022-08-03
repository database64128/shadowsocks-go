package service

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// natEntry is an entry in the NAT table.
type natEntry struct {
	clientOobCache                []byte
	natConn                       *net.UDPConn
	natConnMTU                    int
	natConnRecvBufSize            int
	natConnSendCh                 chan queuedPacket
	natConnPacker                 zerocopy.Packer
	natConnUnpacker               zerocopy.Unpacker
	natConnFixedTargetAddrPort    netip.AddrPort
	natConnUseFixedTargetAddrPort bool
	maxClientPacketSize           int
}

// UDPNATRelay is an address-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the source address and port.
type UDPNATRelay struct {
	serverName               string
	listenAddress            string
	listenerFwmark           int
	mtu                      int
	packetBufFrontHeadroom   int
	packetBufRearHeadroom    int
	packetBufRecvSize        int
	batchSize                int
	preferIPv6               bool
	serverPacker             zerocopy.Packer
	serverUnpacker           zerocopy.Unpacker
	serverConn               *net.UDPConn
	router                   *router.Router
	logger                   *zap.Logger
	packetBufPool            *sync.Pool
	mu                       sync.Mutex
	wg                       sync.WaitGroup
	table                    map[netip.AddrPort]*natEntry
	relayServerConnToNatConn func(clientAddrPort netip.AddrPort, entry *natEntry)
	relayNatConnToServerConn func(clientAddrPort netip.AddrPort, entry *natEntry)
}

func NewUDPNATRelay(
	batchMode, serverName, listenAddress string,
	batchSize, listenerFwmark, mtu, maxClientFrontHeadroom, maxClientRearHeadroom int,
	preferIPv6 bool,
	serverPacker zerocopy.Packer,
	serverUnpacker zerocopy.Unpacker,
	router *router.Router,
	logger *zap.Logger,
) *UDPNATRelay {
	packetBufFrontHeadroom := maxClientFrontHeadroom - serverUnpacker.FrontHeadroom()
	if packetBufFrontHeadroom < 0 {
		packetBufFrontHeadroom = 0
	}
	packetBufRearHeadroom := maxClientRearHeadroom - serverUnpacker.RearHeadroom()
	if packetBufRearHeadroom < 0 {
		packetBufRearHeadroom = 0
	}
	packetBufRecvSize := mtu - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength
	packetBufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, packetBufFrontHeadroom+packetBufRecvSize+packetBufRearHeadroom)
			return &b
		},
	}
	s := UDPNATRelay{
		serverName:             serverName,
		listenAddress:          listenAddress,
		listenerFwmark:         listenerFwmark,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufFrontHeadroom,
		packetBufRearHeadroom:  packetBufRearHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		batchSize:              batchSize,
		preferIPv6:             preferIPv6,
		serverPacker:           serverPacker,
		serverUnpacker:         serverUnpacker,
		router:                 router,
		logger:                 logger,
		packetBufPool:          packetBufPool,
		table:                  make(map[netip.AddrPort]*natEntry),
	}
	s.setRelayServerConnToNatConnFunc(batchMode)
	s.setRelayNatConnToServerConnFunc(batchMode)
	return &s
}

// String implements the Service String method.
func (s *UDPNATRelay) String() string {
	return fmt.Sprintf("UDP NAT relay service for %s", s.serverName)
}

// Start implements the Service Start method.
func (s *UDPNATRelay) Start() error {
	serverConn, err, serr := conn.ListenUDP("udp", s.listenAddress, true, s.listenerFwmark)
	if err != nil {
		return err
	}
	if serr != nil {
		s.logger.Warn("An error occurred while setting socket options on serverConn",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.Int("listenerFwmark", s.listenerFwmark),
			zap.NamedError("serr", serr),
		)
	}
	s.serverConn = serverConn

	go func() {
		oobBuf := make([]byte, conn.UDPOOBBufferSize)

		for {
			packetBufp := s.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			recvBuf := packetBuf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

			n, oobn, flags, clientAddrPort, err := s.serverConn.ReadMsgUDPAddrPort(recvBuf, oobBuf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					s.packetBufPool.Put(packetBufp)
					break
				}

				s.logger.Warn("Failed to read packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}
			err = conn.ParseFlagsForError(flags)
			if err != nil {
				s.logger.Warn("Failed to read packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			// Workaround for https://github.com/golang/go/issues/52264
			clientAddrPort = conn.Tov4Mappedv6(clientAddrPort)

			targetAddr, hasTargetAddr, payloadStart, payloadLength, err := s.serverUnpacker.UnpackInPlace(packetBuf, s.packetBufFrontHeadroom, n)
			if err != nil {
				s.logger.Warn("Failed to unpack packet",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("packetLength", n),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}
			if !hasTargetAddr {
				s.logger.Error("Server unpacker returned no target address",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("packetLength", n),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			s.mu.Lock()

			entry := s.table[clientAddrPort]
			if entry == nil {
				c, err := s.router.GetUDPClient(s.serverName, clientAddrPort, targetAddr)
				if err != nil {
					s.logger.Warn("Failed to get UDP client for new NAT session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}

				natConnFixedTargetAddrPort, natConnMTU, natConnFwmark, natConnUseFixedTargetAddrPort := c.AddrPort()
				natConnPacker, natConnUnpacker, err := c.NewSession()
				if err != nil {
					s.logger.Warn("Failed to create new UDP client session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}

				natConn, err, serr := conn.ListenUDP("udp", "", false, natConnFwmark)
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new NAT session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}
				if serr != nil {
					s.logger.Warn("An error occurred while setting socket options on natConn",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Error(serr),
					)
				}

				err = natConn.SetReadDeadline(time.Now().Add(natTimeout))
				if err != nil {
					s.logger.Warn("Failed to set read deadline on natConn",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
						zap.Error(err),
					)

					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}

				entry = &natEntry{
					natConn:                       natConn,
					natConnMTU:                    natConnMTU,
					natConnRecvBufSize:            natConnMTU - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength,
					natConnSendCh:                 make(chan queuedPacket, sendChannelCapacity),
					natConnPacker:                 natConnPacker,
					natConnUnpacker:               natConnUnpacker,
					natConnFixedTargetAddrPort:    natConnFixedTargetAddrPort,
					natConnUseFixedTargetAddrPort: natConnUseFixedTargetAddrPort,
					maxClientPacketSize:           zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr()),
				}

				s.table[clientAddrPort] = entry

				s.wg.Add(2)

				go func() {
					s.relayNatConnToServerConn(clientAddrPort, entry)

					s.mu.Lock()
					close(entry.natConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					s.wg.Done()
				}()

				go func() {
					s.relayServerConnToNatConn(clientAddrPort, entry)
					entry.natConn.Close()
					s.wg.Done()
				}()

				s.logger.Info("New UDP NAT session",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
				)
			}

			entry.clientOobCache, err = conn.UpdateOobCache(entry.clientOobCache, oobBuf[:oobn], s.logger)
			if err != nil {
				s.logger.Warn("Failed to process OOB from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Error(err),
				)
			}

			select {
			case entry.natConnSendCh <- queuedPacket{packetBufp, payloadStart, payloadLength, targetAddr}:
			default:
				s.logger.Debug("Dropping packet due to full send channel",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
				)

				s.packetBufPool.Put(packetBufp)
			}

			s.mu.Unlock()
		}
	}()

	s.logger.Info("Started UDP NAT relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Int("listenerFwmark", s.listenerFwmark),
	)

	return nil
}

func (s *UDPNATRelay) relayServerConnToNatConnGeneric(clientAddrPort netip.AddrPort, entry *natEntry) {
	// Cache the last used target address.
	//
	// When the target address is a domain, it is very likely that the target address won't change
	// throughout the lifetime of the session. In this case, caching the target address can eliminate
	// the per-packet DNS lookup overhead.
	var (
		cachedTargetAddr          socks5.Addr
		cachedTargetAddrPort      netip.AddrPort = entry.natConnFixedTargetAddrPort
		cachedTargetMaxPacketSize int            = zerocopy.MaxPacketSizeForAddr(entry.natConnMTU, entry.natConnFixedTargetAddrPort.Addr())
		packetsSent               uint64
		payloadBytesSent          uint64
	)

	for {
		queuedPacket, ok := <-entry.natConnSendCh
		if !ok {
			break
		}

		if !entry.natConnUseFixedTargetAddrPort && !bytes.Equal(cachedTargetAddr, queuedPacket.targetAddr) {
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
			cachedTargetAddrPort = targetAddrPort
			cachedTargetMaxPacketSize = zerocopy.MaxPacketSizeForAddr(entry.natConnMTU, targetAddrPort.Addr())
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

		_, err = entry.natConn.WriteToUDPAddrPort((*queuedPacket.bufp)[packetStart:packetStart+packetLength], cachedTargetAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Stringer("writeTargetAddress", cachedTargetAddrPort),
				zap.Error(err),
			)
		}

		err = entry.natConn.SetReadDeadline(time.Now().Add(natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
		}

		s.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		payloadBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("lastWriteTargetAddress", cachedTargetAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

func (s *UDPNATRelay) relayNatConnToServerConnGeneric(clientAddrPort netip.AddrPort, entry *natEntry) {
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
		packetsSent              uint64
		payloadBytesSent         uint64
	)

	packetBuf := make([]byte, frontHeadroom+entry.natConnRecvBufSize+rearHeadroom)
	recvBuf := packetBuf[frontHeadroom : frontHeadroom+entry.natConnRecvBufSize]

	for {
		n, _, flags, packetFromAddrPort, err := entry.natConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to read packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetFromAddress", packetFromAddrPort),
				zap.Error(err),
			)
			continue
		}

		targetAddr, hasTargetAddr, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, frontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetFromAddress", packetFromAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !hasTargetAddr {
			if packetFromAddrPort != cachedPacketFromAddrPort {
				cachedPacketFromAddrPort = packetFromAddrPort
				cachedTargetAddr = socks5.AppendAddrFromAddrPort(cachedTargetAddr[:0], packetFromAddrPort)
			}

			targetAddr = cachedTargetAddr
		}

		packetStart, packetLength, err := s.serverPacker.PackInPlace(packetBuf, targetAddr, payloadStart, payloadLength, entry.maxClientPacketSize)
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

		_, _, err = s.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], entry.clientOobCache, clientAddrPort)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			s.logger.Warn("Failed to write packet to serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("targetAddress", targetAddr),
				zap.Stringer("packetFromAddress", packetFromAddrPort),
				zap.Error(err),
			)
		}

		packetsSent++
		payloadBytesSent += uint64(payloadLength)
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

// Stop implements the Service Stop method.
func (s *UDPNATRelay) Stop() error {
	if s.serverConn == nil {
		return nil
	}
	s.serverConn.Close()

	now := time.Now()

	s.mu.Lock()
	for clientAddrPort, entry := range s.table {
		if err := entry.natConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	s.wg.Wait()
	return nil
}
