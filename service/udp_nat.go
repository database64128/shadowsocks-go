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
	natConnSendCh                 chan queuedPacket
	natConnPacker                 zerocopy.Packer
	natConnUnpacker               zerocopy.Unpacker
	natConnFixedTargetAddrPort    netip.AddrPort
	natConnUseFixedTargetAddrPort bool
	natConnLastTargetAddr         socks5.Addr
	natConnLastTargetAddrPort     netip.AddrPort
	maxClientPacketSize           int
}

// UDPNATRelay is a UDP relay service based on NAT.
//
// Incoming UDP packets are dispatched to NAT sessions based on the source address and port.
type UDPNATRelay struct {
	batchMode      string
	serverName     string
	listenAddress  string
	listenerFwmark int
	mtu            int
	preferIPv6     bool
	serverPacker   zerocopy.Packer
	serverUnpacker zerocopy.Unpacker
	serverConn     *net.UDPConn
	router         *router.Router
	logger         *zap.Logger
	packetBufPool  *sync.Pool
	mu             sync.Mutex
	wg             sync.WaitGroup
	table          map[netip.AddrPort]*natEntry
}

func NewUDPNATRelay(
	batchMode, serverName, listenAddress string,
	listenerFwmark, mtu int,
	serverPacker zerocopy.Packer,
	serverUnpacker zerocopy.Unpacker,
	router *router.Router,
	logger *zap.Logger,
) (*UDPNATRelay, error) {
	if mtu < 1280 {
		return nil, ErrMTUTooSmall
	}

	packetBufSize := mtu - IPv4HeaderLength - UDPHeaderLength
	packetBufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, packetBufSize)
			return &b
		},
	}

	return &UDPNATRelay{
		batchMode:      batchMode,
		serverName:     serverName,
		listenAddress:  listenAddress,
		listenerFwmark: listenerFwmark,
		mtu:            mtu,
		serverPacker:   serverPacker,
		serverUnpacker: serverUnpacker,
		router:         router,
		logger:         logger,
		packetBufPool:  packetBufPool,
		table:          make(map[netip.AddrPort]*natEntry),
	}, nil
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

			n, oobn, flags, clientAddrPort, err := s.serverConn.ReadMsgUDPAddrPort(packetBuf, oobBuf)
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

			targetAddr, payloadStart, payloadLength, err := s.serverUnpacker.UnpackInPlace(packetBuf, 0, n)
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
					natConnSendCh:                 make(chan queuedPacket, sendChannelCapacity),
					natConnPacker:                 natConnPacker,
					natConnUnpacker:               natConnUnpacker,
					natConnFixedTargetAddrPort:    natConnFixedTargetAddrPort,
					natConnUseFixedTargetAddrPort: natConnUseFixedTargetAddrPort,
				}

				if addr := clientAddrPort.Addr(); addr.Is4() || addr.Is4In6() {
					entry.maxClientPacketSize = s.mtu - IPv4HeaderLength - UDPHeaderLength
				} else {
					entry.maxClientPacketSize = s.mtu - IPv6HeaderLength - UDPHeaderLength
				}

				s.table[clientAddrPort] = entry

				s.wg.Add(2)

				go func() {
					s.relayNatConnToServerConnGeneric(clientAddrPort, entry)

					s.mu.Lock()
					close(entry.natConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					s.wg.Done()
				}()

				go func() {
					s.relayServerConnToNatConnGeneric(clientAddrPort, entry)
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
	for {
		queuedPacket, ok := <-entry.natConnSendCh
		if !ok {
			break
		}

		packetStart, packetLength, err := entry.natConnPacker.PackInPlace(*queuedPacket.bufp, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
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

		targetAddrPort := entry.natConnFixedTargetAddrPort
		if !entry.natConnUseFixedTargetAddrPort {
			// Try cached targetAddrPort first.
			if bytes.Equal(entry.natConnLastTargetAddr, queuedPacket.targetAddr) {
				targetAddrPort = entry.natConnLastTargetAddrPort
			} else {
				targetAddrPort, err = queuedPacket.targetAddr.AddrPort(s.preferIPv6)
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

				entry.natConnLastTargetAddr = queuedPacket.targetAddr
				entry.natConnLastTargetAddrPort = targetAddrPort
			}
		}

		_, err = entry.natConn.WriteToUDPAddrPort((*queuedPacket.bufp)[packetStart:packetStart+packetLength], targetAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Stringer("writeTargetAddress", targetAddrPort),
				zap.Error(err),
			)
		}

		s.packetBufPool.Put(queuedPacket.bufp)
	}
}

func (s *UDPNATRelay) relayNatConnToServerConnGeneric(clientAddrPort netip.AddrPort, entry *natEntry) {
	serverFrontHeadroom := s.serverPacker.FrontHeadroom()
	serverRearHeadroom := s.serverPacker.RearHeadroom()
	clientFrontHeadroom := entry.natConnPacker.FrontHeadroom()
	clientRearHeadroom := entry.natConnPacker.RearHeadroom()

	var frontHeadroom, rearHeadroom int
	if serverFrontHeadroom > clientFrontHeadroom {
		frontHeadroom = serverFrontHeadroom - clientFrontHeadroom
	}
	if serverRearHeadroom > clientRearHeadroom {
		rearHeadroom = serverRearHeadroom - clientRearHeadroom
	}

	packetBuf := make([]byte, frontHeadroom+entry.maxClientPacketSize+rearHeadroom)
	recvBuf := packetBuf[frontHeadroom : frontHeadroom+entry.maxClientPacketSize]

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

		targetAddr, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, frontHeadroom, n)
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

		packetStart, packetLength, err := s.serverPacker.PackInPlace(packetBuf, targetAddr, payloadStart, payloadLength)
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
	}
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
