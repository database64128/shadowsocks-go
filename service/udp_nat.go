package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// natQueuedPacket is the structure used by send channels to queue packets for sending.
type natQueuedPacket struct {
	buf        []byte
	start      int
	length     int
	targetAddr conn.Addr
}

// natEntry is an entry in the NAT table.
type natEntry struct {
	// state synchronizes session initialization and shutdown.
	//
	//  - Swap the natConn in to signal initialization completion.
	//  - Swap the serverConn in to signal shutdown.
	//
	// Callers must check the swapped-out value to determine the next action.
	//
	//  - During initialization, if the swapped-out value is non-nil,
	//    initialization must not proceed.
	//  - During shutdown, if the swapped-out value is nil, preceed to the next entry.
	state              atomic.Pointer[net.UDPConn]
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	natConnSendCh      chan<- *natQueuedPacket
	serverConn         *net.UDPConn
	serverConnUnpacker zerocopy.ServerUnpacker
	logger             *zap.Logger
}

// natUplinkGeneric is used for passing information about relay uplink to the relay goroutine.
type natUplinkGeneric struct {
	clientName     string
	clientAddrPort netip.AddrPort
	natConn        *net.UDPConn
	natConnSendCh  <-chan *natQueuedPacket
	natConnPacker  zerocopy.ClientPacker
	natTimeout     time.Duration
	logger         *zap.Logger
}

// natDownlinkGeneric is used for passing information about relay downlink to the relay goroutine.
type natDownlinkGeneric struct {
	clientName         string
	clientAddrPort     netip.AddrPort
	clientPktinfo      *atomic.Pointer[[]byte]
	natConn            *net.UDPConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConn         *net.UDPConn
	serverConnPacker   zerocopy.ServerPacker
	logger             *zap.Logger
}

// UDPNATRelay is an address-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the source address and port.
type UDPNATRelay struct {
	serverName             string
	serverIndex            int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	listeners              []udpRelayServerConn
	server                 zerocopy.UDPNATServer
	collector              stats.Collector
	router                 *router.Router
	logger                 *zap.Logger
	queuedPacketPool       sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[netip.AddrPort]*natEntry
}

func NewUDPNATRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	server zerocopy.UDPNATServer,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *UDPNATRelay {
	return &UDPNATRelay{
		serverName:             serverName,
		serverIndex:            serverIndex,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufFrontHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		listeners:              listeners,
		server:                 server,
		collector:              collector,
		router:                 router,
		logger:                 logger,
		queuedPacketPool: sync.Pool{
			New: func() any {
				return &natQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table: make(map[netip.AddrPort]*natEntry),
	}
}

// String implements the Service String method.
func (s *UDPNATRelay) String() string {
	return "UDP NAT relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *UDPNATRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		if err := s.start(ctx, i, &s.listeners[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *UDPNATRelay) startGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) (err error) {
	lnc.serverConn, err = lnc.listenConfig.ListenUDP(ctx, lnc.network, lnc.address)
	if err != nil {
		return
	}
	lnc.address = lnc.serverConn.LocalAddr().String()
	lnc.logger = s.logger.With(
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
	)

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnGeneric(ctx, lnc)
		s.mwg.Done()
	}()

	lnc.logger.Info("Started UDP NAT relay service listener")
	return
}

func (s *UDPNATRelay) recvFromServerConnGeneric(ctx context.Context, lnc *udpRelayServerConn) {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		queuedPacket := s.getQueuedPacket()
		packetBuf := queuedPacket.buf
		recvBuf := packetBuf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, clientAddrPort, err := lnc.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putQueuedPacket(queuedPacket)
				break
			}

			lnc.logger.Warn("Failed to read packet from serverConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			lnc.logger.Warn("Failed to read packet from serverConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		s.mu.Lock()

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
				s.mu.Unlock()
				continue
			}
		}

		queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(packetBuf, clientAddrPort, s.packetBufFrontHeadroom, n)
		if err != nil {
			lnc.logger.Warn("Failed to unpack packet from serverConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			s.mu.Unlock()
			continue
		}

		packetsReceived++
		payloadBytesReceived += uint64(queuedPacket.length)

		cmsg := cmsgBuf[:cmsgn]

		if !bytes.Equal(entry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				lnc.logger.Warn("Failed to parse pktinfo control message from serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.mu.Unlock()
				continue
			}

			clientPktinfoCache := make([]byte, len(cmsg))
			copy(clientPktinfoCache, cmsg)
			entry.clientPktinfo.Store(&clientPktinfoCache)
			entry.clientPktinfoCache = clientPktinfoCache

			if ce := lnc.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
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

				natConn, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
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
					lnc.logger.Warn("Failed to set read deadline on natConn",
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

				oldState := entry.state.Swap(natConn)
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
					s.relayServerConnToNatConnGeneric(ctx, natUplinkGeneric{
						clientName:     clientInfo.Name,
						clientAddrPort: clientAddrPort,
						natConn:        natConn,
						natConnSendCh:  natConnSendCh,
						natConnPacker:  clientSession.Packer,
						natTimeout:     lnc.natTimeout,
						logger:         lnc.logger,
					})
					natConn.Close()
					clientSession.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(natDownlinkGeneric{
					clientName:         clientInfo.Name,
					clientAddrPort:     clientAddrPort,
					clientPktinfo:      &entry.clientPktinfo,
					natConn:            natConn,
					natConnRecvBufSize: clientSession.MaxPacketSize,
					natConnUnpacker:    clientSession.Unpacker,
					serverConn:         lnc.serverConn,
					serverConnPacker:   serverConnPacker,
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

		s.mu.Unlock()
	}

	lnc.logger.Info("Finished receiving from serverConn",
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPNATRelay) relayServerConnToNatConnGeneric(ctx context.Context, uplink natUplinkGeneric) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range uplink.natConnSendCh {
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
			continue
		}

		_, err = uplink.natConn.WriteToUDPAddrPort(queuedPacket.buf[packetStart:packetStart+packetLength], destAddrPort)
		if err != nil {
			uplink.logger.Warn("Failed to write packet to natConn",
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.String("client", uplink.clientName),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		err = uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout))
		if err != nil {
			uplink.logger.Warn("Failed to set read deadline on natConn",
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.String("client", uplink.clientName),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.Duration("natTimeout", uplink.natTimeout),
				zap.Error(err),
			)
		}

		s.putQueuedPacket(queuedPacket)
		packetsSent++
		payloadBytesSent += uint64(queuedPacket.length)
	}

	uplink.logger.Info("Finished relay serverConn -> natConn",
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.String("client", uplink.clientName),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionUplink("", packetsSent, payloadBytesSent)
}

func (s *UDPNATRelay) relayNatConnToServerConnGeneric(downlink natDownlinkGeneric) {
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, downlink.clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		clientPktinfo    []byte
		clientPktinfop   *[]byte
		packetsSent      uint64
		payloadBytesSent uint64
	)

	packetBuf := make([]byte, headroom.Front+downlink.natConnRecvBufSize+headroom.Rear)
	recvBuf := packetBuf[headroom.Front : headroom.Front+downlink.natConnRecvBufSize]

	for {
		n, _, flags, packetSourceAddrPort, err := downlink.natConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			downlink.logger.Warn("Failed to read packet from natConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			downlink.logger.Warn("Failed to read packet from natConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, n)
		if err != nil {
			downlink.logger.Warn("Failed to unpack packet from natConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
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

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = downlink.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, downlink.clientAddrPort)
		if err != nil {
			downlink.logger.Warn("Failed to write packet to serverConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Error(err),
			)
		}

		packetsSent++
		payloadBytesSent += uint64(payloadLength)
	}

	downlink.logger.Info("Finished relay serverConn <- natConn",
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.String("client", downlink.clientName),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionDownlink("", packetsSent, payloadBytesSent)
}

// getQueuedPacket retrieves a queued packet from the pool.
func (s *UDPNATRelay) getQueuedPacket() *natQueuedPacket {
	return s.queuedPacketPool.Get().(*natQueuedPacket)
}

// putQueuedPacket puts the queued packet back into the pool.
func (s *UDPNATRelay) putQueuedPacket(queuedPacket *natQueuedPacket) {
	s.queuedPacketPool.Put(queuedPacket)
}

// Stop implements the Service Stop method.
func (s *UDPNATRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Warn("Failed to set read deadline on serverConn", zap.Error(err))
		}
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.mu.Lock()
	for clientAddrPort, entry := range s.table {
		natConn := entry.state.Swap(entry.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			entry.logger.Warn("Failed to set read deadline on natConn",
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.Close(); err != nil {
			lnc.logger.Warn("Failed to close serverConn", zap.Error(err))
		}
	}

	return nil
}
