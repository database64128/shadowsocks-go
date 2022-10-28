package service

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
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
	natConn            *net.UDPConn
	natConnRecvBufSize int
	natConnSendCh      chan *natQueuedPacket
	natConnPacker      zerocopy.ClientPacker
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConnPacker   zerocopy.ServerPacker
	serverConnUnpacker zerocopy.ServerUnpacker
}

// UDPNATRelay is an address-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the source address and port.
type UDPNATRelay struct {
	serverName             string
	listenAddress          string
	listenerFwmark         int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	batchSize              int
	natTimeout             time.Duration
	server                 zerocopy.UDPNATServer
	serverConn             *net.UDPConn
	router                 *router.Router
	logger                 *zap.Logger
	queuedPacketPool       sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[netip.AddrPort]*natEntry
	recvFromServerConn     func()
}

func NewUDPNATRelay(
	batchMode, serverName, listenAddress string,
	batchSize, listenerFwmark, mtu, maxClientFrontHeadroom, maxClientRearHeadroom int,
	natTimeout time.Duration,
	server zerocopy.UDPNATServer,
	router *router.Router,
	logger *zap.Logger,
) *UDPNATRelay {
	packetBufFrontHeadroom := maxClientFrontHeadroom - server.FrontHeadroom()
	if packetBufFrontHeadroom < 0 {
		packetBufFrontHeadroom = 0
	}
	packetBufRearHeadroom := maxClientRearHeadroom - server.RearHeadroom()
	if packetBufRearHeadroom < 0 {
		packetBufRearHeadroom = 0
	}
	packetBufRecvSize := mtu - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength
	packetBufSize := packetBufFrontHeadroom + packetBufRecvSize + packetBufRearHeadroom
	s := UDPNATRelay{
		serverName:             serverName,
		listenAddress:          listenAddress,
		listenerFwmark:         listenerFwmark,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufFrontHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		batchSize:              batchSize,
		natTimeout:             natTimeout,
		server:                 server,
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
	s.setRelayFunc(batchMode)
	return &s
}

// String implements the Service String method.
func (s *UDPNATRelay) String() string {
	return fmt.Sprintf("UDP NAT relay service for %s", s.serverName)
}

// Start implements the Service Start method.
func (s *UDPNATRelay) Start() error {
	serverConn, err := conn.ListenUDP("udp", s.listenAddress, true, s.listenerFwmark)
	if err != nil {
		return err
	}
	s.serverConn = serverConn

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConn()
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP NAT relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

func (s *UDPNATRelay) recvFromServerConnGeneric() {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		queuedPacket := s.getQueuedPacket()
		packetBuf := queuedPacket.buf
		recvBuf := packetBuf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, clientAddrPort, err := s.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putQueuedPacket(queuedPacket)
				break
			}

			s.logger.Warn("Failed to read packet from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read packet from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
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
			entry = &natEntry{}

			entry.serverConnPacker, entry.serverConnUnpacker, err = s.server.NewSession()
			if err != nil {
				s.logger.Warn("Failed to create new session for serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
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
			s.logger.Warn("Failed to unpack packet from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
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

		var clientPktinfop *[]byte
		cmsg := cmsgBuf[:cmsgn]

		if !bytes.Equal(entry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse pktinfo control message from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
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
			clientPktinfop = &clientPktinfoCache
			entry.clientPktinfo.Store(clientPktinfop)
			entry.clientPktinfoCache = clientPktinfoCache

			if ce := s.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}
		}

		if !ok {
			entry.natConnSendCh = make(chan *natQueuedPacket, sendChannelCapacity)
			s.table[clientAddrPort] = entry

			go func() {
				var sendChClean bool

				defer func() {
					s.mu.Lock()
					close(entry.natConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					if !sendChClean {
						for queuedPacket := range entry.natConnSendCh {
							s.putQueuedPacket(queuedPacket)
						}
					}
				}()

				c, err := s.router.GetUDPClient(s.serverName, clientAddrPort, queuedPacket.targetAddr)
				if err != nil {
					s.logger.Warn("Failed to get UDP client for new NAT session",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Duration("natTimeout", s.natTimeout),
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

				s.logger.Info("UDP NAT relay started",
					zap.String("server", s.serverName),
					zap.String("client", clientName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				)

				s.wg.Add(1)

				go func() {
					s.relayServerConnToNatConnGeneric(clientAddrPort, entry)
					entry.natConn.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(clientAddrPort, entry, clientPktinfop)
			}()

			if ce := s.logger.Check(zap.DebugLevel, "New UDP NAT session"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
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
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				)
			}

			s.putQueuedPacket(queuedPacket)
		}

		s.mu.Unlock()
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPNATRelay) relayServerConnToNatConnGeneric(clientAddrPort netip.AddrPort, entry *natEntry) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range entry.natConnSendCh {
		destAddrPort, packetStart, packetLength, err = entry.natConnPacker.PackInPlace(queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
		if err != nil {
			s.logger.Warn("Failed to pack packet for natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Int("payloadLength", queuedPacket.length),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		_, err = entry.natConn.WriteToUDPAddrPort(queuedPacket.buf[packetStart:packetStart+packetLength], destAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		err = entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.Error(err),
			)
		}

		s.putQueuedPacket(queuedPacket)
		packetsSent++
		payloadBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

func (s *UDPNATRelay) relayNatConnToServerConnGeneric(clientAddrPort netip.AddrPort, entry *natEntry, clientPktinfop *[]byte) {
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
		clientPktinfo    []byte
		packetsSent      uint64
		payloadBytesSent uint64
	)

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

	packetBuf := make([]byte, frontHeadroom+entry.natConnRecvBufSize+rearHeadroom)
	recvBuf := packetBuf[frontHeadroom : frontHeadroom+entry.natConnRecvBufSize]

	for {
		n, _, flags, packetSourceAddrPort, err := entry.natConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to read packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
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
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, frontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
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
				zap.Int("payloadLength", payloadLength),
				zap.Int("maxClientPacketSize", maxClientPacketSize),
				zap.Error(err),
			)
			continue
		}

		if cpp := entry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = s.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
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
	if s.serverConn == nil {
		return nil
	}

	now := time.Now()

	if err := s.serverConn.SetReadDeadline(now); err != nil {
		return err
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.mu.Lock()
	for clientAddrPort, entry := range s.table {
		natConn := entry.state.Swap(s.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	return s.serverConn.Close()
}
