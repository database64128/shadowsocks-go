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

// sessionQueuedPacket is the structure used by send channels to queue packets for sending.
type sessionQueuedPacket struct {
	bufp           *[]byte
	start          int
	length         int
	targetAddr     conn.Addr
	clientAddrPort netip.AddrPort
}

// sessionClientAddrInfo stores a session's client address information.
type sessionClientAddrInfo struct {
	addrPort netip.AddrPort
	pktinfo  []byte
}

// session keeps track of a UDP session.
type session struct {
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
	state               atomic.Pointer[net.UDPConn]
	clientAddrInfo      atomic.Pointer[sessionClientAddrInfo]
	clientAddrPortCache netip.AddrPort
	clientPktinfoCache  []byte
	natConn             *net.UDPConn
	natConnRecvBufSize  int
	natConnSendCh       chan sessionQueuedPacket
	natConnPacker       zerocopy.ClientPacker
	natConnUnpacker     zerocopy.ClientUnpacker
	serverConnPacker    zerocopy.ServerPacker
	serverConnUnpacker  zerocopy.ServerUnpacker
}

// UDPSessionRelay is a session-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the client session ID.
type UDPSessionRelay struct {
	serverName             string
	listenAddress          string
	listenerFwmark         int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	batchSize              int
	natTimeout             time.Duration
	server                 zerocopy.UDPSessionServer
	serverConn             *net.UDPConn
	router                 *router.Router
	logger                 *zap.Logger
	packetBufPool          *sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[uint64]*session
	recvFromServerConn     func()
}

func NewUDPSessionRelay(
	batchMode, serverName, listenAddress string,
	batchSize, listenerFwmark, mtu, maxClientFrontHeadroom, maxClientRearHeadroom int,
	natTimeout time.Duration,
	server zerocopy.UDPSessionServer,
	router *router.Router,
	logger *zap.Logger,
) *UDPSessionRelay {
	packetBufFrontHeadroom := maxClientFrontHeadroom - server.FrontHeadroom()
	if packetBufFrontHeadroom < 0 {
		packetBufFrontHeadroom = 0
	}
	packetBufRearHeadroom := maxClientRearHeadroom - server.RearHeadroom()
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
	s := UDPSessionRelay{
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
		packetBufPool:          packetBufPool,
		table:                  make(map[uint64]*session),
	}
	s.setRelayFunc(batchMode)
	return &s
}

// String implements the Service String method.
func (s *UDPSessionRelay) String() string {
	return fmt.Sprintf("UDP session relay service for %s", s.serverName)
}

// Start implements the Service Start method.
func (s *UDPSessionRelay) Start() error {
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

	s.logger.Info("Started UDP session relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

func (s *UDPSessionRelay) recvFromServerConnGeneric() {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		packetBufp := s.packetBufPool.Get().(*[]byte)
		packetBuf := *packetBufp
		recvBuf := packetBuf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, clientAddrPort, err := s.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.packetBufPool.Put(packetBufp)
				break
			}

			s.logger.Warn("Failed to read packet from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
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
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.packetBufPool.Put(packetBufp)
			continue
		}
		packet := recvBuf[:n]
		cmsg := cmsgBuf[:cmsgn]

		csid, err := s.server.SessionInfo(packet)
		if err != nil {
			s.logger.Warn("Failed to extract session info from packet",
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
					zap.Int("packetLength", n),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				s.mu.Unlock()
				continue
			}
		}

		targetAddr, payloadStart, payloadLength, err := entry.serverConnUnpacker.UnpackInPlace(packetBuf, clientAddrPort, s.packetBufFrontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Uint64("clientSessionID", csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.packetBufPool.Put(packetBufp)
			s.mu.Unlock()
			continue
		}

		packetsReceived++
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
				s.mu.Unlock()
				continue
			}

			clientAddrInfop = &sessionClientAddrInfo{clientAddrPort, entry.clientPktinfoCache}
			entry.clientAddrInfo.Store(clientAddrInfop)

			if ce := s.logger.Check(zap.DebugLevel, "Updated client address info"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
					zap.Uint64("clientSessionID", csid),
				)
			}
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
						zap.String("client", clientName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddr),
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

				s.logger.Info("UDP session relay started",
					zap.String("server", s.serverName),
					zap.String("client", clientName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Uint64("clientSessionID", csid),
				)

				s.wg.Add(1)

				go func() {
					s.relayServerConnToNatConnGeneric(csid, entry)
					entry.natConn.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(csid, entry, clientAddrInfop)
			}()

			if ce := s.logger.Check(zap.DebugLevel, "New UDP session"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Uint64("clientSessionID", csid),
				)
			}
		}

		select {
		case entry.natConnSendCh <- sessionQueuedPacket{packetBufp, payloadStart, payloadLength, targetAddr, clientAddrPort}:
		default:
			if ce := s.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddr),
					zap.Uint64("clientSessionID", csid),
				)
			}

			s.packetBufPool.Put(packetBufp)
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

func (s *UDPSessionRelay) relayServerConnToNatConnGeneric(csid uint64, entry *session) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range entry.natConnSendCh {
		destAddrPort, packetStart, packetLength, err = entry.natConnPacker.PackInPlace(*queuedPacket.bufp, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Uint64("clientSessionID", csid),
				zap.Int("payloadLength", queuedPacket.length),
				zap.Error(err),
			)

			s.packetBufPool.Put(queuedPacket.bufp)
			continue
		}

		_, err = entry.natConn.WriteToUDPAddrPort((*queuedPacket.bufp)[packetStart:packetStart+packetLength], destAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
				zap.Stringer("targetAddress", queuedPacket.targetAddr),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}

		err = entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", queuedPacket.clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.Uint64("clientSessionID", csid),
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
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

func (s *UDPSessionRelay) relayNatConnToServerConnGeneric(csid uint64, entry *session, clientAddrInfop *sessionClientAddrInfo) {
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
		packetsSent      uint64
		payloadBytesSent uint64
	)

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
				zap.Uint64("clientSessionID", csid),
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
				zap.Uint64("clientSessionID", csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, frontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Uint64("clientSessionID", csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		if caip := entry.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
		}

		packetStart, packetLength, err := entry.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Uint64("clientSessionID", csid),
				zap.Int("payloadLength", payloadLength),
				zap.Int("maxClientPacketSize", maxClientPacketSize),
				zap.Error(err),
			)
			continue
		}

		_, _, err = s.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Uint64("clientSessionID", csid),
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
		zap.Uint64("clientSessionID", csid),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

// Stop implements the Service Stop method.
func (s *UDPSessionRelay) Stop() error {
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
	for csid, entry := range s.table {
		natConn := entry.state.Swap(s.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Uint64("clientSessionID", csid),
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
