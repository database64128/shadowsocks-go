package service

import (
	"bytes"
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
	"github.com/database64128/tfo-go/v2"
	"go.uber.org/zap"
)

// sessionQueuedPacket is the structure used by send channels to queue packets for sending.
type sessionQueuedPacket struct {
	buf            []byte
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
	natConnSendCh       chan<- *sessionQueuedPacket
	serverConnUnpacker  zerocopy.SessionServerUnpacker
	username            string
}

// sessionUplinkGeneric is used for passing information about relay uplink to the relay goroutine.
type sessionUplinkGeneric struct {
	csid          uint64
	natConn       *net.UDPConn
	natConnSendCh <-chan *sessionQueuedPacket
	natConnPacker zerocopy.ClientPacker
	username      string
}

// sessionDownlinkGeneric is used for passing information about relay downlink to the relay goroutine.
type sessionDownlinkGeneric struct {
	csid               uint64
	clientAddrInfop    *sessionClientAddrInfo
	clientAddrInfo     *atomic.Pointer[sessionClientAddrInfo]
	natConn            *net.UDPConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	serverConn         *net.UDPConn
	serverConnPacker   zerocopy.ServerPacker
	username           string
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
	relayBatchSize         int
	serverRecvBatchSize    int
	sendChannelCapacity    int
	natTimeout             time.Duration
	server                 zerocopy.UDPSessionServer
	serverConn             *net.UDPConn
	serverConnListenConfig tfo.ListenConfig
	collector              stats.Collector
	router                 *router.Router
	logger                 *zap.Logger
	queuedPacketPool       sync.Pool
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[uint64]*session
	startFunc              func() error
}

func NewUDPSessionRelay(
	batchMode, serverName, listenAddress string,
	relayBatchSize, serverRecvBatchSize, sendChannelCapacity, mtu int,
	maxClientPackerHeadroom zerocopy.Headroom,
	natTimeout time.Duration,
	server zerocopy.UDPSessionServer,
	serverConnListenConfig tfo.ListenConfig,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *UDPSessionRelay {
	serverInfo := server.Info()
	packetBufHeadroom := zerocopy.UDPRelayHeadroom(maxClientPackerHeadroom, serverInfo.UnpackerHeadroom)
	packetBufRecvSize := mtu - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength
	packetBufSize := packetBufHeadroom.Front + packetBufRecvSize + packetBufHeadroom.Rear
	s := UDPSessionRelay{
		serverName:             serverName,
		listenAddress:          listenAddress,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufHeadroom.Front,
		packetBufRecvSize:      packetBufRecvSize,
		relayBatchSize:         relayBatchSize,
		serverRecvBatchSize:    serverRecvBatchSize,
		sendChannelCapacity:    sendChannelCapacity,
		natTimeout:             natTimeout,
		server:                 server,
		serverConnListenConfig: serverConnListenConfig,
		collector:              collector,
		router:                 router,
		logger:                 logger,
		queuedPacketPool: sync.Pool{
			New: func() any {
				return &sessionQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table: make(map[uint64]*session),
	}
	s.setStartFunc(batchMode)
	return &s
}

// String implements the Service String method.
func (s *UDPSessionRelay) String() string {
	return "UDP session relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *UDPSessionRelay) Start() error {
	return s.startFunc()
}

func (s *UDPSessionRelay) startGeneric() error {
	serverConn, err := conn.ListenUDP(s.serverConnListenConfig, "udp", s.listenAddress)
	if err != nil {
		return err
	}
	s.serverConn = serverConn

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnGeneric(serverConn)
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP session relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

func (s *UDPSessionRelay) recvFromServerConnGeneric(serverConn *net.UDPConn) {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		n                    int
		cmsgn                int
		flags                int
		err                  error
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		queuedPacket := s.getQueuedPacket()
		recvBuf := queuedPacket.buf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, queuedPacket.clientAddrPort, err = serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putQueuedPacket(queuedPacket)
				break
			}

			s.logger.Warn("Failed to read packet from serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
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
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		packet := recvBuf[:n]

		csid, err := s.server.SessionInfo(packet)
		if err != nil {
			s.logger.Warn("Failed to extract session info from packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		s.server.Lock()

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
					zap.Int("packetLength", n),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.server.Unlock()
				continue
			}
		}

		queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, queuedPacket.clientAddrPort, s.packetBufFrontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", entry.username),
				zap.Uint64("clientSessionID", csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			s.server.Unlock()
			continue
		}

		packetsReceived++
		payloadBytesReceived += uint64(queuedPacket.length)

		var clientAddrInfop *sessionClientAddrInfo
		cmsg := cmsgBuf[:cmsgn]

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
				s.server.Unlock()
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
			natConnSendCh := make(chan *sessionQueuedPacket, s.sendChannelCapacity)
			entry.natConnSendCh = natConnSendCh
			s.table[csid] = entry

			go func() {
				var sendChClean bool

				defer func() {
					s.server.Lock()
					close(natConnSendCh)
					delete(s.table, csid)
					s.server.Unlock()

					if !sendChClean {
						for queuedPacket := range natConnSendCh {
							s.putQueuedPacket(queuedPacket)
						}
					}
				}()

				c, err := s.router.GetUDPClient(router.RequestInfo{
					Server:         s.serverName,
					Username:       entry.username,
					SourceAddrPort: queuedPacket.clientAddrPort,
					TargetAddr:     queuedPacket.targetAddr,
				})
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

				// Only add for the current goroutine here, since we don't want the router to block exiting.
				s.wg.Add(1)
				defer s.wg.Done()

				clientInfo, natConnPacker, natConnUnpacker, err := c.NewSession()
				if err != nil {
					s.logger.Warn("Failed to create new UDP client session",
						zap.String("server", s.serverName),
						zap.String("client", clientInfo.Name),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Error(err),
					)
					return
				}

				serverConnPacker, err := entry.serverConnUnpacker.NewPacker()
				if err != nil {
					s.logger.Warn("Failed to create packer for client session",
						zap.String("server", s.serverName),
						zap.String("client", clientInfo.Name),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Error(err),
					)
					return
				}

				natConn, err := conn.ListenUDP(clientInfo.ListenConfig, "udp", "")
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new NAT session",
						zap.String("server", s.serverName),
						zap.String("client", clientInfo.Name),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Error(err),
					)
					return
				}

				err = natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
				if err != nil {
					s.logger.Warn("Failed to set read deadline on natConn",
						zap.String("server", s.serverName),
						zap.String("client", clientInfo.Name),
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

				s.logger.Info("UDP session relay started",
					zap.String("server", s.serverName),
					zap.String("client", clientInfo.Name),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
				)

				s.wg.Add(1)

				go func() {
					s.relayServerConnToNatConnGeneric(sessionUplinkGeneric{
						csid:          csid,
						natConn:       natConn,
						natConnSendCh: natConnSendCh,
						natConnPacker: natConnPacker,
						username:      entry.username,
					})
					natConn.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(sessionDownlinkGeneric{
					csid:               csid,
					clientAddrInfop:    clientAddrInfop,
					clientAddrInfo:     &entry.clientAddrInfo,
					natConn:            natConn,
					natConnRecvBufSize: clientInfo.MaxPacketSize,
					natConnUnpacker:    natConnUnpacker,
					serverConn:         serverConn,
					serverConnPacker:   serverConnPacker,
					username:           entry.username,
				})
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

		s.server.Unlock()
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnGeneric(uplink sessionUplinkGeneric) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range uplink.natConnSendCh {
		destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.Int("payloadLength", queuedPacket.length),
				zap.Error(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		_, err = uplink.natConn.WriteToUDPAddrPort(queuedPacket.buf[packetStart:packetStart+packetLength], destAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.Error(err),
			)
		}

		err = uplink.natConn.SetReadDeadline(time.Now().Add(s.natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
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
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.String("username", uplink.username),
		zap.Uint64("clientSessionID", uplink.csid),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionUplink(uplink.username, packetsSent, payloadBytesSent)
}

func (s *UDPSessionRelay) relayNatConnToServerConnGeneric(downlink sessionDownlinkGeneric) {
	clientAddrInfop := downlink.clientAddrInfop
	clientAddrPort := clientAddrInfop.addrPort
	clientPktinfo := clientAddrInfop.pktinfo
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
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

			s.logger.Warn("Failed to read packet from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
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
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		if caip := downlink.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
		}

		packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Int("payloadLength", payloadLength),
				zap.Int("maxClientPacketSize", maxClientPacketSize),
				zap.Error(err),
			)
			continue
		}

		_, _, err = downlink.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to serverConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
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
		zap.String("username", downlink.username),
		zap.Uint64("clientSessionID", downlink.csid),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionDownlink(downlink.username, packetsSent, payloadBytesSent)
}

// getQueuedPacket retrieves a queued packet from the pool.
func (s *UDPSessionRelay) getQueuedPacket() *sessionQueuedPacket {
	return s.queuedPacketPool.Get().(*sessionQueuedPacket)
}

// putQueuedPacket puts the queued packet back into the pool.
func (s *UDPSessionRelay) putQueuedPacket(queuedPacket *sessionQueuedPacket) {
	s.queuedPacketPool.Put(queuedPacket)
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

	s.server.Lock()
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
	s.server.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	return s.serverConn.Close()
}
