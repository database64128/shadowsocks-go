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
	state                   atomic.Pointer[net.UDPConn]
	clientAddrInfo          atomic.Pointer[sessionClientAddrInfo]
	clientAddrPortCache     netip.AddrPort
	clientPktinfoCache      []byte
	natConnSendCh           chan<- *sessionQueuedPacket
	serverConn              *net.UDPConn
	serverConnUnpacker      zerocopy.ServerUnpacker
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// sessionUplinkGeneric is used for passing information about relay uplink to the relay goroutine.
type sessionUplinkGeneric struct {
	csid                    uint64
	clientName              string
	natConn                 *net.UDPConn
	natConnSendCh           <-chan *sessionQueuedPacket
	natConnPacker           zerocopy.ClientPacker
	natTimeout              time.Duration
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// sessionDownlinkGeneric is used for passing information about relay downlink to the relay goroutine.
type sessionDownlinkGeneric struct {
	csid                    uint64
	clientName              string
	clientAddrInfop         *sessionClientAddrInfo
	clientAddrInfo          *atomic.Pointer[sessionClientAddrInfo]
	natConn                 *net.UDPConn
	natConnRecvBufSize      int
	natConnUnpacker         zerocopy.ClientUnpacker
	serverConn              *net.UDPConn
	serverConnPacker        zerocopy.ServerPacker
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// UDPSessionRelay is a session-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the client session ID.
type UDPSessionRelay struct {
	serverName             string
	serverIndex            int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	listeners              []udpRelayServerConn
	server                 zerocopy.UDPSessionServer
	collector              stats.Collector
	router                 *router.Router
	logger                 *zap.Logger
	queuedPacketPool       sync.Pool
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[uint64]*session
}

func NewUDPSessionRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	server zerocopy.UDPSessionServer,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *UDPSessionRelay {
	return &UDPSessionRelay{
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
				return &sessionQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table: make(map[uint64]*session),
	}
}

// String implements the Service String method.
func (s *UDPSessionRelay) String() string {
	return "UDP session relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *UDPSessionRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		if err := s.start(ctx, i, &s.listeners[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *UDPSessionRelay) startGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) (err error) {
	lnc.serverConn, err = lnc.listenConfig.ListenUDP(ctx, lnc.network, lnc.address)
	if err != nil {
		return
	}

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnGeneric(ctx, index, lnc)
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP session relay service listener",
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
	)

	return
}

func (s *UDPSessionRelay) recvFromServerConnGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) {
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

		n, cmsgn, flags, queuedPacket.clientAddrPort, err = lnc.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putQueuedPacket(queuedPacket)
				break
			}

			s.logger.Warn("Failed to read packet from serverConn",
				zap.String("server", s.serverName),
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
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
			entry = &session{
				serverConn:              lnc.serverConn,
				serverConnListenAddress: lnc.address,
				listenerIndex:           index,
			}

			entry.serverConnUnpacker, entry.username, err = s.server.NewUnpacker(packet, csid)
			if err != nil {
				s.logger.Warn("Failed to create unpacker for client session",
					zap.String("server", s.serverName),
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
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
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
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
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}
		}

		if !ok {
			natConnSendCh := make(chan *sessionQueuedPacket, lnc.sendChannelCapacity)
			entry.natConnSendCh = natConnSendCh
			s.table[csid] = entry
			s.wg.Add(1)

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

					s.wg.Done()
				}()

				c, err := s.router.GetUDPClient(ctx, router.RequestInfo{
					ServerIndex:    s.serverIndex,
					Username:       entry.username,
					SourceAddrPort: queuedPacket.clientAddrPort,
					TargetAddr:     queuedPacket.targetAddr,
				})
				if err != nil {
					s.logger.Warn("Failed to get UDP client for new NAT session",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.Error(err),
					)
					return
				}

				clientInfo, clientSession, err := c.NewSession(ctx)
				if err != nil {
					s.logger.Warn("Failed to create new UDP client session",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
						zap.Error(err),
					)
					return
				}

				natConn, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new NAT session",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
						zap.Stringer("targetAddress", &queuedPacket.targetAddr),
						zap.String("client", clientInfo.Name),
						zap.Error(err),
					)
					clientSession.Close()
					return
				}

				err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout))
				if err != nil {
					s.logger.Warn("Failed to set read deadline on natConn",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
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
					s.logger.Warn("Failed to create packer for client session",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
						zap.String("username", entry.username),
						zap.Uint64("clientSessionID", csid),
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

				s.logger.Info("UDP session relay started",
					zap.String("server", s.serverName),
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
					zap.String("client", clientInfo.Name),
				)

				s.wg.Add(1)

				go func() {
					s.relayServerConnToNatConnGeneric(ctx, sessionUplinkGeneric{
						csid:                    csid,
						clientName:              clientInfo.Name,
						natConn:                 natConn,
						natConnSendCh:           natConnSendCh,
						natConnPacker:           clientSession.Packer,
						natTimeout:              lnc.natTimeout,
						serverConnListenAddress: lnc.address,
						username:                entry.username,
						listenerIndex:           index,
					})
					natConn.Close()
					clientSession.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(sessionDownlinkGeneric{
					csid:                    csid,
					clientName:              clientInfo.Name,
					clientAddrInfop:         clientAddrInfop,
					clientAddrInfo:          &entry.clientAddrInfo,
					natConn:                 natConn,
					natConnRecvBufSize:      clientSession.MaxPacketSize,
					natConnUnpacker:         clientSession.Unpacker,
					serverConn:              lnc.serverConn,
					serverConnPacker:        serverConnPacker,
					serverConnListenAddress: lnc.address,
					username:                entry.username,
					listenerIndex:           index,
				})
			}()

			if ce := s.logger.Check(zap.DebugLevel, "New UDP session"); ce != nil {
				ce.Write(
					zap.String("server", s.serverName),
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
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
					zap.Int("listener", index),
					zap.String("listenAddress", lnc.address),
					zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
					zap.String("username", entry.username),
					zap.Uint64("clientSessionID", csid),
					zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				)
			}

			s.putQueuedPacket(queuedPacket)
		}

		s.server.Unlock()
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnGeneric(ctx context.Context, uplink sessionUplinkGeneric) {
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
			s.logger.Warn("Failed to pack packet",
				zap.String("server", s.serverName),
				zap.Int("listener", uplink.listenerIndex),
				zap.String("listenAddress", uplink.serverConnListenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
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
			s.logger.Warn("Failed to write packet to natConn",
				zap.String("server", s.serverName),
				zap.Int("listener", uplink.listenerIndex),
				zap.String("listenAddress", uplink.serverConnListenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
				zap.Stringer("targetAddress", &queuedPacket.targetAddr),
				zap.String("client", uplink.clientName),
				zap.Stringer("writeDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		err = uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.Int("listener", uplink.listenerIndex),
				zap.String("listenAddress", uplink.serverConnListenAddress),
				zap.Stringer("clientAddress", &queuedPacket.clientAddrPort),
				zap.String("username", uplink.username),
				zap.Uint64("clientSessionID", uplink.csid),
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

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.Int("listener", uplink.listenerIndex),
		zap.String("listenAddress", uplink.serverConnListenAddress),
		zap.String("username", uplink.username),
		zap.Uint64("clientSessionID", uplink.csid),
		zap.String("client", uplink.clientName),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
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
				zap.Int("listener", downlink.listenerIndex),
				zap.String("listenAddress", downlink.serverConnListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read packet from natConn",
				zap.String("server", s.serverName),
				zap.Int("listener", downlink.listenerIndex),
				zap.String("listenAddress", downlink.serverConnListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				zap.String("server", s.serverName),
				zap.Int("listener", downlink.listenerIndex),
				zap.String("listenAddress", downlink.serverConnListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
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
				zap.Int("listener", downlink.listenerIndex),
				zap.String("listenAddress", downlink.serverConnListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
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
				zap.Int("listener", downlink.listenerIndex),
				zap.String("listenAddress", downlink.serverConnListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.String("username", downlink.username),
				zap.Uint64("clientSessionID", downlink.csid),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.String("client", downlink.clientName),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Error(err),
			)
		}

		packetsSent++
		payloadBytesSent += uint64(payloadLength)
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		zap.String("server", s.serverName),
		zap.Int("listener", downlink.listenerIndex),
		zap.String("listenAddress", downlink.serverConnListenAddress),
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
	now := time.Now()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to set read deadline on serverConn",
				zap.String("server", s.serverName),
				zap.Int("listener", i),
				zap.String("listenAddress", lnc.address),
				zap.Error(err),
			)
		}
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.server.Lock()
	for csid, entry := range s.table {
		natConn := entry.state.Swap(entry.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.Int("listener", entry.listenerIndex),
				zap.String("listenAddress", entry.serverConnListenAddress),
				zap.Uint64("clientSessionID", csid),
				zap.Error(err),
			)
		}
	}
	s.server.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.Close(); err != nil {
			s.logger.Warn("Failed to close serverConn",
				zap.String("server", s.serverName),
				zap.Int("listener", i),
				zap.String("listenAddress", lnc.address),
				zap.Error(err),
			)
		}
	}

	return nil
}
