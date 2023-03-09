package service

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// transparentQueuedPacket is the structure used by send channels to queue packets for sending.
type transparentQueuedPacket struct {
	buf            []byte
	targetAddrPort netip.AddrPort
	msglen         uint32
}

// transparentNATEntry is an entry in the tproxy NAT table.
type transparentNATEntry struct {
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
	state         atomic.Pointer[net.UDPConn]
	natConnSendCh chan<- *transparentQueuedPacket
}

// transparentUplink is used for passing information about relay uplink to the relay goroutine.
type transparentUplink struct {
	clientAddrPort netip.AddrPort
	natConn        *conn.MmsgWConn
	natConnSendCh  <-chan *transparentQueuedPacket
	natConnPacker  zerocopy.ClientPacker
}

// transparentDownlink is used for passing information about relay downlink to the relay goroutine.
type transparentDownlink struct {
	clientAddrPort     netip.AddrPort
	natConn            *conn.MmsgRConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
}

// UDPTransparentRelay is like [UDPNATRelay], but for transparent proxy.
type UDPTransparentRelay struct {
	serverName                  string
	listenAddress               string
	mtu                         int
	packetBufFrontHeadroom      int
	packetBufRecvSize           int
	relayBatchSize              int
	serverRecvBatchSize         int
	sendChannelCapacity         int
	natTimeout                  time.Duration
	serverConn                  *net.UDPConn
	serverConnlistenConfig      tfo.ListenConfig
	transparentConnListenConfig tfo.ListenConfig
	collector                   stats.Collector
	router                      *router.Router
	logger                      *zap.Logger
	queuedPacketPool            sync.Pool
	mu                          sync.Mutex
	wg                          sync.WaitGroup
	mwg                         sync.WaitGroup
	table                       map[netip.AddrPort]*transparentNATEntry
}

func NewUDPTransparentRelay(
	serverName, listenAddress string,
	relayBatchSize, serverRecvBatchSize, sendChannelCapacity, mtu int,
	maxClientPackerHeadroom zerocopy.Headroom,
	natTimeout time.Duration,
	serverConnlistenConfig, transparentConnListenConfig tfo.ListenConfig,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) (Relay, error) {
	packetBufRecvSize := mtu - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength
	packetBufSize := maxClientPackerHeadroom.Front + packetBufRecvSize + maxClientPackerHeadroom.Rear
	return &UDPTransparentRelay{
		serverName:                  serverName,
		listenAddress:               listenAddress,
		mtu:                         mtu,
		packetBufFrontHeadroom:      maxClientPackerHeadroom.Front,
		packetBufRecvSize:           packetBufRecvSize,
		relayBatchSize:              relayBatchSize,
		serverRecvBatchSize:         serverRecvBatchSize,
		sendChannelCapacity:         sendChannelCapacity,
		natTimeout:                  natTimeout,
		serverConnlistenConfig:      serverConnlistenConfig,
		transparentConnListenConfig: transparentConnListenConfig,
		collector:                   collector,
		router:                      router,
		logger:                      logger,
		queuedPacketPool: sync.Pool{
			New: func() any {
				return &transparentQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table: make(map[netip.AddrPort]*transparentNATEntry),
	}, nil
}

// String implements the Relay String method.
func (s *UDPTransparentRelay) String() string {
	return "UDP transparent relay service for " + s.serverName
}

// Start implements the Relay Start method.
func (s *UDPTransparentRelay) Start() error {
	serverConn, err := conn.ListenUDPRawConn(s.serverConnlistenConfig, "udp", s.listenAddress)
	if err != nil {
		return err
	}
	s.serverConn = serverConn.UDPConn

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnRecvmmsg(serverConn.RConn())
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP transparent relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

func (s *UDPTransparentRelay) recvFromServerConnRecvmmsg(serverConn *conn.MmsgRConn) {
	n := s.serverRecvBatchSize
	qpvec := make([]*transparentQueuedPacket, n)
	namevec := make([]unix.RawSockaddrInet6, n)
	iovec := make([]unix.Iovec, n)
	cmsgvec := make([][]byte, n)
	msgvec := make([]conn.Mmsghdr, n)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.TransparentSocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	var (
		err                  error
		recvmmsgCount        uint64
		packetsReceived      uint64
		payloadBytesReceived uint64
		burstBatchSize       int
	)

	for {
		for i := range iovec[:n] {
			queuedPacket := s.getQueuedPacket()
			qpvec[i] = queuedPacket
			iovec[i].Base = &queuedPacket.buf[s.packetBufFrontHeadroom]
			iovec[i].SetLen(s.packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.TransparentSocketControlMessageBufferSize)
		}

		n, err = serverConn.ReadMsgs(msgvec, 0)
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
			s.putQueuedPacket(qpvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		if burstBatchSize < n {
			burstBatchSize = n
		}

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			queuedPacket := qpvec[i]

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				s.logger.Warn("Packet from serverConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			queuedPacket.targetAddrPort, err = conn.ParseOrigDstAddrCmsg(cmsgvec[i][:msg.Msghdr.Controllen])
			if err != nil {
				s.logger.Warn("Failed to parse original destination address control message from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			queuedPacket.msglen = msg.Msglen
			payloadBytesReceived += uint64(msg.Msglen)

			entry := s.table[clientAddrPort]
			if entry == nil {
				natConnSendCh := make(chan *transparentQueuedPacket, s.sendChannelCapacity)
				entry = &transparentNATEntry{natConnSendCh: natConnSendCh}
				s.table[clientAddrPort] = entry

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
					}()

					c, err := s.router.GetUDPClient(router.RequestInfo{
						Server:         s.serverName,
						SourceAddrPort: clientAddrPort,
						TargetAddr:     conn.AddrFromIPPort(queuedPacket.targetAddrPort),
					})
					if err != nil {
						s.logger.Warn("Failed to get UDP client for new NAT session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
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
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.Error(err),
						)
						return
					}

					natConn, err := conn.ListenUDPRawConn(clientInfo.ListenConfig, "udp", "")
					if err != nil {
						s.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.String("server", s.serverName),
							zap.String("client", clientInfo.Name),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.Error(err),
						)
						return
					}

					if err = natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
						s.logger.Warn("Failed to set read deadline on natConn",
							zap.String("server", s.serverName),
							zap.String("client", clientInfo.Name),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.Duration("natTimeout", s.natTimeout),
							zap.Error(err),
						)
						natConn.Close()
						return
					}

					oldState := entry.state.Swap(natConn.UDPConn)
					if oldState != nil {
						natConn.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					s.logger.Info("UDP transparent relay started",
						zap.String("server", s.serverName),
						zap.String("client", clientInfo.Name),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(transparentUplink{
							clientAddrPort: clientAddrPort,
							natConn:        natConn.WConn(),
							natConnSendCh:  natConnSendCh,
							natConnPacker:  natConnPacker,
						})
						natConn.Close()
						s.wg.Done()
					}()

					s.relayNatConnToTransparentConnSendmmsg(transparentDownlink{
						clientAddrPort:     clientAddrPort,
						natConn:            natConn.RConn(),
						natConnRecvBufSize: clientInfo.MaxPacketSize,
						natConnUnpacker:    natConnUnpacker,
					})
				}()

				if ce := s.logger.Check(zap.DebugLevel, "New UDP transparent session"); ce != nil {
					ce.Write(
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
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
						zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
					)
				}

				s.putQueuedPacket(queuedPacket)
			}
		}

		s.mu.Unlock()
	}

	for i := range qpvec {
		s.putQueuedPacket(qpvec[i])
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *UDPTransparentRelay) relayServerConnToNatConnSendmmsg(uplink transparentUplink) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	qpvec := make([]*transparentQueuedPacket, s.relayBatchSize)
	namevec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	iovec := make([]unix.Iovec, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, s.relayBatchSize)

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
		queuedPacket, ok := <-uplink.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(queuedPacket.buf, conn.AddrFromIPPort(queuedPacket.targetAddrPort), s.packetBufFrontHeadroom, int(queuedPacket.msglen))
			if err != nil {
				s.logger.Warn("Failed to pack packet for natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
					zap.Uint32("payloadLength", queuedPacket.msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)

				if count == 0 {
					continue main
				}
				goto next
			}

			qpvec[count] = queuedPacket
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &queuedPacket.buf[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.msglen)

			if count == s.relayBatchSize {
				break
			}

		next:
			select {
			case queuedPacket, ok = <-uplink.natConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		if err := uplink.natConn.WriteMsgs(msgvec[:count], 0); err != nil {
			s.logger.Warn("Failed to batch write packets to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("lastTargetAddress", &qpvec[count-1].targetAddrPort),
				zap.Stringer("lastWriteDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		if err := uplink.natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)
		if burstBatchSize < count {
			burstBatchSize = count
		}

		qpvecn := qpvec[:count]

		for i := range qpvecn {
			s.putQueuedPacket(qpvecn[i])
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionUplink("", packetsSent, payloadBytesSent)
}

// getQueuedPacket retrieves a queued packet from the pool.
func (s *UDPTransparentRelay) getQueuedPacket() *transparentQueuedPacket {
	return s.queuedPacketPool.Get().(*transparentQueuedPacket)
}

// putQueuedPacket puts the queued packet back into the pool.
func (s *UDPTransparentRelay) putQueuedPacket(queuedPacket *transparentQueuedPacket) {
	s.queuedPacketPool.Put(queuedPacket)
}

type transparentConn struct {
	mwc    *conn.MmsgWConn
	iovec  []unix.Iovec
	msgvec []conn.Mmsghdr
	n      int
}

func (s *UDPTransparentRelay) newTransparentConn(address string, name *byte, namelen uint32) (*transparentConn, error) {
	c, err := conn.ListenUDPRawConn(s.transparentConnListenConfig, "udp", address)
	if err != nil {
		return nil, err
	}

	iovec := make([]unix.Iovec, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, s.relayBatchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	return &transparentConn{
		mwc:    c.WConn(),
		iovec:  iovec,
		msgvec: msgvec,
	}, nil
}

func (tc *transparentConn) putMsg(base *byte, length int) {
	tc.iovec[tc.n].Base = base
	tc.iovec[tc.n].SetLen(length)
	tc.n++
}

func (tc *transparentConn) writeMsgvec() (sendmmsgCount, packetsSent int, err error) {
	if tc.n == 0 {
		return
	}
	packetsSent = tc.n
	tc.n = 0
	return 1, packetsSent, tc.mwc.WriteMsgs(tc.msgvec[:packetsSent], 0)
}

func (tc *transparentConn) close() error {
	return tc.mwc.Close()
}

func (s *UDPTransparentRelay) relayNatConnToTransparentConnSendmmsg(downlink transparentDownlink) {
	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, downlink.clientAddrPort.Addr())
	name, namelen := conn.AddrPortUnmappedToSockaddr(downlink.clientAddrPort)
	tcMap := make(map[netip.AddrPort]*transparentConn)

	savec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	bufvec := make([][]byte, s.relayBatchSize)
	iovec := make([]unix.Iovec, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, s.relayBatchSize)

	for i := 0; i < s.relayBatchSize; i++ {
		packetBuf := make([]byte, downlink.natConnRecvBufSize)
		bufvec[i] = packetBuf

		iovec[i].Base = &packetBuf[0]
		iovec[i].SetLen(downlink.natConnRecvBufSize)

		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	for {
		nr, err := downlink.natConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Error(err),
			)
			continue
		}

		var ns int
		msgvecn := msgvec[:nr]

		for i := range msgvecn {
			msg := &msgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				s.logger.Warn("Packet from natConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, 0, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			if payloadLength > maxClientPacketSize {
				s.logger.Warn("Payload too large to send to client",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Int("payloadLength", payloadLength),
					zap.Int("maxClientPacketSize", maxClientPacketSize),
				)
				continue
			}

			tc := tcMap[payloadSourceAddrPort]
			if tc == nil {
				tc, err = s.newTransparentConn(payloadSourceAddrPort.String(), name, namelen)
				if err != nil {
					s.logger.Warn("Failed to create transparentConn",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
						zap.Error(err),
					)
					continue
				}
				tcMap[payloadSourceAddrPort] = tc
			}
			tc.putMsg(&packetBuf[payloadStart], payloadLength)
			ns++
			payloadBytesSent += uint64(payloadLength)
		}

		if ns == 0 {
			continue
		}

		for payloadSourceAddrPort, tc := range tcMap {
			sc, ps, err := tc.writeMsgvec()
			if err != nil {
				s.logger.Warn("Failed to batch write packets to transparentConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Error(err),
				)
			}

			sendmmsgCount += uint64(sc)
			packetsSent += uint64(ps)
			if burstBatchSize < ps {
				burstBatchSize = ps
			}
		}
	}

	for payloadSourceAddrPort, tc := range tcMap {
		if err := tc.close(); err != nil {
			s.logger.Warn("Failed to close transparentConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Error(err),
			)
		}
	}

	s.logger.Info("Finished relay transparentConn <- natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink("", packetsSent, payloadBytesSent)
}

// Stop implements the Relay Stop method.
func (s *UDPTransparentRelay) Stop() error {
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
