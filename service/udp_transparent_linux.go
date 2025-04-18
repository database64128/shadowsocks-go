package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
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
	serverConn    *net.UDPConn
	logger        *zap.Logger
}

// transparentUplink is used for passing information about relay uplink to the relay goroutine.
type transparentUplink struct {
	clientName     string
	clientAddrPort netip.AddrPort
	natConn        *conn.MmsgWConn
	natConnSendCh  <-chan *transparentQueuedPacket
	natConnPacker  zerocopy.ClientPacker
	natTimeout     time.Duration
	relayBatchSize int
	logger         *zap.Logger
}

// transparentDownlink is used for passing information about relay downlink to the relay goroutine.
type transparentDownlink struct {
	clientName         string
	clientAddrPort     netip.AddrPort
	natConn            *conn.MmsgRConn
	natConnRecvBufSize int
	natConnUnpacker    zerocopy.ClientUnpacker
	relayBatchSize     int
	logger             *zap.Logger
}

// UDPTransparentRelay is like [UDPNATRelay], but for transparent proxy.
type UDPTransparentRelay struct {
	serverName                  string
	serverIndex                 int
	mtu                         int
	packetBufFrontHeadroom      int
	packetBufRecvSize           int
	listeners                   []udpRelayServerConn
	transparentConnListenConfig conn.ListenConfig
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
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	transparentConnListenConfig conn.ListenConfig,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) (shadowsocks.Service, error) {
	return &UDPTransparentRelay{
		serverName:                  serverName,
		serverIndex:                 serverIndex,
		mtu:                         mtu,
		packetBufFrontHeadroom:      packetBufFrontHeadroom,
		packetBufRecvSize:           packetBufRecvSize,
		listeners:                   listeners,
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

var _ shadowsocks.Service = (*UDPTransparentRelay)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (s *UDPTransparentRelay) ZapField() zap.Field {
	return zap.String("serverUDPTransparentRelay", s.serverName)
}

// Start implements [shadowsocks.Service.Start].
func (s *UDPTransparentRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		index := i
		lnc := &s.listeners[index]

		serverConn, _, err := lnc.listenConfig.ListenUDPMmsgConn(ctx, lnc.network, lnc.address)
		if err != nil {
			return err
		}
		lnc.serverConn = serverConn.UDPConn
		lnc.address = serverConn.LocalAddr().String()
		lnc.logger = s.logger.With(
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
		)

		s.mwg.Add(1)

		go func() {
			s.recvFromServerConnRecvmmsg(ctx, lnc, serverConn.NewRConn())
			s.mwg.Done()
		}()

		lnc.logger.Info("Started UDP transparent relay service listener")
	}
	return nil
}

func (s *UDPTransparentRelay) recvFromServerConnRecvmmsg(ctx context.Context, lnc *udpRelayServerConn, serverConn *conn.MmsgRConn) {
	n := lnc.serverRecvBatchSize
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
		msgvec[i].Msghdr.Control = unsafe.SliceData(cmsgBuf)
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

			lnc.logger.Warn("Failed to batch read packets from serverConn", zap.Error(err))

			n = 1
			s.putQueuedPacket(qpvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		burstBatchSize = max(burstBatchSize, n)

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]
			queuedPacket := qpvec[i]

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				lnc.logger.Warn("Failed to parse sockaddr of packet from serverConn", zap.Error(err))
				s.putQueuedPacket(queuedPacket)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				lnc.logger.Warn("Packet from serverConn discarded",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				lnc.logger.Warn("Failed to parse socket control message from serverConn",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				s.putQueuedPacket(queuedPacket)
				continue
			}
			if !rscm.OriginalDestinationAddrPort.IsValid() {
				lnc.logger.Warn("Discarded packet from serverConn due to missing original destination address",
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
				)
				s.putQueuedPacket(queuedPacket)
				continue
			}

			queuedPacket.targetAddrPort = rscm.OriginalDestinationAddrPort
			queuedPacket.msglen = msg.Msglen
			payloadBytesReceived += uint64(msg.Msglen)

			entry := s.table[clientAddrPort]
			if entry == nil {
				natConnSendCh := make(chan *transparentQueuedPacket, lnc.sendChannelCapacity)
				entry = &transparentNATEntry{
					natConnSendCh: natConnSendCh,
					serverConn:    lnc.serverConn,
					logger:        lnc.logger,
				}
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
						TargetAddr:     conn.AddrFromIPPort(queuedPacket.targetAddrPort),
					})
					if err != nil {
						lnc.logger.Warn("Failed to get UDP client for new NAT session",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.Error(err),
						)
						return
					}

					clientInfo, clientSession, err := c.NewSession(ctx)
					if err != nil {
						lnc.logger.Warn("Failed to create new UDP client session",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.String("client", clientInfo.Name),
							zap.Error(err),
						)
						return
					}

					natConn, _, err := clientInfo.ListenConfig.ListenUDPMmsgConn(ctx, "udp", "")
					if err != nil {
						lnc.logger.Warn("Failed to create UDP socket for new NAT session",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.String("client", clientInfo.Name),
							zap.Error(err),
						)
						clientSession.Close()
						return
					}

					if err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout)); err != nil {
						lnc.logger.Warn("Failed to set read deadline on natConn",
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
							zap.String("client", clientInfo.Name),
							zap.Duration("natTimeout", lnc.natTimeout),
							zap.Error(err),
						)
						natConn.Close()
						clientSession.Close()
						return
					}

					oldState := entry.state.Swap(natConn.UDPConn)
					if oldState != nil {
						natConn.Close()
						clientSession.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					lnc.logger.Info("UDP transparent relay started",
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
						zap.String("client", clientInfo.Name),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(ctx, transparentUplink{
							clientName:     clientInfo.Name,
							clientAddrPort: clientAddrPort,
							natConn:        natConn.NewWConn(),
							natConnSendCh:  natConnSendCh,
							natConnPacker:  clientSession.Packer,
							natTimeout:     lnc.natTimeout,
							relayBatchSize: lnc.relayBatchSize,
							logger:         lnc.logger,
						})
						natConn.Close()
						clientSession.Close()
						s.wg.Done()
					}()

					s.relayNatConnToTransparentConnSendmmsg(ctx, transparentDownlink{
						clientName:         clientInfo.Name,
						clientAddrPort:     clientAddrPort,
						natConn:            natConn.NewRConn(),
						natConnRecvBufSize: clientSession.MaxPacketSize,
						natConnUnpacker:    clientSession.Unpacker,
						relayBatchSize:     lnc.relayBatchSize,
						logger:             lnc.logger,
					})
				}()

				if ce := lnc.logger.Check(zap.DebugLevel, "New UDP transparent session"); ce != nil {
					ce.Write(
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
					)
				}
			}

			select {
			case entry.natConnSendCh <- queuedPacket:
			default:
				if ce := lnc.logger.Check(zap.DebugLevel, "Dropping packet due to full send channel"); ce != nil {
					ce.Write(
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

	lnc.logger.Info("Finished receiving from serverConn",
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *UDPTransparentRelay) relayServerConnToNatConnSendmmsg(ctx context.Context, uplink transparentUplink) {
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

	qpvec := make([]*transparentQueuedPacket, uplink.relayBatchSize)
	dapvec := make([]netip.AddrPort, uplink.relayBatchSize)
	namevec := make([]unix.RawSockaddrInet6, uplink.relayBatchSize)
	iovec := make([]unix.Iovec, uplink.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, uplink.relayBatchSize)

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
			destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(ctx, queuedPacket.buf, conn.AddrFromIPPort(queuedPacket.targetAddrPort), s.packetBufFrontHeadroom, int(queuedPacket.msglen))
			if err != nil {
				uplink.logger.Warn("Failed to pack packet for natConn",
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("targetAddress", &queuedPacket.targetAddrPort),
					zap.String("client", uplink.clientName),
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
			dapvec[count] = destAddrPort
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &queuedPacket.buf[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.msglen)

			if count == uplink.relayBatchSize {
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

		for start := 0; start < count; {
			n, err := uplink.natConn.WriteMsgs(msgvec[start:count], 0)
			start += n
			if err != nil {
				uplink.logger.Warn("Failed to batch write packets to natConn",
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("targetAddress", &qpvec[start].targetAddrPort),
					zap.String("client", uplink.clientName),
					zap.Stringer("writeDestAddress", &dapvec[start]),
					zap.Uint("packetLength", uint(iovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			packetsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if err := uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout)); err != nil {
			uplink.logger.Warn("Failed to set read deadline on natConn",
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.String("client", uplink.clientName),
				zap.Duration("natTimeout", uplink.natTimeout),
				zap.Error(err),
			)
		}

		qpvecn := qpvec[:count]

		for i := range qpvecn {
			s.putQueuedPacket(qpvecn[i])
		}

		if !ok {
			break
		}
	}

	uplink.logger.Info("Finished relay serverConn -> natConn",
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.String("client", uplink.clientName),
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

func (s *UDPTransparentRelay) newTransparentConn(ctx context.Context, address string, relayBatchSize int, name *byte, namelen uint32) (*transparentConn, error) {
	c, _, err := s.transparentConnListenConfig.ListenUDPMmsgConn(ctx, "udp", address)
	if err != nil {
		return nil, err
	}

	iovec := make([]unix.Iovec, relayBatchSize)
	msgvec := make([]conn.Mmsghdr, relayBatchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	return &transparentConn{
		mwc:    c.NewWConn(),
		iovec:  iovec,
		msgvec: msgvec,
	}, nil
}

func (tc *transparentConn) putMsg(base *byte, length int) {
	tc.iovec[tc.n].Base = base
	tc.iovec[tc.n].SetLen(length)
	tc.n++
}

func (tc *transparentConn) close() error {
	return tc.mwc.Close()
}

func (s *UDPTransparentRelay) relayNatConnToTransparentConnSendmmsg(ctx context.Context, downlink transparentDownlink) {
	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, downlink.clientAddrPort.Addr())
	name, namelen := conn.AddrPortUnmappedToSockaddr(downlink.clientAddrPort)
	tcMap := make(map[netip.AddrPort]*transparentConn)

	savec := make([]unix.RawSockaddrInet6, downlink.relayBatchSize)
	bufvec := make([][]byte, downlink.relayBatchSize)
	iovec := make([]unix.Iovec, downlink.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, downlink.relayBatchSize)

	for i := range downlink.relayBatchSize {
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

			downlink.logger.Warn("Failed to batch read packets from natConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.String("client", downlink.clientName),
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
				downlink.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.String("client", downlink.clientName),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				downlink.logger.Warn("Packet from natConn discarded",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, 0, int(msg.Msglen))
			if err != nil {
				downlink.logger.Warn("Failed to unpack packet from natConn",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			if payloadLength > maxClientPacketSize {
				downlink.logger.Warn("Payload too large to send to client",
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.String("client", downlink.clientName),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Int("payloadLength", payloadLength),
					zap.Int("maxClientPacketSize", maxClientPacketSize),
				)
				continue
			}

			tc := tcMap[payloadSourceAddrPort]
			if tc == nil {
				tc, err = s.newTransparentConn(ctx, payloadSourceAddrPort.String(), downlink.relayBatchSize, name, namelen)
				if err != nil {
					downlink.logger.Warn("Failed to create transparentConn",
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("packetSourceAddress", packetSourceAddrPort),
						zap.String("client", downlink.clientName),
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
			for start := 0; start < tc.n; {
				n, err := tc.mwc.WriteMsgs(tc.msgvec[start:tc.n], 0)
				start += n
				if err != nil {
					downlink.logger.Warn("Failed to batch write packets to transparentConn",
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.String("client", downlink.clientName),
						zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
						zap.Uint("packetLength", uint(tc.iovec[start].Len)),
						zap.Error(err),
					)
					start++
				}

				sendmmsgCount += uint64(n)
				packetsSent += uint64(n)
				burstBatchSize = max(burstBatchSize, n)
			}

			tc.n = 0
		}
	}

	for payloadSourceAddrPort, tc := range tcMap {
		if err := tc.close(); err != nil {
			downlink.logger.Warn("Failed to close transparentConn",
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.String("client", downlink.clientName),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Error(err),
			)
		}
	}

	downlink.logger.Info("Finished relay transparentConn <- natConn",
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.String("client", downlink.clientName),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink("", packetsSent, payloadBytesSent)
}

// Stop implements [shadowsocks.Service.Stop].
func (s *UDPTransparentRelay) Stop() error {
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

	s.logger.Info("Stopped UDP transparent relay service", zap.String("server", s.serverName))
	return nil
}
