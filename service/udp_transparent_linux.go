package service

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// transparentQueuedPacket is the structure used by send channels to queue packets for sending.
type transparentQueuedPacket struct {
	bufp           *[]byte
	targetAddrPort netip.AddrPort
	msglen         uint32
}

// transparentNATEntry is an entry in the tproxy NAT table.
type transparentNATEntry struct {
	natConn            *net.UDPConn
	natConnRecvBufSize int
	natConnSendCh      chan transparentQueuedPacket
	natConnPacker      zerocopy.ClientPacker
	natConnUnpacker    zerocopy.ClientUnpacker
}

// UDPTransparentRelay is like [UDPNATRelay], but for transparent proxy.
type UDPTransparentRelay struct {
	serverName             string
	listenAddress          string
	listenerFwmark         int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	batchSize              int
	natTimeout             time.Duration
	serverConn             *net.UDPConn
	router                 *router.Router
	logger                 *zap.Logger
	packetBufPool          *sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[netip.AddrPort]*transparentNATEntry
}

func NewUDPTransparentRelay(
	serverName, listenAddress string,
	batchSize, listenerFwmark, mtu, maxClientFrontHeadroom, maxClientRearHeadroom int,
	natTimeout time.Duration,
	router *router.Router,
	logger *zap.Logger,
) (Relay, error) {
	packetBufRecvSize := mtu - zerocopy.IPv4HeaderLength - zerocopy.UDPHeaderLength
	packetBufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, maxClientFrontHeadroom+packetBufRecvSize+maxClientRearHeadroom)
			return &b
		},
	}
	return &UDPTransparentRelay{
		serverName:             serverName,
		listenAddress:          listenAddress,
		listenerFwmark:         listenerFwmark,
		mtu:                    mtu,
		packetBufFrontHeadroom: maxClientFrontHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		batchSize:              batchSize,
		natTimeout:             natTimeout,
		router:                 router,
		logger:                 logger,
		packetBufPool:          packetBufPool,
		table:                  make(map[netip.AddrPort]*transparentNATEntry),
	}, nil
}

// String implements the Relay String method.
func (s *UDPTransparentRelay) String() string {
	return "UDP transparent relay service for " + s.serverName
}

// Start implements the Relay Start method.
func (s *UDPTransparentRelay) Start() error {
	serverConn, err := conn.ListenUDPTransparent("udp", s.listenAddress, true, false, s.listenerFwmark)
	if err != nil {
		return err
	}
	s.serverConn = serverConn

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnRecvmmsg()
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP transparent relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

func (s *UDPTransparentRelay) recvFromServerConnRecvmmsg() {
	bufvec := make([]*[]byte, conn.UIO_MAXIOV)
	namevec := make([]unix.RawSockaddrInet6, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	cmsgvec := make([][]byte, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.TransparentSocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	n := conn.UIO_MAXIOV

	var (
		err                  error
		recvmmsgCount        uint64
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		for i := range iovec[:n] {
			packetBufp := s.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			bufvec[i] = packetBufp
			iovec[i].Base = &packetBuf[s.packetBufFrontHeadroom]
			iovec[i].SetLen(s.packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.TransparentSocketControlMessageBufferSize)
		}

		n, err = conn.Recvmmsg(s.serverConn, msgvec)
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
			s.packetBufPool.Put(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)

		s.mu.Lock()

		for i, msg := range msgvec[:n] {
			packetBufp := bufvec[i]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
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

				s.packetBufPool.Put(packetBufp)
				continue
			}

			targetAddrPort, err := conn.ParseOrigDstAddrCmsg(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse original destination address control message from serverConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)

				s.packetBufPool.Put(packetBufp)
				continue
			}

			payloadBytesReceived += uint64(msg.Msglen)

			entry := s.table[clientAddrPort]
			if entry == nil {
				entry = &transparentNATEntry{
					natConnSendCh: make(chan transparentQueuedPacket, sendChannelCapacity),
				}

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
								s.packetBufPool.Put(queuedPacket.bufp)
							}
						}
					}()

					c, err := s.router.GetUDPClient(s.serverName, clientAddrPort, conn.AddrFromIPPort(targetAddrPort))
					if err != nil {
						s.logger.Warn("Failed to get UDP client for new NAT session",
							zap.String("server", s.serverName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddrPort),
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
							zap.Stringer("targetAddress", targetAddrPort),
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
							zap.Stringer("targetAddress", targetAddrPort),
							zap.Int("natConnFwmark", natConnFwmark),
							zap.Error(err),
						)
						return
					}

					if err = natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
						s.logger.Warn("Failed to set read deadline on natConn",
							zap.String("server", s.serverName),
							zap.String("client", clientName),
							zap.String("listenAddress", s.listenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("targetAddress", targetAddrPort),
							zap.Duration("natTimeout", s.natTimeout),
							zap.Error(err),
						)
						natConn.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					entry.natConn = natConn
					entry.natConnRecvBufSize = natConnMaxPacketSize
					entry.natConnPacker = natConnPacker
					entry.natConnUnpacker = natConnUnpacker

					s.logger.Info("UDP transparent relay started",
						zap.String("server", s.serverName),
						zap.String("client", clientName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("targetAddress", targetAddrPort),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(clientAddrPort, entry)
						entry.natConn.Close()
						s.wg.Done()
					}()

					s.relayNatConnToTransparentConnSendmmsg(clientAddrPort, entry)
				}()

				s.logger.Debug("New UDP transparent session",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddrPort),
				)
			}

			select {
			case entry.natConnSendCh <- transparentQueuedPacket{packetBufp, targetAddrPort, msg.Msglen}:
			default:
				s.logger.Debug("Dropping packet due to full send channel",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", targetAddrPort),
				)

				s.packetBufPool.Put(packetBufp)
			}
		}

		s.mu.Unlock()
	}

	for _, packetBufp := range bufvec {
		s.packetBufPool.Put(packetBufp)
	}

	s.logger.Info("Finished receiving from serverConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPTransparentRelay) relayServerConnToNatConnSendmmsg(clientAddrPort netip.AddrPort, entry *transparentNATEntry) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
	)

	dequeuedPackets := make([]transparentQueuedPacket, s.batchSize)
	namevec := make([]unix.RawSockaddrInet6, s.batchSize)
	iovec := make([]unix.Iovec, s.batchSize)
	msgvec := make([]conn.Mmsghdr, s.batchSize)

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
		queuedPacket, ok := <-entry.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			destAddrPort, packetStart, packetLength, err = entry.natConnPacker.PackInPlace(*queuedPacket.bufp, conn.AddrFromIPPort(queuedPacket.targetAddrPort), s.packetBufFrontHeadroom, int(queuedPacket.msglen))
			if err != nil {
				s.logger.Warn("Failed to pack packet for natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("targetAddress", queuedPacket.targetAddrPort),
					zap.Uint32("payloadLength", queuedPacket.msglen),
					zap.Error(err),
				)

				s.packetBufPool.Put(queuedPacket.bufp)

				if count == 0 {
					continue main
				}
				goto next
			}

			dequeuedPackets[count] = queuedPacket
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &(*queuedPacket.bufp)[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.msglen)

			if count == s.batchSize {
				break
			}

		next:
			select {
			case queuedPacket, ok = <-entry.natConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		if err := conn.WriteMsgvec(entry.natConn, msgvec[:count]); err != nil {
			s.logger.Warn("Failed to batch write packets to natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("lastTargetAddress", dequeuedPackets[count-1].targetAddrPort),
				zap.Stringer("lastWriteDestAddress", destAddrPort),
				zap.Error(err),
			)
		}

		if err := entry.natConn.SetReadDeadline(time.Now().Add(s.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Duration("natTimeout", s.natTimeout),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

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
		zap.Stringer("lastWriteDestAddress", destAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
}

type transparentConn struct {
	uc     *net.UDPConn
	iovec  []unix.Iovec
	msgvec []conn.Mmsghdr
	n      int
}

func newTransparentConn(address string, fwmark, batchSize int, name *byte, namelen uint32) (*transparentConn, error) {
	uc, err := conn.ListenUDPTransparent("udp", address, false, true, fwmark)
	if err != nil {
		return nil, err
	}

	iovec := make([]unix.Iovec, batchSize)
	msgvec := make([]conn.Mmsghdr, batchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	return &transparentConn{
		uc:     uc,
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
	return 1, packetsSent, conn.WriteMsgvec(tc.uc, tc.msgvec[:packetsSent])
}

func (tc *transparentConn) close() error {
	return tc.uc.Close()
}

func (s *UDPTransparentRelay) relayNatConnToTransparentConnSendmmsg(clientAddrPort netip.AddrPort, entry *transparentNATEntry) {
	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
	)

	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
	name, namelen := conn.AddrPortUnmappedToSockaddr(clientAddrPort)
	tcMap := make(map[netip.AddrPort]*transparentConn)

	savec := make([]unix.RawSockaddrInet6, s.batchSize)
	bufvec := make([][]byte, s.batchSize)
	iovec := make([]unix.Iovec, s.batchSize)
	msgvec := make([]conn.Mmsghdr, s.batchSize)

	for i := 0; i < s.batchSize; i++ {
		packetBuf := make([]byte, entry.natConnRecvBufSize)
		bufvec[i] = packetBuf

		iovec[i].Base = &packetBuf[0]
		iovec[i].SetLen(entry.natConnRecvBufSize)

		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	for {
		nr, err := conn.Recvmmsg(entry.natConn, msgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from natConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
			continue
		}

		var ns int

		for i, msg := range msgvec[:nr] {
			packetBuf := bufvec[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				s.logger.Warn("Packet from natConn discarded",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			payloadSourceAddrPort, payloadStart, payloadLength, err := entry.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, 0, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from natConn",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
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
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Int("payloadLength", payloadLength),
					zap.Int("maxClientPacketSize", maxClientPacketSize),
				)
				continue
			}

			tc := tcMap[payloadSourceAddrPort]
			if tc == nil {
				tc, err = newTransparentConn(payloadSourceAddrPort.String(), s.listenerFwmark, s.batchSize, name, namelen)
				if err != nil {
					s.logger.Warn("Failed to create transparentConn",
						zap.String("server", s.serverName),
						zap.String("listenAddress", s.listenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
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
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
					zap.Error(err),
				)
			}

			sendmmsgCount += uint64(sc)
			packetsSent += uint64(ps)
		}
	}

	for payloadSourceAddrPort, tc := range tcMap {
		if err := tc.close(); err != nil {
			s.logger.Warn("Failed to close transparentConn",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("payloadSourceAddress", payloadSourceAddrPort),
				zap.Error(err),
			)
		}
	}

	s.logger.Info("Finished relay transparentConn <- natConn",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("payloadBytesSent", payloadBytesSent),
	)
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

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	return s.serverConn.Close()
}
