package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxDNSPacketSize is the maximum packet size to advertise in EDNS(0).
	// We use the same value as Go itself.
	maxDNSPacketSize = 1232

	lookupTimeout = 20 * time.Second
)

var ErrLookup = errors.New("name lookup failed")

// ResolverConfig configures a DNS resolver.
type ResolverConfig struct {
	// Name is the resolver's name.
	// The name must be unique among all resolvers.
	Name string `json:"name"`

	// AddrPort is the upstream server's address and port.
	AddrPort netip.AddrPort `json:"addrPort"`

	// TCPClientName is the name of the TCPClient to use.
	// Leave empty to disable TCP.
	TCPClientName string `json:"tcpClientName"`

	// UDPClientName is the name of the UDPClient to use.
	// Leave empty to disable UDP.
	UDPClientName string `json:"udpClientName"`
}

func (rc *ResolverConfig) Resolver(tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, logger *zap.Logger) (*Resolver, error) {
	if !rc.AddrPort.IsValid() {
		return nil, errors.New("missing resolver address")
	}

	var (
		tcpClient zerocopy.TCPClient
		udpClient zerocopy.UDPClient
	)

	if rc.TCPClientName != "" {
		tcpClient = tcpClientMap[rc.TCPClientName]
		if tcpClient == nil {
			return nil, fmt.Errorf("unknown TCP client: %s", rc.TCPClientName)
		}
	}

	if rc.UDPClientName != "" {
		udpClient = udpClientMap[rc.UDPClientName]
		if udpClient == nil {
			return nil, fmt.Errorf("unknown UDP client: %s", rc.UDPClientName)
		}
	}

	return NewResolver(rc.Name, rc.AddrPort, tcpClient, udpClient, logger), nil
}

// Result represents the result of name resolution.
type Result struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr

	// TTL is the minimum TTL of A and AAAA RRs.
	TTL time.Time
}

type Resolver struct {
	// name stores the resolver's name to make its log messages more useful.
	name string

	// mu protects the DNS cache map.
	mu sync.RWMutex

	// cache is the DNS cache map.
	cache map[string]Result

	// serverAddr is the upstream server's address and port.
	serverAddr conn.Addr

	// serverAddrPort is the upstream server's address and port.
	serverAddrPort netip.AddrPort

	// tcpClient is the TCPClient to use for sending queries and receiving replies.
	tcpClient zerocopy.TCPClient

	// udpClient is the UDPClient to use for sending queries and receiving replies.
	udpClient zerocopy.UDPClient

	// logger is the shared logger instance.
	logger *zap.Logger
}

func NewResolver(name string, serverAddrPort netip.AddrPort, tcpClient zerocopy.TCPClient, udpClient zerocopy.UDPClient, logger *zap.Logger) *Resolver {
	return &Resolver{
		name:           name,
		cache:          make(map[string]Result),
		serverAddr:     conn.AddrFromIPPort(serverAddrPort),
		serverAddrPort: serverAddrPort,
		tcpClient:      tcpClient,
		udpClient:      udpClient,
		logger:         logger,
	}
}

func (r *Resolver) Lookup(ctx context.Context, name string) (Result, error) {
	// Lookup cache first.
	r.mu.RLock()
	result, ok := r.cache[name]
	r.mu.RUnlock()

	if ok && result.TTL.After(time.Now()) {
		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup got result from cache"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", name),
				zap.Time("ttl", result.TTL),
				zap.Stringers("v4", result.IPv4),
				zap.Stringers("v6", result.IPv6),
			)
		}
		return result, nil
	}

	// Send queries to upstream server.
	return r.sendQueries(ctx, name)
}

func (r *Resolver) sendQueries(ctx context.Context, nameString string) (result Result, err error) {
	name, err := dnsmessage.NewName(nameString + ".")
	if err != nil {
		return
	}

	var (
		rh dnsmessage.ResourceHeader
		rb dnsmessage.OPTResource
	)

	err = rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false)
	if err != nil {
		return
	}

	qBuf := make([]byte, 2+512+2+512)

	q4 := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               4,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: rh,
				Body:   &rb,
			},
		},
	}
	q4Pkt := qBuf[2:2]
	q4Pkt, err = q4.AppendPack(q4Pkt)
	if err != nil {
		return
	}
	q4PktEnd := 2 + len(q4Pkt)

	q6 := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               6,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: rh,
				Body:   &rb,
			},
		},
	}
	q6PktStart := q4PktEnd + 2
	q6Pkt := qBuf[q6PktStart:q6PktStart]
	q6Pkt, err = q6.AppendPack(q6Pkt)
	if err != nil {
		return
	}
	q6PktEnd := q6PktStart + len(q6Pkt)

	var (
		minTTL  uint32
		handled bool
	)

	// Try UDP first if available.
	if r.udpClient != nil {
		result, minTTL, handled = r.sendQueriesUDP(ctx, nameString, q4Pkt, q6Pkt)

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via UDP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Uint32("minTTL", minTTL),
				zap.Bool("handled", handled),
				zap.Stringers("v4", result.IPv4),
				zap.Stringers("v6", result.IPv6),
			)
		}
	}

	// Fallback to TCP if UDP failed or is unavailable.
	if !handled && r.tcpClient != nil {
		// Write length fields.
		q4LenBuf := qBuf[:2]
		q6LenBuf := qBuf[q4PktEnd:q6PktStart]
		binary.BigEndian.PutUint16(q4LenBuf, uint16(len(q4Pkt)))
		binary.BigEndian.PutUint16(q6LenBuf, uint16(len(q6Pkt)))

		result, minTTL, handled = r.sendQueriesTCP(ctx, nameString, qBuf[:q6PktEnd])

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via TCP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Uint32("minTTL", minTTL),
				zap.Bool("handled", handled),
				zap.Stringers("v4", result.IPv4),
				zap.Stringers("v6", result.IPv6),
			)
		}
	}

	if !handled {
		err = ErrLookup
		return
	}

	// Add result to cache if minTTL != 0.
	if minTTL != 0 {
		result.TTL = time.Now().Add(time.Duration(minTTL) * time.Second)

		r.mu.Lock()
		r.cache[nameString] = result
		r.mu.Unlock()
	}

	return
}

// sendQueriesUDP sends queries using the resolver's UDP client and returns the result, a detached minTTL,
// and whether the lookup was successful.
//
// It's the caller's responsibility to examine the minTTL and decide whether to cache the result.
func (r *Resolver) sendQueriesUDP(ctx context.Context, nameString string, q4Pkt, q6Pkt []byte) (result Result, minTTL uint32, handled bool) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	clientInfo, clientSession, err := r.udpClient.NewSession(ctx)
	if err != nil {
		r.logger.Warn("Failed to create new UDP client session",
			zap.String("resolver", r.name),
			zap.Error(err),
		)
		return
	}
	defer clientSession.Close()

	udpConn, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
	if err != nil {
		r.logger.Warn("Failed to create UDP socket for DNS lookup",
			zap.String("resolver", r.name),
			zap.Error(err),
		)
		return
	}
	defer udpConn.Close()

	go func() {
		<-ctx.Done()
		udpConn.SetReadDeadline(time.Now())
	}()

	// Spin up senders.
	// Each sender will keep sending at 2s intervals until
	// done unblocks or after 10 iterations.
	sendFunc := func(pkt []byte, done <-chan struct{}) {
		b := make([]byte, clientInfo.PackerHeadroom.Front+len(pkt)+clientInfo.PackerHeadroom.Rear)

		for i := 0; i < 10; i++ {
			copy(b[clientInfo.PackerHeadroom.Front:], pkt)
			destAddrPort, packetStart, packetLength, err := clientSession.Packer.PackInPlace(ctx, b, r.serverAddr, clientInfo.PackerHeadroom.Front, len(pkt))
			if err != nil {
				r.logger.Warn("Failed to pack packet",
					zap.String("resolver", r.name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				cancel()
				return
			}

			_, err = udpConn.WriteToUDPAddrPort(b[packetStart:packetStart+packetLength], destAddrPort)
			if err != nil {
				r.logger.Warn("Failed to write query",
					zap.String("resolver", r.name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("destAddrPort", destAddrPort),
					zap.Error(err),
				)
				cancel()
				return
			}

			select {
			case <-done:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}

	ctx4, cancel4 := context.WithCancel(ctx)
	ctx6, cancel6 := context.WithCancel(ctx)
	defer cancel4()
	defer cancel6()
	go sendFunc(q4Pkt, ctx4.Done())
	go sendFunc(q6Pkt, ctx6.Done())

	// Receive replies.
	minTTL = math.MaxUint32
	recvBuf := make([]byte, clientSession.MaxPacketSize)

	var (
		v4done, v6done bool
		parser         dnsmessage.Parser
	)

read:
	for {
		n, _, flags, packetSourceAddress, err := udpConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.logger.Warn("DNS lookup via UDP timed out",
					zap.String("resolver", r.name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
				)
				break
			}
			r.logger.Warn("Failed to read query response",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			r.logger.Warn("Failed to read query response",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := clientSession.Unpacker.UnpackInPlace(recvBuf, packetSourceAddress, 0, n)
		if err != nil {
			r.logger.Warn("Failed to unpack packet",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(payloadSourceAddrPort, r.serverAddrPort) {
			r.logger.Warn("Ignoring packet from unknown server",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
			)
			continue
		}
		payload := recvBuf[payloadStart : payloadStart+payloadLength]

		// Parse header.
		header, err := parser.Start(payload)
		if err != nil {
			r.logger.Warn("Failed to parse query response header",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			break
		}

		// Check transaction ID.
		switch header.ID {
		case 4:
			if v4done {
				continue
			}
		case 6:
			if v6done {
				continue
			}
		default:
			r.logger.Warn("Unexpected transaction ID",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Uint16("transactionID", header.ID),
			)
			break read
		}

		// Check response bit.
		if !header.Response {
			r.logger.Warn("Received non-response reply",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			break
		}

		// Check truncated bit.
		if header.Truncated {
			r.logger.Warn("Received truncated reply",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			break
		}

		// Check RCode.
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("DNS failure",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("RCode", header.RCode),
			)
			break
		}

		// Skip questions.
		err = parser.SkipAllQuestions()
		if err != nil {
			r.logger.Warn("Failed to skip questions",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			break
		}

		// Parse answers and add to result.
		for {
			answerHeader, err := parser.AnswerHeader()
			if err != nil {
				if err == dnsmessage.ErrSectionDone {
					break
				}
				r.logger.Warn("Failed to parse answer header",
					zap.String("resolver", r.name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				break read
			}

			// Set minimum TTL.
			if answerHeader.TTL < minTTL {
				if ce := r.logger.Check(zap.DebugLevel, "Updating minimum TTL"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("answerType", answerHeader.Type),
						zap.Uint32("oldMinTTL", minTTL),
						zap.Uint32("newMinTTL", answerHeader.TTL),
					)
				}
				minTTL = answerHeader.TTL
			}

			// Skip non-A/AAAA RRs.
			switch answerHeader.Type {
			case dnsmessage.TypeA:
				arr, err := parser.AResource()
				if err != nil {
					r.logger.Warn("Failed to parse A resource",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					break read
				}

				addr4 := netip.AddrFrom4(arr.A)
				result.IPv4 = append(result.IPv4, addr4)

				if ce := r.logger.Check(zap.DebugLevel, "Processing A RR"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("addr", addr4),
					)
				}

			case dnsmessage.TypeAAAA:
				aaaarr, err := parser.AAAAResource()
				if err != nil {
					r.logger.Warn("Failed to parse AAAA resource",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					break read
				}

				addr6 := netip.AddrFrom16(aaaarr.AAAA)
				result.IPv6 = append(result.IPv6, addr6)

				if ce := r.logger.Check(zap.DebugLevel, "Processing AAAA RR"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("addr", addr6),
					)
				}

			default:
				err = parser.SkipAnswer()
				if err != nil {
					r.logger.Warn("Failed to skip answer",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("answerType", answerHeader.Type),
						zap.Error(err),
					)
					break read
				}
			}
		}

		// Stop corresponding sender and mark as done.
		switch header.ID {
		case 4:
			cancel4()
			v4done = true
		case 6:
			cancel6()
			v6done = true
		}

		// Break out of loop if both v4 and v6 are done.
		if v4done && v6done {
			break
		}
	}

	handled = v4done && v6done
	return
}

// sendQueriesTCP sends queries using the resolver's TCP client and returns the result, a detached minTTL,
// and whether the lookup was successful.
//
// It's the caller's responsibility to examine the minTTL and decide whether to cache the result.
func (r *Resolver) sendQueriesTCP(ctx context.Context, nameString string, queries []byte) (result Result, minTTL uint32, handled bool) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	// Write.
	rawRW, rw, err := r.tcpClient.Dial(ctx, r.serverAddr, queries)
	if err != nil {
		r.logger.Warn("Failed to dial DNS server",
			zap.String("resolver", r.name),
			zap.String("name", nameString),
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Error(err),
		)
		return
	}
	defer rawRW.Close()

	// Set read deadline.
	if tc, ok := rawRW.(*net.TCPConn); ok {
		go func() {
			<-ctx.Done()
			tc.SetReadDeadline(time.Now())
		}()
	}

	// Read.
	crw := zerocopy.NewCopyReadWriter(rw)
	lengthBuf := make([]byte, 2)
	minTTL = math.MaxUint32

	var (
		v4done, v6done bool
		parser         dnsmessage.Parser
	)

	for i := 0; i < 2; i++ {
		// Read length field.
		_, err = io.ReadFull(crw, lengthBuf)
		if err != nil {
			r.logger.Warn("Failed to read DNS response length",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			r.logger.Warn("DNS response length is zero",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return
		}

		// Read message.
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(crw, msg)
		if err != nil {
			r.logger.Warn("Failed to read DNS response",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		// Parse header.
		header, err := parser.Start(msg)
		if err != nil {
			r.logger.Warn("Failed to parse query response header",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		// Check transaction ID.
		switch header.ID {
		case 4, 6:
		default:
			r.logger.Warn("Unexpected transaction ID",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Uint16("transactionID", header.ID),
			)
			return
		}

		// Check response bit.
		if !header.Response {
			r.logger.Warn("Received non-response reply",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return
		}

		// Check RCode.
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("DNS failure",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("RCode", header.RCode),
			)
			return
		}

		// Skip questions.
		err = parser.SkipAllQuestions()
		if err != nil {
			r.logger.Warn("Failed to skip questions",
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		// Parse answers and add to result.
		for {
			answerHeader, err := parser.AnswerHeader()
			if err != nil {
				if err == dnsmessage.ErrSectionDone {
					break
				}
				r.logger.Warn("Failed to parse answer header",
					zap.String("resolver", r.name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				return
			}

			// Set minimum TTL.
			if answerHeader.TTL < minTTL {
				if ce := r.logger.Check(zap.DebugLevel, "Updating minimum TTL"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("answerType", answerHeader.Type),
						zap.Uint32("oldMinTTL", minTTL),
						zap.Uint32("newMinTTL", answerHeader.TTL),
					)
				}
				minTTL = answerHeader.TTL
			}

			// Skip non-A/AAAA RRs.
			switch answerHeader.Type {
			case dnsmessage.TypeA:
				arr, err := parser.AResource()
				if err != nil {
					r.logger.Warn("Failed to parse A resource",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					return
				}

				addr4 := netip.AddrFrom4(arr.A)
				result.IPv4 = append(result.IPv4, addr4)

				if ce := r.logger.Check(zap.DebugLevel, "Processing A RR"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("addr", addr4),
					)
				}

			case dnsmessage.TypeAAAA:
				aaaarr, err := parser.AAAAResource()
				if err != nil {
					r.logger.Warn("Failed to parse AAAA resource",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					return
				}

				addr6 := netip.AddrFrom16(aaaarr.AAAA)
				result.IPv6 = append(result.IPv6, addr6)

				if ce := r.logger.Check(zap.DebugLevel, "Processing AAAA RR"); ce != nil {
					ce.Write(
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("addr", addr6),
					)
				}

			default:
				err = parser.SkipAnswer()
				if err != nil {
					r.logger.Warn("Failed to skip answer",
						zap.String("resolver", r.name),
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("answerType", answerHeader.Type),
						zap.Error(err),
					)
					return
				}
			}
		}

		// Mark v4 or v6 as done.
		switch header.ID {
		case 4:
			v4done = true
		case 6:
			v6done = true
		}
	}

	handled = v4done && v6done
	return
}
