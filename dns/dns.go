package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/cache"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxDNSPacketSize is the maximum packet size to advertise in EDNS(0).
	// We use the same value as Go itself.
	maxDNSPacketSize = 1232

	lookupTimeout = 20 * time.Second

	defaultCacheSize = 1024
)

var (
	ErrLookup                       = errors.New("name lookup failed")
	ErrMessageNotResponse           = errors.New("message is not a response")
	ErrResponseNoRecursionAvailable = errors.New("response indicates server does not support recursion")
	ErrDomainNoAssociatedIPs        = errors.New("domain name has no associated IP addresses")
)

// ResolverConfig configures a DNS resolver.
type ResolverConfig struct {
	// Name is the resolver's name.
	// The name must be unique among all resolvers.
	Name string `json:"name"`

	// Type is the resolver type.
	//
	//  - "plain": Resolve names by sending cleartext DNS queries to the configured upstream server.
	//  - "system": Use the system resolver. This does not support custom server addresses or clients.
	//
	// The default value is "plain".
	Type string `json:"type,omitzero"`

	// AddrPort is the upstream server's address and port.
	AddrPort netip.AddrPort `json:"addrPort,omitzero"`

	// TCPClientName is the name of the TCPClient to use.
	// Leave empty to disable TCP.
	TCPClientName string `json:"tcpClientName,omitzero"`

	// UDPClientName is the name of the UDPClient to use.
	// Leave empty to disable UDP.
	UDPClientName string `json:"udpClientName,omitzero"`

	// CacheSize is the size of the DNS cache.
	//
	// If zero, the default cache size is 1024.
	// If negative, the cache will be unbounded.
	CacheSize int `json:"cacheSize,omitzero"`
}

// NewSimpleResolver creates a new [NewSimpleResolver] from the config.
func (rc *ResolverConfig) NewSimpleResolver(tcpClientMap map[string]netio.StreamClient, udpClientMap map[string]zerocopy.UDPClient, logger *zap.Logger) (SimpleResolver, error) {
	switch rc.Type {
	case "plain", "":
	case "system":
		if rc.AddrPort.IsValid() || rc.TCPClientName != "" || rc.UDPClientName != "" {
			return nil, errors.New("system resolver does not support custom server addresses or clients")
		}
		return NewSystemResolver(rc.Name, logger), nil
	default:
		return nil, fmt.Errorf("unknown resolver type: %q", rc.Type)
	}

	if !rc.AddrPort.IsValid() {
		return nil, errors.New("missing resolver address")
	}

	if rc.TCPClientName == "" && rc.UDPClientName == "" {
		return nil, errors.New("neither TCP nor UDP client specified")
	}

	var (
		tcpClient netio.StreamClient
		udpClient zerocopy.UDPClient
	)

	if rc.TCPClientName != "" {
		tcpClient = tcpClientMap[rc.TCPClientName]
		if tcpClient == nil {
			return nil, fmt.Errorf("unknown TCP client: %q", rc.TCPClientName)
		}
	}

	if rc.UDPClientName != "" {
		udpClient = udpClientMap[rc.UDPClientName]
		if udpClient == nil {
			return nil, fmt.Errorf("unknown UDP client: %q", rc.UDPClientName)
		}
	}

	cacheSize := rc.CacheSize
	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}

	return NewResolver(rc.Name, cacheSize, rc.AddrPort, tcpClient, udpClient, logger), nil
}

// Result represents the result of name resolution.
type Result struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr

	// TTL is the minimum TTL of A and AAAA RRs.
	TTL time.Time

	v4done bool
	v6done bool
}

type Resolver struct {
	// name stores the resolver's name to make its log messages more useful.
	name string

	// mu protects the DNS cache.
	mu sync.Mutex

	// cache is the DNS cache.
	cache cache.BoundedCache[string, Result]

	// serverAddr is the upstream server's address and port.
	serverAddr conn.Addr

	// serverAddrPort is the upstream server's address and port.
	serverAddrPort netip.AddrPort

	// tcpClient is the TCP client to use for sending queries and receiving replies.
	tcpClient netio.StreamClient

	// udpClient is the UDPClient to use for sending queries and receiving replies.
	udpClient zerocopy.UDPClient

	// logger is the shared logger instance.
	logger *zap.Logger
}

func NewResolver(name string, cacheSize int, serverAddrPort netip.AddrPort, tcpClient netio.StreamClient, udpClient zerocopy.UDPClient, logger *zap.Logger) *Resolver {
	return &Resolver{
		name:           name,
		cache:          *cache.NewBoundedCache[string, Result](cacheSize),
		serverAddr:     conn.AddrFromIPPort(serverAddrPort),
		serverAddrPort: serverAddrPort,
		tcpClient:      tcpClient,
		udpClient:      udpClient,
		logger:         logger,
	}
}

func (r *Resolver) lookup(ctx context.Context, name string) (Result, error) {
	// Lookup cache first.
	r.mu.Lock()
	result, ok := r.cache.Get(name)
	r.mu.Unlock()

	if ok && !result.HasExpired() {
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

	// Try UDP first if available.
	if r.udpClient != nil {
		r.sendQueriesUDP(ctx, nameString, q4Pkt, q6Pkt, &result)

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via UDP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Bool("handled", result.isDone()),
				zap.Stringers("v4", result.IPv4),
				zap.Stringers("v6", result.IPv6),
				zap.Time("ttl", result.TTL),
			)
		}
	}

	// Fallback to TCP if UDP failed or is unavailable.
	if !result.isDone() && r.tcpClient != nil {
		// Write length fields.
		q4LenBuf := qBuf[:2]
		q6LenBuf := qBuf[q4PktEnd:q6PktStart]
		binary.BigEndian.PutUint16(q4LenBuf, uint16(len(q4Pkt)))
		binary.BigEndian.PutUint16(q6LenBuf, uint16(len(q6Pkt)))

		r.sendQueriesTCP(ctx, nameString, qBuf[:q6PktEnd], q4PktEnd, &result)

		if ce := r.logger.Check(zap.DebugLevel, "DNS lookup sent queries via TCP"); ce != nil {
			ce.Write(
				zap.String("resolver", r.name),
				zap.String("name", nameString),
				zap.Bool("handled", result.isDone()),
				zap.Stringers("v4", result.IPv4),
				zap.Stringers("v6", result.IPv6),
				zap.Time("ttl", result.TTL),
			)
		}
	}

	if !result.isDone() {
		err = ErrLookup
		return
	}

	// Add result to cache if TTL hasn't expired.
	if !result.HasExpired() {
		r.mu.Lock()
		r.cache.Set(nameString, result)
		r.mu.Unlock()
	}

	return
}

// sendQueriesUDP sends queries using the resolver's UDP client and returns the result and whether the lookup was successful.
func (r *Resolver) sendQueriesUDP(ctx context.Context, nameString string, q4Pkt, q6Pkt []byte, result *Result) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	clientInfo, clientSession, err := r.udpClient.NewSession(ctx)
	if err != nil {
		r.logger.Warn("Failed to create new UDP client session",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Error(err),
		)
		return
	}
	defer clientSession.Close()

	udpConn, _, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
	if err != nil {
		r.logger.Warn("Failed to create UDP socket for DNS lookup",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Error(err),
		)
		return
	}
	defer udpConn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = udpConn.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	// Spin up senders.
	// Each sender will keep sending at 2s intervals until
	// done unblocks or after 10 iterations.
	sendFunc := func(pkt []byte, done <-chan struct{}) {
		b := make([]byte, clientInfo.PackerHeadroom.Front+len(pkt)+clientInfo.PackerHeadroom.Rear)

		for range 10 {
			copy(b[clientInfo.PackerHeadroom.Front:], pkt)
			destAddrPort, packetStart, packetLength, err := clientSession.Packer.PackInPlace(ctx, b, r.serverAddr, clientInfo.PackerHeadroom.Front, len(pkt))
			if err != nil {
				r.logger.Warn("Failed to pack UDP DNS query packet",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				cancel()
				return
			}

			_, err = udpConn.WriteToUDPAddrPort(b[packetStart:packetStart+packetLength], destAddrPort)
			if err != nil {
				r.logger.Warn("Failed to write UDP DNS query packet",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
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
	recvBuf := make([]byte, clientSession.MaxPacketSize)

	for {
		n, _, flags, packetSourceAddress, err := udpConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.logger.Warn("DNS lookup via UDP timed out",
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
				)
				break
			}
			r.logger.Warn("Failed to read UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			r.logger.Warn("Failed to read UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
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
			r.logger.Warn("Failed to unpack UDP DNS response packet",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(payloadSourceAddrPort, r.serverAddrPort) {
			r.logger.Warn("Ignoring UDP DNS response packet from unknown server",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
			)
			continue
		}
		msg := recvBuf[payloadStart : payloadStart+payloadLength]

		header, err := result.parseMsg(msg, true)
		if err != nil {
			r.logger.Warn("Failed to parse UDP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			break
		}
		if header.Truncated {
			if ce := r.logger.Check(zap.DebugLevel, "Received truncated UDP DNS response"); ce != nil {
				ce.Write(
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Uint16("transactionID", header.ID),
				)
			}
			// Immediately fall back to TCP.
			break
		}

		// Break out of loop if both v4 and v6 are done.
		if result.isDone() {
			break
		}

		switch header.ID {
		case 4:
			cancel4()
		case 6:
			cancel6()
		}
	}
}

// sendQueriesTCP sends queries using the resolver's TCP client and returns the result and whether the lookup was successful.
func (r *Resolver) sendQueriesTCP(ctx context.Context, nameString string, queries []byte, q4PktEnd int, result *Result) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	dialer, clientInfo := r.tcpClient.NewStreamDialer()

	// Retry unanswered queries.
	for !result.isDone() {
		b := queries
		switch {
		case result.v4done:
			b = b[q4PktEnd:]
		case result.v6done:
			b = b[:q4PktEnd]
		}
		r.doTCP(ctx, dialer, clientInfo, nameString, b, result)
	}
}

func (r *Resolver) doTCP(
	ctx context.Context,
	dialer netio.StreamDialer,
	clientInfo netio.StreamDialerInfo,
	nameString string,
	queries []byte,
	result *Result,
) {
	c, err := dialer.DialStream(ctx, r.serverAddr, queries)
	if err != nil {
		r.logger.Warn("Failed to dial TCP DNS server",
			zap.String("resolver", r.name),
			zap.String("client", clientInfo.Name),
			zap.String("name", nameString),
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Error(err),
		)
		return
	}
	defer c.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = c.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	lengthBuf := make([]byte, 2)

	for {
		// Read length field.
		_, err = io.ReadFull(c, lengthBuf)
		if err != nil {
			if err == io.EOF {
				return
			}
			r.logger.Warn("Failed to read TCP DNS response length",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			r.logger.Warn("TCP DNS response length is zero",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return
		}

		// Read message.
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(c, msg)
		if err != nil {
			r.logger.Warn("Failed to read TCP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		header, err := result.parseMsg(msg, false)
		if err != nil {
			r.logger.Warn("Failed to parse TCP DNS response",
				zap.String("resolver", r.name),
				zap.String("client", clientInfo.Name),
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}
		if header.Truncated {
			if ce := r.logger.Check(zap.DebugLevel, "Received truncated TCP DNS response"); ce != nil {
				ce.Write(
					zap.String("resolver", r.name),
					zap.String("client", clientInfo.Name),
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Uint16("transactionID", header.ID),
				)
			}
			// TCP DNS responses exceeding 65535 bytes are truncated.
			// Use the truncated response like how Go std & the glibc resolver do.
		}

		if result.isDone() {
			break
		}
	}
}

func (r *Result) parseMsg(msg []byte, isUDP bool) (dnsmessage.Header, error) {
	var parser dnsmessage.Parser

	// Parse header.
	header, err := parser.Start(msg)
	if err != nil {
		return dnsmessage.Header{}, fmt.Errorf("failed to parse query response header: %w", err)
	}

	// Check transaction ID.
	switch header.ID {
	case 4:
		if r.v4done {
			return header, nil
		}
		r.IPv4 = r.IPv4[:0]
	case 6:
		if r.v6done {
			return header, nil
		}
		r.IPv6 = r.IPv6[:0]
	default:
		return dnsmessage.Header{}, fmt.Errorf("unexpected transaction ID: %d", header.ID)
	}

	// Check response bit.
	if !header.Response {
		return dnsmessage.Header{}, ErrMessageNotResponse
	}

	// Continue parsing even if truncated.
	// The caller may still want to use the result.

	// Check RecursionAvailable.
	if !header.RecursionAvailable {
		return dnsmessage.Header{}, ErrResponseNoRecursionAvailable
	}

	// Check RCode.
	if header.RCode != dnsmessage.RCodeSuccess {
		return dnsmessage.Header{}, fmt.Errorf("DNS failure: %s", header.RCode)
	}

	// Skip questions.
	if err = parser.SkipAllQuestions(); err != nil {
		return dnsmessage.Header{}, fmt.Errorf("failed to skip questions: %w", err)
	}

	// Parse answers and add to result.
	for {
		answerHeader, err := parser.AnswerHeader()
		if err != nil {
			if err == dnsmessage.ErrSectionDone {
				break
			}
			return dnsmessage.Header{}, fmt.Errorf("failed to parse answer header: %w", err)
		}

		// Set minimum TTL.
		ttl := time.Now().Add(time.Duration(answerHeader.TTL) * time.Second)
		if r.TTL.IsZero() || r.TTL.After(ttl) {
			r.TTL = ttl
		}

		// Skip non-A/AAAA RRs.
		switch answerHeader.Type {
		case dnsmessage.TypeA:
			arr, err := parser.AResource()
			if err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to parse A resource: %w", err)
			}
			r.IPv4 = append(r.IPv4, netip.AddrFrom4(arr.A))

		case dnsmessage.TypeAAAA:
			aaaarr, err := parser.AAAAResource()
			if err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to parse AAAA resource: %w", err)
			}
			r.IPv6 = append(r.IPv6, netip.AddrFrom16(aaaarr.AAAA))

		default:
			if err = parser.SkipAnswer(); err != nil {
				return dnsmessage.Header{}, fmt.Errorf("failed to skip answer: %w", err)
			}
		}
	}

	// Mark v4 or v6 as done.
	if !header.Truncated || !isUDP {
		switch header.ID {
		case 4:
			r.v4done = true
		case 6:
			r.v6done = true
		}
	}

	return header, nil
}

func (r *Result) isDone() bool {
	return r.v4done && r.v6done
}

// HasExpired returns true if the result's TTL has expired.
func (r *Result) HasExpired() bool {
	return r.TTL.Before(time.Now())
}

// Clone returns a deep copy of the result.
// Modifying values in the address slices will not affect the original result.
func (r *Result) Clone() Result {
	return Result{
		IPv4:   slices.Clone(r.IPv4),
		IPv6:   slices.Clone(r.IPv6),
		TTL:    r.TTL,
		v4done: r.v4done,
		v6done: r.v6done,
	}
}

// Lookup looks up [name] and returns the result.
func (r *Resolver) Lookup(ctx context.Context, name string) (Result, error) {
	result, err := r.lookup(ctx, name)
	if err != nil {
		return Result{}, err
	}
	return result.Clone(), nil
}

// SimpleResolver defines methods that only return the resolved IP addresses.
type SimpleResolver interface {
	// LookupIP looks up [name] and returns one of the associated IP addresses.
	LookupIP(ctx context.Context, name string) (netip.Addr, error)

	// LookupIPs looks up [name] and returns all associated IP addresses.
	LookupIPs(ctx context.Context, name string) ([]netip.Addr, error)
}

// LookupIP implements [SimpleResolver.LookupIP].
func (r *Resolver) LookupIP(ctx context.Context, name string) (netip.Addr, error) {
	result, err := r.lookup(ctx, name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(result.IPv6) > 0 {
		return result.IPv6[0], nil
	}
	if len(result.IPv4) > 0 {
		return result.IPv4[0], nil
	}
	return netip.Addr{}, ErrDomainNoAssociatedIPs
}

// LookupIPs implements [SimpleResolver.LookupIPs].
func (r *Resolver) LookupIPs(ctx context.Context, name string) ([]netip.Addr, error) {
	result, err := r.lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	return slices.Concat(result.IPv6, result.IPv4), nil
}

// SystemResolver resolves names using [net.DefaultResolver].
// It implements [SimpleResolver].
type SystemResolver struct {
	name   string
	logger *zap.Logger
}

// NewSystemResolver returns a new [SystemResolver].
func NewSystemResolver(name string, logger *zap.Logger) *SystemResolver {
	return &SystemResolver{
		name:   name,
		logger: logger,
	}
}

// LookupIP implements [SimpleResolver.LookupIP].
func (r *SystemResolver) LookupIP(ctx context.Context, name string) (netip.Addr, error) {
	ips, err := r.LookupIPs(ctx, name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, ErrDomainNoAssociatedIPs
	}
	return ips[0], nil
}

// LookupIPs implements [SimpleResolver.LookupIPs].
func (r *SystemResolver) LookupIPs(ctx context.Context, name string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}

	if ce := r.logger.Check(zap.DebugLevel, "DNS lookup got result from system resolver"); ce != nil {
		ce.Write(
			zap.String("resolver", r.name),
			zap.String("name", name),
			zap.Stringers("ips", ips),
		)
	}

	return ips, nil
}
