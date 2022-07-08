package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
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

	return NewResolver(rc.AddrPort, tcpClient, udpClient, logger), nil
}

// Result represents the result of name resolution.
type Result struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr

	// TTL is the minimum TTL of A and AAAA RRs.
	TTL time.Time
}

type Resolver struct {
	// mu protects the DNS cache map.
	mu sync.RWMutex

	// cache is the DNS cache map.
	cache map[string]Result

	// serverAddrPort is the upstream server's address and port.
	serverAddrPort netip.AddrPort

	// tcpClient is the TCPClient to use for sending queries and receiving replies.
	tcpClient zerocopy.TCPClient

	// udpClient is the UDPClient to use for sending queries and receiving replies.
	udpClient zerocopy.UDPClient

	// logger is the shared logger instance.
	logger *zap.Logger
}

func NewResolver(serverAddrPort netip.AddrPort, tcpClient zerocopy.TCPClient, udpClient zerocopy.UDPClient, logger *zap.Logger) *Resolver {
	return &Resolver{
		cache:          make(map[string]Result),
		serverAddrPort: serverAddrPort,
		tcpClient:      tcpClient,
		udpClient:      udpClient,
		logger:         logger,
	}
}

func (r *Resolver) Lookup(name string) (Result, error) {
	// Lookup cache first.
	r.mu.RLock()
	result, ok := r.cache[name]
	r.mu.RUnlock()

	if ok && result.TTL.After(time.Now()) {
		r.logger.Debug("DNS lookup got result from cache",
			zap.String("name", name),
			zap.Time("ttl", result.TTL),
			zap.Int("v4Count", len(result.IPv4)),
			zap.Int("v6Count", len(result.IPv6)),
		)

		return result, nil
	}

	// Send queries to upstream server.
	return r.sendQueries(name)
}

func (r *Resolver) sendQueries(nameString string) (result Result, err error) {
	name, err := dnsmessage.NewName(nameString + ".")
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
		result, minTTL, handled = r.sendQueriesUDP(nameString, q4Pkt, q6Pkt)

		r.logger.Debug("DNS lookup sent queries via UDP",
			zap.String("name", nameString),
			zap.Uint32("minTTL", minTTL),
			zap.Bool("handled", handled),
			zap.Int("v4Count", len(result.IPv4)),
			zap.Int("v6Count", len(result.IPv6)),
		)
	}

	// Fallback to TCP if UDP failed or is unavailable.
	if !handled && r.tcpClient != nil {
		// Write length fields.
		q4LenBuf := qBuf[:2]
		q6LenBuf := qBuf[q4PktEnd:q6PktStart]
		binary.BigEndian.PutUint16(q4LenBuf, uint16(len(q4Pkt)))
		binary.BigEndian.PutUint16(q6LenBuf, uint16(len(q6Pkt)))

		result, minTTL, handled = r.sendQueriesTCP(nameString, qBuf[:q6PktEnd])

		r.logger.Debug("DNS lookup sent queries via TCP",
			zap.String("name", nameString),
			zap.Uint32("minTTL", minTTL),
			zap.Bool("handled", handled),
			zap.Int("v4Count", len(result.IPv4)),
			zap.Int("v6Count", len(result.IPv6)),
		)
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
func (r *Resolver) sendQueriesUDP(nameString string, q4Pkt, q6Pkt []byte) (result Result, minTTL uint32, handled bool) {
	// Target address of outgoing packets.
	targetAddrPort := r.serverAddrPort
	ap, _, fwmark, ok := r.udpClient.AddrPort()
	if ok {
		targetAddrPort = ap
	}

	// Workaround for https://github.com/golang/go/issues/52264
	targetAddrPort = conn.Tov4Mappedv6(targetAddrPort)

	// Create client session.
	packer, unpacker, err := r.udpClient.NewSession()
	if err != nil {
		r.logger.Warn("Failed to create new UDP client session",
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Stringer("targetAddrPort", targetAddrPort),
			zap.Int("fwmark", fwmark),
			zap.Error(err),
		)
		return
	}

	frontHeadroom := packer.FrontHeadroom()
	rearHeadroom := packer.RearHeadroom()

	// Prepare UDP socket.
	conn, err, serr := conn.ListenUDP("udp", "", false, fwmark)
	if err != nil {
		r.logger.Warn("Failed to listen UDP",
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Stringer("targetAddrPort", targetAddrPort),
			zap.Int("fwmark", fwmark),
			zap.Error(err),
		)
		return
	}
	if serr != nil {
		r.logger.Warn("An error occurred while setting socket options on listener",
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Stringer("targetAddrPort", targetAddrPort),
			zap.Int("fwmark", fwmark),
			zap.NamedError("serr", serr),
		)
	}
	defer conn.Close()

	// Set 20s read deadline.
	err = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if err != nil {
		r.logger.Warn("Failed to set read deadline",
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Stringer("targetAddrPort", targetAddrPort),
			zap.Int("fwmark", fwmark),
			zap.Error(err),
		)
		return
	}

	// Spin up senders.
	// Each sender will keep sending at 2s intervals until the stop signal
	// is received or after 10 iterations.
	sendFunc := func(pkt []byte, ctrlCh <-chan struct{}) {
		b := make([]byte, frontHeadroom+len(pkt)+rearHeadroom)
		serverAddr := socks5.AddrFromAddrPort(r.serverAddrPort)

	write:
		for i := 0; i < 10; i++ {
			copy(b[frontHeadroom:], pkt)
			packetStart, packetLength, err := packer.PackInPlace(b, serverAddr, frontHeadroom, len(pkt))
			if err != nil {
				r.logger.Warn("Failed to pack packet",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Error(err),
				)
				goto cleanup
			}

			_, err = conn.WriteToUDPAddrPort(b[packetStart:packetStart+packetLength], targetAddrPort)
			if err != nil {
				r.logger.Warn("Failed to write query",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Int("fwmark", fwmark),
					zap.Error(err),
				)
				goto cleanup
			}

			time.Sleep(2 * time.Second)

			select {
			case <-ctrlCh:
				break write
			default:
				continue write
			}

		cleanup:
			err = conn.SetReadDeadline(time.Now())
			if err != nil {
				r.logger.Warn("Failed to set read deadline",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Int("fwmark", fwmark),
					zap.Error(err),
				)
			}
			break
		}
	}

	ctrlCh4 := make(chan struct{}, 1)
	ctrlCh6 := make(chan struct{}, 1)
	go sendFunc(q4Pkt, ctrlCh4)
	go sendFunc(q6Pkt, ctrlCh6)

	// Receive replies.
	minTTL = math.MaxUint32
	recvBuf := make([]byte, 514)

	var (
		v4done, v6done bool
		parser         dnsmessage.Parser
	)

	for {
		n, ap, err := conn.ReadFromUDPAddrPort(recvBuf)
		if err != nil {
			r.logger.Warn("Failed to read query response",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Int("fwmark", fwmark),
				zap.Error(err),
			)
			return
		}
		if ap != targetAddrPort {
			r.logger.Warn("Ignoring packet from unknown address",
				zap.String("name", nameString),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Stringer("packetAddrPort", ap),
			)
			continue
		}

		_, payloadStart, payloadLength, err := unpacker.UnpackInPlace(recvBuf, 0, n)
		if err != nil {
			r.logger.Warn("Failed to unpack packet",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Int("fwmark", fwmark),
				zap.Error(err),
			)
			continue
		}
		payload := recvBuf[payloadStart : payloadStart+payloadLength]

		// Parse header.
		header, err := parser.Start(payload)
		if err != nil {
			r.logger.Warn("Failed to parse query response header",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Error(err),
			)
			return
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
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Uint16("transactionID", header.ID),
			)
			return
		}

		// Check response bit.
		if !header.Response {
			r.logger.Warn("Received non-response reply",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
			)
			return
		}

		// Check truncated bit.
		if header.Truncated {
			r.logger.Warn("Received truncated reply",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
			)
			return
		}

		// Check RCode.
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("DNS failure",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
				zap.Stringer("RCode", header.RCode),
			)
			return
		}

		// Skip questions.
		err = parser.SkipAllQuestions()
		if err != nil {
			r.logger.Warn("Failed to skip questions",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Stringer("targetAddrPort", targetAddrPort),
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
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Error(err),
				)
				return
			}

			// Set minimum TTL.
			if answerHeader.TTL < minTTL {
				r.logger.Debug("Updating minimum TTL",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Uint32("oldMinTTL", minTTL),
					zap.Uint32("newMinTTL", answerHeader.TTL),
				)
				minTTL = answerHeader.TTL
			}

			// Skip non-A/AAAA RRs.
			switch answerHeader.Type {
			case dnsmessage.TypeA:
				arr, err := parser.AResource()
				if err != nil {
					r.logger.Warn("Failed to parse A resource",
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("targetAddrPort", targetAddrPort),
						zap.Error(err),
					)
					return
				}

				addr4 := netip.AddrFrom4(arr.A)
				r.logger.Debug("Processing A RR",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Stringer("addr", addr4),
				)

				result.IPv4 = append(result.IPv4, addr4)

			case dnsmessage.TypeAAAA:
				aaaarr, err := parser.AAAAResource()
				if err != nil {
					r.logger.Warn("Failed to parse AAAA resource",
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Stringer("targetAddrPort", targetAddrPort),
						zap.Error(err),
					)
					return
				}

				addr6 := netip.AddrFrom16(aaaarr.AAAA)
				r.logger.Debug("Processing AAAA RR",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("targetAddrPort", targetAddrPort),
					zap.Stringer("addr", addr6),
				)

				result.IPv6 = append(result.IPv6, addr6)

			default:
				continue
			}
		}

		// Stop corresponding sender and mark as done.
		switch header.ID {
		case 4:
			ctrlCh4 <- struct{}{}
			close(ctrlCh4)
			v4done = true
		case 6:
			ctrlCh6 <- struct{}{}
			close(ctrlCh6)
			v6done = true
		}

		// Break out of loop if both v4 and v6 are done.
		if v4done && v6done {
			break
		}
	}

	// Clean up in case of error.
	if !v4done {
		ctrlCh4 <- struct{}{}
		close(ctrlCh4)
	}
	if !v6done {
		ctrlCh6 <- struct{}{}
		close(ctrlCh6)
	}

	handled = v4done && v6done
	return
}

// sendQueriesTCP sends queries using the resolver's TCP client and returns the result, a detached minTTL,
// and whether the lookup was successful.
//
// It's the caller's responsibility to examine the minTTL and decide whether to cache the result.
func (r *Resolver) sendQueriesTCP(nameString string, queries []byte) (result Result, minTTL uint32, handled bool) {
	// Write.
	rwConn, err := r.tcpClient.Dial(socks5.AddrFromAddrPort(r.serverAddrPort), queries)
	if err != nil {
		r.logger.Warn("Failed to dial DNS server",
			zap.String("name", nameString),
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Error(err),
		)
		return
	}
	defer rwConn.Close()

	// Set read deadline.
	err = rwConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if err != nil {
		r.logger.Warn("Failed to set read deadline",
			zap.String("name", nameString),
			zap.Stringer("serverAddrPort", r.serverAddrPort),
			zap.Error(err),
		)
		return
	}

	// Read.
	rw := zerocopy.NewCopyReadWriter(rwConn)
	lengthBuf := make([]byte, 2)
	minTTL = math.MaxUint32

	var (
		v4done, v6done bool
		parser         dnsmessage.Parser
	)

	for i := 0; i < 2; i++ {
		// Read length field.
		_, err = io.ReadFull(rw, lengthBuf)
		if err != nil {
			r.logger.Warn("Failed to read DNS response length",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Error(err),
			)
			return
		}

		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			r.logger.Warn("DNS response length is zero",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return
		}

		// Read message.
		msg := make([]byte, msgLen)
		_, err = io.ReadFull(rw, msg)
		if err != nil {
			r.logger.Warn("Failed to read DNS response",
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
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
				zap.Uint16("transactionID", header.ID),
			)
			return
		}

		// Check response bit.
		if !header.Response {
			r.logger.Warn("Received non-response reply",
				zap.String("name", nameString),
				zap.Stringer("serverAddrPort", r.serverAddrPort),
			)
			return
		}

		// Check RCode.
		if header.RCode != dnsmessage.RCodeSuccess {
			r.logger.Warn("DNS failure",
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
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Error(err),
				)
				return
			}

			// Set minimum TTL.
			if answerHeader.TTL < minTTL {
				r.logger.Debug("Updating minimum TTL",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Uint32("oldMinTTL", minTTL),
					zap.Uint32("newMinTTL", answerHeader.TTL),
				)
				minTTL = answerHeader.TTL
			}

			// Skip non-A/AAAA RRs.
			switch answerHeader.Type {
			case dnsmessage.TypeA:
				arr, err := parser.AResource()
				if err != nil {
					r.logger.Warn("Failed to parse A resource",
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					return
				}

				addr4 := netip.AddrFrom4(arr.A)
				r.logger.Debug("Processing A RR",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("addr", addr4),
				)

				result.IPv4 = append(result.IPv4, addr4)

			case dnsmessage.TypeAAAA:
				aaaarr, err := parser.AAAAResource()
				if err != nil {
					r.logger.Warn("Failed to parse AAAA resource",
						zap.String("name", nameString),
						zap.Stringer("serverAddrPort", r.serverAddrPort),
						zap.Error(err),
					)
					return
				}

				addr6 := netip.AddrFrom16(aaaarr.AAAA)
				r.logger.Debug("Processing AAAA RR",
					zap.String("name", nameString),
					zap.Stringer("serverAddrPort", r.serverAddrPort),
					zap.Stringer("addr", addr6),
				)

				result.IPv6 = append(result.IPv6, addr6)

			default:
				continue
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
