package probe

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

// UDPProbeConfig is the configuration for a UDP probe.
type UDPProbeConfig struct {
	// Addr is the address of the UDP DNS server.
	Addr conn.Addr

	// Logger is the logger to use for the probe.
	Logger *zap.Logger
}

// NewProbe creates a new UDP probe from the configuration.
func (c UDPProbeConfig) NewProbe() UDPProbe {
	return UDPProbe{
		addr:   c.Addr,
		logger: c.Logger,
	}
}

// UDPProbe tests the connectivity of a UDP client by sending a DNS query to the configured server.
// The DNS server must support the HTTPS RR type and return a response indicating success.
type UDPProbe struct {
	addr   conn.Addr
	logger *zap.Logger
}

// Probe runs the connectivity test.
func (p UDPProbe) Probe(ctx context.Context, client zerocopy.UDPClient) error {
	sessionInfo, session, err := client.NewSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to create client session: %w", err)
	}
	defer session.Close()

	uc, _, err := sessionInfo.ListenConfig.ListenUDP(ctx, "udp", "")
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer uc.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = uc.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	b := make([]byte, session.MaxPacketSize)

	const domainName = "www.google.com."
	name, err := dnsmessage.NewName(domainName)
	if err != nil {
		return fmt.Errorf("failed to create DNS name: %w", err)
	}

	// maxDNSPacketSize is the maximum packet size to advertise in EDNS(0).
	// We use the same value as Go itself.
	const maxDNSPacketSize = 1232
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false); err != nil {
		return fmt.Errorf("failed to set EDNS(0) options: %w", err)
	}

	const rrTypeHTTPS = 65
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(rand.Uint64()),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  rrTypeHTTPS,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: rh,
				Body:   &dnsmessage.OPTResource{},
			},
		},
	}
	sendBuf, err := msg.AppendPack(b[:sessionInfo.PackerHeadroom.Front])
	if err != nil {
		return fmt.Errorf("failed to pack DNS message: %w", err)
	}
	payloadLen := len(sendBuf) - sessionInfo.PackerHeadroom.Front
	sendBuf = slices.Grow(sendBuf, sessionInfo.PackerHeadroom.Rear)[:len(sendBuf)+sessionInfo.PackerHeadroom.Rear]

	destAddrPort, packetStart, packetLen, err := session.Packer.PackInPlace(ctx, sendBuf, p.addr, sessionInfo.PackerHeadroom.Front, payloadLen)
	if err != nil {
		return fmt.Errorf("failed to pack DNS query packet: %w", err)
	}

	if _, err = uc.WriteToUDPAddrPort(sendBuf[packetStart:packetStart+packetLen], destAddrPort); err != nil {
		return fmt.Errorf("failed to send DNS query packet: %w", err)
	}

	for {
		n, _, flags, packetSourceAddress, err := uc.ReadMsgUDPAddrPort(b, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return err
			}
			p.logger.Warn("Failed to read DNS response packet",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			p.logger.Warn("Failed to read DNS response packet",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLen, err := session.Unpacker.UnpackInPlace(b, packetSourceAddress, 0, n)
		if err != nil {
			p.logger.Warn("Failed to unpack DNS response packet",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("packetSourceAddress", packetSourceAddress),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if p.addr.IsIP() {
			if !conn.AddrPortMappedEqual(payloadSourceAddrPort, p.addr.IPPort()) {
				p.logger.Warn("Ignoring DNS response packet from unexpected source",
					zap.String("client", sessionInfo.Name),
					zap.Stringer("targetAddr", p.addr),
					zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				)
				continue
			}
		}

		var parser dnsmessage.Parser

		header, err := parser.Start(b[payloadStart : payloadStart+payloadLen])
		if err != nil {
			p.logger.Warn("Failed to parse DNS response header",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Int("payloadLength", payloadLen),
				zap.Error(err),
			)
			continue
		}
		if header.ID != msg.Header.ID {
			p.logger.Warn("Ignoring DNS response packet with unexpected transaction ID",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Uint16("receivedID", header.ID),
				zap.Uint16("expectedID", msg.Header.ID),
			)
			continue
		}
		if !header.Response {
			p.logger.Warn("Ignoring non-response DNS packet",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
			)
			continue
		}
		if header.RCode != dnsmessage.RCodeSuccess {
			p.logger.Warn("Ignoring non-success DNS response",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Stringer("rcode", header.RCode),
			)
			continue
		}

		question, err := parser.Question()
		if err != nil {
			p.logger.Warn("Failed to parse question in DNS response packet",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Error(err),
			)
			continue
		}
		if question.Name.String() != domainName {
			p.logger.Warn("Ignoring DNS response packet with unexpected question name",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Stringer("receivedName", question.Name),
			)
			continue
		}
		if question.Type != rrTypeHTTPS {
			p.logger.Warn("Ignoring DNS response packet with unexpected question type",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Stringer("receivedType", question.Type),
			)
			continue
		}
		if question.Class != dnsmessage.ClassINET {
			p.logger.Warn("Ignoring DNS response packet with unexpected question class",
				zap.String("client", sessionInfo.Name),
				zap.Stringer("targetAddr", p.addr),
				zap.Stringer("payloadSourceAddrPort", payloadSourceAddrPort),
				zap.Stringer("receivedClass", question.Class),
			)
			continue
		}

		return nil
	}
}
