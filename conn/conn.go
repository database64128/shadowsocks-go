package conn

import (
	"context"
	"net"
	"syscall"

	"github.com/database64128/tfo-go/v2"
)

// SocketInfo contains information about a socket.
type SocketInfo struct {
	// MaxUDPGSOSegments is the maximum number of UDP GSO segments supported by the socket.
	//
	// If UDP GSO is not enabled on the socket, or the system does not support UDP GSO, the value is 1.
	//
	// The value is 0 if the socket is not a UDP socket.
	MaxUDPGSOSegments int

	// UDPGenericReceiveOffload indicates whether UDP GRO is enabled on the socket.
	UDPGenericReceiveOffload bool
}

type setFunc = func(fd int, network string, info *SocketInfo) error

type setFuncSlice []setFunc

func (fns setFuncSlice) controlContextFunc(info *SocketInfo) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network, info); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

func (fns setFuncSlice) controlFunc(info *SocketInfo) func(network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network, info); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

// ListenConfig wraps a [tfo.ListenConfig] and provides a subjectively nicer API.
type ListenConfig struct {
	tlc tfo.ListenConfig
	fns setFuncSlice
}

// ListenTCP wraps [tfo.ListenConfig.Listen] and returns a [*net.TCPListener] directly.
func (lc *ListenConfig) ListenTCP(ctx context.Context, network, address string) (tln *net.TCPListener, info SocketInfo, err error) {
	tlc := lc.tlc
	tlc.Control = lc.fns.controlFunc(&info)
	ln, err := tlc.Listen(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return ln.(*net.TCPListener), info, nil
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (lc *ListenConfig) ListenUDP(ctx context.Context, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	nlc := lc.tlc.ListenConfig
	nlc.Control = lc.fns.controlFunc(&info)
	pc, err := nlc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return pc.(*net.UDPConn), info, nil
}

// ListenerSocketOptions contains listener-specific socket options.
type ListenerSocketOptions struct {
	// SendBufferSize sets the send buffer size of the listener.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the listener.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// TCPFastOpenBacklog specifies the maximum number of pending TFO connections on Linux.
	// If the value is 0, Go std's listen(2) backlog is used.
	//
	// On other platforms, a non-negative value is ignored, as they do not have the option to set the TFO backlog.
	//
	// On all platforms, a negative value disables TFO.
	TCPFastOpenBacklog int

	// TCPDeferAcceptSecs sets TCP_DEFER_ACCEPT to the given number of seconds on the listener.
	//
	// Available on Linux.
	TCPDeferAcceptSecs int

	// TCPUserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the listener.
	//
	// Available on Linux.
	TCPUserTimeoutMsecs int

	// ReusePort enables SO_REUSEPORT on the listener.
	//
	// Available on Linux and the BSDs.
	ReusePort bool

	// Transparent enables transparent proxy on the listener.
	//
	// Only available on Linux.
	Transparent bool

	// PathMTUDiscovery enables Path MTU Discovery on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery bool

	// TCPFastOpen enables TCP Fast Open on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	TCPFastOpen bool

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the listener.
	//
	// When enabled, the listener will start without TFO if TFO is not available on the system.
	// When disabled, the listener will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool

	// MultipathTCP enables multipath TCP on the listener.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	MultipathTCP bool

	// UDPGenericReceiveOffload enables UDP Generic Receive Offload (GRO) on the listener.
	//
	// Available on Linux and Windows.
	UDPGenericReceiveOffload bool

	// ReceivePacketInfo enables the reception of packet information control messages on the listener.
	//
	// Available on Linux, macOS, and Windows.
	ReceivePacketInfo bool

	// ReceiveOriginalDestAddr enables the reception of original destination address control messages on the listener.
	//
	// Only available on Linux.
	ReceiveOriginalDestAddr bool
}

// ListenConfig returns a [ListenConfig] that sets the socket options.
func (lso ListenerSocketOptions) ListenConfig() ListenConfig {
	lc := ListenConfig{
		tlc: tfo.ListenConfig{
			Backlog:    lso.TCPFastOpenBacklog,
			DisableTFO: !lso.TCPFastOpen,
			Fallback:   lso.TCPFastOpenFallback,
		},
		fns: lso.buildSetFns(),
	}
	lc.tlc.SetMultipathTCP(lso.MultipathTCP)
	return lc
}

// DefaultUDPSocketBufferSize is the default send and receive buffer size of UDP sockets.
//
// We use the same value of 7 MiB as wireguard-go:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/conn/controlfns.go#L13-L18
const DefaultUDPSocketBufferSize = 7 << 20

var (
	// DefaultTCPListenerSocketOptions is the default [ListenerSocketOptions] for TCP servers.
	DefaultTCPListenerSocketOptions = ListenerSocketOptions{
		TCPFastOpen: true,
	}

	// DefaultTCPListenConfig is the default [ListenConfig] for TCP listeners.
	DefaultTCPListenConfig = DefaultTCPListenerSocketOptions.ListenConfig()

	// DefaultUDPServerSocketOptions is the default [ListenerSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = ListenerSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  true,
		ReceivePacketInfo: true,
	}

	// DefaultUDPServerListenConfig is the default [ListenConfig] for UDP servers.
	DefaultUDPServerListenConfig = DefaultUDPServerSocketOptions.ListenConfig()

	// DefaultUDPClientSocketOptions is the default [ListenerSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = ListenerSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  true,
	}

	// DefaultUDPClientListenConfig is the default [ListenConfig] for UDP clients.
	DefaultUDPClientListenConfig = DefaultUDPClientSocketOptions.ListenConfig()
)

// Dialer is [tfo.Dialer] but provides a subjectively nicer API.
type Dialer tfo.Dialer

// DialTCP wraps [tfo.Dialer.DialContext] and returns a [*net.TCPConn] directly.
func (d *Dialer) DialTCP(ctx context.Context, network, address string, b []byte) (*net.TCPConn, error) {
	c, err := (*tfo.Dialer)(d).DialContext(ctx, network, address, b)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

// DialUDP wraps [net.Dialer.DialContext] and returns a [*net.UDPConn] directly.
func (d *Dialer) DialUDP(ctx context.Context, network, address string) (*net.UDPConn, error) {
	c, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// DialerSocketOptions contains dialer-specific socket options.
type DialerSocketOptions struct {
	// Fwmark sets the dialer's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the dialer.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// TCPFastOpen enables TCP Fast Open on the dialer.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	TCPFastOpen bool

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the dialer.
	//
	// When enabled, the dialer will connect without TFO if TFO is not available on the system.
	// When disabled, the dialer will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool

	// MultipathTCP enables multipath TCP on the dialer.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	MultipathTCP bool
}

// Dialer returns a [Dialer] with a control function that sets the socket options.
func (dso DialerSocketOptions) Dialer() Dialer {
	d := Dialer{
		Dialer: net.Dialer{
			ControlContext: dso.buildSetFns().controlContextFunc(nil),
		},
		DisableTFO: !dso.TCPFastOpen,
		Fallback:   dso.TCPFastOpenFallback,
	}
	d.SetMultipathTCP(dso.MultipathTCP)
	return d
}

var (
	// DefaultTCPDialerSocketOptions is the default [DialerSocketOptions] for TCP clients.
	DefaultTCPDialerSocketOptions = DialerSocketOptions{
		TCPFastOpen:         true,
		TCPFastOpenFallback: true,
	}

	// DefaultTCPDialer is the default [Dialer] for TCP clients.
	DefaultTCPDialer = DefaultTCPDialerSocketOptions.Dialer()
)

// ListenConfigCache is a map of [ListenerSocketOptions] to [ListenConfig].
type ListenConfigCache map[ListenerSocketOptions]ListenConfig

// NewListenConfigCache creates a new cache for [ListenConfig] with a few default entries.
func NewListenConfigCache() ListenConfigCache {
	return ListenConfigCache{
		DefaultTCPListenerSocketOptions: DefaultTCPListenConfig,
		DefaultUDPServerSocketOptions:   DefaultUDPServerListenConfig,
		DefaultUDPClientSocketOptions:   DefaultUDPClientListenConfig,
	}
}

// Get returns a [ListenConfig] for the given [ListenerSocketOptions].
func (cache ListenConfigCache) Get(lso ListenerSocketOptions) (lc ListenConfig) {
	lc, ok := cache[lso]
	if ok {
		return
	}
	lc = lso.ListenConfig()
	cache[lso] = lc
	return
}

// DialerCache is a map of [DialerSocketOptions] to [Dialer].
type DialerCache map[DialerSocketOptions]Dialer

// NewDialerCache creates a new cache for [Dialer] with a few default entries.
func NewDialerCache() DialerCache {
	return DialerCache{
		DefaultTCPDialerSocketOptions: DefaultTCPDialer,
	}
}

// Get returns a [Dialer] for the given [DialerSocketOptions].
func (cache DialerCache) Get(dso DialerSocketOptions) (d Dialer) {
	d, ok := cache[dso]
	if ok {
		return
	}
	d = dso.Dialer()
	cache[dso] = d
	return
}
