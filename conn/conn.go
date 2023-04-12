package conn

import (
	"context"
	"net"
	"syscall"

	"github.com/database64128/tfo-go/v2"
)

type setFunc = func(fd int, network string) error

type setFuncSlice []setFunc

func (fns setFuncSlice) controlContextFunc() func(ctx context.Context, network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

func (fns setFuncSlice) controlFunc() func(network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

// ListenConfig is [tfo.ListenConfig] but provides a subjectively nicer API.
type ListenConfig tfo.ListenConfig

// ListenTCP wraps [tfo.ListenConfig.Listen] and returns a [*net.TCPListener] directly.
func (lc *ListenConfig) ListenTCP(ctx context.Context, network, address string) (*net.TCPListener, error) {
	l, err := (*tfo.ListenConfig)(lc).Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return l.(*net.TCPListener), nil
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (lc *ListenConfig) ListenUDP(ctx context.Context, network, address string) (*net.UDPConn, error) {
	pc, err := lc.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ListenerSocketOptions contains listener-specific socket options.
type ListenerSocketOptions struct {
	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int

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

	// ReceivePacketInfo enables the reception of packet information control messages on the listener.
	//
	// Available on Linux, macOS, and Windows.
	ReceivePacketInfo bool

	// ReceiveOriginalDestAddr enables the reception of original destination address control messages on the listener.
	//
	// Only available on Linux.
	ReceiveOriginalDestAddr bool
}

// ListenConfig returns a [ListenConfig] with a control function that sets the socket options.
func (lso ListenerSocketOptions) ListenConfig() ListenConfig {
	return ListenConfig{
		ListenConfig: net.ListenConfig{
			Control: lso.buildSetFns().controlFunc(),
		},
		DisableTFO: !lso.TCPFastOpen,
	}
}

var (
	// DefaultTCPListenerSocketOptions is the default [ListenerSocketOptions] for TCP servers.
	DefaultTCPListenerSocketOptions = ListenerSocketOptions{
		TCPFastOpen: true,
	}

	// DefaultTCPListenConfig is the default [ListenConfig] for TCP listeners.
	DefaultTCPListenConfig = DefaultTCPListenerSocketOptions.ListenConfig()

	// DefaultUDPServerSocketOptions is the default [ListenerSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = ListenerSocketOptions{
		PathMTUDiscovery:  true,
		ReceivePacketInfo: true,
	}

	// DefaultUDPServerListenConfig is the default [ListenConfig] for UDP servers.
	DefaultUDPServerListenConfig = DefaultUDPServerSocketOptions.ListenConfig()

	// DefaultUDPClientSocketOptions is the default [ListenerSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = ListenerSocketOptions{
		PathMTUDiscovery: true,
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
}

// Dialer returns a [Dialer] with a control function that sets the socket options.
func (dso DialerSocketOptions) Dialer() Dialer {
	return Dialer{
		Dialer: net.Dialer{
			ControlContext: dso.buildSetFns().controlContextFunc(),
		},
		DisableTFO: !dso.TCPFastOpen,
	}
}

var (
	// DefaultTCPDialerSocketOptions is the default [DialerSocketOptions] for TCP clients.
	DefaultTCPDialerSocketOptions = DialerSocketOptions{
		TCPFastOpen: true,
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
