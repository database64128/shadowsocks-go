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

// ListenConfig returns a [tfo.ListenConfig] with a control function that sets the socket options.
func (lso ListenerSocketOptions) ListenConfig() tfo.ListenConfig {
	return tfo.ListenConfig{
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

	// DefaultTCPListenConfig is the default [tfo.ListenConfig] for TCP listeners.
	DefaultTCPListenConfig = DefaultTCPListenerSocketOptions.ListenConfig()

	// DefaultUDPServerSocketOptions is the default [ListenerSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = ListenerSocketOptions{
		PathMTUDiscovery:  true,
		ReceivePacketInfo: true,
	}

	// DefaultUDPServerListenConfig is the default [tfo.ListenConfig] for UDP servers.
	DefaultUDPServerListenConfig = DefaultUDPServerSocketOptions.ListenConfig()

	// DefaultUDPClientSocketOptions is the default [ListenerSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = ListenerSocketOptions{
		PathMTUDiscovery: true,
	}

	// DefaultUDPClientListenConfig is the default [tfo.ListenConfig] for UDP clients.
	DefaultUDPClientListenConfig = DefaultUDPClientSocketOptions.ListenConfig()
)

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

// Dialer returns a [tfo.Dialer] with a control function that sets the socket options.
func (dso DialerSocketOptions) Dialer() tfo.Dialer {
	return tfo.Dialer{
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

	// DefaultTCPDialer is the default [tfo.Dialer] for TCP clients.
	DefaultTCPDialer = DefaultTCPDialerSocketOptions.Dialer()
)

// ListenConfigCache is a map of [ListenerSocketOptions] to [tfo.ListenConfig].
type ListenConfigCache map[ListenerSocketOptions]tfo.ListenConfig

// NewListenConfigCache creates a new cache for [tfo.ListenConfig] with a few default entries.
func NewListenConfigCache() ListenConfigCache {
	cache := make(ListenConfigCache)
	cache[DefaultTCPListenerSocketOptions] = DefaultTCPListenConfig
	cache[DefaultUDPServerSocketOptions] = DefaultUDPServerListenConfig
	cache[DefaultUDPClientSocketOptions] = DefaultUDPClientListenConfig
	return cache
}

// Get returns a [tfo.ListenConfig] for the given [ListenerSocketOptions].
func (cache ListenConfigCache) Get(lso ListenerSocketOptions) (lc tfo.ListenConfig) {
	lc, ok := cache[lso]
	if ok {
		return
	}
	lc = lso.ListenConfig()
	cache[lso] = lc
	return
}

// DialerCache is a map of [DialerSocketOptions] to [tfo.Dialer].
type DialerCache map[DialerSocketOptions]tfo.Dialer

// NewDialerCache creates a new cache for [tfo.Dialer] with a few default entries.
func NewDialerCache() DialerCache {
	cache := make(DialerCache)
	cache[DefaultTCPDialerSocketOptions] = DefaultTCPDialer
	return cache
}

// Get returns a [tfo.Dialer] for the given [DialerSocketOptions].
func (cache DialerCache) Get(dso DialerSocketOptions) (d tfo.Dialer) {
	d, ok := cache[dso]
	if ok {
		return
	}
	d = dso.Dialer()
	cache[dso] = d
	return
}

// ListenUDP creates a [*net.UDPConn] from the given [tfo.ListenConfig].
func ListenUDP(listenConfig tfo.ListenConfig, network, address string) (*net.UDPConn, error) {
	packetConn, err := listenConfig.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return packetConn.(*net.UDPConn), nil
}
