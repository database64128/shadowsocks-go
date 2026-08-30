package conn

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
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
	MaxUDPGSOSegments uint32

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

// PMTUDMode is the Path MTU Discovery mode of a socket.
type PMTUDMode uint8

const (
	// PMTUDModeDefault is the default PMTUD mode of the socket.
	PMTUDModeDefault PMTUDMode = iota

	// PMTUDModeDont sets the socket to not perform Path MTU Discovery.
	//
	// DF is never set. Fragmentation happens both locally and on path.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_DONT.
	//  - On macOS and FreeBSD, this sets IP{,V6}_DONTFRAG to 0.
	//  - On other platforms, this is ignored.
	PMTUDModeDont

	// PMTUDModeDo sets the socket to always perform Path MTU Discovery.
	//
	// DF is always set. Fragmentation is disallowed.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_DO.
	//  - On macOS and FreeBSD, this sets IP{,V6}_DONTFRAG to 1.
	//  - On other platforms, this is ignored.
	PMTUDModeDo

	// PMTUDModeProbe is like [PMTUDModeDo], but permits sending packets larger than
	// the probed path MTU, with DF always set.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_PROBE.
	//  - On other platforms, this is ignored.
	PMTUDModeProbe

	// PMTUDModeWant sets IP_PMTUDISC_WANT on Linux.
	//
	// Fragmentation will happen locally if needed according to the path MTU,
	// otherwise the DF flag will be set.
	//
	// On other platforms, this is ignored.
	PMTUDModeWant

	// PMTUDModeInterface sets IP_PMTUDISC_INTERFACE on Linux.
	//
	// DF is never set. Fragmentation is disallowed locally. Ignore the path MTU and
	// always use the interface MTU.
	//
	// On other platforms, this is ignored.
	PMTUDModeInterface

	// PMTUDModeOmit sets IP_PMTUDISC_OMIT on Linux.
	//
	// This is a weaker version of [PMTUDModeInterface] that permits fragmentation if
	// interface MTU is exceeded.
	//
	// On other platforms, this is ignored.
	PMTUDModeOmit
)

// String returns its string representation.
func (m PMTUDMode) String() string {
	switch m {
	case PMTUDModeDefault:
		return "default"
	case PMTUDModeDont:
		return "dont"
	case PMTUDModeDo:
		return "do"
	case PMTUDModeProbe:
		return "probe"
	case PMTUDModeWant:
		return "want"
	case PMTUDModeInterface:
		return "interface"
	case PMTUDModeOmit:
		return "omit"
	default:
		return fmt.Sprintf("invalid(%d)", m)
	}
}

// AppendText implements [encoding.TextAppender].
func (m PMTUDMode) AppendText(b []byte) ([]byte, error) {
	switch m {
	case PMTUDModeDefault:
		return append(b, "default"...), nil
	case PMTUDModeDont:
		return append(b, "dont"...), nil
	case PMTUDModeDo:
		return append(b, "do"...), nil
	case PMTUDModeProbe:
		return append(b, "probe"...), nil
	case PMTUDModeWant:
		return append(b, "want"...), nil
	case PMTUDModeInterface:
		return append(b, "interface"...), nil
	case PMTUDModeOmit:
		return append(b, "omit"...), nil
	default:
		return b, fmt.Errorf("invalid PMTUDMode: %d", m)
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (m PMTUDMode) MarshalText() ([]byte, error) {
	return m.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (m *PMTUDMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "default", "":
		*m = PMTUDModeDefault
	case "dont":
		*m = PMTUDModeDont
	case "do":
		*m = PMTUDModeDo
	case "probe":
		*m = PMTUDModeProbe
	case "want":
		*m = PMTUDModeWant
	case "interface":
		*m = PMTUDModeInterface
	case "omit":
		*m = PMTUDModeOmit
	default:
		return fmt.Errorf("invalid PMTUDMode: %q", text)
	}
	return nil
}

// TCPListenSocketOptions contains socket options for TCP listeners.
type TCPListenSocketOptions struct {
	// SendBufferSize sets the send buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the socket.
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

	// TCPDeferAcceptSecs sets TCP_DEFER_ACCEPT to the given number of seconds on the socket.
	//
	// Available on Linux.
	TCPDeferAcceptSecs int

	// TCPUserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the socket.
	//
	// Available on Linux.
	TCPUserTimeoutMsecs int

	// ReusePort enables SO_REUSEPORT on the socket.
	//
	// Available on Linux and the BSDs.
	ReusePort bool

	// Transparent enables transparent proxy on the socket.
	//
	// Available on Linux, FreeBSD, and OpenBSD.
	Transparent bool

	// PathMTUDiscovery sets the Path MTU Discovery mode of the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery PMTUDMode

	// TCPFastOpen enables TCP Fast Open on the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	TCPFastOpen bool

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the socket.
	//
	// When enabled, the socket will start without TFO if TFO is not available on the system.
	// When disabled, the socket will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool

	// MultipathTCP enables multipath TCP on the socket.
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

// DefaultTCPListenSocketOptions returns a [TCPListenSocketOptions] with our defaults for TCP listeners.
func DefaultTCPListenSocketOptions() TCPListenSocketOptions {
	return TCPListenSocketOptions{
		TCPFastOpen:         true,
		TCPFastOpenFallback: true,
	}
}

// Build returns a [TCPListenConfig] that sets the socket options.
func (opts TCPListenSocketOptions) Build() TCPListenConfig {
	cfg := TCPListenConfig{
		listenConfig: tfo.ListenConfig{
			Control:    opts.buildSetFns().controlFunc(nil),
			Backlog:    opts.TCPFastOpenBacklog,
			DisableTFO: !opts.TCPFastOpen,
			Fallback:   opts.TCPFastOpenFallback,
		},
	}
	cfg.listenConfig.SetMultipathTCP(opts.MultipathTCP)
	return cfg
}

// TCPListenConfig is the constructed configuration for opening TCP listeners.
type TCPListenConfig struct {
	listenConfig tfo.ListenConfig
}

// Listen wraps [tfo.ListenConfig.Listen] and returns a [*net.TCPListener] directly.
func (cfg *TCPListenConfig) Listen(ctx context.Context, network, address string) (*net.TCPListener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Err: net.UnknownNetworkError(network)}
	}

	ln, err := cfg.listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return ln.(*net.TCPListener), nil
}

// TCPConnectSocketOptions contains socket options for outgoing TCP connections.
type TCPConnectSocketOptions struct {
	// SendBufferSize sets the send buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the socket.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// TCPUserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the socket.
	//
	// Available on Linux.
	TCPUserTimeoutMsecs int

	// PathMTUDiscovery sets the Path MTU Discovery mode of the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery PMTUDMode

	// TCPFastOpen enables TCP Fast Open on the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	TCPFastOpen bool

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the socket.
	//
	// When enabled, the socket will connect without TFO if TFO is not available on the system.
	// When disabled, the socket will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool

	// MultipathTCP enables multipath TCP on the socket.
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

// DefaultTCPConnectSocketOptions returns a [TCPConnectSocketOptions] with our defaults for outgoing TCP connections.
func DefaultTCPConnectSocketOptions() TCPConnectSocketOptions {
	return TCPConnectSocketOptions{
		TCPFastOpen:         true,
		TCPFastOpenFallback: true,
	}
}

// Build returns a [TCPDialer] that sets the socket options.
func (opts TCPConnectSocketOptions) Build() TCPDialer {
	cfg := TCPDialer{
		dialer: tfo.Dialer{
			ControlContext: opts.buildSetFns().controlContextFunc(nil),
			DisableTFO:     !opts.TCPFastOpen,
			Fallback:       opts.TCPFastOpenFallback,
		},
	}
	cfg.dialer.SetMultipathTCP(opts.MultipathTCP)
	return cfg
}

// TCPDialer is the constructed configuration for opening TCP connections.
type TCPDialer struct {
	dialer tfo.Dialer
}

// WithResolver returns a copy of the configuration with the resolver replaced.
func (cfg TCPDialer) WithResolver(resolver *net.Resolver) TCPDialer {
	cfg.dialer.Resolver = resolver
	return cfg
}

// Resolver returns the resolver used by the dialer.
func (cfg *TCPDialer) Resolver() *net.Resolver {
	return cfg.dialer.Resolver
}

// TFO returns true if the next Dial call will attempt to enable TFO.
func (cfg *TCPDialer) TFO() bool {
	return cfg.dialer.TFO()
}

// Dial wraps [tfo.Dialer.DialContext] and returns a [*net.TCPConn] directly.
func (cfg *TCPDialer) Dial(ctx context.Context, network, address string, b []byte) (*net.TCPConn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}

	c, err := cfg.dialer.DialContext(ctx, network, address, b)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

// UDPSocketOptions contains socket options for UDP sockets.
type UDPSocketOptions struct {
	// SendBufferSize sets the send buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the socket.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// ReusePort enables SO_REUSEPORT on the socket.
	//
	// Available on Linux and the BSDs.
	ReusePort bool

	// Transparent enables transparent proxy on the socket.
	//
	// Available on Linux, FreeBSD, and OpenBSD.
	Transparent bool

	// PathMTUDiscovery sets the Path MTU Discovery mode of the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery PMTUDMode

	// ProbeUDPGSOSupport enables best-effort probing of
	// UDP Generic Segmentation Offload (GSO) support on the socket.
	//
	// Available on Linux and Windows.
	ProbeUDPGSOSupport bool

	// UDPGenericReceiveOffload enables UDP Generic Receive Offload (GRO) on the socket.
	//
	// Available on Linux and Windows.
	UDPGenericReceiveOffload bool

	// ReceivePacketInfo enables the reception of packet information control messages on the socket.
	//
	// Available on POSIX systems.
	ReceivePacketInfo bool

	// ReceiveOriginalDestAddr enables the reception of original destination address control messages on the socket.
	//
	// Available on Linux, FreeBSD, and OpenBSD.
	ReceiveOriginalDestAddr bool
}

// DefaultUDPSocketBufferSize is the default send and receive buffer size of UDP sockets.
//
// We use the same value of 7 MiB as wireguard-go:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/conn/controlfns.go#L13-L18
//
// Some platforms will silently clamp the value to other maximums, such as Linux clamping to net.core.{r,w}mem_max.
// Other platforms may return an error, which we simply ignore.
const DefaultUDPSocketBufferSize = 7 << 20

// DefaultUDPServerSocketOptions returns a [UDPSocketOptions] with our defaults for UDP servers.
func DefaultUDPServerSocketOptions() UDPSocketOptions {
	return UDPSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  PMTUDModeDo,
		ReceivePacketInfo: true,
	}
}

// DefaultUDPClientSocketOptions returns a [UDPSocketOptions] with our defaults for UDP clients.
func DefaultUDPClientSocketOptions() UDPSocketOptions {
	return UDPSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  PMTUDModeDo,
	}
}

// Build returns a [UDPSocketConfig] that sets the socket options.
func (opts UDPSocketOptions) Build() UDPSocketConfig {
	return UDPSocketConfig{
		fns: opts.buildSetFns(),
	}
}

// UDPSocketConfig is the constructed configuration for opening UDP sockets.
type UDPSocketConfig struct {
	fns setFuncSlice
}

// Listen wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (cfg UDPSocketConfig) Listen(ctx context.Context, network, address string, info *SocketInfo) (*net.UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Err: net.UnknownNetworkError(network)}
	}

	if info != nil {
		*info = SocketInfo{
			MaxUDPGSOSegments: 1,
		}
	}

	lc := net.ListenConfig{
		Control: cfg.fns.controlFunc(info),
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// Dial wraps [net.Dialer.DialUDP].
func (cfg UDPSocketConfig) Dial(ctx context.Context, network string, laddr, raddr netip.AddrPort, info *SocketInfo) (*net.UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}

	if info != nil {
		*info = SocketInfo{
			MaxUDPGSOSegments: 1,
		}
	}

	dialer := net.Dialer{
		ControlContext: cfg.fns.controlContextFunc(info),
	}
	return dialer.DialUDP(ctx, network, laddr, raddr)
}

// UnixDomainSocketOptions contains socket options for Unix domain sockets.
type UnixDomainSocketOptions struct {
	// SendBufferSize sets the send buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int
}

// DefaultUnixDomainSocketOptions returns a [UnixDomainSocketOptions] with our defaults.
func DefaultUnixDomainSocketOptions() UnixDomainSocketOptions {
	return UnixDomainSocketOptions{}
}

// Build returns a [UnixDomainSocketConfig] that sets the socket options.
func (opts UnixDomainSocketOptions) Build() UnixDomainSocketConfig {
	fns := opts.buildSetFns()
	return UnixDomainSocketConfig{
		controlContext: fns.controlContextFunc(nil),
		control:        fns.controlFunc(nil),
	}
}

// UnixDomainSocketPermissions specifies the file permissions of a Unix domain socket.
type UnixDomainSocketPermissions struct {
	// UID is the user ID of the socket file.
	//
	// If -1, the UID is not changed.
	UID int

	// GID is the group ID of the socket file.
	//
	// If -1, the GID is not changed.
	GID int

	// Mode is the file mode of the socket file.
	//
	// If 0, the mode is not changed.
	Mode fs.FileMode
}

// DefaultUnixDomainSocketPermissions returns a [UnixDomainSocketPermissions] with unspecified permissions.
func DefaultUnixDomainSocketPermissions() UnixDomainSocketPermissions {
	return UnixDomainSocketPermissions{
		UID: -1,
		GID: -1,
	}
}

// Apply applies the permissions to the given socket file path.
func (p UnixDomainSocketPermissions) Apply(path string) error {
	if p.UID != -1 || p.GID != -1 {
		if err := os.Chown(path, p.UID, p.GID); err != nil {
			return fmt.Errorf("failed to chown %q to uid=%d, gid=%d: %w", path, p.UID, p.GID, err)
		}
	}

	if p.Mode != 0 {
		if err := os.Chmod(path, p.Mode); err != nil {
			return fmt.Errorf("failed to chmod %q to %o: %w", path, p.Mode, err)
		}
	}

	return nil
}

// UnixDomainSocketConfig is the constructed configuration for opening Unix domain sockets.
type UnixDomainSocketConfig struct {
	controlContext func(ctx context.Context, network, address string, c syscall.RawConn) error
	control        func(network, address string, c syscall.RawConn) error
}

// Listen wraps [net.ListenConfig.Listen] and returns a [*net.UnixListener] directly.
func (cfg UnixDomainSocketConfig) Listen(ctx context.Context, network, address string, perms UnixDomainSocketPermissions) (*net.UnixListener, error) {
	switch network {
	case "unix", "unixpacket":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Err: net.UnknownNetworkError(network)}
	}

	lc := net.ListenConfig{
		Control: cfg.control,
	}
	ln, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	uln := ln.(*net.UnixListener)

	if err := perms.Apply(address); err != nil {
		_ = uln.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Addr: uln.Addr(), Err: err}
	}

	return uln, nil
}

// ListenPacket wraps [net.ListenConfig.ListenPacket] and returns a [*net.UnixConn] directly.
func (cfg UnixDomainSocketConfig) ListenPacket(ctx context.Context, network, address string, perms UnixDomainSocketPermissions) (*net.UnixConn, error) {
	if network != "unixgram" {
		return nil, &net.OpError{Op: "listen", Net: network, Err: net.UnknownNetworkError(network)}
	}

	lc := net.ListenConfig{
		Control: cfg.control,
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UnixConn)

	if err := perms.Apply(address); err != nil {
		_ = uc.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Addr: uc.LocalAddr(), Err: err}
	}

	return uc, nil
}

// Dial wraps [net.Dialer.DialUnix].
func (cfg UnixDomainSocketConfig) Dial(ctx context.Context, network string, laddr, raddr *net.UnixAddr) (*net.UnixConn, error) {
	dialer := net.Dialer{
		ControlContext: cfg.controlContext,
	}
	return dialer.DialUnix(ctx, network, laddr, raddr)
}

// Dialer is [TCPDialer], [UDPSocketConfig], and [UnixDomainSocketConfig] combined into a universal dialer
// that can open outgoing TCP, UDP, and Unix domain socket connections, each with their own socket options.
type Dialer struct {
	resolver                       *net.Resolver
	tcpDialerControlContext        func(ctx context.Context, network, address string, c syscall.RawConn) error
	udpSocketConfig                UDPSocketConfig
	unixDomainSocketControlContext func(ctx context.Context, network, address string, c syscall.RawConn) error
}

// NewDialer returns a new universal dialer.
//
// Name resolution uses the resolver of tcpDialer.
func NewDialer(tcpDialer TCPDialer, udpSocketConfig UDPSocketConfig, unixDomainSocketConfig UnixDomainSocketConfig) Dialer {
	return Dialer{
		resolver:                       tcpDialer.dialer.Resolver,
		tcpDialerControlContext:        tcpDialer.dialer.ControlContext,
		udpSocketConfig:                udpSocketConfig,
		unixDomainSocketControlContext: unixDomainSocketConfig.controlContext,
	}
}

// Dial opens a connection to the given network and address, using the appropriate socket options for the network type.
func (d *Dialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{
		Resolver: d.resolver,
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		dialer.ControlContext = d.tcpDialerControlContext
	case "udp", "udp4", "udp6":
		dialer.ControlContext = d.udpSocketConfig.fns.controlContextFunc(nil)
	case "unix", "unixpacket", "unixgram":
		dialer.ControlContext = d.unixDomainSocketControlContext
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	return dialer.DialContext(ctx, network, address)
}

// TCPListenConfigCache caches [TCPListenConfig] instances by [TCPListenSocketOptions].
type TCPListenConfigCache = socketConfigCache[TCPListenSocketOptions, TCPListenConfig]

// NewTCPListenConfigCache creates a new cache for [TCPListenConfig] with default entries.
func NewTCPListenConfigCache() TCPListenConfigCache {
	return newSocketConfigCache[TCPListenSocketOptions]()
}

// TCPDialerCache caches [TCPDialer] instances by [TCPConnectSocketOptions].
type TCPDialerCache = socketConfigCache[TCPConnectSocketOptions, TCPDialer]

// NewTCPDialerCache creates a new cache for [TCPDialer] with default entries.
func NewTCPDialerCache() TCPDialerCache {
	return newSocketConfigCache[TCPConnectSocketOptions]()
}

// UDPSocketConfigCache caches [UDPSocketConfig] instances by [UDPSocketOptions].
type UDPSocketConfigCache = socketConfigCache[UDPSocketOptions, UDPSocketConfig]

// NewUDPSocketConfigCache creates a new cache for [UDPSocketConfig] with default entries.
func NewUDPSocketConfigCache() UDPSocketConfigCache {
	return newSocketConfigCache[UDPSocketOptions]()
}

// UnixDomainSocketConfigCache caches [UnixDomainSocketConfig] instances by [UnixDomainSocketOptions].
type UnixDomainSocketConfigCache = socketConfigCache[UnixDomainSocketOptions, UnixDomainSocketConfig]

// NewUnixDomainSocketConfigCache creates a new cache for [UnixDomainSocketConfig] with default entries.
func NewUnixDomainSocketConfigCache() UnixDomainSocketConfigCache {
	return newSocketConfigCache[UnixDomainSocketOptions]()
}

type socketConfigBuilder[SocketConfig any] interface {
	comparable
	Build() SocketConfig
}

type socketConfigCache[SocketOptions socketConfigBuilder[SocketConfig], SocketConfig any] struct {
	socketConfigByOptions map[SocketOptions]SocketConfig
}

func newSocketConfigCache[SocketOptions socketConfigBuilder[SocketConfig], SocketConfig any]() socketConfigCache[SocketOptions, SocketConfig] {
	return socketConfigCache[SocketOptions, SocketConfig]{
		socketConfigByOptions: make(map[SocketOptions]SocketConfig),
	}
}

// Get returns a [SocketConfig] for the given [SocketOptions].
func (cache socketConfigCache[SocketOptions, SocketConfig]) Get(opts SocketOptions) (cfg SocketConfig) {
	cfg, ok := cache.socketConfigByOptions[opts]
	if ok {
		return cfg
	}
	cfg = opts.Build()
	cache.socketConfigByOptions[opts] = cfg
	return cfg
}
