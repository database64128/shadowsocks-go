package service

import (
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
)

// PMTUDMode is the Path MTU Discovery mode of a socket.
type PMTUDMode uint8

const (
	// PMTUDModeAppDefault is the default PMTUD mode we set on sockets.
	//
	// For TCP sockets, we default to [PMTUDModeSystemDefault].
	//
	// For UDP sockets, we default to [PMTUDModeDo] to disable IP fragmentation
	// for better performance and reliability.
	PMTUDModeAppDefault PMTUDMode = iota

	// PMTUDModeSystemDefault is the system default PMTUD mode.
	PMTUDModeSystemDefault

	// PMTUDModeDont is an alias for [conn.PMTUDModeDont].
	PMTUDModeDont

	// PMTUDModeDo is an alias for [conn.PMTUDModeDo].
	PMTUDModeDo

	// PMTUDModeProbe is an alias for [conn.PMTUDModeProbe].
	PMTUDModeProbe

	// PMTUDModeWant is an alias for [conn.PMTUDModeWant].
	PMTUDModeWant

	// PMTUDModeInterface is an alias for [conn.PMTUDModeInterface].
	PMTUDModeInterface

	// PMTUDModeOmit is an alias for [conn.PMTUDModeOmit].
	PMTUDModeOmit
)

// TCP returns the corresponding [conn.PMTUDMode] for TCP sockets.
func (m PMTUDMode) TCP() conn.PMTUDMode {
	switch m {
	case PMTUDModeAppDefault:
		return conn.PMTUDModeDefault
	case PMTUDModeSystemDefault:
		return conn.PMTUDModeDefault
	case PMTUDModeDont:
		return conn.PMTUDModeDont
	case PMTUDModeDo:
		return conn.PMTUDModeDo
	case PMTUDModeProbe:
		return conn.PMTUDModeProbe
	case PMTUDModeWant:
		return conn.PMTUDModeWant
	case PMTUDModeInterface:
		return conn.PMTUDModeInterface
	case PMTUDModeOmit:
		return conn.PMTUDModeOmit
	default:
		return conn.PMTUDMode(m)
	}
}

// UDP returns the corresponding [conn.PMTUDMode] for UDP sockets.
func (m PMTUDMode) UDP() conn.PMTUDMode {
	switch m {
	case PMTUDModeAppDefault:
		return conn.PMTUDModeDo
	case PMTUDModeSystemDefault:
		return conn.PMTUDModeDefault
	case PMTUDModeDont:
		return conn.PMTUDModeDont
	case PMTUDModeDo:
		return conn.PMTUDModeDo
	case PMTUDModeProbe:
		return conn.PMTUDModeProbe
	case PMTUDModeWant:
		return conn.PMTUDModeWant
	case PMTUDModeInterface:
		return conn.PMTUDModeInterface
	case PMTUDModeOmit:
		return conn.PMTUDModeOmit
	default:
		return conn.PMTUDMode(m)
	}
}

// String returns its string representation.
func (m PMTUDMode) String() string {
	switch m {
	case PMTUDModeAppDefault:
		return "default"
	case PMTUDModeSystemDefault:
		return "system"
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
	case PMTUDModeAppDefault:
		return append(b, "default"...), nil
	case PMTUDModeSystemDefault:
		return append(b, "system"...), nil
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
		return nil, fmt.Errorf("invalid PMTUD mode: %d", m)
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
		*m = PMTUDModeAppDefault
	case "system":
		*m = PMTUDModeSystemDefault
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
		return fmt.Errorf("invalid PMTUD mode: %q", text)
	}
	return nil
}
