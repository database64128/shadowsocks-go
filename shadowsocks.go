// Package shadowsocks implements the Shadowsocks protocol edition 2022 and later.
package shadowsocks

import (
	"context"
	"log/slog"
)

// Version is the current version of shadowsocks-go.
const Version = "1.15.0"

// Service is the common service abstraction in this module.
type Service interface {
	// SlogAttr returns a [slog.Attr] that identifies the service.
	SlogAttr() slog.Attr

	// Start starts the service.
	Start(ctx context.Context) error

	// Stop stops the service.
	Stop() error
}
