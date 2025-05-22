// Package shadowsocks implements the Shadowsocks protocol edition 2022 and later.
package shadowsocks

import (
	"context"

	"go.uber.org/zap"
)

// Version is the current version of shadowsocks-go.
const Version = "1.14.0"

// Service is the common service abstraction in this module.
type Service interface {
	// ZapField returns a [zap.Field] that identifies the service.
	ZapField() zap.Field

	// Start starts the service.
	Start(ctx context.Context) error

	// Stop stops the service.
	Stop() error
}
