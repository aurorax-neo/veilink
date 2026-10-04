// Package server runs a public gateway with a locally configured TLS identity.
package server

import (
	"context"
	"veilink/internal/config"
	"veilink/internal/node"
)

func Run(ctx context.Context, c config.Config) error { return node.Run(ctx, c, "server") }
