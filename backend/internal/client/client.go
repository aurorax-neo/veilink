// Package client runs an outbound-only private network agent.
package client

import (
	"context"
	"veilink/internal/config"
	"veilink/internal/node"
)

func Run(ctx context.Context, c config.Config) error { return node.Run(ctx, c, "client") }
