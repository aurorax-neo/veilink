package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"veilink/internal/cli"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.Run(ctx, os.Args[1:], os.Stdout); err != nil {
		slog.Error("veilink stopped", "error", err.Error())
		os.Exit(1)
	}
}
