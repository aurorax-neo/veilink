package logring

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestHandlerPreservesLevel(t *testing.T) {
	for _, tc := range []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelError, "ERROR"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			r := New(4)
			h := NewHandler(r, "master", slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
			if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), tc.level, "level check", 0)); err != nil {
				t.Fatal(err)
			}
			entries := r.Query("master", "", "", 4)
			if len(entries) != 1 || entries[0].Level != tc.want {
				t.Fatalf("got %+v, want %s", entries, tc.want)
			}
		})
	}
}
