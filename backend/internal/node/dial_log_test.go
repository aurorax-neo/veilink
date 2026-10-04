package node

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"veilink/internal/logring"
)

func TestNodeDialLogHeartbeatVisibleByNode(t *testing.T) {
	local := logring.New(10)
	logger := slog.New(logring.NewHandler(local, "node", slog.NewTextHandler(io.Discard, nil)))
	logger.Warn("client tunnel connection failed (connection_refused); retrying", "role", "client", "id", "binding-1", "node_id", "gateway-1")
	packet, err := heartbeatEnvelope("client-1", "secret", 2, false, local)
	if err != nil {
		t.Fatal(err)
	}
	remote := logring.New(10)
	var received []logring.Entry
	for _, value := range packet.Fields["logs"].GetListValue().Values {
		obj := value.GetStructValue()
		received = append(received, logring.Entry{At: int64(obj.Fields["at"].GetNumberValue()), Level: obj.Fields["level"].GetStringValue(), Message: obj.Fields["message"].GetStringValue()})
	}
	logring.NewNodeRing(remote).Ingest("client-1", received)
	got := remote.Query("node", "client-1", "WARN", 10)
	if len(got) != 1 || !strings.Contains(got[0].Message, "connection_refused") || !strings.Contains(got[0].Message, "binding-1") {
		t.Fatalf("node logs: %+v", got)
	}
	if strings.Contains(got[0].Message, "secret") {
		t.Fatal("credential leaked")
	}
}
