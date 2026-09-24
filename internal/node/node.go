package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/config"
	"veilink/internal/control"
	"veilink/internal/logring"
	"veilink/internal/model"
	"veilink/internal/tunnel"
)

type diskState struct {
	NodeID     string          `json:"node_id"`
	Master     string          `json:"master"`
	Credential string          `json:"credential"`
	Snapshot   *model.Snapshot `json:"snapshot,omitempty"`
}

func save(path string, s diskState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func tlsConfig(c config.Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ControlServerName}
	if c.ControlCA != "" {
		pem, e := os.ReadFile(c.ControlCA)
		if e != nil {
			return nil, e
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid control CA")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}
func Run(ctx context.Context, c config.Config, role string) error {
	if e := c.Validate(role); e != nil {
		return e
	}

	ring := logring.New(200)
	slog.SetDefault(slog.New(logring.NewHandler(ring, "node", slog.NewTextHandler(os.Stderr, nil))))

	tc, e := tlsConfig(c)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return e
	}
	if e = os.Chmod(c.StateDir, 0700); e != nil {
		return e
	}
	path := filepath.Join(c.StateDir, "state.json")
	st := diskState{NodeID: c.NodeID, Master: c.MasterAddr}
	if b, er := os.ReadFile(path); er == nil {
		if json.Unmarshal(b, &st) != nil || st.NodeID != c.NodeID || st.Master != c.MasterAddr {
			return errors.New("local state identity mismatch or corruption")
		}
		if e = os.Chmod(path, 0600); e != nil {
			return e
		}
	} else if !os.IsNotExist(er) {
		return er
	}
	local := c.TLS
	local.Pool = c.Pool
	runtime := tunnel.New(local)
	defer runtime.Close()
	failed := false
	if st.Snapshot != nil {
		if st.Snapshot.Node.ID != c.NodeID || st.Snapshot.Node.Role != role {
			return errors.New("cached node identity mismatch")
		}
		if e = runtime.Apply(*st.Snapshot); e != nil {
			failed = true
			slog.Warn("cached runtime configuration could not be restored")
		}
	}
	conn, e := grpc.NewClient(c.MasterAddr, grpc.WithTransportCredentials(credentials.NewTLS(tc)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20), grpc.MaxCallSendMsgSize(64<<10)))
	if e != nil {
		return e
	}
	defer conn.Close()
	client := pb.NewControlClient(conn)
	backoff := time.Second
	for ctx.Err() == nil {
		if st.Credential == "" {
			if c.EnrollToken == "" {
				return errors.New("enrollment token required for first start")
			}
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			in, _ := control.Envelope(map[string]any{"node_id": c.NodeID, "token": c.EnrollToken})
			out, er := client.Enroll(call, in)
			cancel()
			e = er
			if e == nil {
				st.Credential = control.String(out, "credential")
				if st.Credential == "" {
					return errors.New("empty enrollment credential")
				}
				if e = save(path, st); e != nil {
					return errors.New("cannot persist node credential")
				}
			}
		} else {
			e = nil
		}
		if e == nil {
			e = cycle(ctx, client, c, role, &st, runtime, &failed, path, ring)
		}
		if ctx.Err() != nil {
			return nil
		}
		if status.Code(e) == codes.Unauthenticated || status.Code(e) == codes.PermissionDenied {
			runtime.Close()
			if er := os.Remove(path); er != nil && !os.IsNotExist(er) {
				return errors.New("credential rejected; local state removal failed")
			}
			return errors.New("node credential rejected; local state wiped; administrator must re-enroll")
		}
		slog.Warn("control connection unavailable; retaining last successful configuration")
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
	return nil
}

// A bounded stream avoids indefinitely hung Recv/Send; each reconnection pulls
// regardless of revision. All runtime operations execute in this one goroutine.
func cycle(ctx context.Context, client pb.ControlClient, c config.Config, role string, st *diskState, runtime *tunnel.Runtime, failed *bool, path string, ring *logring.Ring) error {
	streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stream, e := client.Events(streamCtx)
	if e != nil {
		return e
	}
	first := true
	for {
		applied := runtime.Revision()
		if applied < 0 {
			applied = 0
		}
		errText := ""
		if *failed {
			errText = "apply failed"
		}

		// Collect log entries from the ring to send with heartbeat
		logEntries := ring.Query("", "", "", 0)
		var logMaps []any
		for _, entry := range logEntries {
			logMaps = append(logMaps, map[string]any{
				"at":      entry.At,
				"level":   entry.Level,
				"message": entry.Message,
			})
		}

		in, _ := control.Envelope(map[string]any{"node_id": c.NodeID, "credential": st.Credential, "applied_revision": applied, "error": errText, "logs": logMaps})
		if e = stream.Send(in); e != nil {
			_, recvErr := stream.Recv()
			if recvErr != nil {
				return recvErr
			}
			return e
		}
		out, e := stream.Recv()
		if e != nil {
			return e
		}
		desired := int64(out.GetFields()["revision"].GetNumberValue())
		if first || desired > runtime.Revision() || *failed {
			first = false
			call, stop := context.WithTimeout(ctx, 10*time.Second)
			req, _ := control.Envelope(map[string]any{"node_id": c.NodeID, "credential": st.Credential})
			response, er := client.Pull(call, req)
			stop()
			if er != nil {
				return er
			}
			b, er := json.Marshal(response.AsMap())
			if er != nil {
				return er
			}
			var snap model.Snapshot
			if er = json.Unmarshal(b, &snap); er != nil {
				return er
			}
			if snap.Node.ID != c.NodeID || snap.Node.Role != role || snap.Node.Revoked {
				return status.Error(codes.PermissionDenied, "node identity rejected")
			}
			if snap.Revision < runtime.Revision() {
				return errors.New("stale snapshot")
			}
			if er = runtime.Apply(snap); er != nil {
				*failed = true
				slog.Warn("runtime configuration apply failed", "revision", snap.Revision, "err", er)
			} else {
				*failed = false
				st.Snapshot = &snap
				if er = save(path, *st); er != nil {
					*failed = true
					return errors.New("cannot persist runtime cache")
				}
			}
		}
		select {
		case <-streamCtx.Done():
			return streamCtx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}
