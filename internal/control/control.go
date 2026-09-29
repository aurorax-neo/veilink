package control

import (
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"io"
	"math"
	"time"
	pb "veilink/api/control/v1"
	"veilink/internal/logring"
	"veilink/internal/store"
)

type Service struct {
	pb.UnimplementedControlServer
	Store    *store.Store
	NodeRing *logring.NodeRing
}

func Envelope(v any) (*structpb.Struct, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	if e = json.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	return structpb.NewStruct(m)
}
func String(m *structpb.Struct, k string) string { return m.GetFields()[k].GetStringValue() }
func rpcError(e error) error {
	if errors.Is(e, store.ErrAuth) {
		return status.Error(codes.Unauthenticated, "credential rejected")
	}
	if errors.Is(e, store.ErrInvalid) {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	return status.Error(codes.Internal, "control operation failed")
}
func (s *Service) Enroll(ctx context.Context, m *structpb.Struct) (*structpb.Struct, error) {
	c, e := s.Store.Enroll(String(m, "node_id"), String(m, "token"))
	if e != nil {
		return nil, rpcError(e)
	}
	return Envelope(map[string]any{"credential": c})
}
func (s *Service) Pull(ctx context.Context, m *structpb.Struct) (*structpb.Struct, error) {
	for name := range m.GetFields() {
		if name != "node_id" && name != "credential" {
			return nil, status.Error(codes.InvalidArgument, "unknown pull field: "+name)
		}
	}
	snap, e := s.Store.Snapshot(String(m, "node_id"), String(m, "credential"))
	if e != nil {
		return nil, rpcError(e)
	}
	return Envelope(snap)
}

// trafficPayload rejects malformed or oversized structpb values before touching state.
func trafficPayload(m *structpb.Struct) (string, uint64, map[string]store.TrafficBytes, error) {
	fields := m.GetFields()
	epoch, ok := fields["traffic_epoch"].GetKind().(*structpb.Value_StringValue)
	if !ok {
		return "", 0, nil, store.ErrInvalid
	}
	seqValue, ok := fields["traffic_seq"].GetKind().(*structpb.Value_NumberValue)
	if !ok || seqValue.NumberValue < 1 || seqValue.NumberValue > 9007199254740991 || math.Trunc(seqValue.NumberValue) != seqValue.NumberValue {
		return "", 0, nil, store.ErrInvalid
	}
	v, ok := fields["traffic"].GetKind().(*structpb.Value_StructValue)
	if !ok || len(v.StructValue.GetFields()) > 128 {
		return "", 0, nil, store.ErrInvalid
	}
	out := make(map[string]store.TrafficBytes, len(v.StructValue.GetFields()))
	for id, entry := range v.StructValue.GetFields() {
		if entry == nil {
			return "", 0, nil, store.ErrInvalid
		}
		pair := entry.GetStructValue()
		if pair == nil || len(pair.GetFields()) != 2 {
			return "", 0, nil, store.ErrInvalid
		}
		get := func(k string) (uint64, bool) {
			val, ok := pair.GetFields()[k].GetKind().(*structpb.Value_NumberValue)
			if !ok || val.NumberValue < 0 || val.NumberValue > 9007199254740991 || math.Trunc(val.NumberValue) != val.NumberValue {
				return 0, false
			}
			return uint64(val.NumberValue), true
		}
		up, a := get("up")
		down, b := get("down")
		if !a || !b {
			return "", 0, nil, store.ErrInvalid
		}
		out[id] = store.TrafficBytes{Up: up, Down: down}
	}
	return epoch.StringValue, uint64(seqValue.NumberValue), out, nil
}
func (s *Service) Events(stream grpc.BidiStreamingServer[structpb.Struct, structpb.Struct]) error {
	type result struct {
		m *structpb.Struct
		e error
	}
	ch := make(chan result, 1)
	// Recv is unblocked by gRPC when this handler returns; channel never blocks it.
	go func() {
		for {
			m, e := stream.Recv()
			select {
			case ch <- result{m, e}:
			case <-stream.Context().Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	identity := ""
	credential := ""
	var updates <-chan int64
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-updates:
			snap, err := s.Store.Snapshot(identity, credential)
			if err != nil {
				return rpcError(err)
			}
			out, _ := Envelope(map[string]any{"revision": snap.Revision, "refresh": true})
			if err := stream.Send(out); err != nil {
				return err
			}
		case <-timer.C:
			return status.Error(codes.DeadlineExceeded, "heartbeat timeout")
		case r := <-ch:
			if r.e == io.EOF {
				return nil
			}
			if r.e != nil {
				return r.e
			}
			id := String(r.m, "node_id")
			if identity != "" && identity != id {
				return status.Error(codes.Unauthenticated, "identity changed")
			}
			identity = id
			v := r.m.GetFields()["applied_revision"].GetNumberValue()
			if v < 0 || v > 9007199254740991 || v != float64(int64(v)) {
				return status.Error(codes.InvalidArgument, "invalid revision")
			}
			for _, field := range []string{"software_version", "software_commit"} {
				if value, ok := r.m.GetFields()[field]; ok {
					if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
						return status.Error(codes.InvalidArgument, "invalid software identity")
					}
				}
			}
			rev, e := s.Store.HeartbeatSoftware(id, String(r.m, "credential"), int64(v), String(r.m, "error") != "", store.SoftwareReport{
				SoftwareVersion: String(r.m, "software_version"), SoftwareCommit: String(r.m, "software_commit"),
			})
			if e != nil {
				return rpcError(e)
			}
			if _, present := r.m.GetFields()["traffic"]; present {
				epoch, seq, totals, parseErr := trafficPayload(r.m)
				if parseErr != nil {
					return rpcError(parseErr)
				}
				reportErr := s.Store.ReportTraffic(id, String(r.m, "credential"), epoch, seq, totals)
				// A stale mapping may be removed while the node is applying the
				// new snapshot. Do not block configuration sync on old telemetry.
				if reportErr != nil && !errors.Is(reportErr, store.ErrInvalid) {
					return rpcError(reportErr)
				}
			}
			if updates == nil {
				var unsubscribe func()
				updates, unsubscribe = s.Store.Subscribe(id)
				defer unsubscribe()
				// Close the gap between the first heartbeat and subscription.
				snap, err := s.Store.Snapshot(id, String(r.m, "credential"))
				if err != nil {
					return rpcError(err)
				}
				rev = snap.Revision
			}
			credential = String(r.m, "credential")
			// Ingest node logs if present
			if s.NodeRing != nil {
				if logsVal, ok := r.m.GetFields()["logs"]; ok {
					if logsList := logsVal.GetListValue(); logsList != nil {
						var entries []logring.Entry
						for _, item := range logsList.GetValues() {
							obj := item.GetStructValue()
							if obj == nil {
								continue
							}
							entries = append(entries, logring.Entry{
								At:      int64(obj.GetFields()["at"].GetNumberValue()),
								Level:   obj.GetFields()["level"].GetStringValue(),
								Message: obj.GetFields()["message"].GetStringValue(),
							})
						}
						if len(entries) > 0 {
							s.NodeRing.Ingest(id, entries)
						}
					}
				}
			}
			out, _ := Envelope(map[string]any{"revision": rev})
			if e = stream.Send(out); e != nil {
				return e
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(45 * time.Second)
		}
	}
}
