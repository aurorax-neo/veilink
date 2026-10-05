package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"veilink/internal/model"
)

func TestOptionalMuxTCPAndReconcile(t *testing.T) {
	for _, flow := range []string{"", flowVision} {
		for _, kind := range singKinds {
			t.Run(fmt.Sprintf("flow=%s/type=%s", flow, kind), func(t *testing.T) {
				local := tlsFiles(t)
				local.Flow = flow
				s, c := fixtures(t, echoServer(t))
				c.Nodes[0].Tunnel = model.DeriveClientTunnel(local, c.Nodes[0])
				server := run(t, s, local)
				client := run(t, c, model.LocalTLS{})
				for i, enabled := range []bool{false, true, false} {
					s.Mappings[0].Mux, c.Mappings[0].Mux = enabled, enabled
					s.Mappings[0].MuxType, c.Mappings[0].MuxType = "", ""
					if enabled {
						s.Mappings[0].MuxType, c.Mappings[0].MuxType = kind, kind
					}
					s.Revision, c.Revision = int64(i+1), int64(i+1)
					oldServer, oldClient := testBindingService(server.instance, s.Bindings[0].ID), testBindingService(client.instance, c.Bindings[0].ID)
					if err := server.Apply(s); err != nil {
						t.Fatal(err)
					}
					if err := client.Apply(c); err != nil {
						t.Fatal(err)
					}
					if testBindingService(server.instance, s.Bindings[0].ID) != oldServer || testBindingService(client.instance, c.Bindings[0].ID) != oldClient {
						t.Fatal("mux change replaced the shared binding")
					}
					port := s.Mappings[0].ListenPort
					awaitEcho(t, port)
					var wg sync.WaitGroup
					for range 4 {
						wg.Add(1)
						go func() {
							defer wg.Done()
							if err := exchange(port, bytes.Repeat([]byte("optional-mux"), 8192), true); err != nil {
								t.Error(err)
							}
						}()
					}
					wg.Wait()
					var doc policy
					if err := json.Unmarshal(client.document, &doc); err != nil {
						t.Fatal(err)
					}
					if doc.Outbounds[1].Mux.Enabled != enabled {
						t.Fatal("policy disagrees with mapping")
					}
					if bindingDedicated(c.Mappings, c.Bindings[0].ID) == enabled {
						t.Fatal("incorrect dedicated mode")
					}
				}
			})
		}
	}
}

func TestMuxModeAuthorization(t *testing.T) {
	s, _ := fixtures(t, 80)
	svc := &service{snapshot: s}
	m := s.Mappings[0]
	for _, mode := range []bool{false, true} {
		svc.snapshot.Mappings[0].Mux = mode
		if !svc.tcpModeAllowed(m.BindingID, m.TargetHost, m.TargetPort, mode) {
			t.Fatal("authorized mode rejected")
		}
		if svc.tcpModeAllowed(m.BindingID, m.TargetHost, m.TargetPort, !mode) {
			t.Fatal("wrong mode accepted")
		}
		if svc.tcpModeAllowed("foreign", m.TargetHost, m.TargetPort, mode) {
			t.Fatal("foreign binding accepted")
		}
	}
	svc.snapshot.Mappings[0].Network = "udp"
	if svc.tcpModeAllowed(m.BindingID, m.TargetHost, m.TargetPort, true) {
		t.Fatal("UDP authorized as TCP")
	}
	svc.snapshot.Mappings[0].Network = "tcp"
	svc.snapshot.Mappings[0].Enabled = false
	if svc.tcpModeAllowed(m.BindingID, m.TargetHost, m.TargetPort, true) {
		t.Fatal("disabled mapping authorized")
	}
}

func TestOptionalMuxMixedMappings(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	for _, kind := range singKinds {
		m := s.Mappings[0]
		m.ID, m.Name, m.ListenPort, m.Mux, m.MuxType = kind, kind, freePort(t), true, kind
		s.Mappings = append(s.Mappings, m)
		c.Mappings = append(c.Mappings, m)
	}
	run(t, s, local)
	run(t, c, local)
	for _, m := range s.Mappings {
		awaitEcho(t, m.ListenPort)
	}
	var wg sync.WaitGroup
	for _, m := range s.Mappings {
		for range 4 {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				if err := exchange(port, bytes.Repeat([]byte("mixed"), 8192), true); err != nil {
					t.Error(err)
				}
			}(m.ListenPort)
		}
	}
	wg.Wait()
}

func TestOptionalMuxUnknownTypePreservesRuntime(t *testing.T) {
	local := tlsFiles(t)
	s, c := fixtures(t, echoServer(t))
	c.Nodes[0].Tunnel = model.DeriveClientTunnel(local, c.Nodes[0])
	server := run(t, s, local)
	client := run(t, c, model.LocalTLS{})
	awaitEcho(t, s.Mappings[0].ListenPort)
	oldServer, oldClient := server.instance, client.instance
	s.Mappings[0].Mux, c.Mappings[0].Mux = true, true
	s.Mappings[0].MuxType, c.Mappings[0].MuxType = "unknown", "unknown"
	s.Revision++
	c.Revision++
	if server.Apply(s) == nil || client.Apply(c) == nil {
		t.Fatal("unknown mux type accepted")
	}
	if server.instance != oldServer || client.instance != oldClient {
		t.Fatal("invalid snapshot replaced runtime")
	}
	awaitEcho(t, s.Mappings[0].ListenPort)
}
