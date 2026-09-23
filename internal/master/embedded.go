package master

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"veilink/internal/config"
	"veilink/internal/model"
	"veilink/internal/node"
	"veilink/internal/store"
)

func runEmbeddedServer(ctx context.Context, c config.Config, s *store.Store) error {
	name := c.EmbeddedServer.Name
	if name == "" {
		name = "embedded-server"
	}
	port := c.EmbeddedServer.Port
	if port == 0 {
		port = 8444
	}
	addr := c.EmbeddedServer.Address
	if addr == "" {
		addr = "127.0.0.1"
	}
	srvName := c.EmbeddedServer.ServerName
	if srvName == "" {
		srvName = "localhost"
	}

	n, found, err := s.FindNodeByName(name)
	if err != nil {
		return fmt.Errorf("failed to query node %q: %w", name, err)
	}
	if !found {
		n = model.Node{
			Name:       name,
			Role:       "server",
			Address:    addr,
			Port:       port,
			ServerName: srvName,
			LastSeen:   time.Now().Unix(),
		}
		saved, err := s.SaveNode(n)
		if err != nil {
			return fmt.Errorf("failed to auto-register embedded server node: %w", err)
		}
		n = saved
		slog.Info("registered embedded server node", "node_id", n.ID, "name", n.Name, "port", n.Port)
	} else {
		if n.Address != addr || n.Port != port || n.ServerName != srvName {
			n.Address = addr
			n.Port = port
			n.ServerName = srvName
			if _, err := s.SaveNode(n); err != nil {
				return fmt.Errorf("failed to update embedded server node: %w", err)
			}
		}
	}

	token, err := s.EnrollToken(n.ID, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to issue enrollment token for embedded server: %w", err)
	}

	masterAddr := c.BindAddr
	bindHost, bindPortStr, err := net.SplitHostPort(c.BindAddr)
	if err == nil {
		if bindHost == "" || bindHost == "0.0.0.0" {
			masterAddr = net.JoinHostPort("127.0.0.1", bindPortStr)
		} else if bindHost == "::" {
			masterAddr = net.JoinHostPort("::1", bindPortStr)
		}
	}

	controlCA := c.ControlCA
	if controlCA == "" && c.ControlCert != "" {
		controlCA = c.ControlCert
	}
	controlSNI := c.ControlServerName
	if controlSNI == "" {
		controlSNI = "localhost"
	}

	stateDir := c.EmbeddedServer.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(c.StateDir, "embedded-server")
	}
	srvTLS := c.EmbeddedServer.TLS
	if !srvTLS.Reality.Enabled() && srvTLS.CertFile == "" && srvTLS.KeyFile == "" {
		srvTLS.CertFile = c.ControlCert
		srvTLS.KeyFile = c.ControlKey
	}

	srvConfig := config.Config{
		MasterAddr:        masterAddr,
		ControlCert:       "",
		ControlKey:        "",
		ControlCA:         controlCA,
		ControlServerName: controlSNI,
		NodeID:            n.ID,
		EnrollToken:       token,
		StateDir:          stateDir,
		TLS:               srvTLS,
	}
	return node.Run(ctx, srvConfig, "server")
}
