package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"veilink/internal/client"
	"veilink/internal/config"
	"veilink/internal/master"
	"veilink/internal/server"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

var Version = "dev"
var Commit = "unknown"

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: veilink master|server|client|init-admin|x25519|vlessenc|version -config file")
	}
	if args[0] == "version" {
		fmt.Fprintf(out, "veilink %s (%s)\n", Version, Commit)
		return nil
	}
	if args[0] == "x25519" {
		priv, pub, e := tunnel.GenerateX25519()
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "Private key: %s\nPublic key: %s\n", priv, pub)
		return nil
	}
	if args[0] == "vlessenc" {
		xDec, xEnc, pqDec, pqEnc, e := tunnel.GenerateVLESSEnc()
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "Authentication: X25519, not Post-Quantum\ndecryption: %s\nencryption: %s\n\nAuthentication: ML-KEM-768, Post-Quantum\ndecryption: %s\nencryption: %s\n", xDec, xEnc, pqDec, pqEnc)
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(out)
	path := f.String("config", "veilink.yaml", "strict YAML configuration file")
	user := f.String("username", "", "initial administrator username")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	configPath := *path
	if envPath := os.Getenv("VEILINK_CONFIG"); envPath != "" && configPath == "veilink.yaml" {
		configPath = envPath
	}
	c, e := config.Load(configPath)
	if e != nil {
		return e
	}
	switch args[0] {
	case "master":
		return master.Run(ctx, c)
	case "server":
		return server.Run(ctx, c)
	case "client":
		return client.Run(ctx, c)
	case "init-admin":
		s, e := store.Open(c.Database, c.DeploymentKey)
		if e != nil {
			return e
		}
		defer s.Close()
		adminUser := *user
		if adminUser == "" {
			adminUser = os.Getenv("VEILINK_INIT_ADMIN_USERNAME")
			if adminUser == "" {
				adminUser = "admin"
			}
		}
		adminPass := os.Getenv("VEILINK_INIT_ADMIN_PASSWORD")
		if adminPass == "" {
			adminPass = os.Getenv("VEILINK_ADMIN_PASSWORD")
		}
		if e = s.InitAdmin(adminUser, adminPass); e != nil {
			return e
		}
		fmt.Fprintln(out, "Administrator initialized.")
		return nil
	default:
		return errors.New("unknown command")
	}
}
