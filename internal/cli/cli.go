package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"veilink/internal/buildinfo"
	"veilink/internal/client"
	"veilink/internal/config"
	"veilink/internal/httpapi/backend"
	"veilink/internal/master"
	"veilink/internal/server"
	"veilink/internal/store"
	"veilink/internal/tunnel"
)

func Run(ctx context.Context, args []string, out io.Writer) error {
	return RunWithInput(ctx, args, os.Stdin, out)
}

// runKeys API Key 管理子命令：veilink keys list|create|revoke
func runKeys(args []string, out io.Writer) error {
	// --help 直接输出用法，不触碰数据库
	for _, a := range args {
		if a == "--help" || a == "-h" {
			_, err := fmt.Fprintln(out, "Usage: veilink keys list|create|revoke [flags]\n\nSubcommands:\n  list              List API keys (prefix only, never plaintext)\n  create [name]     Create a new API key (plaintext shown once)\n  revoke <id>       Revoke an API key by ID\n\nFlags:\n  -database         Database path (default /data/veilink.db)\n  -deployment-key   Deployment key path (default /data/veilink.key)")
			return err
		}
	}
	if len(args) == 0 {
		return errors.New("usage: veilink keys list|create|revoke [flags]")
	}
	f := flag.NewFlagSet("keys", flag.ContinueOnError)
	var db, key string
	f.StringVar(&db, "database", "/data/veilink.db", "database path")
	f.StringVar(&key, "deployment-key", "/data/veilink.key", "deployment key path")
	if err := f.Parse(args); err != nil {
		return err
	}
	s, err := store.OpenExisting(db, key)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer s.Close()
	ks := backend.NewKeyStore(s.DB())
	if err := ks.Migrate(); err != nil {
		return err
	}

	switch f.Arg(0) {
	case "list":
		keys, err := ks.List()
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Fprintln(out, "no API keys")
			return nil
		}
		fmt.Fprintf(out, "%-5s %-20s %-10s %-10s %s\n", "ID", "NAME", "PREFIX", "ROLE", "CREATED")
		for _, k := range keys {
			fmt.Fprintf(out, "%-5d %-20s %-10s %-10s %s\n", k.ID, k.Name, k.KeyPrefix, k.Role, k.CreatedAt.Format("2006-01-02 15:04"))
		}
	case "create":
		name := f.Arg(1)
		if name == "" {
			name = fmt.Sprintf("key-%d", ks.Count()+1)
		}
		role := backend.RoleAdmin
		plaintext, err := ks.Create(name, role)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "API Key created (shown only once):\n%s\n", plaintext)
	case "revoke":
		if f.Arg(1) == "" {
			return errors.New("usage: veilink keys revoke <id>")
		}
		id, err := strconv.ParseInt(f.Arg(1), 10, 64)
		if err != nil {
			return errors.New("invalid key id")
		}
		if err := ks.Revoke(id); err != nil {
			return err
		}
		fmt.Fprintln(out, "API Key revoked")
	default:
		return errors.New("usage: veilink keys list|create|revoke [flags]")
	}
	return nil
}

func RunWithInput(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: veilink master|server|client|keys|x25519|vlessenc|version [flags]")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		if len(args) == 1 {
			_, err := fmt.Fprintln(out, "Usage: veilink master|server|client|keys|x25519|vlessenc|version [flags]\nUse veilink help <command> for command help.")
			return err
		}
		if args[0] != "help" || len(args) != 2 {
			return errors.New("unexpected help arguments")
		}
		args = []string{args[1], "--help"}
	} else if len(args) == 2 && args[1] == "help" {
		args = []string{args[0], "--help"}
	}
	if (args[0] == "version" || args[0] == "x25519" || args[0] == "vlessenc") && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		_, err := fmt.Fprintf(out, "Usage: veilink %s\nThis command accepts no flags.\n", args[0])
		return err
	}
	if args[0] == "keys" && len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		_, err := fmt.Fprintln(out, "Usage: veilink keys list|create|revoke [flags]\n\nSubcommands:\n  list              List API keys (prefix only, never plaintext)\n  create [name]     Create a new API key (plaintext shown once)\n  revoke <id>       Revoke an API key by ID\n\nFlags:\n  -database         Database path (default /data/veilink.db)\n  -deployment-key   Deployment key path (default /data/veilink.key)")
		return err
	}
	if (args[0] == "version" || args[0] == "x25519" || args[0] == "vlessenc") && len(args) != 1 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "version" {
		fmt.Fprintf(out, "veilink %s (%s)\n", buildinfo.Version, buildinfo.Commit)
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
	if args[0] == "keys" {
		return runKeys(args[1:], out)
	}
	if strings.HasPrefix(args[0], "-") {
		return errors.New("missing role: put master, server or client before role flags (example: veilink master -database /data/veilink.db)")
	}
	if args[0] != "master" && args[0] != "server" && args[0] != "client" {
		return errors.New("unknown command")
	}
	roleArgs := args[1:]
	c, e := config.ParseFlagsOutput(args[0], roleArgs, out)
	if errors.Is(e, flag.ErrHelp) {
		return nil
	}
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
	default:
		return errors.New("unknown command")
	}
}
