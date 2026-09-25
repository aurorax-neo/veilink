package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	return RunWithInput(ctx, args, os.Stdin, out)
}

func RunWithInput(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: veilink master|server|client|reset-admin-username|reset-admin-password|x25519|vlessenc|version [flags]")
	}
	if (args[0] == "version" || args[0] == "x25519" || args[0] == "vlessenc") && len(args) != 1 {
		return errors.New("unexpected arguments")
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
	if args[0] == "reset-admin-username" || args[0] == "reset-admin-password" {
		rename := args[0] == "reset-admin-username"
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		f.SetOutput(io.Discard)
		var user, db, key string
		var stdin bool
		f.StringVar(&db, "database", "/data/veilink.db", "")
		f.StringVar(&key, "deployment-key", "/data/veilink.key", "")
		if rename {
			f.StringVar(&user, "username", "", "new administrator username")
		} else {
			f.BoolVar(&stdin, "password-stdin", false, "read password from stdin")
		}
		if err := f.Parse(args[1:]); err != nil {
			return fmt.Errorf("invalid %s flags", args[0])
		}
		if f.NArg() != 0 {
			return errors.New("no positional arguments allowed")
		}
		if rename && strings.TrimSpace(user) == "" {
			return errors.New("reset-admin-username requires nonempty -username")
		}
		if !rename && !stdin {
			return errors.New("reset-admin-password requires -password-stdin")
		}
		s, err := store.OpenExisting(db, key)
		if err != nil {
			return err
		}
		defer s.Close()
		if rename {
			err = s.ResetAdminUsername(user)
		} else {
			password, readErr := io.ReadAll(io.LimitReader(in, 75))
			if readErr != nil {
				return errors.New("cannot read password")
			}
			if len(password) > 74 {
				return errors.New("password too long")
			}
			secret := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
			err = s.ResetAdminPassword(secret)
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "Administrator credential updated; previous sessions revoked.")
		return nil
	}
	if args[0] != "master" && args[0] != "server" && args[0] != "client" {
		return errors.New("unknown command")
	}
	roleArgs := args[1:]
	c, e := config.ParseFlags(args[0], roleArgs)
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
