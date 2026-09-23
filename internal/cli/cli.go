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
)

var Version = "dev"
var Commit = "unknown"

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: veilink master|server|client|init-admin|version -config file")
	}
	if args[0] == "version" {
		fmt.Fprintf(out, "veilink %s (%s)\n", Version, Commit)
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
	c, e := config.Load(*path)
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
		if e = s.InitAdmin(*user, os.Getenv("VEILINK_ADMIN_PASSWORD")); e != nil {
			return e
		}
		fmt.Fprintln(out, "Administrator initialized.")
		return nil
	default:
		return errors.New("unknown command")
	}
}
