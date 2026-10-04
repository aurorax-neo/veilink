package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type forbiddenHelpInput struct{}

func (forbiddenHelpInput) Read([]byte) (int, error) { panic("help read stdin") }

func helpCases() [][]string {
	cases := [][]string{{"--help"}, {"-h"}, {"help"}}
	for _, command := range []string{"master", "server", "client", "keys", "version", "x25519", "vlessenc"} {
		for _, flag := range []string{"--help", "-h", "help"} {
			cases = append(cases, []string{command, flag})
		}
		cases = append(cases, []string{"help", command})
	}
	return cases
}
func invalidHelpCases() [][]string {
	return [][]string{{}, {"help", "unknown"}, {"unknown", "--help"}, {"help", "master", "extra"}, {"--help", "master"},
		{"master", "--bad", "--help"}, {"master", "-embedded-server-port=bad", "-h"}, {"client", "--", "-h"},
		{"server", "extra", "--help"}, {"version", "--bad"}, {"x25519", "--help", "extra"},
		{"keys", "unknown"}}
}
func TestHelpHasNoSideEffects(t *testing.T) {
	for _, args := range helpCases() {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if err := RunWithInput(context.Background(), args, forbiddenHelpInput{}, &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Usage") {
				t.Fatalf("missing usage: %q", out.String())
			}
			if strings.Contains(out.String(), "Private key:") || strings.Contains(out.String(), "decryption:") {
				t.Fatal("help generated keys")
			}
		})
	}
	for _, args := range invalidHelpCases() {
		var out bytes.Buffer
		if err := RunWithInput(context.Background(), args, forbiddenHelpInput{}, &out); err == nil {
			t.Fatalf("invalid accepted: %v", args)
		}
		if strings.Contains(out.String(), "private-value") {
			t.Fatal("credential leaked")
		}
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "missing.db")
	for _, command := range []string{"master", "keys"} {
		var out bytes.Buffer
		if err := RunWithInput(context.Background(), []string{command, "-database", db, "--help"}, forbiddenHelpInput{}, &out); err != nil {
			t.Fatal(err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("help touched database", entries, err)
	}
}
func TestHelpProcessExitCodes(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "veilink")
	build := exec.Command("go", "build", "-o", bin, "./cmd/veilink")
	build.Dir = filepath.Clean(filepath.Join("..", ".."))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, args := range helpCases() {
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Usage") || strings.Contains(string(out), "veilink stopped") {
			t.Fatalf("help %v: %v %s", args, err, out)
		}
	}
	for _, args := range invalidHelpCases() {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err == nil {
			t.Fatalf("invalid exit 0 %v: %s", args, out)
		}
	}
}
