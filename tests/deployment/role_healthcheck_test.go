package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthcheckRoleDispatch(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "docker-healthcheck.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"server", "client", "unknown", ""} {
		t.Run(role, func(t *testing.T) {
			dir := t.TempDir()
			cmdline := filepath.Join(dir, "cmdline")
			if err := os.WriteFile(cmdline, []byte("veilink\x00"+role+"\x00"), 0600); err != nil {
				t.Fatal(err)
			}
			// The test shell owns itself; avoid host PID 1 permission differences.
			script := strings.ReplaceAll(string(body), "/proc/1/cmdline", cmdline)
			script = strings.ReplaceAll(script, "kill -0 1", "kill -0 $$")
			for _, tool := range []string{"curl", "sqlite3"} {
				if err := os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/sh\ntouch \"$PROBE_MARKER\"\nexit 99\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", script)
			marker := filepath.Join(dir, "probe-called")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "PROBE_MARKER="+marker)
			output, err := cmd.CombinedOutput()
			want := role == "server" || role == "client"
			if (err == nil) != want {
				t.Fatalf("success=%t want=%t: %s", err == nil, want, output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("non-master ran master probe")
			}
		})
	}
}
