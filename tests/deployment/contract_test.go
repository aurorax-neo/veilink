package deployment

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate deployment contract")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func TestUnifiedImageAndDockerRunOnly(t *testing.T) {
	root := projectRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)
	for _, required := range []string{"GET /api/setup", "POST /api/register", "docker exec -i veilink-master /usr/local/bin/veilink reset-admin-username -username", "docker exec -i veilink-master /usr/local/bin/veilink reset-admin-password -password-stdin", "可信网络"} {
		if !strings.Contains(readme, required) {
			t.Errorf("missing registration/reset contract %q", required)
		}
	}
	for _, obsolete := range []string{"--env-file", "VEILINK_INIT_ADMIN_PASSWORD=", "VEILINK_INIT_ADMIN_USERNAME=", "/usr/local/bin/veilink reset-admin "} {
		if strings.Contains(readme, obsolete) {
			t.Errorf("obsolete bootstrap instruction %q", obsolete)
		}
	}
	if !strings.Contains(readme, "docker build -t veilink:latest .") {
		t.Error("missing unified image build")
	}
	blocks := strings.Split(readme, "```sh\n")[1:]
	for _, role := range []string{"master", "server", "client"} {
		if strings.Contains(readme, "veilink:"+role) || strings.Contains(readme, "--target "+role) {
			t.Errorf("obsolete %s release product", role)
		}
		var runs []string
		for _, part := range blocks {
			block := strings.SplitN(part, "\n```", 2)[0]
			if strings.HasPrefix(block, "docker run -itd") && strings.Contains(block, "veilink:latest "+role+" ") {
				runs = append(runs, block)
			}
		}
		if len(runs) != 1 {
			t.Fatalf("expected one Docker Run command for %s, got %d", role, len(runs))
		}
		cmd := runs[0]
		for _, required := range []string{"docker run -itd", "--name veilink-" + role, "--restart unless-stopped", "-e TZ=Asia/Shanghai", "/opt/docker/veilink-" + role + "/data:/data"} {
			if !strings.Contains(cmd, required) {
				t.Errorf("%s missing %q", role, required)
			}
		}
		if strings.Contains(cmd, " -config") || strings.Contains(cmd, " -p ") || strings.Contains(cmd, "--publish") {
			t.Errorf("%s contains obsolete file or fixed-port deployment", role)
		}
		if (role != "client") != strings.Contains(cmd, "--net host") {
			t.Errorf("%s violates Host/Bridge choice", role)
		}
		if role != "master" {
			for _, flag := range []string{"-master-addr", "-node-id", "-enroll-token", "-state-dir", "-control-server-name"} {
				if !strings.Contains(cmd, flag+" ") {
					t.Errorf("%s missing role argument %s", role, flag)
				}
			}
		}
	}
	for _, gone := range []string{"compose.yaml", "examples", "docs", "frontend/README.md"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("obsolete secondary deployment/documentation %s remains: %v", gone, err)
		}
	}
	for _, required := range []string{"AGENTS.md", "LICENSE", "THIRD_PARTY_NOTICES.md"} {
		if _, err := os.Stat(filepath.Join(root, required)); err != nil {
			t.Errorf("project constraints or legal notice missing: %s: %v", required, err)
		}
	}
}

func TestUnifiedImageContents(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	file := string(body)
	for _, required := range []string{`ENTRYPOINT ["/usr/local/bin/veilink"]`, "USER 65532:65532", "COPY --from=ui /src/html /usr/local/html", "COPY --from=build /out/veilink /usr/local/bin/veilink", `CMD ["/usr/local/bin/docker-healthcheck.sh"]`, "ca-certificates tzdata curl sqlite"} {
		if !strings.Contains(file, required) {
			t.Errorf("unified image missing %q", required)
		}
	}
	if strings.Count("\n"+file, "\nFROM ") != 3 || strings.Count(file, "ENTRYPOINT ") != 1 || strings.Count(file, "HEALTHCHECK ") != 1 {
		t.Error("expected two build stages and one runtime product")
	}
	for _, role := range []string{"master", "server", "client"} {
		if strings.Contains(strings.ToLower(file), " as "+role+"\n") {
			t.Errorf("obsolete role target %s", role)
		}
	}
}
