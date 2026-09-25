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

func TestRoleImagesAndDockerRunOnly(t *testing.T) {
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
	blocks := strings.Split(readme, "```sh\n")[1:]
	for _, role := range []string{"master", "server", "client"} {
		build := "docker build --target " + role + " -t veilink:" + role + " ."
		if !strings.Contains(readme, build) {
			t.Errorf("missing separate %s release image build", role)
		}
		var runs []string
		for _, part := range blocks {
			block := strings.SplitN(part, "\n```", 2)[0]
			if strings.HasPrefix(block, "docker run -itd") && strings.Contains(block, "veilink:"+role+" ") {
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

func TestImageContentsAreRoleScoped(t *testing.T) {
	root := projectRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	file := string(body)
	for _, role := range []string{"master", "server", "client"} {
		marker := "FROM runtime AS " + role + "\n"
		if strings.Count(file, marker) != 1 {
			t.Fatalf("missing unique %s release target", role)
		}
		stage := strings.SplitN(strings.SplitN(file, marker, 2)[1], "\nFROM ", 2)[0]
		if !strings.Contains(stage, `ENTRYPOINT ["/usr/local/bin/veilink", "`+role+`"]`) || !strings.Contains(stage, "USER 65532:65532") {
			t.Errorf("%s lacks fixed role or nonroot runtime", role)
		}
		health := `CMD ["kill", "-0", "1"]`
		if role == "master" {
			health = `CMD ["/usr/local/bin/docker-healthcheck.sh"]`
		}
		if strings.Count(stage, "HEALTHCHECK ") != 1 || !strings.Contains(stage, health) || strings.Contains(stage, `"CMD-SHELL"`) {
			t.Errorf("%s has invalid healthcheck command", role)
		}
		ui := strings.Contains(stage, "COPY --from=ui /src/html /usr/local/html")
		if ui != (role == "master") {
			t.Errorf("%s has incorrect Web UI packaging", role)
		}
		curl := strings.Contains(stage, "apk add --no-cache curl")
		if curl != (role == "master") {
			t.Errorf("%s has incorrect HTTP health dependency", role)
		}
		sqlite := strings.Contains(stage, "apk add --no-cache curl sqlite")
		if sqlite != (role == "master") {
			t.Errorf("%s has incorrect persisted-config health dependency", role)
		}
	}
}
