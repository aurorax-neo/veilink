package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevelopmentWorkflowContract(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), ".github/workflows/development-artifacts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"go-version-file: backend/go.mod", "cache-dependency-path: frontend/package-lock.json",
		"working-directory: backend", "working-directory: frontend", "go test ./...", "go vet ./...",
		"go test -tags integration ./tests/integration -count=1", "node --test tests/*.mjs", "npm run build",
		"path: frontend/dist/", "./cmd/veilink", "VERSION=dev", "COMMIT=${{ github.sha }}",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing directory-aware workflow contract %q", required)
		}
	}
	if strings.Contains(workflow, "web/") || strings.Contains(workflow, "go-version-file: go.mod") {
		t.Error("workflow contains old root paths")
	}
}

func TestReleaseWorkflowPaths(t *testing.T) {
	root := projectRoot(t)
	for _, name := range []string{"release-backend.yml", "release-image.yml"} {
		body, err := os.ReadFile(filepath.Join(root, ".github/workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		workflow := string(body)
		if strings.Contains(workflow, "web/") || strings.Contains(workflow, "go-version-file: go.mod") {
			t.Errorf("%s contains old root paths", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".github/workflows/release-web.yml")); !os.IsNotExist(err) {
		t.Error("standalone web release must not exist")
	}
	body, err := os.ReadFile(filepath.Join(root, ".github/workflows/release-backend.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{"target: unified", "platforms: linux/amd64,linux/arm64", "needs: docker", "body_path: RELEASE_NOTES.md"} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing unified release contract %q", required)
		}
	}
	for _, retired := range []string{"matrix:", "goos:", "download-artifact", "dist/veilink-*"} {
		if strings.Contains(workflow, retired) {
			t.Errorf("retired release matrix %q", retired)
		}
	}
}
