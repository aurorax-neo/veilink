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
	for _, name := range []string{"release-web.yml", "release-backend.yml", "release-image.yml"} {
		body, err := os.ReadFile(filepath.Join(root, ".github/workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		workflow := string(body)
		if strings.Contains(workflow, "web/") || strings.Contains(workflow, "go-version-file: go.mod") {
			t.Errorf("%s contains old root paths", name)
		}
	}
	body, err := os.ReadFile(filepath.Join(root, ".github/workflows/release-web.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "frontend/package-lock.json") || !strings.Contains(string(body), "-C frontend/dist") {
		t.Error("web release workflow is not rooted at frontend/")
	}
	body, err = os.ReadFile(filepath.Join(root, ".github/workflows/release-backend.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "working-directory: backend") || !strings.Contains(string(body), "./cmd/veilink") {
		t.Error("backend release workflow is not rooted at backend/")
	}
}
