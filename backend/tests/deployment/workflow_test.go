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
		"working-directory: backend", "working-directory: frontend",
		"while IFS= read -r pkg", "go test -count=1 \"$pkg\" -timeout=5m",
		"::error title=Go package test failed::${pkg}: ${details}",
		"-skip '^(TestProtocolMatrixRoundTrip|TestXHTTPCombinationMatrix)$'",
		"go test ./internal/tunnel -run '^TestProtocolMatrixRoundTrip$' -count=1 -timeout=5m",
		"go test ./internal/tunnel -run '^TestXHTTPCombinationMatrix$' -count=1 -timeout=5m",
		"go vet ./...",
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
	body, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, retired := range []string{"release-backend.yml", "release-image.yml", "release-web.yml"} {
		if _, err := os.Stat(filepath.Join(root, ".github/workflows", retired)); !os.IsNotExist(err) {
			t.Errorf("retired release workflow %s remains", retired)
		}
	}
	for _, required := range []string{
		"build-frontend:", "build-binaries:", "publish-release:", "docker:",
		"needs: build-frontend", "needs: build-binaries",
		"actions/upload-artifact@v4", "actions/download-artifact@v4",
		"Dockerfile.release", "platforms: linux/amd64,linux/arm64",
		"concurrency:", "cancel-in-progress: true",
		"CGO_ENABLED: \"0\"", "go build -trimpath", "frontend/dist",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing release workflow contract %q", required)
		}
	}
	for _, forbidden := range []string{"docker/build-push-action@v6\n        with:\n          context: .\n          target: unified", "cargo build", "cross build"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("release workflow still contains obsolete build path %q", forbidden)
		}
	}
	for _, required := range []string{"body_path: RELEASE_NOTES.md", "package-linux-amd64", "package-linux-arm64"} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing release asset contract %q", required)
		}
	}
}
