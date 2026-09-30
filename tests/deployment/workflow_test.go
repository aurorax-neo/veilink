package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keep the intentionally narrow development distribution contract visible.
// actionlint separately validates YAML, expressions and action inputs.
func TestDevelopmentWorkflowContract(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), ".github/workflows/development-artifacts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"on:\n  workflow_dispatch:\n",
		"goos: [linux, darwin, windows]", "goarch: [amd64, arm64]",
		"./cmd/veilink", "path: bundle/html", "CGO_ENABLED: '0'",
		"platforms: linux/amd64,linux/arm64",
		"push: ${{ inputs.push_dev_image }}", "if: ${{ inputs.draft_release }}",
		"ghcr.io/${GITHUB_REPOSITORY,,}:dev-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
		"--draft --prerelease --latest=false", "git archive --format=tar.gz",
		"sha256sum", "LICENSE NOTICE THIRD_PARTY_NOTICES.md",
		"-X veilink/internal/buildinfo.Version=dev", "-X veilink/internal/buildinfo.Commit=${GITHUB_SHA}",
		"VERSION=dev", "COMMIT=${{ github.sha }}",
		"SOURCE_URL=https://github.com/${{ github.repository }}",
		"org.opencontainers.image.source=https://github.com/${{ github.repository }}",
		"org.opencontainers.image.revision=${{ github.sha }}",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing development workflow contract %q", required)
		}
	}
	if strings.Count(workflow, "default: false") != 2 || strings.Contains(workflow, "default: true") {
		t.Error("both publishing inputs must default to false")
	}
	for _, forbidden := range []string{
		"\n  push:", "\n  pull_request:", "\n  schedule:", "\n  workflow_run:",
		"role:", "target:", ":latest", ":stable", "push: true",
		"gh release edit", "--draft=false", "--draft false",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("forbidden development workflow behavior %q", forbidden)
		}
	}
	if strings.Count(workflow, "gh release create") != 1 {
		t.Error("expected exactly one guarded draft creation command")
	}
}

func TestDockerSoftwareIdentity(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"ARG VERSION=dev", "ARG COMMIT=unknown", "-X veilink/internal/buildinfo.Version=${VERSION}", "-X veilink/internal/buildinfo.Commit=${COMMIT}"} {
		if !strings.Contains(string(body), value) {
			t.Errorf("missing build identity %q", value)
		}
	}
}

func TestReleaseWorkflowContract(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	for _, required := range []string{
		"actions/checkout@v7.0.1", "actions/setup-go@v7.0.0", "actions/setup-node@v7.0.0",
		"docker/setup-qemu-action@v4.4.0", "docker/setup-buildx-action@v4.4.1",
		"docker/login-action@v4.6.0", "docker/metadata-action@v6.2.0", "docker/build-push-action@v7.4.0",
		"go test ./... -count=1", "go vet ./...",
		"go test -race ./internal/store ./internal/control ./internal/httpapi ./internal/master",
		"go test -tags=integration ./tests/integration -count=1",
		"npm ci", "node --test tests/*.mjs", "npm run typecheck", "npm run build", "git diff --check",
		"needs: checks", "needs: [checks, image]", "platforms: linux/amd64,linux/arm64",
		"cache-from: type=gha", "cache-to: type=gha,mode=max", "provenance: mode=max", "sbom: true",
		"push: true", "--verify-tag", "persist-credentials: false",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("missing release workflow contract %q", required)
		}
	}
	if strings.Count(workflow, "runs-on: ubuntu-24.04") != 3 {
		t.Error("all three release jobs must pin Ubuntu 24.04")
	}
	if strings.Count(workflow, "uses: docker/build-push-action@") != 1 {
		t.Error("release must publish one unified multi-platform image")
	}
	for _, forbidden := range []string{"ubuntu-latest", "continue-on-error:", "target:", "role:", "matrix:"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("forbidden release workflow behavior %q", forbidden)
		}
	}
}
