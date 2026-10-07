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
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func TestProjectLayout(t *testing.T) {
	root := projectRoot(t)
	for _, required := range []string{"frontend/package.json", "frontend/package-lock.json", "backend/go.mod", "backend/go.sum", "backend/cmd/veilink", "backend/internal", "backend/tests", "ref", "tools"} {
		if _, err := os.Stat(filepath.Join(root, required)); err != nil {
			t.Errorf("required project path %q: %v", required, err)
		}
	}
	for _, gone := range []string{"web", "api", "cmd", "internal", "go.mod", "go.sum", "html", "docs"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("obsolete or generated root path %q remains: %v", gone, err)
		}
	}
}

func TestUnifiedImageAndDockerRunOnly(t *testing.T) {
	root := projectRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)
	for _, required := range []string{"API Key", "tools/backup-master.sh backup", "tools/backup-master.sh restore", "nginx -t && nginx -s reload", "grpc_pass", "docker pull ghcr.io/aurorax-neo/veilink:latest"} {
		if !strings.Contains(readme, required) {
			t.Errorf("missing deployment contract %q", required)
		}
	}
	for _, required := range []string{"master", "server", "client"} {
		if !strings.Contains(readme, "ghcr.io/aurorax-neo/veilink:latest "+required) {
			t.Errorf("README missing unified image role command %q", required)
		}
	}
}

func TestUnifiedImageContents(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(projectRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	file := string(body)
	for _, required := range []string{
		"FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.23 AS build-backend",
		"FROM --platform=$BUILDPLATFORM node:22-alpine3.23 AS build-web",
		"WORKDIR /src/backend", "WORKDIR /src/frontend",
		"COPY backend/go.mod backend/go.sum ./", "COPY frontend/package.json frontend/package-lock.json ./",
		"ARG TARGETOS\n", "ARG TARGETARCH\n",
		"CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build",
		"COPY --from=build-backend /out/veilink /usr/local/bin/veilink",
		"COPY --from=build-web /src/frontend/dist /opt/veilink-web/",
		"ENTRYPOINT [\"/usr/local/bin/docker-entrypoint.sh\"]",
		"apk add --no-cache ca-certificates tzdata sqlite su-exec curl",
		"HEALTHCHECK ", "org.opencontainers.image.version", "org.opencontainers.image.revision", "org.opencontainers.image.source",
	} {
		if !strings.Contains(file, required) {
			t.Errorf("unified image missing %q", required)
		}
	}
	for _, forbidden := range []string{"COPY web", "/src/web", " AS master", " AS server", " AS client", " AS web", "/data/web", "WEB_PREBUNDLED_DIR"} {
		if strings.Contains(file, forbidden) {
			t.Errorf("obsolete Dockerfile reference %q", forbidden)
		}
	}
	if strings.Count("\n"+file, "\nFROM ") != 4 || strings.Count(file, "ENTRYPOINT ") != 1 || strings.Count(file, "HEALTHCHECK ") != 1 {
		t.Error("expected two build stages, backend intermediate, unified runtime and one healthcheck")
	}
}
