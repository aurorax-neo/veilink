package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func webArchive(t *testing.T, name, body string, kind byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	hdr := &tar.Header{Name: name, Typeflag: kind, Mode: 0644}
	if kind == tar.TypeReg {
		hdr.Size = int64(len(body))
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if kind == tar.TypeReg {
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReleaseArchiveRootAndUnsafeEntries(t *testing.T) {
	for _, name := range []string{"./index.html", "../escape", "/absolute", "link"} {
		t.Run(name, func(t *testing.T) {
			kind := byte(tar.TypeReg)
			if name == "link" {
				kind = tar.TypeSymlink
			}
			err := extractTarGz(bytes.NewReader(webArchive(t, name, "<html>ok</html>", kind)), t.TempDir())
			if name == "./index.html" && err != nil {
				t.Fatal(err)
			}
			if name != "./index.html" && err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestUpdateFreshLatestAndRollback(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "owner/repo", CacheDir: t.TempDir(), Version: "web-v1.0.0", GithubMirrors: []string{"https://gx.aorz.kdns.fr"}})
	archive := webArchive(t, "./index.html", "<html>fresh</html>", tar.TypeReg)
	var mu sync.Mutex
	requests, downloads := 0, 0
	fail := false
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		code, body := 200, archive
		if strings.HasSuffix(r.URL.Path, "releases.atom") {
			body = []byte(`<feed><entry><title>renamed backend</title><link href="https://github.com/owner/repo/releases/tag/v2.0.0"/></entry><entry><title>renamed web</title><link href="https://github.com/owner/repo/releases/tag/web-v2.0.0"/></entry></feed>`)
		} else {
			downloads++
			if fail {
				code = 404
			}
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	var persisted string
	m.SetPersist(func(_ []string, version string, _ *string) error { persisted = version; return nil })
	if err := m.Update(""); err != nil {
		t.Fatal(err)
	}
	if persisted != "" || m.Status().WantVersion != "" || m.Version() != "web-v2.0.0" || m.Status().Prebundled {
		t.Fatal("latest did not clear pinned version or report actual release")
	}
	oldRoot := m.Root()
	restarted := NewWebManager(WebConfig{Mode: WebModePull, Repo: "owner/repo", CacheDir: m.cfg.CacheDir, PrebundledDir: t.TempDir()})
	if root, err := restarted.Ensure(); err != nil || root != oldRoot || restarted.Version() != "web-v2.0.0" {
		t.Fatalf("updated frontend did not survive restart: %q %v", root, err)
	}
	if err := m.Update(""); err != nil {
		t.Fatal(err)
	}
	if downloads != 2 || m.Root() == oldRoot {
		t.Fatal("update reused stale cache")
	}
	oldRoot = m.Root()
	fail = true
	if err := m.Update("web-v9.9.9"); err == nil {
		t.Fatal("missing pinned version accepted")
	}
	if m.Root() != oldRoot || m.Version() != "web-v2.0.0" || m.Status().WantVersion != "" {
		t.Fatal("failed update changed active configuration")
	}
	if _, err := os.Stat(filepath.Join(oldRoot, "index.html")); err != nil {
		t.Fatal("old web was removed", err)
	}
	fail = false
	m.SetPersist(func([]string, string, *string) error { return errors.New("database unavailable") })
	if err := m.Update("web-v3.0.0"); err == nil || m.Root() != oldRoot {
		t.Fatal("persist failure switched frontend")
	}
	before := requests
	if err := m.Update("../../bad"); err == nil || requests != before {
		t.Fatal("invalid version reached network")
	}
}

func TestLiveConfiguredMirror(t *testing.T) {
	mirror := os.Getenv("VEILINK_TEST_WEB_MIRROR")
	if mirror == "" {
		t.Skip("explicit network verification only")
	}
	m := NewWebManager(WebConfig{Mode: WebModePull, Repo: "aurorax-neo/veilink", CacheDir: t.TempDir(), GithubMirrors: []string{mirror}})
	for _, version := range []string{"web-v0.4.2", ""} {
		if err := m.Update(version); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(m.Root(), "index.html")); err != nil {
			t.Fatal(err)
		}
		t.Logf("requested=%q active=%s", version, m.Version())
	}
}

func TestPinnedCandidatesNeverUseLatest(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "owner/repo", GithubMirrors: []string{"https://gx.aorz.kdns.fr"}})
	var fullURL bool
	for _, url := range m.downloadCandidates("web-v1.2.0") {
		if strings.Contains(url, "/latest/") {
			t.Fatal("pinned version falls back to latest")
		}
		if strings.HasPrefix(url, "https://gx.aorz.kdns.fr/https://github.com/") {
			fullURL = true
		}
	}
	if !fullURL {
		t.Fatal("full URL proxy format missing")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "owner/repo", CacheDir: t.TempDir()})
	archive := webArchive(t, "index.html", "<html>ok</html>", tar.TypeReg)
	m.client = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Update("web-v1.2.0"); err != nil {
				t.Error(err)
			}
			_ = m.Status()
		}()
	}
	wg.Wait()
	if _, err := os.Stat(filepath.Join(m.Root(), "index.html")); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorProbeFormatsAndPersistFailure(t *testing.T) {
	m := NewWebManager(WebConfig{Repo: "owner/repo", GithubMirrors: []string{"https://mirror.example"}, FrontendURL: "https://old.example"})
	m.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		code := 404
		if strings.Contains(r.URL.Path, "/https://github.com/") {
			code = 200
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	results := m.Probe("web-v1.0.0")
	if len(results) != 1 || !results[0].OK || results[0].Error != "" {
		t.Fatalf("probe: %+v", results)
	}
	m.SetPersist(func([]string, string, *string) error { return errors.New("write failed") })
	if err := m.SetMirrors(nil); err == nil || len(m.Status().Mirrors) != 1 {
		t.Fatal("failed save changed mirrors")
	}
	if err := m.SetFrontendURL(""); err == nil || m.FrontendRedirect() != "https://old.example" {
		t.Fatal("failed save changed frontend URL")
	}
}
