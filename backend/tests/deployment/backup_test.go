package deployment

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"veilink/internal/model"
	"veilink/internal/store"
)

func runBackupTool(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(projectRoot(t), "tools", "backup-master.sh"), args...)
	return cmd.CombinedOutput()
}

func TestMasterBackupRestorePreservesStore(t *testing.T) {
	root := t.TempDir()
	source, backup, restored := filepath.Join(root, "source"), filepath.Join(root, "backup"), filepath.Join(root, "restored")
	if err := os.MkdirAll(filepath.Join(source, "state", ".hidden", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(source, "veilink.db"), filepath.Join(source, "veilink.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitAdmin("admin", "a-secure-password"); err != nil {
		t.Fatal(err)
	}
	n, err := s.SaveNode(model.Node{Name: "backup-node", Role: "client", Address: "localhost", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.EnrollToken(n.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	credential, err = s.Enroll(n.ID, credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "state", ".hidden", "nested", "marker"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}

	if output, err := runBackupTool(t, "backup", "master", source, backup); err != nil {
		t.Fatalf("backup failed: %v\n%s", err, output)
	}
	if output, err := runBackupTool(t, "restore", "master", backup, restored); err != nil {
		t.Fatalf("restore failed: %v\n%s", err, output)
	}
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := runBackupTool(t, "restore", "master", backup, filepath.Join(root, "existing")); err == nil {
		_ = output
		t.Fatal("unexpected restore success")
	}
	r, err := store.OpenExisting(filepath.Join(restored, "veilink.db"), filepath.Join(restored, "veilink.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ok := r.Login("admin", "a-secure-password"); !ok {
		t.Fatal("admin credential did not survive")
	}
	snap, err := r.Snapshot(n.ID, credential)
	if err != nil {
		t.Fatalf("node credential missing: %v", err)
	}
	if snap.Node.ID != n.ID {
		t.Fatalf("node id changed: %q", snap.Node.ID)
	}
	want, _ := os.ReadFile(filepath.Join(source, "state", ".hidden", "nested", "marker"))
	got, _ := os.ReadFile(filepath.Join(restored, "state", ".hidden", "nested", "marker"))
	if !bytes.Equal(want, got) {
		t.Fatal("nested state differs")
	}
}

func TestNodeOnlyBackupAndFailClosed(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "node-source")
	backup := filepath.Join(root, "node-backup")
	restored := filepath.Join(root, "node-restored")
	if err := os.MkdirAll(filepath.Join(source, ".state", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := map[string]string{"node_id": "stable-node", "credential": "secret-credential"}
	encoded, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(source, ".state", "deep", "state.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runBackupTool(t, "backup", "node", source, backup); err != nil {
		t.Fatalf("node backup failed: %v\n%s", err, output)
	}
	if err := os.WriteFile(filepath.Join(backup, "data", "extra"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runBackupTool(t, "restore", "node", backup, restored); err == nil {
		t.Fatalf("extra file accepted: %s", output)
	}
	if _, err := os.Stat(restored); !os.IsNotExist(err) {
		t.Fatal("failed restore created destination")
	}
}
