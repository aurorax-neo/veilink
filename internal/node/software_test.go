package node

import (
	"testing"
	"veilink/internal/buildinfo"
	"veilink/internal/control"
)

func TestHeartbeatSoftwareIdentity(t *testing.T) {
	m, err := heartbeatEnvelope("node", "credential", 7, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if control.String(m, "software_version") != buildinfo.Version || control.String(m, "software_commit") != buildinfo.Commit {
		t.Fatal(m)
	}
	if m.Fields["applied_revision"].GetNumberValue() != 7 {
		t.Fatal("software identity changed revision")
	}
}
