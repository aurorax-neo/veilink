package tunnel

import (
	"strings"
	"testing"
)

func TestHysteriaReverse(t *testing.T) {
	files := tlsFiles(t)
	serverSnap, clientSnap := fixtures(t, echoServer(t))
	serverLocal, clientLocal := files, files
	serverLocal.Hysteria2.Password = "pool-secret"
	clientLocal.Hysteria2.Password = "pool-secret"
	clientSnap.Mappings[0].Pool = 2
	run(t, serverSnap, serverLocal)
	run(t, clientSnap, clientLocal)
	awaitEcho(t, serverSnap.Mappings[0].ListenPort)
}

func TestTransportExclusions(t *testing.T) {
	files := tlsFiles(t)
	serverSnap, _ := fixtures(t, 1)
	local := files
	local.Reality.PrivateKey = "not-a-key"
	local.Hysteria2.Password = "x"
	r := New(local)
	defer r.Close()
	err := r.Apply(serverSnap)
	if err == nil || !strings.Contains(err.Error(), "cannot both") {
		t.Fatal(err)
	}
}
