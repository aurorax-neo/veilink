package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/refraction-networking/utls"
	"veilink/internal/model"
)

func TestMLDSAValidationAndDerivation(t *testing.T) {
	seed, verify, err := GenerateMldsa65()
	if err != nil {
		t.Fatal(err)
	}
	private, public, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	server := model.Reality{Dest: "example.com:443", PrivateKey: private, ShortIDs: "aa", ServerNames: "example.com", Mldsa65Seed: seed, Mldsa65Verify: verify}
	if err := checkRealityServer(server, ""); err != nil {
		t.Fatal(err)
	}
	if model.DeriveMldsa65Verify(seed) != verify {
		t.Fatal("seed derivation differs from generator")
	}
	client := model.DeriveClientTunnel(model.LocalTLS{Reality: server}, model.Node{})
	if client.Reality.Mldsa65Seed != "" || client.Reality.PrivateKey != "" || client.Reality.Mldsa65Verify != verify {
		t.Fatal("secret leaked or public key lost")
	}
	server.Mldsa65Verify = ""
	if model.DeriveClientTunnel(model.LocalTLS{Reality: server}, model.Node{}).Reality.Mldsa65Verify != verify {
		t.Fatal("seed-only config did not derive verification key")
	}
	_, wrong, _ := GenerateMldsa65()
	for _, mutate := range []func(*model.Reality){
		func(r *model.Reality) { r.Mldsa65Seed = "bad" },
		func(r *model.Reality) { r.Mldsa65Seed = base64.RawURLEncoding.EncodeToString(make([]byte, 4032)) },
		func(r *model.Reality) { r.Mldsa65Seed = private },
		func(r *model.Reality) { r.Mldsa65Verify = wrong },
		func(r *model.Reality) { r.Mldsa65Seed = ""; r.Mldsa65Verify = verify },
	} {
		bad := server
		mutate(&bad)
		if err := checkRealityServer(bad, ""); err == nil {
			t.Fatal("invalid server ML-DSA material accepted")
		}
	}
	for _, r := range []model.Reality{
		{PublicKey: public, ShortID: "aa", Mldsa65Verify: "bad"},
		{PublicKey: public, ShortID: "aa", Mldsa65Seed: seed},
	} {
		if err := checkRealityClient(r); err == nil {
			t.Fatal("invalid client material accepted")
		}
	}
}

func TestMLDSASignatureTranscriptAndConcurrency(t *testing.T) {
	seed, verify, _ := GenerateMldsa65()
	data, _ := decodeMLDSA(seed, mldsa65.SeedSize)
	_, signing := mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(data))
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	auth := make([]byte, 32)
	_, _ = rand.Read(auth)
	hello, serverHello := []byte("authenticated client hello"), []byte("authenticated server hello")
	mac := hmac.New(sha512.New, auth)
	mac.Write(public)
	mac.Write(hello)
	mac.Write(serverHello)
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(signing, mac.Sum(nil), nil, false, signature); err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: signature}}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	check := func(h, sh []byte, key string, certificates [][]byte) bool {
		u := &utls.UConn{}
		u.HandshakeState.Hello = &utls.PubClientHelloMsg{Raw: h}
		u.HandshakeState.ServerHello = &utls.PubServerHelloMsg{Raw: sh}
		return realityMldsa65Verify(auth, certificates, key, u)
	}
	if !check(hello, serverHello, verify, [][]byte{der}) {
		t.Fatal("valid signature rejected")
	}
	_, wrong, _ := GenerateMldsa65()
	if check([]byte("tampered"), serverHello, verify, [][]byte{der}) || check(hello, []byte("tampered"), verify, [][]byte{der}) || check(hello, serverHello, wrong, [][]byte{der}) || check(nil, serverHello, verify, [][]byte{der}) || check(hello, serverHello, verify, [][]byte{[]byte("invalid")}) {
		t.Fatal("invalid transcript/certificate/key accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !check(hello, serverHello, verify, [][]byte{der}) {
				t.Error("concurrent verification failed")
			}
		}()
	}
	wg.Wait()
}

func TestRealityMLDSAEnableDisableReapply(t *testing.T) {
	files := tlsFiles(t)
	private, public, _ := GenerateX25519()
	seed, verify, _ := GenerateMldsa65()
	local := model.LocalTLS{Reality: model.Reality{Dest: camouflage(t, files.CertPEM, files.KeyPEM, true), PrivateKey: private, ShortIDs: "aa", ServerNames: "gateway.test", Mldsa65Seed: seed, Mldsa65Verify: verify}}
	s, c := fixtures(t, echoServer(t))
	s.Node.Tunnel = local
	s.Node.Tunnel.ListenPort = s.Node.Port
	c.Nodes[0].Tunnel = model.DeriveClientTunnel(s.Node.Tunnel, s.Node)
	server, client := run(t, s, model.LocalTLS{}), run(t, c, model.LocalTLS{})
	awaitEcho(t, s.Mappings[0].ListenPort)
	for _, enabled := range []bool{false, true} {
		s.Revision++
		c.Revision++
		s.Node.Tunnel.Reality.Mldsa65Seed, s.Node.Tunnel.Reality.Mldsa65Verify = "", ""
		if enabled {
			s.Node.Tunnel.Reality.Mldsa65Seed, s.Node.Tunnel.Reality.Mldsa65Verify = seed, verify
		}
		c.Nodes[0].Tunnel = model.DeriveClientTunnel(s.Node.Tunnel, s.Node)
		if err := server.Apply(s); err != nil {
			t.Fatal(err)
		}
		if err := client.Apply(c); err != nil {
			t.Fatal(err)
		}
		awaitEcho(t, s.Mappings[0].ListenPort)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialReality(ctx, "127.0.0.1:1", "gateway.test", model.Reality{PublicKey: public, ShortID: "aa", Mldsa65Verify: verify})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancellation not honored: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, wrong, _ := GenerateMldsa65()
	_, err = dialReality(ctx, net.JoinHostPort(s.Node.Address, strconv.Itoa(s.Node.Port)), "gateway.test", model.Reality{PublicKey: public, ShortID: "aa", ServerNames: "gateway.test", Mldsa65Verify: wrong})
	if err == nil {
		t.Fatal("wrong ML-DSA public key connected")
	}
}
