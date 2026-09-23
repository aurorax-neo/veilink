// devcert creates short-lived certificates for local demonstrations only.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "", "required output directory (private, must not contain certificate files)")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1,master,server", "comma-separated DNS names/IP SANs")
	flag.Parse()
	if *out == "" {
		fail(fmt.Errorf("-out is required"))
	}
	if err := run(*out, strings.Split(*hosts, ",")); err != nil {
		fail(err)
	}
	fmt.Println("Created development CA and server certificate; expires in 7 days. Do not use in production.")
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func run(out string, hosts []string) error {
	if len(hosts) == 0 {
		return fmt.Errorf("at least one host required")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	if err := os.Chmod(out, 0700); err != nil {
		return err
	}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if _, err := os.Lstat(filepath.Join(out, name)); !os.IsNotExist(err) {
			return fmt.Errorf("refusing to replace %s", name)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			fail(e)
		}
		return n
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Veilink DEVELOPMENT CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Veilink DEVELOPMENT server"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			return fmt.Errorf("empty host")
		}
		if ip := net.ParseIP(h); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, h)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name, kind string
		data       []byte
	}{{"ca.pem", "CERTIFICATE", caDER}, {"cert.pem", "CERTIFICATE", certDER}, {"key.pem", "PRIVATE KEY", keyDER}} {
		file, err := os.OpenFile(filepath.Join(out, f.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		err = pem.Encode(file, &pem.Block{Type: f.kind, Bytes: f.data})
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
