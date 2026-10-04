// Command hy2bench measures a loopback fixed-target proxy, not UDP line rate.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	dir := flag.String("cert-dir", "", "directory with cert.pem and key.pem")
	network := flag.String("network", "tcp", "tcp or udp")
	flag.Parse()
	if *network == "udp" {
		udp()
		return
	}
	if *network != "tcp" {
		panic("invalid network")
	}
	cert, err := tls.LoadX509KeyPair(*dir+"/cert.pem", *dir+"/key.pem")
	must(err)
	listener, err := tls.Listen("tcp", "127.0.0.1:19443", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	must(err)
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	pem, err := os.ReadFile(*dir + "/cert.pem")
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid CA")
	}
	for round := 1; round <= 3; round++ {
		raw, err := net.Dial("tcp", "127.0.0.1:19080")
		must(err)
		c := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
		must(c.SetDeadline(time.Now().Add(90 * time.Second)))
		must(c.Handshake())
		block := bytes.Repeat([]byte("veilink-perf-data"), 4096)
		transfer := func(n int) time.Duration {
			result := make(chan error, 1)
			start := time.Now()
			go func() {
				for i := 0; i < n; i++ {
					if _, err := c.Write(block); err != nil {
						result <- err
						return
					}
				}
				result <- nil
			}()
			got := make([]byte, len(block))
			for i := 0; i < n; i++ {
				_, err := io.ReadFull(c, got)
				must(err)
				if !bytes.Equal(got, block) {
					panic("TCP corruption")
				}
			}
			must(<-result)
			return time.Since(start)
		}
		transfer(16)
		elapsed := transfer(8192)
		lat := make([]time.Duration, 200)
		got := make([]byte, 64)
		for i := range lat {
			start := time.Now()
			_, err = c.Write(block[:64])
			must(err)
			_, err = io.ReadFull(c, got)
			must(err)
			lat[i] = time.Since(start)
			if !bytes.Equal(got, block[:64]) {
				panic("RTT corruption")
			}
		}
		report("tcp", round, 512<<20, elapsed, lat)
		must(c.Close())
	}
}
func report(network string, round, size int, elapsed time.Duration, lat []time.Duration) {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	fmt.Printf("network=%s round=%d bytes=%d seconds=%.6f MiBps=%.3f p50_us=%.3f p95_us=%.3f\n", network, round, size, elapsed.Seconds(), float64(size)/(1<<20)/elapsed.Seconds(), float64(lat[99])/1e3, float64(lat[189])/1e3)
}
func udp() {
	listener, err := net.ListenPacket("udp", "127.0.0.1:19443")
	must(err)
	defer listener.Close()
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := listener.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err = listener.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	for round := 1; round <= 3; round++ {
		c, err := net.Dial("udp", "127.0.0.1:19080")
		must(err)
		payload := bytes.Repeat([]byte{0x5a}, 1200)
		got := make([]byte, 1500)
		batch := func(base, count int) {
			must(c.SetDeadline(time.Now().Add(5 * time.Second)))
			for i := 0; i < count; i++ {
				binary.BigEndian.PutUint64(payload, uint64(base+i))
				_, err := c.Write(payload)
				must(err)
			}
			seen := make(map[uint64]bool, count)
			for i := 0; i < count; i++ {
				n, err := c.Read(got)
				if err != nil {
					panic(fmt.Sprintf("UDP loss/timeout: received=%d/%d: %v", i, count, err))
				}
				if n != len(payload) {
					panic("UDP size mismatch")
				}
				id := binary.BigEndian.Uint64(got)
				if id < uint64(base) || id >= uint64(base+count) || seen[id] {
					panic("UDP sequence mismatch")
				}
				seen[id] = true
				if !bytes.Equal(got[8:n], payload[8:]) {
					panic("UDP corruption")
				}
			}
		}
		for i := 0; i < 256; i += 16 {
			batch(i, 16)
		}
		start := time.Now()
		for i := 0; i < 16384; i += 16 {
			batch(i, 16)
		}
		elapsed := time.Since(start)
		lat := make([]time.Duration, 200)
		payload = payload[:64]
		for i := range lat {
			start := time.Now()
			batch(i, 1)
			lat[i] = time.Since(start)
		}
		report("udp", round, 16384*1200, elapsed, lat)
		must(c.Close())
	}
}
