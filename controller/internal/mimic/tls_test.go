package mimic

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/reality"
)

// The TLS session between the two roles with no sidecar and no pipe around it: a REALITY server that
// the library runs, and a client that makes the proof with the ClientHello of each browser. What one
// end writes comes out of the other end, in both directions, and both ends export the same channel
// binding, the one that the nodes put into their Noise handshake.
func TestRealityAndUTLSCarryBytesAndExportTheSameBinding(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	scfg, err := parseServer(borrowSettings(private, site.addr))
	if err != nil {
		t.Fatal(err)
	}
	rcfg := realityConfig(scfg, site.addr)
	// The library probes the real site for the records after a handshake, in the background: a test needs none of it
	for _, key := range detectionKeys(site.addr, scfg.serverNames) {
		reality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	// The server takes each connection, tells how it went, and sends back what it reads
	type served struct {
		binding string
		err     error
	}
	results := make(chan served, 4)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, err := reality.Server(context.Background(), raw, rcfg)
				if err != nil {
					results <- served{err: err}
					return
				}
				defer conn.Close()
				state := conn.ConnectionState()
				buf := make([]byte, 100000)
				conn.SetDeadline(time.Now().Add(testTimeout))
				if _, err := io.ReadFull(conn, buf); err != nil {
					results <- served{err: err}
					return
				}
				_, err = conn.Write(buf)
				results <- served{binding: bindingText(&state), err: err}
			}()
		}
	}()

	for _, name := range []string{FingerprintEdge, FingerprintChrome, FingerprintFirefox} {
		t.Run(name, func(t *testing.T) {
			l := mustLink(t, Link{Address: ln.Addr().String(), ServerName: testName, PublicKey: public, ShortID: testShortID, Fingerprint: name})
			raw, err := net.DialTimeout("tcp", l.address, testTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			conn, err := realityHandshake(ctx, raw, l, time.Now())
			if err != nil {
				t.Fatalf("the handshake: %v", err)
			}
			state := conn.ConnectionState()
			binding := bindingText(&state)
			if len(binding) != 2*BindingSize {
				t.Errorf("the client exports the binding %q, not %d bytes as hex digits", binding, BindingSize)
			}

			data := make([]byte, 100000)
			for i := range data {
				data[i] = byte(i * 7)
			}
			conn.SetDeadline(time.Now().Add(testTimeout))
			if _, err := conn.Write(data); err != nil {
				t.Fatalf("writing to the server: %v", err)
			}
			back := make([]byte, len(data))
			if _, err := io.ReadFull(conn, back); err != nil {
				t.Fatalf("reading what the server sent back: %v", err)
			}
			if string(back) != string(data) {
				t.Error("what came back is not what went out")
			}
			select {
			case r := <-results:
				if r.err != nil {
					t.Fatalf("the server: %v", r.err)
				}
				if r.binding != binding {
					t.Errorf("the server exports the binding %q and the client %q", r.binding, binding)
				}
			case <-time.After(testTimeout):
				t.Fatal("the server did not tell how it went")
			}
		})
	}
}
