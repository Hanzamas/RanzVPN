package mimic

import (
	"bytes"
	"testing"
)

// The fuzz tests of the sidecar package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the ranz workflow runs with go test -fuzz.

// FuzzRead reads the input as what the node writes into the control pipe (Reader.Read), message after
// message until the first error, and checks the settings of each start message as the session does
// before anything listens or dials (parseServer and parseClient).
func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"type":"start","role":"server","pipe":"p","server":{"listen":"127.0.0.1:0","private_key":"` + testPrivate +
		`","short_ids":["0123456789abcdef"],"server_names":["www.example.com"],"decoy":{"mode":"borrow","dest":"www.example.com:443"},"padding":{"profile":"shape"}}}` +
		"\n" + `{"type":"stats"}` + "\n"))
	f.Add([]byte(`{"type":"start","role":"server","pipe":"p","server":{"private_key":"` + testPrivate +
		`","short_ids":[""],"decoy":{"name":"www.example.com","self_signed":true,"page":"<p>x</p>"}}}` + "\r\n\r\n"))
	f.Add([]byte(`{"type":"start","role":"client","pipe":"p","client":{"links":[{"address":"192.0.2.1:443","server_name":"www.example.com","public_key":"` + testPrivate +
		`","short_id":"ab","fingerprint":"firefox","padding":{"sizes":[300,1200],"min_gap_ms":5}}]}}`))
	// The Hysteria mode (hysteria.go): the hysteria part of a server and of a link
	f.Add([]byte(`{"type":"start","role":"server","pipe":"p","server":{"private_key":"` + testPrivate + `","short_ids":["ab"],"decoy":{"name":"www.example.com","self_signed":true},` +
		`"hysteria":{"listen":":8443","secrets":["` + testSecret + `"],"salamander":"` + testSalamander + `","max_mbps":100}}}`))
	f.Add([]byte(`{"type":"start","role":"client","pipe":"p","client":{"links":[{"address":"192.0.2.1:8443","server_name":"www.example.com","hysteria":{"secret":"` + testSecret +
		`","pin_sha256":"` + testPrivate + `","salamander":"` + testSalamander + `","brutal":{"up_mbps":20,"down_mbps":100}}}]}}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReader(bytes.NewReader(b))
		// Every message takes at least one byte of the input
		for i := 0; i <= len(b); i++ {
			m, err := r.Read()
			if err != nil {
				return
			}
			if m.Type == "" {
				t.Fatal("Read returned a message without a type")
			}
			if m.Type != TypeStart {
				continue
			}
			if m.Server != nil {
				s := *m.Server
				// The page file is a file of the node's own: the test reads none
				s.Decoy.PageFile = ""
				if cfg, err := parseServer(&s); err == nil {
					if cfg.key == nil || len(cfg.shortIDs) == 0 || len(cfg.serverNames) == 0 {
						t.Fatalf("a server without a key, a short id or a name is accepted: %+v", s)
					}
					switch cfg.decoy.mode {
					case DecoyOwn:
						if !contains(cfg.serverNames, cfg.decoy.name) {
							t.Fatalf("the own decoy %q is none of the server names %q", cfg.decoy.name, cfg.serverNames)
						}
					case DecoyBorrow:
						if cfg.decoy.dest == "" {
							t.Fatalf("a borrow decoy without a dest is accepted: %+v", s)
						}
					default:
						t.Fatalf("a decoy of the mode %q is accepted", cfg.decoy.mode)
					}
					if h := cfg.hysteria; h != nil && (h.listen == "" || len(h.secrets) == 0 || cfg.decoy.mode != DecoyOwn) {
						t.Fatalf("a hysteria part without a listen, a secret or the own decoy is accepted: %+v", s)
					}
				}
			}
			if m.Client != nil {
				if cfg, err := parseClient(m.Client); err == nil {
					if len(cfg.links) == 0 {
						t.Fatalf("a client without a link is accepted: %+v", m.Client)
					}
					for _, l := range cfg.links {
						if h := l.hysteria; h != nil && (len(h.secret) < 2*minSecret || (h.up == 0) != (h.down == 0)) {
							t.Fatalf("a hysteria link without a secret, or with Brutal in one direction, is accepted: %+v", m.Client)
						}
					}
				}
			}
		}
		t.Fatalf("Read returned more messages than the %d bytes of the input hold", len(b))
	})
}

// FuzzFrame reads the input as what the other sidecar sends through the TLS session (frameReader.Read,
// reached by the connection through frameConn.Read), in reads of 1 to 100 bytes, and checks that the
// payload that comes out is never more than the input holds, and that the reader ends.
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 5, 0, 3, 'h', 'e', 'l', 'l', 'o', 0, 0, 0})
	f.Add([]byte{0, 0, 0, 3, 9, 9, 9, 0, 2, 0, 0, 'o', 'k'})
	f.Add([]byte{0x40, 0, 0, 0})
	f.Add([]byte{0, 10, 0, 0, 'a'})
	f.Add([]byte{0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		fr := &frameReader{r: bytes.NewReader(b)}
		buf := make([]byte, 1+len(b)%100)
		total := 0
		for i := 0; i <= len(b); i++ {
			n, err := fr.Read(buf)
			total += n
			if total > len(b) {
				t.Fatalf("Read returned %d bytes of payload, more than the %d bytes of the input", total, len(b))
			}
			if err != nil {
				return
			}
		}
		t.Fatalf("Read did not end within %d reads of an input of %d bytes", len(b)+1, len(b))
	})
}
