package sidecar

import (
	"bytes"
	"testing"
)

// The fuzz test of the sidecar package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the ranz workflow runs with go test -fuzz.

// FuzzRead reads the input as what the node writes into the pipe (Reader.Read), message after
// message until the first error, and checks the settings of each start message as the session
// does before BGP starts (parseStart).
func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","peers":[{"address":"192.0.2.2","asn":65002,"passive":true}],"accept":["198.51.100.0/24","2001:db8::/32"]}` + "\n" +
		"\r\n" + `{"type":"announce","prefix":"203.0.113.0/24","next_hop":"192.0.2.1"}` + "\n" + `{"type":"withdraw","prefix":"203.0.113.0/24"}` + "\n"))
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","listen_port":-1,"listen_addresses":["192.0.2.1"],"peers":[{"address":"2001:db8::2","asn":65002,"port":1179}]}`))
	// The peering of the standard mode (SDN-77 #357): a start with the node's address, peers messages with more, and ping
	// (SDN-77-R1 #531)
	f.Add([]byte(`{"type":"start","asn":4200000000,"router_id":"192.0.2.2","address":"127.0.0.2","peers":[{"address":"127.0.0.3","asn":4200000000,"hold_time":9,"vrfs":[{"id":101,"accept":["10.0.0.3/32","192.168.2.0/24"]}]}]}` + "\n" +
		`{"type":"peers","more":true,"peers":[{"address":"127.0.0.4","asn":4200000000,"vrfs":[{"id":102,"accept":["fd00::4/128"]}]}]}` + "\n" +
		`{"type":"peers"}` + "\n" + `{"type":"announce","vrf":101,"prefix":"192.168.1.0/24"}` + "\n" + `{"type":"ping"}` + "\n"))

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
			if m.Type == TypeStart {
				// Only a node of the peering of the standard mode may start without peers: it may be alone in its VRFs
				if cfg, err := parseStart(m); err == nil && len(cfg.peers) == 0 && !cfg.address.IsValid() {
					t.Fatalf("a start without peers is accepted: %+v", m)
				}
			}
		}
		t.Fatalf("Read returned more messages than the %d bytes of the input hold", len(b))
	})
}
