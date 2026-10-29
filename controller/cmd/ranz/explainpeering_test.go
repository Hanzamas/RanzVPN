package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// ranz explain NODE prints the BGP peering of a Node (SDN-77, #357): with a controller whose intent has no VRF that peers
// by BGP it says that the Node has none, and a Node that the intent does not have is refused with 404.
func TestExplainPeeringWithoutBGP(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s := explain.Scenario{Name: "peering", Nodes: map[string]uint8{"node-x": 1}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "node-x", "spec": {"vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.1"}}}
	]}`), &s.Intent); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}).Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte(admin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test server is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	fingerprint := fingerprintOf(srv.Certificate())

	var out, errOut bytes.Buffer
	if code := runExplain(ctx, []string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "node-x"}, &out, &errOut); code != 0 {
		t.Fatalf("ranz explain node-x: exit code %d: %s", code, errOut.String())
	}
	if want := "BGP peering of node-x: none, no VRF of the Node peers by BGP\n"; out.String() != want {
		t.Errorf("ranz explain node-x printed %q, want %q", out.String(), want)
	}
	out.Reset()
	errOut.Reset()
	if code := runExplain(ctx, []string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "nowhere"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), `Node "nowhere" (404 Not Found)`) {
		t.Errorf("ranz explain nowhere: exit code %d, %q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runExplain(ctx, []string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "-o", "json", "node-x"}, &out, &errOut); code != 0 {
		t.Fatalf("ranz explain -o json node-x: exit code %d: %s", code, errOut.String())
	}
	var st controller.PeeringStatus
	if err := json.Unmarshal(out.Bytes(), &st); err != nil || st.Node != "node-x" || st.ASN != 0 || len(st.Expected) != 0 || len(st.Peers) != 0 || !st.Reported.IsZero() {
		t.Errorf("ranz explain -o json node-x: %+v, %v:\n%s", st, err, out.String())
	}
}

// ranz explain NODE prints each peer of the sidecar of a Node with its Node, its address and the state of its session,
// the prefixes learned from it with their VRF below, and a peer that the intent names and the report lacks; -o json
// prints the answer of the API as it is. The answer is the one of a stand-in of the API.
func TestExplainPeeringPrintsThePeers(t *testing.T) {
	ctx := context.Background()
	st := controller.PeeringStatus{
		Node:     "gw-1",
		ASN:      4200000000,
		Expected: []string{"db", "gw-2"},
		Reported: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		Peers: []controller.PeeringPeer{
			{Node: "db", Address: "10.1.0.2", State: "established", Learned: []controller.PeeringRoute{{VRF: "dc", Prefix: "10.30.0.2/32"}, {VRF: "dc", Prefix: "192.168.20.0/24"}}},
			{Address: "10.1.0.9", State: "active", Learned: []controller.PeeringRoute{}},
		},
		Refused: 3,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/peering/gw-1" || r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(api.Problem{Error: "not this one"})
			return
		}
		json.NewEncoder(w).Encode(st)
	}))
	t.Cleanup(srv.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The stand-in is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	run := func(out, errOut *bytes.Buffer, args ...string) int {
		t.Helper()
		return runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprintOf(srv.Certificate())}, args...), out, errOut)
	}

	var out, errOut bytes.Buffer
	if code := run(&out, &errOut, "gw-1"); code != 0 {
		t.Fatalf("ranz explain gw-1: exit code %d: %s", code, errOut.String())
	}
	want := "BGP peering of gw-1 in AS 4200000000: 2 peers, 3 sessions refused (reported 2026-10-28T12:00:00Z)\n" +
		"  db         10.1.0.2  established, 2 prefixes learned\n" +
		"               dc  10.30.0.2/32\n" +
		"               dc  192.168.20.0/24\n" +
		"  (no Node)  10.1.0.9  active, 0 prefixes learned\n" +
		"  gw-2       no session in the report\n"
	if out.String() != want {
		t.Errorf("ranz explain gw-1 printed\n%s\nwant\n%s", out.String(), want)
	}

	out.Reset()
	if code := run(&out, &errOut, "-o", "json", "gw-1"); code != 0 {
		t.Fatalf("ranz explain -o json gw-1: exit code %d: %s", code, errOut.String())
	}
	var got controller.PeeringStatus
	err := json.Unmarshal(out.Bytes(), &got)
	same := err == nil && got.Reported.Equal(st.Reported)
	got.Reported = st.Reported
	if !same || !reflect.DeepEqual(got, st) {
		t.Errorf("ranz explain -o json gw-1 gave %+v, %v, want %+v", got, err, st)
	}

	errOut.Reset()
	if code := run(&out, &errOut, "db"); code != 1 || !strings.Contains(errOut.String(), "not this one (404 Not Found)") {
		t.Errorf("ranz explain db: exit code %d, %q", code, errOut.String())
	}
}
