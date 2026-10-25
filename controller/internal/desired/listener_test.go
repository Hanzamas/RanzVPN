package desired

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The node that a Listener names gets it in its NodeConfig: the ports, with 443 for one that the
// Listener leaves out, and the source of the certificate, with the defaults of ACME; a node that no
// Listener names gets none. A change of the Listener is a change of the NodeConfig only.
func TestCompileListener(t *testing.T) {
	const thumbprint = "00112233445566778899AABBCCDDEEFF00112233"
	rs := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(intent.KindListener, "edge-a", `{"node": "a", "certificate": {"acme": {"names": ["vpn.example.com"], "httpPort": 5002, "caFile": "C:\\ranz\\ca.pem", "renewDays": 60}}}`),
		res(intent.KindListener, "edge-b", `{"node": "b", "port": 8443, "certificate": {"file": "C:\\ranz\\b.pfx", "passwordFile": "C:\\ranz\\b.txt"}}`),
	}
	states := compile(t, rs...)
	want := map[string]*controlpb.Listener{
		"a": {Name: "edge-a", Port: 443, QuicPort: 443, Certificate: &controlpb.Listener_Acme{Acme: &controlpb.CertificateAcme{Directory: intent.DefaultACMEDirectory,
			Names: []string{"vpn.example.com"}, HttpPort: 5002, CaFile: `C:\ranz\ca.pem`, RenewDays: 60}}},
		"b": {Name: "edge-b", Port: 8443, QuicPort: 443, Certificate: &controlpb.Listener_File{File: &controlpb.CertificateFile{Path: `C:\ranz\b.pfx`, PasswordFile: `C:\ranz\b.txt`}}},
		"c": nil,
	}
	for node, w := range want {
		got := states[node][Key{controlpb.Kind_KIND_NODE, node}].GetNode().GetListener()
		if !proto.Equal(got, w) {
			t.Errorf("the Listener of %s is %v, want %v", node, got, w)
		}
	}

	// The Listener of c by the thumbprint of a KSP certificate changes the NodeConfig of c alone
	in, err := intent.Apply(intent.New(), intent.Document{Resources: rs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := intent.Apply(in, intent.Document{Resources: []intent.Resource{res(intent.KindListener, "edge-c", `{"node": "c", "quicPort": 4433, "certificate": {"ksp": "`+thumbprint+`"}}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Compile(next)
	if err != nil {
		t.Fatal(err)
	}
	u := Delta(states["c"], 1, after["c"], 2)
	if len(u.GetSet()) != 1 || len(u.GetRemove()) != 0 || u.GetSet()[0].GetNode().GetName() != "c" {
		t.Fatalf("the update of c is %v, want its NodeConfig alone", u)
	}
	got := u.GetSet()[0].GetNode().GetListener()
	if w := (&controlpb.Listener{Name: "edge-c", Port: 443, QuicPort: 4433, Certificate: &controlpb.Listener_Ksp{Ksp: thumbprint}}); !proto.Equal(got, w) {
		t.Errorf("the Listener of c is %v, want %v", got, w)
	}
	for _, node := range []string{"a", "b"} {
		if u := Delta(states[node], 1, after[node], 2); len(u.GetSet()) != 0 || len(u.GetRemove()) != 0 {
			t.Errorf("the Listener of c changed the state of %s: %v", node, u)
		}
	}
}
