package intent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// listenerBase is an intent with two Nodes for the Listeners of the tests.
func listenerBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// A Listener gets the default ports, the defaults of ACME and the fixed TLS policy, and the
// thumbprint of a KSP certificate in its one form; it reads back from the resources, after the
// DnsRecords, and an import without it takes it away.
func TestApplyListener(t *testing.T) {
	in, err := Apply(listenerBase(t), doc(
		res(KindListener, "edge-a", `{"node": "a", "certificate": {"acme": {"names": ["vpn.example.com", "a.example.com"], "email": "ops@example.com"}}}`),
		res(KindListener, "edge-b", `{"node": "b", "port": 8443, "quicPort": 8443, "certificate": {"ksp": "aa bb:CC dd eeff00112233445566778899aabbccdd"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := in.Listeners["edge-a"]
	want := ListenerACME{Directory: DefaultACMEDirectory, Email: "ops@example.com", Names: []string{"vpn.example.com", "a.example.com"}, HTTPPort: DefaultACMEHTTPPort, RenewDays: DefaultRenewDays}
	if a.Port != DefaultListenerPort || a.QUICPort != DefaultListenerPort || a.Certificate.ACME == nil || !reflect.DeepEqual(*a.Certificate.ACME, want) {
		t.Errorf("Listener edge-a is %+v with ACME %+v, want the ports 443 and the defaults of ACME", a, a.Certificate.ACME)
	}
	if a.TLS != ListenerPolicy || a.TLS.NewProtocol != "1.3" || a.TLS.WebUI != "1.2, 1.3" {
		t.Errorf("the TLS policy of edge-a is %+v, want %+v", a.TLS, ListenerPolicy)
	}
	b := in.Listeners["edge-b"]
	if b.Port != 8443 || b.QUICPort != 8443 || b.Certificate.KSP != "AABBCCDDEEFF00112233445566778899AABBCCDD" {
		t.Errorf("Listener edge-b is %+v, want its own ports and the thumbprint in upper case without separators", b)
	}
	for node, want := range map[string]string{"a": "edge-a", "b": "edge-b"} {
		if got, ok := in.ListenerOf(node); !ok || got != want {
			t.Errorf("the Listener of %s is %q (%v), want %q", node, got, ok, want)
		}
	}
	if _, ok := in.ListenerOf("c"); ok {
		t.Error("a Node that does not exist has a Listener")
	}

	// The Listeners read back from the resources, after the DnsRecords
	rs := in.Resources()
	if last := rs[len(rs)-1]; last.Kind != KindListener || last.Name != "edge-b" {
		t.Errorf("the last resource is %s %q, want Listener edge-b", last.Kind, last.Name)
	}
	if kindOrder(KindListener) <= kindOrder(KindDNSRecord) {
		t.Error("a Listener is not ordered after the DnsRecords")
	}
	back, err := FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Listeners, in.Listeners) {
		t.Errorf("the Listeners read back are %+v, want %+v", back.Listeners, in.Listeners)
	}
	// What the controller filled in applies again unchanged
	if again, err := Apply(in, doc(rs...), nil); err != nil || !reflect.DeepEqual(again.Listeners, in.Listeners) {
		t.Errorf("the resources applied again: %v, the Listeners %+v", err, again.Listeners)
	}
	// A clone shares no names of ACME
	c := in.Clone()
	c.Listeners["edge-a"].Certificate.ACME.Names[0] = "other.example.com"
	if in.Listeners["edge-a"].Certificate.ACME.Names[0] != "vpn.example.com" {
		t.Error("a change of a clone changed the names of ACME of the intent")
	}

	// An import of a document without edge-b takes it away
	var rest []Resource
	for _, r := range rs {
		if r.Kind != KindListener || r.Name == "edge-a" {
			rest = append(rest, r)
		}
	}
	next, err := Replace(in, Document{Resources: rest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.Listeners["edge-b"]; ok || len(next.Listeners) != 1 {
		t.Errorf("after the import the Listeners are %+v, want edge-a alone", next.Listeners)
	}

	// A PKCS #12 file and the file of its password
	f, err := Apply(listenerBase(t), doc(res(KindListener, "f", `{"node": "a", "certificate": {"file": "C:\\ProgramData\\Ranz\\node.pfx", "passwordFile": "\\\\server\\share\\pfx.txt"}}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := f.Listeners["f"].Certificate; c.File != `C:\ProgramData\Ranz\node.pfx` || c.PasswordFile != `\\server\share\pfx.txt` {
		t.Errorf("the certificate of Listener f is %+v", c)
	}
}

func TestApplyListenerRejects(t *testing.T) {
	base := listenerBase(t)
	long := strings.Repeat("a", 60)
	for _, c := range []struct {
		spec string
		want string
	}{
		{`{"node": "c", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}}`, `Listener "l": Node "c" does not exist`},
		{`{"node": "a", "certificate": {}}`, `it needs exactly one source: file, ksp or acme`},
		{`{"node": "a", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `", "file": "C:\\a.pfx"}}`, `exactly one source`},
		{`{"node": "a", "certificate": {"ksp": "abc"}}`, `ksp "abc" is not the 40 hex digits of a SHA-1 thumbprint`},
		{`{"node": "a", "certificate": {"ksp": "` + strings.Repeat("xy", 20) + `"}}`, `is not the 40 hex digits`},
		{`{"node": "a", "certificate": {"file": "node.pfx"}}`, `file: "node.pfx" is not an absolute path of the node`},
		{`{"node": "a", "certificate": {"file": "C:\\` + strings.Repeat("p", 260) + `"}}`, `is not an absolute path of the node of at most 259 characters`},
		{`{"node": "a", "certificate": {"file": "C:\\a?.pfx"}}`, `is not an absolute path`},
		{`{"node": "a", "certificate": {"file": "C:\\a.pfx", "passwordFile": "pw.txt"}}`, `passwordFile: "pw.txt" is not an absolute path`},
		{`{"node": "a", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `", "passwordFile": "C:\\pw.txt"}}`, `passwordFile needs a file`},
		{`{"node": "a", "certificate": {"acme": {"names": []}}}`, `acme: names holds 0 names, not 1 to 4`},
		{`{"node": "a", "certificate": {"acme": {"names": ["a.test", "b.test", "c.test", "d.test", "e.test"]}}}`, `names holds 5 names`},
		{`{"node": "a", "certificate": {"acme": {"names": ["Vpn.Example.com"]}}}`, `acme: names: "Vpn.Example.com" is not DNS labels`},
		{`{"node": "a", "certificate": {"acme": {"names": ["vpn..example"]}}}`, `is not DNS labels`},
		{`{"node": "a", "certificate": {"acme": {"names": ["` + strings.Join([]string{long, long, long, long, long}, ".") + `"]}}}`, `is longer than 253 characters`},
		{`{"node": "a", "certificate": {"acme": {"names": ["a.test", "a.test"]}}}`, `acme: names: "a.test" is listed twice`},
		{`{"node": "a", "certificate": {"acme": {"directory": "http://acme.test/dir", "names": ["a.test"]}}}`, `acme: directory "http://acme.test/dir" is not an https URL`},
		{`{"node": "a", "certificate": {"acme": {"directory": "https:///dir", "names": ["a.test"]}}}`, `is not an https URL`},
		{`{"node": "a", "certificate": {"acme": {"email": "ops", "names": ["a.test"]}}}`, `acme: email "ops" is not an e-mail address`},
		{`{"node": "a", "certificate": {"acme": {"email": "a@b@c", "names": ["a.test"]}}}`, `is not an e-mail address`},
		{`{"node": "a", "certificate": {"acme": {"names": ["a.test"], "caFile": "ca.pem"}}}`, `acme: caFile: "ca.pem" is not an absolute path`},
		{`{"node": "a", "certificate": {"acme": {"names": ["a.test"], "renewDays": 3651}}}`, `acme: renewDays 3651 is more than 3650`},
		{`{"node": "a", "certificate": {"acme": {"names": ["a.test"], "staging": true}}}`, `spec: json: unknown field "staging"`},
		{`{"node": "a", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}, "tls": {"newProtocol": "1.2", "webUI": "1.2, 1.3", "api": "1.2, 1.3", "compat": "1.2, 1.3"}}`, `the TLS policy is fixed`},
		{`{"node": "a", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}, "tls": {"newProtocol": "1.3", "webUI": "1.0, 1.2, 1.3", "api": "1.2, 1.3", "compat": "1.2, 1.3"}}`, `the TLS policy is fixed`},
		{`{"node": "a", "port": 65536, "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}}`, `spec: json: cannot unmarshal`},
	} {
		_, err := Apply(base, doc(res(KindListener, "l", c.spec)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}

	// A Node has one Listener at most
	ksp := `"certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}`
	_, err := Apply(base, doc(res(KindListener, "l1", `{"node": "a", `+ksp+`}`), res(KindListener, "l2", `{"node": "a", `+ksp+`}`)), nil)
	if err == nil || !strings.Contains(err.Error(), `Listener "l2": Node "a" has the Listener "l1" already`) {
		t.Errorf("two Listeners of one Node: %v, want an error", err)
	}
}

// A Node that a Listener names cannot be deleted; the Listener can.
func TestDeleteListener(t *testing.T) {
	in, err := Apply(listenerBase(t), doc(res(KindListener, "l", `{"node": "a", "certificate": {"ksp": "`+strings.Repeat("ab", 20)+`"}}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(in, KindNode, "a"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "a" is used by Listener "l"`) {
		t.Errorf("deleting Node a, which Listener l names: %v, want an error that names the Listener", err)
	}
	next, err := Delete(in, KindListener, "l")
	if err != nil || len(next.Listeners) != 0 || len(in.Listeners) != 1 {
		t.Errorf("deleting Listener l: %v, %d Listeners left, %d in the intent before", err, len(next.Listeners), len(in.Listeners))
	}
	if _, err := Delete(next, KindListener, "l"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting Listener l again: %v, want ErrNotFound", err)
	}
	if _, err := Delete(next, KindNode, "a"); err != nil {
		t.Errorf("deleting Node a once its Listener is gone: %v", err)
	}
}
