package intent

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The mimic section of a Listener (SDN-94 #423, listener_mimic.go). The cases that the tests of the sidecar use run against
// the sidecar and against this section in one table in internal/mimic (section_test.go); these tests are the rest: the
// forms that the section is kept in, what it does not hold, and the settings that only the Controller refuses.

// mimicKSP is the certificate of the Listeners of these tests.
var mimicKSP = `"certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}`

// mimicSection returns a mimic section with the address listen, the server names names and the decoy decoy, each as JSON.
func mimicSection(listen, names, decoy string) string {
	return `{"listen": ` + listen + `, "serverNames": ` + names + `, "decoy": ` + decoy + `}`
}

// mimicListener returns the spec of a Listener of the Node a, whose front door is on the TCP port port, with the mimic
// section section.
func mimicListener(port int, section string) string {
	return `{"node": "a", "port": ` + strconv.Itoa(port) + `, ` + mimicKSP + `, "mimic": ` + section + `}`
}

// A section that leaves out the clock tolerance and the mode of the decoy gets the defaults, and the forms that the Node
// reads: the server names in lower case, the address of the sidecar and the site of a borrow decoy as netip and ParseEndpointAddress
// write them, the directory of ACME. It reads back from the resources, applies again unchanged, and a clone shares
// nothing with it.
func TestApplyListenerMimic(t *testing.T) {
	in, err := Apply(listenerBase(t), doc(
		res(KindListener, "edge-a", `{"node": "a", `+mimicKSP+`, "mimic": {"listen": "[::ffff:192.0.2.10]:08443", "serverNames": ["WWW.Example.COM", "cdn.example.com"],
			"decoy": {"acme": {"cacheDir": "C:\\ProgramData\\Ranz\\mimic-acme", "email": "ops@example.com"}}}}`),
		res(KindListener, "edge-b", `{"node": "b", `+mimicKSP+`, "mimic": {"listen": "[2001:0db8::1]:8443", "serverNames": ["site.example"], "maxTimeDiffMs": 5000,
			"decoy": {"mode": "borrow", "dest": "WWW.Example.COM:0443"}}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &ListenerMimic{
		Listen: "192.0.2.10:8443", ServerNames: []string{"www.example.com", "cdn.example.com"}, MaxTimeDiffMs: DefaultMimicMaxTimeDiffMs,
		Decoy: MimicDecoy{Mode: MimicDecoyOwn, ACME: &MimicACME{Directory: DefaultACMEDirectory, Email: "ops@example.com", CacheDir: `C:\ProgramData\Ranz\mimic-acme`}},
	}
	b := &ListenerMimic{
		Listen: "[2001:db8::1]:8443", ServerNames: []string{"site.example"}, MaxTimeDiffMs: 5000,
		Decoy: MimicDecoy{Mode: MimicDecoyBorrow, Dest: "www.example.com:443"},
	}
	for node, want := range map[string]*ListenerMimic{"a": a, "b": b} {
		got, ok := in.MimicOf(node)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("the mimic section of Node %s is %+v (%v), want %+v", node, got, ok, want)
		}
	}

	// It reads back from the resources, and what the controller filled in applies again unchanged
	rs := in.Resources()
	back, err := FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Listeners, in.Listeners) {
		t.Errorf("the Listeners read back are %+v, want %+v", back.Listeners, in.Listeners)
	}
	again, err := Apply(in, doc(rs...), nil)
	if err != nil || !reflect.DeepEqual(again.Listeners, in.Listeners) {
		t.Errorf("the resources applied again: %v, the Listeners %+v", err, again.Listeners)
	}
	if put, gone := Changed(in, again); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the same intent applied again changed %+v and removed %+v", put, gone)
	}

	// A clone shares no name and no ACME source with the intent
	c := in.Clone()
	ca, _ := c.MimicOf("a")
	ca.ServerNames[0] = "changed.example"
	ca.Decoy.ACME.CacheDir = `C:\changed`
	if got, _ := in.MimicOf("a"); got.ServerNames[0] != "www.example.com" || got.Decoy.ACME.CacheDir != `C:\ProgramData\Ranz\mimic-acme` {
		t.Errorf("a change of a clone changed the mimic section of the intent: %+v", got)
	}

	// A Listener without a section has none, and the section is the Listener's own: an import without it takes it away
	if _, ok := in.MimicOf("c"); ok {
		t.Error("a Node that does not exist has a mimic section")
	}
	plain, err := Apply(in, doc(res(KindListener, "edge-a", `{"node": "a", `+mimicKSP+`}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.MimicOf("a"); ok {
		t.Error("a Listener that is applied again without a section keeps it")
	}
	if got, ok := plain.MimicOf("b"); !ok || got.Listen != "[2001:db8::1]:8443" {
		t.Errorf("an apply of the Listener of a changed the section of b: %+v, %v", got, ok)
	}
	next, err := Replace(in, Document{Resources: slices.DeleteFunc(slices.Clone(rs), func(r Resource) bool { return r.Kind == KindListener && r.Name == "edge-b" })}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.MimicOf("b"); ok || len(next.Listeners) != 1 {
		t.Errorf("after the import without edge-b its section is %v, and the Listeners are %+v", ok, next.Listeners)
	}
}

// The section holds no key and no short id: what the controller keeps of it has the four settings of the operator and
// nothing that names a key, and a section that names one is refused with the reason.
func TestListenerMimicHoldsNoKey(t *testing.T) {
	in, err := Apply(listenerBase(t), doc(res(KindListener, "edge", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"selfSigned": true}`)))), nil)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]json.RawMessage
	for _, r := range in.Resources() {
		if r.Kind == KindListener {
			if err := json.Unmarshal(r.Spec, &spec); err != nil {
				t.Fatal(err)
			}
		}
	}
	var section map[string]json.RawMessage
	if err := json.Unmarshal(spec["mimic"], &section); err != nil {
		t.Fatalf("the mimic section of the stored Listener %s: %v", spec["mimic"], err)
	}
	var names []string
	for name := range section {
		names = append(names, name)
	}
	slices.Sort(names)
	if want := []string{"decoy", "listen", "maxTimeDiffMs", "serverNames"}; !slices.Equal(names, want) {
		t.Errorf("the stored mimic section has the settings %v, want %v", names, want)
	}
	for _, r := range []struct{ field, what string }{{"privateKey", "a private key"}, {"private_key", "a private key"}, {"publicKey", "a public key"},
		{"key", "a key"}, {"shortId", "a short id"}, {"short_ids", "a short id"}, {"shortIDs", "a short id"}} {
		listener := mimicListener(443, `{"listen": ":8443", "serverNames": ["www.example.com"], "decoy": {"selfSigned": true}, "`+r.field+`": "00"}`)
		_, err := Apply(listenerBase(t), doc(res(KindListener, "edge", listener)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Listener "edge": spec: mimic: "`+r.field+`" is refused: the section holds no `) {
			t.Errorf("%s in the section: the error is %v, want a refusal that names it", r.what, err)
		}
	}
}

// The settings that only the Controller refuses, beside the cases that it shares with the sidecar: an address of the
// sidecar that the Node cannot listen on, the port of the front door, more server names than the control protocol holds, and a
// section whose JSON is none.
func TestApplyListenerMimicRejects(t *testing.T) {
	good := mimicSection(`":8443"`, `["www.example.com"]`, `{"selfSigned": true}`)
	nine := `["a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example", "i.example"]`
	for _, c := range []struct {
		name string
		spec string
		want string
	}{
		{"an empty section", mimicListener(443, `{}`), `Listener "l": mimic: listen "" is not host:port`},
		{"an empty section has no server name", mimicListener(443, `{}`), `serverNames holds 0 names, not 1 to 8`},
		{"an empty section has no certificate", mimicListener(443, `{}`), `decoy: the own decoy needs exactly one certificate source`},
		{"an address without a port", mimicListener(443, mimicSection(`"8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `listen "8443" is not host:port`},
		{"an IPv6 address without brackets", mimicListener(443, mimicSection(`"2001:db8::1:8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `an IPv6 address goes in brackets`},
		{"port 0", mimicListener(443, mimicSection(`":0"`, `["www.example.com"]`, `{"selfSigned": true}`)), `listen ":0" has the port "0", not a number from 1 to 65535`},
		{"a port that is no number", mimicListener(443, mimicSection(`":https"`, `["www.example.com"]`, `{"selfSigned": true}`)), `has the port "https"`},
		{"a port above 65535", mimicListener(443, mimicSection(`":70000"`, `["www.example.com"]`, `{"selfSigned": true}`)), `has the port "70000"`},
		{"a host name", mimicListener(443, mimicSection(`"example.com:8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `the host "example.com" is not an IP address without a zone`},
		{"an IP address with a zone", mimicListener(443, mimicSection(`"[fe80::1%eth0]:8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `the host "fe80::1%eth0" is not an IP address without a zone`},
		{"a very long address", mimicListener(443, mimicSection(`"`+strings.Repeat("1", 256)+`:8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `listen is longer than 255 characters`},
		{"the port of the front door", mimicListener(443, mimicSection(`":443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `listen ":443" takes TCP port 443, the port of the front door of this Listener`},
		{"the port of a front door that is not on 443", mimicListener(8443, mimicSection(`"192.0.2.10:8443"`, `["www.example.com"]`, `{"selfSigned": true}`)), `takes TCP port 8443, the port of the front door`},
		{"nine server names", mimicListener(443, mimicSection(`":8443"`, nine, `{"selfSigned": true}`)), `serverNames holds 9 names, not 1 to 8`},
		{"an empty server name", mimicListener(443, mimicSection(`":8443"`, `[""]`, `{"selfSigned": true}`)), `serverNames: "" is not DNS labels`},
		{"a clock tolerance of 0 ms with a negative number", mimicListener(443, `{"listen": ":8443", "serverNames": ["www.example.com"], "maxTimeDiffMs": -1, "decoy": {"selfSigned": true}}`), `maxTimeDiffMs -1 is not from 1 to 86400000`},
		{"a clock tolerance of more than a day", mimicListener(443, `{"listen": ":8443", "serverNames": ["www.example.com"], "maxTimeDiffMs": 86400001, "decoy": {"selfSigned": true}}`), `maxTimeDiffMs 86400001 is not from 1 to 86400000`},
		{"a clock tolerance that is no number", mimicListener(443, `{"listen": ":8443", "serverNames": ["www.example.com"], "maxTimeDiffMs": "x", "decoy": {"selfSigned": true}}`), `cannot unmarshal string`},
		{"a setting that the section does not have", mimicListener(443, `{"listen": ":8443", "serverNames": ["www.example.com"], "decoy": {"selfSigned": true}, "padding": "shape"}`), `unknown field "padding"`},
		{"a setting that the decoy does not have", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"selfSigned": true, "page": "x"}`)), `unknown field "page"`},
		{"a section that is no object", mimicListener(443, `5`), `cannot unmarshal number`},
		{"a section that is a list", mimicListener(443, `["listen"]`), `cannot unmarshal array`},
		{"a borrow decoy with a certificate file and a self-signed certificate", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"mode": "borrow", "dest": "example.com:443", "selfSigned": true, "certFile": "C:\\c.pem"}`)), `decoy: the borrow decoy takes a dest only, not certFile, selfSigned`},
		{"an own decoy with a dest", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"selfSigned": true, "dest": "example.com:443"}`)), `decoy: the own decoy takes no dest`},
		{"a certificate file that is not absolute", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"certFile": "cert.pem", "keyFile": "C:\\key.pem"}`)), `decoy: certFile: "cert.pem" is not an absolute path of the node`},
		{"a cache that is not absolute", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"acme": {"cacheDir": "cache"}}`)), `decoy: acme: cacheDir: "cache" is not an absolute path of the node`},
		{"an ACME contact that is no address", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"acme": {"cacheDir": "C:\\cache", "email": "ops"}}`)), `decoy: acme: email "ops" is not an e-mail address`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Apply(listenerBase(t), doc(res(KindListener, "l", c.spec)), nil)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error is %v, want one with %q", err, c.want)
			}
		})
	}

	// The same sections without the fault apply, so that none of the rows above fails for another reason
	for _, c := range []struct{ name, spec string }{
		{"the good section", mimicListener(443, good)},
		{"an address with a host, and a front door on another port", mimicListener(8443, mimicSection(`"192.0.2.10:443"`, `["www.example.com"]`, `{"selfSigned": true}`))},
		{"eight server names", mimicListener(443, mimicSection(`":8443"`, `["a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example"]`, `{"selfSigned": true}`))},
		{"a certificate in files", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"certFile": "C:\\c.pem", "keyFile": "\\\\server\\share\\k.pem"}`))},
		{"a borrow decoy", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"mode": "borrow", "dest": "example.com:443"}`))},
	} {
		if _, err := Apply(listenerBase(t), doc(res(KindListener, "l", c.spec)), nil); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A Listener of one Node does not change the section of another, and the problems of two Listeners are both named.
func TestApplyListenerMimicNamesEachListener(t *testing.T) {
	bad := mimicSection(`"8443"`, `["www.example.com"]`, `{"selfSigned": true}`)
	_, err := Apply(listenerBase(t), doc(
		res(KindListener, "edge-a", `{"node": "a", `+mimicKSP+`, "mimic": `+bad+`}`),
		res(KindListener, "edge-b", `{"node": "b", `+mimicKSP+`, "mimic": `+bad+`}`),
	), nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("two bad sections: %v, want ErrInvalid", err)
	}
	for _, name := range []string{"edge-a", "edge-b"} {
		if want := `Listener "` + name + `": mimic: listen "8443" is not host:port`; !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name %q", err, want)
		}
	}
}

// The files and the folder that the mimic section names are opened by the node, so a UNC path among them is outside the lists
// of an admin unless its server is allowed, as the files of the certificate of a Listener are (AUD1-DT-9 #457).
func TestMimicPathsAreOutsideUnlessAllowed(t *testing.T) {
	in, err := Apply(listenerBase(t), doc(
		res(KindListener, "own", mimicListener(443, mimicSection(`":8443"`, `["www.example.com"]`, `{"certFile": "\\\\fs01\\ca\\c.pem", "keyFile": "\\\\evil.example\\ca\\k.pem"}`))),
		res(KindListener, "acme2", `{"node": "b", `+mimicKSP+`, "mimic": `+mimicSection(`":8443"`, `["www.example.com"]`,
			`{"acme": {"cacheDir": "\\\\evil.example\\cache", "caFile": "\\\\fs01\\ca\\roots.pem"}}`)+`}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := ParseUNCServers([]string{"fs01"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range in.OutsideDestinations(nil, servers) {
		got = append(got, p.Error())
	}
	want := []string{
		`Listener "acme2": mimic: decoy: acme: cacheDir: the UNC path "\\\\evil.example\\cache" names the server "evil.example", which no admin allows (listed: fs01)`,
		`Listener "own": mimic: decoy: keyFile: the UNC path "\\\\evil.example\\ca\\k.pem" names the server "evil.example", which no admin allows (listed: fs01)`,
	}
	if len(got) != len(want) {
		t.Fatalf("the problems are\n%s\nwant %d", strings.Join(got, "\n"), len(want))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("problem %d is\n%s\nwant it to start with\n%s", i, got[i], want[i])
		}
	}
	// With the server allowed, nothing is outside
	both, err := ParseUNCServers([]string{"fs01", "evil.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.OutsideDestinations(nil, both); len(got) != 0 {
		t.Errorf("with both servers allowed the problems are %v", got)
	}
}
