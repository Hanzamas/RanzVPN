package mimic

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The mimic section of a Listener against the settings of the sidecar (SDN-94 #423, first criterion). The Controller checks the
// section with the rules of the sidecar, so that a bad value is refused when the intent is applied, with a message that says
// which, and is never found first on the Node. The cases here are the cases that config_test.go uses for the settings of the
// server role (TestParseServerRefuses, TestBorrowDecoyTakesADestOnly), put to both in one table: each is a section, as an
// operator writes it, and what the Controller says of it when the Listener is applied, and what the sidecar says of the settings
// that the Node writes from it (parseServer). The sidecar and the Controller may differ in one direction only: the Controller is
// stricter where the Node and the control protocol need it (an IP address and a port of its own for the sidecar, at most 8 server
// names, absolute paths), so a section that the sidecar refuses is refused by the Controller as well.
//
// The cases are copies, by name, of the cases of config_test.go, which keeps them in lists of its own (serverRefusals, borrowExtras and
// borrowBad). TestEverySidecarCaseIsPutToTheController fails when a case of those lists is neither a case of sectionCases nor in
// noSection with the reason that a section cannot hold it, so a case that is added to the sidecar's tests is put to the Controller
// too (AUD1-DT-20, #522).

// noSettings is the answer of the sidecar for a section that holds nothing that a Node could write for it: a setting that the
// section has no place for.
const noSettings = "-"

type sectionCase struct {
	name string
	// section is the mimic section of the Listener, as JSON.
	section string
	// controller is what the Controller says when it applies the Listener: empty for none, else a part of its refusal.
	controller string
	// sidecar is what the sidecar says of the settings that the Node writes from the section: empty when it takes them, a part
	// of its error when it refuses them, or noSettings.
	sidecar string
}

// A good section, and the pieces that the cases change.
const (
	goodAddress = `"192.0.2.10:8443"`
	goodNames   = `["www.example.com"]`
	goodDecoy   = `{"selfSigned": true}`
)

// sectionJSON returns the mimic section with the address listen, the server names names and the decoy decoy, each as JSON.
func sectionJSON(listen, names, decoy string) string {
	return `{"listen": ` + listen + `, "serverNames": ` + names + `, "decoy": ` + decoy + `}`
}

// namesJSON returns a list of n server names as JSON.
func namesJSON(n int) string {
	list := make([]string, n)
	for i := range list {
		list[i] = fmt.Sprintf(`"h%d.example"`, i)
	}
	return "[" + strings.Join(list, ", ") + "]"
}

func sectionCases() []sectionCase {
	borrow := func(extra string) string {
		return sectionJSON(goodAddress, goodNames, `{"mode": "borrow", "dest": "example.com:443"`+extra+`}`)
	}
	return []sectionCase{
		// What both take
		{"an own decoy with a self-signed certificate", sectionJSON(goodAddress, goodNames, goodDecoy), "", ""},
		{"an own decoy with ACME", sectionJSON(goodAddress, goodNames, `{"acme": {"cacheDir": "C:\\cache", "directory": "https://ca.example/dir"}}`), "", ""},
		{"an own decoy with its certificate in files", sectionJSON(goodAddress, goodNames, `{"certFile": "C:\\c.pem", "keyFile": "C:\\k.pem"}`), "", ""},
		{"a borrow decoy", borrow(""), "", ""},
		{"a listen without a host", sectionJSON(`":8443"`, goodNames, goodDecoy), "", ""},
		{"server names in capitals", sectionJSON(goodAddress, `["WWW.Example.COM", "cdn.example.com"]`, goodDecoy), "", ""},
		{"eight server names", sectionJSON(goodAddress, namesJSON(8), goodDecoy), "", ""},
		{"a clock tolerance", `{"listen": ` + goodAddress + `, "serverNames": ` + goodNames + `, "maxTimeDiffMs": 5000, "decoy": ` + goodDecoy + `}`, "", ""},

		// The cases of TestParseServerRefuses, which both refuse
		{"a listen without a port", sectionJSON(`"443"`, goodNames, goodDecoy), "is not host:port", "not a host and a port"},
		{"a port out of range", sectionJSON(`":70000"`, goodNames, goodDecoy), `has the port "70000"`, "no valid port"},
		{"a server name that is no name", sectionJSON(goodAddress, `["bad_name"]`, goodDecoy), "is not DNS labels", "not a DNS name"},
		{"a server name twice", sectionJSON(goodAddress, `["www.example.com", "WWW.example.com"]`, goodDecoy), "is listed twice", "twice"},
		{"too many server names", sectionJSON(goodAddress, namesJSON(33), goodDecoy), "holds 33 names, not 1 to 8", "at most"},
		{"no server name", sectionJSON(goodAddress, `[]`, goodDecoy), "holds 0 names, not 1 to 8", "not a DNS name"},
		{"a negative time difference", `{"listen": ` + goodAddress + `, "serverNames": ` + goodNames + `, "maxTimeDiffMs": -1, "decoy": ` + goodDecoy + `}`, "maxTimeDiffMs -1 is not from 1 to", "max_time_diff_ms"},
		{"a time difference of days", `{"listen": ` + goodAddress + `, "serverNames": ` + goodNames + `, "maxTimeDiffMs": 172800000, "decoy": ` + goodDecoy + `}`, "maxTimeDiffMs 172800000 is not from 1 to", "max_time_diff_ms"},
		{"an unknown decoy mode", sectionJSON(goodAddress, goodNames, `{"mode": "mirror"}`), `mode "mirror" is neither own nor borrow`, "neither"},
		{"an own decoy with a dest", sectionJSON(goodAddress, goodNames, `{"selfSigned": true, "dest": "example.com:443"}`), "the own decoy takes no dest", "takes no dest"},
		{"no certificate source", sectionJSON(goodAddress, goodNames, `{}`), "exactly one certificate source", "one certificate source"},
		{"two certificate sources", sectionJSON(goodAddress, goodNames, `{"selfSigned": true, "acme": {"cacheDir": "C:\\cache"}}`), "exactly one certificate source", "one certificate source"},
		{"a certificate without its key", sectionJSON(goodAddress, goodNames, `{"certFile": "C:\\c.pem"}`), "certFile and keyFile go together", "go together"},
		{"an ACME decoy without a cache", sectionJSON(goodAddress, goodNames, `{"acme": {}}`), "acme needs a cacheDir", "cache_dir"},
		{"an ACME directory that is no https URL", sectionJSON(goodAddress, goodNames, `{"acme": {"cacheDir": "C:\\cache", "directory": "http://ca.example/dir"}}`), "https URL", "https URL"},

		// The cases of TestBorrowDecoyTakesADestOnly: the borrow decoy takes a dest and nothing else
		{"a borrow decoy with a certificate file", borrow(`, "certFile": "C:\\c.pem"`), "the borrow decoy takes a dest only", "takes a dest only"},
		{"a borrow decoy with a key file", borrow(`, "keyFile": "C:\\k.pem"`), "the borrow decoy takes a dest only", "takes a dest only"},
		{"a borrow decoy with a self-signed certificate", borrow(`, "selfSigned": true`), "the borrow decoy takes a dest only", "takes a dest only"},
		{"a borrow decoy with ACME", borrow(`, "acme": {"cacheDir": "C:\\cache"}`), "the borrow decoy takes a dest only", "takes a dest only"},
		{"a borrow decoy with no dest", sectionJSON(goodAddress, goodNames, `{"mode": "borrow"}`), "the borrow decoy needs a dest", "not a host and a port"},
		{"a borrow decoy with a dest with no port", sectionJSON(goodAddress, goodNames, `{"mode": "borrow", "dest": "example.com"}`), "has no port", "not a host and a port"},
		{"a borrow decoy with a dest on port 0", sectionJSON(goodAddress, goodNames, `{"mode": "borrow", "dest": "example.com:0"}`), "not a number from 1 to 65535", "no valid port"},
		{"a borrow decoy with no server names", sectionJSON(goodAddress, `[]`, `{"mode": "borrow", "dest": "example.com:443"}`), "holds 0 names, not 1 to 8", "needs server_names"},

		// Where the Controller is stricter, because the Node and the control protocol need it: the sidecar takes these
		{"a listen on port 0", sectionJSON(`":0"`, goodNames, goodDecoy), `has the port "0"`, ""},
		{"a listen with a host name", sectionJSON(`"example.com:8443"`, goodNames, goodDecoy), "is not an IP address without a zone", ""},
		{"the port of the front door", sectionJSON(`":443"`, goodNames, goodDecoy), "the port of the front door", ""},
		{"nine server names", sectionJSON(goodAddress, namesJSON(9), goodDecoy), "holds 9 names, not 1 to 8", ""},
		{"a certificate file that is not absolute", sectionJSON(goodAddress, goodNames, `{"certFile": "cert.pem", "keyFile": "key.pem"}`), "is not an absolute path of the node", ""},
		{"a cache that is not absolute", sectionJSON(goodAddress, goodNames, `{"acme": {"cacheDir": "cache"}}`), "is not an absolute path of the node", ""},

		// A key and a short id are the Node's and the Controller's, never the operator's: the section has no place for them
		{"a private key in the section", `{"listen": ` + goodAddress + `, "serverNames": ` + goodNames + `, "decoy": ` + goodDecoy + `, "private_key": "` + strings.Repeat("11", 32) + `"}`,
			"the section holds no key", noSettings},
		{"a short id in the section", `{"listen": ` + goodAddress + `, "serverNames": ` + goodNames + `, "decoy": ` + goodDecoy + `, "short_ids": ["0102"]}`,
			"the section holds no short id", noSettings},
	}
}

// applyListener applies a Listener of the Node hub with the mimic section section to an empty intent.
func applyListener(section string) (intent.Intent, error) {
	return intent.Apply(intent.New(), intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
		{Kind: intent.KindNode, Name: "hub", Spec: json.RawMessage(`{"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"]}`)},
		{Kind: intent.KindListener, Name: "edge-hub", Spec: json.RawMessage(`{"node": "hub", "certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}, "mimic": ` + section + `}`)},
	}}, nil)
}

// settingsOf returns the settings that a Node writes for the sidecar from the section m of the intent: the fields of the section,
// with the private key that the Node made and the short id that the Controller made.
func settingsOf(m *intent.ListenerMimic) *ServerSettings {
	d := m.Decoy
	s := &ServerSettings{Listen: m.Listen, PrivateKey: strings.Repeat("11", keySize), ShortIDs: []string{"0102030405060708"}, ServerNames: m.ServerNames,
		MaxTimeDiffMs: m.MaxTimeDiffMs, Decoy: Decoy{Mode: d.Mode, Dest: d.Dest, CertFile: d.CertFile, KeyFile: d.KeyFile, SelfSigned: d.SelfSigned}}
	if a := d.ACME; a != nil {
		s.Decoy.ACME = &ACME{Directory: a.Directory, Email: a.Email, CacheDir: a.CacheDir, CAFile: a.CAFile}
	}
	return s
}

// settingsOfServer returns the settings that a Node writes for the sidecar from the settings of the server that the control
// protocol carries, the way that the Node writes them (CORE-P2-7): the fields of the message, with its short id as hex digits and
// the private key that the Node made.
func settingsOfServer(m *controlpb.MimicServer) *ServerSettings {
	d := m.GetDecoy()
	s := &ServerSettings{Listen: m.GetListen(), PrivateKey: strings.Repeat("11", keySize), ShortIDs: []string{hex.EncodeToString(m.GetShortId())}, ServerNames: m.GetServerNames(),
		MaxTimeDiffMs: int(m.GetMaxTimeDiffMs()), Decoy: Decoy{Mode: DecoyOwn, Dest: d.GetDest(), CertFile: d.GetCertFile(), KeyFile: d.GetKeyFile(), SelfSigned: d.GetSelfSigned()}}
	if d.GetMode() == controlpb.MimicDecoyMode_MIMIC_DECOY_MODE_BORROW {
		s.Decoy.Mode = DecoyBorrow
	}
	if a := d.GetAcme(); a != nil {
		s.Decoy.ACME = &ACME{Directory: a.GetDirectory(), Email: a.GetEmail(), CacheDir: a.GetCacheDir(), CAFile: a.GetCaFile()}
	}
	return s
}

// Each case is put to the Controller and to the sidecar. The Controller refuses what the table says with a message that says
// which setting, the sidecar takes or refuses the settings that the Node writes as the table says, a section that the sidecar
// refuses is refused by the Controller as well, and a section that the Controller takes becomes, through the control protocol,
// settings that the sidecar takes.
func TestSectionRulesAreTheRulesOfTheSidecar(t *testing.T) {
	for _, c := range sectionCases() {
		t.Run(c.name, func(t *testing.T) {
			in, ctrlErr := applyListener(c.section)
			switch {
			case c.controller == "" && ctrlErr != nil:
				t.Fatalf("the Controller refuses the section: %v", ctrlErr)
			case c.controller != "" && (!errors.Is(ctrlErr, intent.ErrInvalid) || !strings.Contains(ctrlErr.Error(), c.controller)):
				t.Errorf("the Controller says %v, want a refusal with %q", ctrlErr, c.controller)
			}

			// The settings that a Node writes from the section as the operator wrote it
			var m intent.ListenerMimic
			if err := json.Unmarshal([]byte(c.section), &m); err != nil {
				if c.sidecar != noSettings {
					t.Fatalf("the section does not read as a mimic section: %v", err)
				}
				return
			}
			if c.sidecar == noSettings {
				t.Fatal("the section reads as a mimic section, but the table says that it holds nothing that the Node could write")
			}
			_, sidecarErr := parseServer(settingsOf(&m))
			switch {
			case c.sidecar == "" && sidecarErr != nil:
				t.Errorf("the sidecar refuses the settings: %v", sidecarErr)
			case c.sidecar != "" && (sidecarErr == nil || !strings.Contains(sidecarErr.Error(), c.sidecar)):
				t.Errorf("the sidecar says %v, want a refusal with %q", sidecarErr, c.sidecar)
			}
			if sidecarErr != nil && ctrlErr == nil {
				t.Errorf("the sidecar refuses a section that the Controller takes, so a bad value would be found first on the Node: %v", sidecarErr)
			}

			// What the Controller takes goes through the control protocol to the Node, which writes it for the sidecar
			if ctrlErr != nil {
				return
			}
			states, err := desired.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			if err := desired.WithMimic(in, states, desired.Mimic{ShortIDs: map[string][]byte{"hub": []byte("ABCDEFGH")}}); err != nil {
				t.Fatal(err)
			}
			server := states["hub"][desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: "hub"}].GetNode().GetMimic().GetServer()
			if server == nil {
				t.Fatal("the state of hub has no server settings")
			}
			if _, err := parseServer(settingsOfServer(server)); err != nil {
				t.Errorf("the sidecar refuses the settings that the control protocol carries for a section that the Controller took: %v", err)
			}
		})
	}
}

// noSection are the cases of the sidecar's tests that a section cannot hold, each group with its reason. The Node writes some of the
// settings that they change, or the Controller makes them (the private key, the short ids), and no field of the section sets the
// others (the page, the name and the address of the decoy, the padding). Every other case of the sidecar's tests is a case of
// sectionCases, of the same name.
var noSection = []struct {
	why   string
	cases []string
}{
	{"the private key is the Node's, and the section has no place for it", []string{
		"a short private key", "a private key that is no hex",
	}},
	{"the short ids are the Controller's, and the section has no place for them", []string{
		"no short id", "too many short ids", "a short id that is no hex", "a short id of more than 8 bytes", "a short id twice",
	}},
	{"the section has no place for the name or the address of the decoy: its name is the first server name, and it listens on the loopback address that the sidecar picks", []string{
		"a decoy name that is no name", "a decoy name that no client reaches", "a decoy on a public address", "a decoy on a host name",
		"a decoy listen without a host", "a borrow decoy with a listen address", "a borrow decoy with a name",
	}},
	{"the section has no place for the page of the decoy", []string{
		"a decoy page twice", "a page file that is missing", "a page that is too large", "a borrow decoy with a page", "a borrow decoy with a page file",
	}},
	{"the section has no place for the padding", []string{
		"a padding profile that does not exist",
	}},
}

// sidecarCases returns the names of the cases that the sidecar's tests put to parseServer for the settings of the server role: the
// refusals of TestParseServerRefuses (serverRefusals), and those of TestBorrowDecoyTakesADestOnly (borrowExtras and borrowBad), which
// are cases of a borrow decoy and take its name.
func sidecarCases(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, c := range serverRefusals(t.TempDir()) {
		names = append(names, c.name)
	}
	for _, e := range borrowExtras {
		names = append(names, "a borrow decoy with "+e.name)
	}
	for _, b := range borrowBad {
		names = append(names, "a borrow decoy with "+b.name)
	}
	return names
}

// sidecarCaseProblems returns what is wrong when the names of the cases of the sidecar's tests, sidecar, are held against the names of
// the cases of sectionCases, inTable, and the cases that a section cannot hold, excused, by name with their reasons: a case of the
// sidecar's tests that is neither a case of sectionCases nor excused, a case that is both, and an excused case that the sidecar's tests
// do not have. It returns nothing when they agree.
func sidecarCaseProblems(sidecar []string, inTable map[string]bool, excused map[string]string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, name := range sidecar {
		seen[name] = true
		_, isExcused := excused[name]
		switch {
		case !inTable[name] && !isExcused:
			problems = append(problems, fmt.Sprintf("the case %q of the sidecar's tests is not a case of sectionCases: add it there, to put it to the Controller as well, or say in noSection why a section cannot hold it", name))
		case inTable[name] && isExcused:
			problems = append(problems, fmt.Sprintf("the case %q is a case of sectionCases and is in noSection: it belongs to one of the two", name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(excused)) {
		if !seen[name] {
			problems = append(problems, fmt.Sprintf("noSection names the case %q, which the sidecar's tests do not have", name))
		}
	}
	return problems
}

// TestEverySidecarCaseIsPutToTheController: the cases of the section are copies of the cases of the sidecar's tests, so a case that
// is added to those tests would not be put to the Controller by this file. The test fails when a case of the sidecar's tests is
// neither a case of sectionCases, of the same name, nor in noSection with the reason that a section cannot hold it, and when noSection
// names a case that the sidecar's tests do not have, or one that sectionCases has.
func TestEverySidecarCaseIsPutToTheController(t *testing.T) {
	inTable := map[string]bool{}
	for _, c := range sectionCases() {
		inTable[c.name] = true
	}
	excused := map[string]string{}
	for _, g := range noSection {
		for _, name := range g.cases {
			excused[name] = g.why
		}
	}
	for _, problem := range sidecarCaseProblems(sidecarCases(t), inTable, excused) {
		t.Error(problem)
	}
}

// TestTheGuardOfTheSidecarCasesFindsEachDifference holds the guard to its word: it is shown each way in which the sidecar's tests and
// the section tests can differ, and says each of them, and it says nothing of lists that agree. A guard that cannot fail would let a
// case of the sidecar's tests stay out of the Controller's.
func TestTheGuardOfTheSidecarCasesFindsEachDifference(t *testing.T) {
	inTable := map[string]bool{"a case of both": true, "a case in both lists": true}
	excused := map[string]string{"a case that a section cannot hold": "the reason", "a case in both lists": "the reason", "a case that is gone": "the reason"}
	sidecar := []string{"a case of both", "a case that a section cannot hold", "a case in both lists", "a case that is new"}
	got := sidecarCaseProblems(sidecar, inTable, excused)
	want := []string{`"a case in both lists"`, `"a case that is new"`, `"a case that is gone"`}
	if len(got) != len(want) {
		t.Fatalf("the guard says %q, want one problem for each of %q", got, want)
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("the problem %d is %q, want one about %s", i, got[i], w)
		}
	}

	agreeing := map[string]string{"a case that a section cannot hold": "the reason"}
	if got := sidecarCaseProblems([]string{"a case of both", "a case that a section cannot hold"}, inTable, agreeing); len(got) != 0 {
		t.Errorf("the guard says %q of lists that agree", got)
	}
}
