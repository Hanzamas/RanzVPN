package mimic

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
		{"a borrow decoy without a dest", sectionJSON(goodAddress, goodNames, `{"mode": "borrow"}`), "the borrow decoy needs a dest", "not a host and a port"},
		{"a borrow decoy with a dest with no port", sectionJSON(goodAddress, goodNames, `{"mode": "borrow", "dest": "example.com"}`), "has no port", "not a host and a port"},
		{"a borrow decoy with a dest on port 0", sectionJSON(goodAddress, goodNames, `{"mode": "borrow", "dest": "example.com:0"}`), "not a number from 1 to 65535", "no valid port"},
		{"a borrow decoy without server names", sectionJSON(goodAddress, `[]`, `{"mode": "borrow", "dest": "example.com:443"}`), "holds 0 names, not 1 to 8", "needs server_names"},

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
