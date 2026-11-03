package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/forkimport"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// sampleConfig is the sample Config file of the import (SDN-27, #203), whose Virtual Hubs are LAB and OFFICE.
const sampleConfig = "../../../tests/golden/configimport/sample.config"

// importConfig runs ranz import-config with the arguments args and the standard input stdin, and returns its exit code, its
// standard output and its standard error.
func importConfig(stdin string, args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = runImportConfig(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

// importedDocument runs ranz import-config with args, which must succeed, and returns the document that it wrote and its
// report.
func importedDocument(t *testing.T, args ...string) (intent.Document, string) {
	t.Helper()
	code, out, report := importConfig("", args...)
	if code != 0 {
		t.Fatalf("ranz import-config %v: exit code %d: %s", args, code, report)
	}
	doc, err := intent.ParseDocument([]byte(out))
	if err != nil {
		t.Fatalf("ranz import-config %v wrote no intent document: %v\n%s", args, err, out)
	}
	return doc, report
}

// importedNames returns the names of the resources of the kind that doc holds, in its order.
func importedNames(doc intent.Document, kind string) []string {
	var names []string
	for _, r := range doc.Resources {
		if r.Kind == kind {
			names = append(names, r.Name)
		}
	}
	return names
}

// sameResources reports whether the documents a and b hold the same resources in the same order: the same kinds, names
// and specs, whichever way JSON or YAML spells a spec.
func sameResources(t *testing.T, a, b intent.Document) bool {
	t.Helper()
	if len(a.Resources) != len(b.Resources) {
		return false
	}
	for i := range a.Resources {
		x, y := a.Resources[i], b.Resources[i]
		if x.Kind != y.Kind || x.Name != y.Name {
			return false
		}
		var vx, vy any
		if err := json.Unmarshal(x.Spec, &vx); err != nil {
			t.Fatalf("%s %s: %v", x.Kind, x.Name, err)
		}
		if err := json.Unmarshal(y.Spec, &vy); err != nil {
			t.Fatalf("%s %s: %v", y.Kind, y.Name, err)
		}
		if !reflect.DeepEqual(vx, vy) {
			return false
		}
	}
	return true
}

// ranz import-config writes the intent document that the Virtual Hubs of a Config file make, and ranz apply -f applies it to
// a controller: the first criterion of #203, through the two commands that an operator types. The document is the one that
// the import makes, and it is alone on standard output, so that it can be piped to ranz apply; what the import left out is
// on standard error.
func TestImportConfigMakesADocumentThatApplies(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}

	code, doc, report := importConfig("", "-pool", "LAB=10.0.0.0/24", "-pool", "office=10.1.0.0/24", sampleConfig)
	if code != 0 {
		t.Fatalf("ranz import-config: exit code %d: %s", code, report)
	}
	for _, want := range []string{
		`Virtual Hub "LAB": VRF lab and Network lab, 5 Groups, 8 Users, 15 Policies of 16 access list entries`,
		`Virtual Hub "OFFICE": VRF office and Network office, 0 Groups, 3 Users, 1 Policies of 0 access list entries`,
		"entry 5 left out: it lets through what it matches by source MAC addresses",
		"Not imported: the password of a user",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report is\n%s\nwant it to say %q", report, want)
		}
	}
	if strings.Contains(report, "no IPv4 pool") {
		t.Errorf("the report is\n%s\nwant no note about a missing pool: both Virtual Hubs got one", report)
	}
	if strings.Contains(doc, "Virtual Hub") || strings.Contains(doc, "Not imported") {
		t.Errorf("standard output is\n%s\nwant the document alone", doc)
	}
	parsed, err := intent.ParseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("standard output is no intent document: %v\n%s", err, doc)
	}
	b, err := os.ReadFile(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	root, err := forkimport.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	want, err := forkimport.Import(root, forkimport.Options{Pools: map[string]string{"LAB": "10.0.0.0/24", "office": "10.1.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if !sameResources(t, parsed, want.Document) {
		t.Errorf("the document that ranz import-config wrote is not the one that the import makes:\n%s", doc)
	}

	file := filepath.Join(t.TempDir(), "hubs.yaml")
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := do(ctx, cli, []string{"apply", "-f", file}, &out); err != nil {
		t.Fatalf("ranz apply -f the document of ranz import-config: %v", err)
	}
	rs, err := cli.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range rs {
		have[r.Kind+"/"+r.Name] = true
	}
	for _, r := range parsed.Resources {
		if !have[r.Kind+"/"+r.Name] {
			t.Errorf("the intent has no %s %s after ranz apply -f", r.Kind, r.Name)
		}
	}
	if got, want := importedNames(parsed, intent.KindVRF), []string{"lab", "office"}; !slices.Equal(got, want) {
		t.Errorf("the VRFs of the document are %v, want %v", got, want)
	}
}

// The document is YAML unless -o json says otherwise, and the two are one document.
func TestImportConfigWritesYAMLOrJSON(t *testing.T) {
	code, yamlDoc, report := importConfig("", "-o", "yaml", sampleConfig)
	if code != 0 {
		t.Fatalf("ranz import-config -o yaml: exit code %d: %s", code, report)
	}
	code, jsonDoc, report := importConfig("", "-o", "json", sampleConfig)
	if code != 0 {
		t.Fatalf("ranz import-config -o json: exit code %d: %s", code, report)
	}
	if _, plain, _ := importConfig("", sampleConfig); plain != yamlDoc {
		t.Errorf("ranz import-config without -o wrote\n%s\nwant the YAML of -o yaml", plain)
	}
	if strings.HasPrefix(strings.TrimSpace(yamlDoc), "{") {
		t.Errorf("-o yaml wrote JSON:\n%s", yamlDoc)
	}
	if !strings.HasPrefix(strings.TrimSpace(jsonDoc), "{") {
		t.Errorf("-o json wrote\n%s\nwant JSON", jsonDoc)
	}
	fromYAML, err := intent.ParseDocument([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := intent.ParseDocument([]byte(jsonDoc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fromYAML.Resources) == 0 || !sameResources(t, fromYAML, fromJSON) {
		t.Errorf("the YAML and the JSON of ranz import-config are not one document: %d and %d resources", len(fromYAML.Resources), len(fromJSON.Resources))
	}
}

// -hub takes the Virtual Hubs that it names, -mode gives the Networks their mode and -pool the Network of a Virtual Hub its
// IPv4 pool, each name without regard to case.
func TestImportConfigTakesTheHubsTheModeAndThePoolsThatItIsGiven(t *testing.T) {
	office, report := importedDocument(t, "-hub", "office", sampleConfig)
	if got := importedNames(office, intent.KindVRF); !slices.Equal(got, []string{"office"}) {
		t.Errorf("-hub office made the VRFs %v", got)
	}
	if strings.Contains(report, "LAB") {
		t.Errorf("-hub office reported on a Virtual Hub that it did not take:\n%s", report)
	}
	both, _ := importedDocument(t, "-hub", "lab", "-hub", "OFFICE", sampleConfig)
	if got := importedNames(both, intent.KindVRF); !slices.Equal(got, []string{"lab", "office"}) {
		t.Errorf("-hub lab -hub OFFICE made the VRFs %v", got)
	}

	l2, _ := importedDocument(t, "-hub", "lab", "-mode", "l2", "-pool", "Lab=10.0.0.0/24", sampleConfig)
	var lab intent.Network
	found := false
	for _, r := range l2.Resources {
		if r.Kind == intent.KindNetwork && r.Name == "lab" {
			found = true
			if err := json.Unmarshal(r.Spec, &lab); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || lab.VRF != "lab" || lab.Mode != intent.ModeL2 || lab.IPv4Pool != "10.0.0.0/24" {
		t.Errorf("-mode l2 -pool Lab=10.0.0.0/24 made the Network %+v (made: %v), want an L2 Network of VRF lab with the pool", lab, found)
	}
}

// Two imports of one file, each taking one Virtual Hub, make the resources that one import of both makes, so a hub that
// moves later never makes a name that an earlier import made.
func TestImportConfigOfOneHubAtATimeMakesTheNamesOfBoth(t *testing.T) {
	both, _ := importedDocument(t, sampleConfig)
	var apart []intent.Resource
	for _, hub := range []string{"LAB", "OFFICE"} {
		doc, _ := importedDocument(t, "-hub", hub, sampleConfig)
		apart = append(apart, doc.Resources...)
	}
	if !sameResources(t, intent.Document{Resources: apart}, both) {
		t.Errorf("the imports of LAB and of OFFICE make %d resources, which are not the %d that one import of both makes", len(apart), len(both.Resources))
	}
}

// - is the standard input, and a Config file read from it gives the document that the same file gives.
func TestImportConfigReadsStandardInput(t *testing.T) {
	b, err := os.ReadFile(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	code, fromStdin, report := importConfig(string(b), "-")
	if code != 0 {
		t.Fatalf("ranz import-config -: exit code %d: %s", code, report)
	}
	if _, fromFile, _ := importConfig("", sampleConfig); fromStdin != fromFile {
		t.Errorf("the Config file on standard input gave\n%s\nand the same file gave\n%s", fromStdin, fromFile)
	}
}

// The command takes the arguments it can and refuses the others with the usage (exit code 2) or with the reason (exit code
// 1), and a refusal writes no document.
func TestImportConfigRefusesWhatItCannotTake(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.config")
	for _, c := range []struct {
		name  string
		stdin string
		args  []string
		code  int
		err   string
	}{
		{"no file", "", nil, 2, "usage: ranz import-config"},
		{"two files", "", []string{sampleConfig, sampleConfig}, 2, "usage: ranz import-config"},
		{"a form that is none", "", []string{"-o", "xml", sampleConfig}, 2, "usage: ranz import-config"},
		{"a flag that is none", "", []string{"-no-such-flag", sampleConfig}, 2, "flag provided but not defined"},
		{"a pool without a prefix", "", []string{"-pool", "LAB", sampleConfig}, 2, `-pool "LAB" is not NAME=PREFIX`},
		{"a pool without a name", "", []string{"-pool", "=10.0.0.0/24", sampleConfig}, 2, `-pool "=10.0.0.0/24" is not NAME=PREFIX`},
		{"a pool with an empty prefix", "", []string{"-pool", "LAB=", sampleConfig}, 2, `-pool "LAB=" is not NAME=PREFIX`},
		{"two pools for one hub", "", []string{"-pool", "LAB=10.0.0.0/24", "-pool", "lab=10.1.0.0/24", sampleConfig}, 2, `gives Virtual Hub "lab" a pool twice`},
		{"a hub that the file has not", "", []string{"-hub", "nope", sampleConfig}, 1, `no Virtual Hub "nope"`},
		{"a mode that is none", "", []string{"-mode", "l4", sampleConfig}, 1, "the mode of a Network"},
		{"a pool that is no prefix", "", []string{"-pool", "LAB=ten", sampleConfig}, 1, "the pool of Virtual Hub"},
		{"a pool of a hub that is not taken", "", []string{"-hub", "lab", "-pool", "OFFICE=10.1.0.0/24", sampleConfig}, 1, "does not take that Virtual Hub"},
		{"a file that is not there", "", []string{missing}, 1, "missing.config"},
		{"a file that is no Config file", "hello", []string{"-"}, 1, "no folder root"},
		{"a Config file of the binary format", "SEVPN_DB", []string{"-"}, 1, "binary format"},
		{"a Config file without a Virtual Hub", "declare root\n{\ndeclare ServerConfiguration\n{\n}\n}\n", []string{"-"}, 1, "no Virtual Hub"},
	} {
		code, out, errOut := importConfig(c.stdin, c.args...)
		if code != c.code || !strings.Contains(errOut, c.err) || out != "" {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q; want %d, no stdout and %q", c.name, code, out, errOut, c.code, c.err)
		}
	}
	if code, out, errOut := importConfig("", "-h"); code != 0 || out != "" || !strings.Contains(errOut, "usage: ranz import-config") {
		t.Errorf("ranz import-config -h: exit code %d, stdout %q, stderr %q, want 0, no stdout and the usage", code, out, errOut)
	}
}

// ranz import-config is a subcommand of the one executable.
func TestImportConfigIsASubcommand(t *testing.T) {
	if subcommands["import-config"] == nil {
		t.Error("ranz has no subcommand import-config")
	}
}
