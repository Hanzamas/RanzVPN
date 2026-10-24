package bundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fixed is the time of the bundles of the tests.
var fixed = time.Date(2026, time.October, 23, 12, 0, 0, 500, time.UTC)

// testInfo is what the bundles of the tests are told about themselves.
var testInfo = Info{Kind: "host", Version: "1.2.3", Host: "test-host", Now: func() time.Time { return fixed }}

// given is a source of the parts it is given.
func given(name string, parts ...Part) Source {
	return Source{Name: name, Collect: func(context.Context) ([]Part, error) { return parts, nil }}
}

// unzip returns the files of the archive by name, and their names in the order of the archive.
func unzip(t *testing.T, data []byte) (map[string]string, []string) {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("the bundle is no ZIP archive: %v", err)
	}
	files := map[string]string{}
	var order []string
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
		order = append(order, f.Name)
	}
	return files, order
}

// manifestOf returns the manifest in the files of a bundle.
func manifestOf(t *testing.T, files map[string]string) Manifest {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal([]byte(files[ManifestName]), &m); err != nil {
		t.Fatalf("the manifest is not JSON: %v\n%s", err, files[ManifestName])
	}
	return m
}

// A bundle is a ZIP archive that starts with its manifest, holds every part under its name in the
// order of the names, and the manifest lists each with its size and its hash.
func TestBuildWritesTheManifestFirstAndEveryPart(t *testing.T) {
	status, err := JSON("controller/status.json", map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	m, err := Build(context.Background(), &out, testInfo, given("logs", Text("logs/b.log", "bee\n")), given("status", status), given("notes", Text("a.txt", "ay\n")))
	if err != nil {
		t.Fatal(err)
	}
	files, order := unzip(t, out.Bytes())
	if want := []string{ManifestName, "a.txt", "controller/status.json", "logs/b.log"}; !slices.Equal(order, want) {
		t.Fatalf("the archive holds %q, want %q", order, want)
	}
	got := manifestOf(t, files)
	if got.Product != "Ranz" || got.Kind != "host" || got.Host != "test-host" || got.Version != "1.2.3" || !got.Created.Equal(fixed.Truncate(time.Second)) {
		t.Errorf("the manifest is %+v", got)
	}
	if len(got.Parts) != 3 || len(m.Parts) != 3 || len(got.Problems) != 0 || !strings.Contains(got.Redaction, "No secret") {
		t.Errorf("the manifest lists %+v and the problems %q", got.Parts, got.Problems)
	}
	for _, p := range got.Parts {
		content, ok := files[p.Name]
		sum := sha256.Sum256([]byte(content))
		if !ok || p.Size != len(content) || p.SHA256 != hex.EncodeToString(sum[:]) || p.Source == "" {
			t.Errorf("the manifest says %+v of a part that holds %q", p, content)
		}
	}
}

// A source that fails is named in the manifest, with its error, and the others still go in; so is
// what a part may not be: a name that leaves the folder of the archive, a name that is taken, a part
// that is too large. The error that reaches the manifest has no secret in it either.
func TestBuildLeavesOutWhatItCannotTake(t *testing.T) {
	failing := Source{Name: "store", Collect: func(context.Context) ([]Part, error) {
		return []Part{Text("store/ok.txt", "kept\n")}, errors.New("cannot reach http://rqlite:s3cretUrlPassw0rd@127.0.0.1:4001")
	}}
	names := given("names",
		Text("../escape.txt", "x"), Text("/absolute.txt", "x"), Text("a//b.txt", "x"), Text("", "x"), Text(ManifestName, "x"),
		Text("with space.txt", "x"), Text("..", "x"), Text("good/one.txt", "1"))
	var out bytes.Buffer
	_, err := Build(context.Background(), &out, testInfo, failing, names, given("again", Text("good/one.txt", "2")),
		given("big", Part{Name: "big.bin", Data: make([]byte, MaxPartBytes+1)}))
	if err != nil {
		t.Fatal(err)
	}
	files, order := unzip(t, out.Bytes())
	if want := []string{ManifestName, "good/one.txt", "store/ok.txt"}; !slices.Equal(order, want) {
		t.Fatalf("the archive holds %q, want %q", order, want)
	}
	if files["good/one.txt"] != "1" {
		t.Errorf("the first part of a name is %q, want 1", files["good/one.txt"])
	}
	m := manifestOf(t, files)
	problems := strings.Join(m.Problems, "\n")
	for _, want := range []string{"store: cannot reach", "../escape.txt", "/absolute.txt", "a//b.txt", "with space.txt", `".."`, "in the bundle already, from names", "big.bin"} {
		if !strings.Contains(problems, want) {
			t.Errorf("the problems of the manifest do not name %q:\n%s", want, problems)
		}
	}
	if strings.Contains(problems, "s3cretUrlPassw0rd") {
		t.Errorf("a password is in the problems:\n%s", problems)
	}
}

// A bundle that is cut by its context is no bundle.
func TestBuildStopsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if _, err := Build(ctx, &out, testInfo, given("x", Text("x.txt", "x"))); !errors.Is(err, context.Canceled) {
		t.Errorf("Build with a context that ended: %v", err)
	}
}

// brokenWriter is a writer that fails.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

// A writer that fails fails the build.
func TestBuildFailsWhenItCannotWrite(t *testing.T) {
	if _, err := Build(context.Background(), brokenWriter{}, testInfo, given("x", Text("x.txt", "x"))); err == nil {
		t.Error("Build wrote to a writer that fails")
	}
}

// A JSON part is redacted by the names of its fields, the text of a part by the rules of text, and
// a JSON part that is not JSON as text.
func TestBuildRedactsEveryPart(t *testing.T) {
	var out bytes.Buffer
	_, err := Build(context.Background(), &out, testInfo, given("parts",
		Text("data.json", `{"password": "hunter2-correct-horse", "name": "alice"}`),
		Text("broken.json", `{"password": "hunter2-correct-horse"`),
		Text("notes.txt", "password=hunter2-correct-horse\n"),
	))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := unzip(t, out.Bytes())
	for name, content := range files {
		if strings.Contains(content, "hunter2-correct-horse") {
			t.Errorf("%s holds the password:\n%s", name, content)
		}
	}
	if !strings.Contains(files["data.json"], `"alice"`) {
		t.Errorf("data.json lost what is no secret:\n%s", files["data.json"])
	}
	for _, p := range manifestOf(t, files).Parts {
		if p.Redactions != 1 {
			t.Errorf("the manifest counts %d secrets replaced in %s, want 1", p.Redactions, p.Name)
		}
	}
}

// The criterion of SDN-54 (#247): a bundle holds the expected parts and no secrets. Secrets of every
// kind that the Controller handles, tokens, keys and password hashes, are planted in the sources, in
// the log, in the configuration and in the status, written the ways that they are written there,
// and none of them is in any part of the bundle, nor in its manifest.
func TestBundleHoldsNoPlantedSecret(t *testing.T) {
	secrets := []string{
		"ranz_ABCDEFGHIJKLMNOPQRSTUVWX23",
		"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
		"hunter2-correct-horse",
		"c2FsdHNhbHRzYWx0",
		"ZGVyaXZlZGtleWRlcml2ZWRrZXk",
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7planted",
		"eyJzdWIiOiJwbGFudGVkIn0",
		"s3cretUrlPassw0rd",
		"eyJ0aWVyIjoiYnVzaW5lc3Mi",
		"whsec_plantedwebhooksecret123456",
		"JBSWY3DPEHPK3PXP",
		"Sup3rS3cretApiKeyValue",
	}
	dir := t.TempDir()
	logText := strings.Join([]string{
		`2026-10-23T10:00:00.000Z INFO first start: the admin token is created token=ranz_ABCDEFGHIJKLMNOPQRSTUVWX23 file=` + filepath.Join(dir, "admin.token"),
		`2026-10-23T10:00:01.000Z WARN call refused Authorization: Bearer Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA from 192.0.2.7`,
		`level=ERROR msg="login failed" user=alice password=hunter2-correct-horse`,
		`level=INFO msg="user created" user=alice passwordHash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo`,
		`level=INFO msg="stored" derived=pbkdf2-sha256$600000$c2FsdA$ZGVyaXZlZGtleWRlcml2ZWRrZXk`,
		`level=INFO msg="rqlite" url=http://rqlite:s3cretUrlPassw0rd@127.0.0.1:4001`,
		`level=INFO msg="oidc" idToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0.c2lnbmF0dXJlcGxhbnRlZA`,
		`level=INFO msg="licence" key/eyJ0aWVyIjoiYnVzaW5lc3MiLCJub2RlcyI6NTB9.c2lnbmF0dXJlcGxhbnRlZGxpY2VuY2U`,
		`level=INFO msg="webhook" secret=whsec_plantedwebhooksecret123456 target=slack`,
		"-----BEGIN PRIVATE KEY-----",
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7planted",
		"-----END PRIVATE KEY-----",
		`level=INFO msg="done"`,
		"",
	}, "\r\n")
	if err := os.WriteFile(filepath.Join(dir, "controller.log"), []byte(logText), 0o600); err != nil {
		t.Fatal(err)
	}
	config := `{"resources": [{"kind": "User", "name": "alice", "spec": {"passwordHash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo",
		"mfa": {"totpSecret": "JBSWY3DPEHPK3PXP"}, "apiKey": "Sup3rS3cretApiKeyValue"}},
		{"kind": "Node", "name": "branch-1", "spec": {"publicKey": "cHVibGljS2V5", "privateKey": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7planted"}}]}`
	status := map[string]any{"publicKey": "cHVibGljS2V5", "token": "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23", "message": "licence key/eyJ0aWVyIjoiYnVzaW5lc3MiLCJub2RlcyI6NTB9.c2lnbmF0dXJlcGxhbnRlZGxpY2VuY2U"}
	statusPart, err := JSON("controller/status.json", status)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	m, err := Build(context.Background(), &out, testInfo,
		LogSource("controller log", "controller/logs", func() ([]string, error) { return Matching(dir, "*.log") }),
		given("intent", Text("controller/intent.json", config)),
		given("status", statusPart),
	)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := unzip(t, out.Bytes())
	for _, name := range []string{ManifestName, "controller/logs/controller.log", "controller/intent.json", "controller/status.json"} {
		if _, ok := files[name]; !ok {
			t.Errorf("the bundle has no part %s: %v", name, m.Parts)
		}
	}
	for name, content := range files {
		for _, secret := range secrets {
			if strings.Contains(content, secret) {
				t.Errorf("the part %s holds the planted secret %q:\n%s", name, secret, content)
			}
		}
	}
	for _, p := range m.Parts {
		if p.Redactions == 0 {
			t.Errorf("the manifest counts no secret replaced in %s, which held some", p.Name)
		}
	}
	// What is no secret is still there for the person who reads the bundle
	for _, c := range []struct{ part, keep string }{
		{"controller/logs/controller.log", "user=alice"},
		{"controller/intent.json", "branch-1"},
		{"controller/status.json", "cHVibGljS2V5"},
	} {
		if !strings.Contains(files[c.part], c.keep) {
			t.Errorf("the part %s lost %q:\n%s", c.part, c.keep, files[c.part])
		}
	}
}

// JSON, Text and JSONSource give parts under the names they are told.
func TestJSONAndText(t *testing.T) {
	p, err := JSON("x.json", map[string]int{"a": 1})
	if err != nil || p.Name != "x.json" || string(p.Data) != "{\n  \"a\": 1\n}\n" {
		t.Errorf("JSON gave %+v, %v", p, err)
	}
	if _, err := JSON("x.json", func() {}); err == nil {
		t.Error("JSON took a value that has no JSON form")
	}
	if p := Text("t.txt", "hi"); p.Name != "t.txt" || string(p.Data) != "hi" {
		t.Errorf("Text gave %+v", p)
	}
	src := JSONSource("thing", "thing.json", func(context.Context) (any, error) { return []int{1, 2}, nil })
	parts, err := src.Collect(context.Background())
	if err != nil || len(parts) != 1 || parts[0].Name != "thing.json" || src.Name != "thing" {
		t.Errorf("JSONSource gave %+v, %v", parts, err)
	}
	failing := JSONSource("thing", "thing.json", func(context.Context) (any, error) { return nil, errors.New("no") })
	if parts, err := failing.Collect(context.Background()); err == nil || parts != nil {
		t.Errorf("a failing JSONSource gave %+v, %v", parts, err)
	}
	unmarshalable := JSONSource("thing", "thing.json", func(context.Context) (any, error) { return make(chan int), nil })
	if _, err := unmarshalable.Collect(context.Background()); err == nil {
		t.Error("a JSONSource took a value that has no JSON form")
	}
}

// The names of the parts: what may be one, and what a file name becomes as the last element.
func TestNames(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"manifest.json", true}, {"logs/controller.log", true}, {"node/logs/node_20261023~01.log", true}, {"a-b/c.d", true},
		{"", false}, {".", false}, {"..", false}, {"../a", false}, {"/a", false}, {"a/", false}, {"a//b", false}, {"a/../b", false},
		{"a b", false}, {`a\b`, false}, {"é.txt", false}, {strings.Repeat("a", maxName+1), false},
	} {
		if got := validName(c.name); got != c.want {
			t.Errorf("validName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"controller.log", "controller.log"},
		{`C:\ProgramData\Ranz\node_log\node.log`, "node.log"},
		{"/var/lib/ranz/x y.log", "x_y.log"},
		{"a/b/c~01.log", "c~01.log"},
	} {
		if got := FileName(c.in); got != c.want {
			t.Errorf("FileName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The name for the file of a bundle holds its kind, its host and its time in UTC, and no character
// that a file name may not have.
func TestArchiveName(t *testing.T) {
	for _, c := range []struct {
		m    Manifest
		want string
	}{
		{Manifest{Kind: "controller", Host: "vpn 1", Created: fixed}, "ranz-controller-vpn_1-20261023T120000Z.zip"},
		{Manifest{Created: fixed}, "ranz-bundle-host-20261023T120000Z.zip"},
		{Manifest{Kind: "host", Host: "NODE-02.corp", Created: fixed.In(time.FixedZone("WIB", 7*3600))}, "ranz-host-NODE-02.corp-20261023T120000Z.zip"},
	} {
		if got := c.m.ArchiveName(); got != c.want {
			t.Errorf("ArchiveName of %+v is %q, want %q", c.m, got, c.want)
		}
	}
}

// What a bundle says of its host holds no environment and no argument, and its services source
// gives a part on Windows only.
func TestSystemInfoAndServices(t *testing.T) {
	t.Setenv("RANZ_TOKEN", "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23")
	s := SystemInfo(fixed)
	if s.OS != runtime.GOOS || s.Arch != runtime.GOARCH || s.CPUs < 1 || s.GoVersion == "" || s.ProcessID != os.Getpid() || !s.Time.Equal(fixed) {
		t.Errorf("SystemInfo is %+v", s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23") {
		t.Errorf("the system information holds the environment: %s", b)
	}
	parts, err := SystemSource().Collect(context.Background())
	if err != nil || len(parts) != 1 || parts[0].Name != "system.json" {
		t.Errorf("SystemSource gave %+v, %v", parts, err)
	}
	parts, err = ServicesSource().Collect(context.Background())
	if runtime.GOOS != "windows" {
		if err != nil || len(parts) != 0 {
			t.Errorf("ServicesSource gave %+v, %v on a host with no services", parts, err)
		}
		return
	}
	if err != nil {
		t.Skipf("the service control manager is not open to this process: %v", err)
	}
	if len(parts) != 1 || parts[0].Name != "services.json" {
		t.Fatalf("ServicesSource gave %+v", parts)
	}
	var list []Service
	if err := json.Unmarshal(parts[0].Data, &list); err != nil || len(list) != 2 || list[0].Name != "ranzvpnserver" || list[1].Name != "ranz-controller" {
		t.Errorf("the services are %+v, %v", list, err)
	}
}
