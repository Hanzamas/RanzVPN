package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// The credential file is the one that rqlited reads, holds a random password, is readable by its
// owner only, and is never replaced.
func TestCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rqlite-auth.json")
	user, password, err := WriteCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if user != CredentialUser || len(password) != 2*credentialBytes {
		t.Errorf("WriteCredential returned %q and a password of %d characters", user, len(password))
	}
	u, p, err := ReadCredential(path)
	if err != nil || u != user || p != password {
		t.Errorf("ReadCredential = %q %q, %v, want what was written", u, p, err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("the file has the mode %v (%v), want 0600", fi.Mode().Perm(), err)
		}
	}
	if _, _, err := WriteCredential(path); !errors.Is(err, ErrCredentialExists) {
		t.Errorf("a second WriteCredential gave %v, want ErrCredentialExists", err)
	}
	if u, p, err := ReadCredential(path); err != nil || p != password || u != user {
		t.Errorf("the second WriteCredential changed the file (%v)", err)
	}
	other := filepath.Join(filepath.Dir(path), "other.json")
	if _, p2, err := WriteCredential(other); err != nil || p2 == password {
		t.Errorf("a second credential has the same password (%v)", err)
	}
}

func TestReadCredentialRefuses(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := ReadCredential(filepath.Join(dir, "none.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file gave %v, want os.ErrNotExist", err)
	}
	for name, body := range map[string]string{
		"not JSON":      "hello",
		"not a list":    `{"username":"controller","password":"x"}`,
		"no password":   `[{"username":"controller","password":"","perms":["all"]}]`,
		"another user":  `[{"username":"someone","password":"x","perms":["all"]}]`,
		"empty list":    `[]`,
		"a null":        `null`,
		"a number list": `[1]`,
	} {
		path := filepath.Join(dir, "a.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadCredential(path); err == nil {
			t.Errorf("%s: the file was accepted", name)
		}
	}
}

// The command line of rqlited carries the credential file, never the password, and the
// certificates of the members only as a set.
func TestArgsAuthAndNodeEncryption(t *testing.T) {
	r := &Rqlited{HTTPAddr: "127.0.0.1:4001", RaftAddr: "127.0.0.1:4002", DataDir: "data"}
	if a := r.args(); slices.Contains(a, "-auth") || slices.Contains(a, "-node-cert") {
		t.Errorf("a member with neither has %v", a)
	}
	r.AuthFile, r.Join = "auth.json", []string{"127.0.0.1:4012"}
	r.NodeCACert, r.NodeCert, r.NodeKey = "ca.pem", "node.pem", "node.key"
	a := r.args()
	for _, want := range [][]string{{"-auth", "auth.json"}, {"-join-as", CredentialUser}, {"-node-cert", "node.pem"}, {"-node-key", "node.key"}, {"-node-ca-cert", "ca.pem"}} {
		i := slices.Index(a, want[0])
		if i < 0 || a[i+1] != want[1] {
			t.Errorf("the arguments %v lack %v", a, want)
		}
	}
	if !slices.Contains(a, "-node-verify-client") {
		t.Errorf("the arguments %v lack -node-verify-client", a)
	}
	if a[len(a)-1] != "data" {
		t.Errorf("the data directory is not the last argument: %v", a)
	}
}

func FuzzParseCredential(f *testing.F) {
	f.Add([]byte(`[{"username":"controller","password":"x","perms":["all"]}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		user, password, err := parseCredential(b)
		if err == nil && (user != CredentialUser || password == "") {
			t.Errorf("parseCredential accepted %q as %q %q", b, user, password)
		}
	})
}
