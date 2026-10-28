package servercert

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
)

// The fingerprint file holds the fingerprint whole, in lower case, and nothing stays beside it; a second
// write replaces the first; text that is no fingerprint and a directory that is not there are refused.
func TestFingerprintFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp, other := strings.Repeat("ab", 32), strings.Repeat("01", 32)
	if _, err := ReadFingerprint(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading from a directory with no file gave %v, want that the file is not there", err)
	}

	if err := WriteFingerprint(dir, strings.ToUpper(fp)); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFingerprint(dir); err != nil || got != fp {
		t.Errorf("the fingerprint is %q, %v, want %q", got, err, fp)
	}
	if b, err := os.ReadFile(filepath.Join(dir, FingerprintFile)); err != nil || string(b) != fp+"\n" {
		t.Errorf("the file holds %q, %v, want the fingerprint and a line end", b, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != FingerprintFile {
		t.Errorf("the directory holds %v, %v, want the one file", entries, err)
	}

	if err := WriteFingerprint(dir, other); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFingerprint(dir); err != nil || got != other {
		t.Errorf("after the second write the fingerprint is %q, %v, want %q", got, err, other)
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("a", 63), strings.Repeat("a", 65), "0x" + strings.Repeat("a", 62)} {
		if err := WriteFingerprint(dir, bad); err == nil {
			t.Errorf("WriteFingerprint took %q, which is no fingerprint", bad)
		}
	}
	if got, err := ReadFingerprint(dir); err != nil || got != other {
		t.Errorf("after the refusals the fingerprint is %q, %v, want %q as before", got, err, other)
	}
	if err := WriteFingerprint(filepath.Join(dir, "none"), fp); err == nil {
		t.Error("a fingerprint was written into a directory that is not there")
	}
}

// A file that holds no fingerprint is refused with the file named, and one that has white space and a
// carriage return around its fingerprint is not.
func TestReadFingerprintRefusesWhatIsNoFingerprint(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, FingerprintFile)
	fp := strings.Repeat("ab", 32)
	for name, content := range map[string]string{
		"an empty file":        "",
		"text":                 "hello\n",
		"a short fingerprint":  fp[:63] + "\n",
		"two fingerprints":     fp + "\n" + fp + "\n",
		"a long file of space": strings.Repeat(" ", 1000) + fp,
	} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadFingerprint(dir); err == nil || got != "" || !strings.Contains(err.Error(), "no TLS fingerprint") || !strings.Contains(err.Error(), FingerprintFile) {
			t.Errorf("%s: %q, %v, want a refusal that names the file", name, got, err)
		}
	}

	if err := os.WriteFile(file, []byte("  "+strings.ToUpper(fp)+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFingerprint(dir); err != nil || got != fp {
		t.Errorf("a fingerprint in upper case with white space around it is %q, %v, want %q", got, err, fp)
	}

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFingerprint(dir); err == nil || got != "" {
		t.Errorf("a directory in place of the file gave %q, %v, want an error", got, err)
	}
}

// The Manager keeps the file at the fingerprint that it serves: when it is told to, and then at every change
// of the certificate, whether an Adopt, a look at the store that another member changed, or the clearing
// of a setting. A write that failed is tried again at the next change, and a Manager with no data directory
// writes nothing.
func TestPublishFingerprintFollowsTheCertificate(t *testing.T) {
	dir := t.TempDir()
	st := &memStore{}
	m := newManager(t, st, "")
	m.PublishFingerprint(dir)
	self := m.Fingerprint()
	published := func(want string) {
		t.Helper()
		if got, err := ReadFingerprint(dir); err != nil || got != want {
			t.Errorf("the file holds %q, %v, want %q", got, err, want)
		}
	}
	published(self)

	c := writeCert(t, t.TempDir(), "ctl", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, ecKey(t), nil)
	setting := Setting{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: c.cert, Key: c.keyFile}}
	l, err := m.Load(context.Background(), setting)
	if err != nil {
		t.Fatal(err)
	}
	if l.Info.Fingerprint == self {
		t.Fatal("the two certificates have the same fingerprint")
	}
	m.Adopt(l)
	published(l.Info.Fingerprint)
	m.Adopt(m.SelfSigned())
	published(self)

	// Another member sets it, and this one finds it in the store; the setting is gone again
	s, err := ParseSetting([]byte(setting.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	st.set(s.Encode(), l.Info.Fingerprint)
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	published(l.Info.Fingerprint)
	st.set("", "")
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	published(self)

	// A directory that is not there: the write fails, the Manager goes on, and the next change writes
	gone := filepath.Join(t.TempDir(), "data")
	n := newManager(t, nil, "")
	n.PublishFingerprint(gone)
	if _, err := ReadFingerprint(gone); err == nil {
		t.Fatal("a fingerprint was written into a directory that is not there")
	}
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	n.Adopt(l)
	if got, err := ReadFingerprint(gone); err != nil || got != l.Info.Fingerprint {
		t.Errorf("the next change wrote %q, %v, want %q", got, err, l.Info.Fingerprint)
	}

	// No data directory, nothing to write
	none := newManager(t, nil, "")
	none.PublishFingerprint("")
	none.Adopt(l)
}

// ReadFingerprint reads the file through parseFingerprint, which never panics and takes the 64 hex digits of
// a SHA-256 with white space around them, as one form: in lower case.
func FuzzReadFingerprint(f *testing.F) {
	for _, s := range []string{
		"",
		strings.Repeat("ab", 32) + "\n",
		"  " + strings.Repeat("AB", 32) + "\r\n",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		"0x" + strings.Repeat("a", 62),
		strings.Repeat("ab", 32) + "\n" + strings.Repeat("ab", 32),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		fp, err := parseFingerprint(text)
		if err != nil {
			if fp != "" {
				t.Errorf("parseFingerprint refused %q and returned %q", text, fp)
			}
			return
		}
		if len(fp) != 64 || fp != strings.ToLower(fp) {
			t.Errorf("parseFingerprint took %q as %q, want 64 hex digits in lower case", text, fp)
		}
		if again, err := parseFingerprint(fp + "\n"); err != nil || again != fp {
			t.Errorf("parseFingerprint took %q as %q, then not its own form: %q, %v", text, fp, again, err)
		}
	})
}
