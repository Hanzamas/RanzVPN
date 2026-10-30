package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The docs of AUD1-DT-19 (#506), its fourth and fifth criteria. The runbook of the first test lists tls.fingerprint
// among the files that the Controller makes and has an entry for each of the two refusals of ranz toward a Controller
// on its own host, and the row AP-2 of the threat model names the ticket of the scope below the role and the tests that
// show what it says about the logins. A page is written for a person, so these tests look for what a reader needs, and
// tie what the runbook quotes of a refusal to the words that the code says it in: a message that changes fails here
// until the page follows it.

// docLines returns the lines of the page docs/name. A checkout on Windows may hold the page with CRLF line endings
// (core.autocrlf), so the lines are cut after the carriage returns are gone.
func docLines(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// holdsInOrder reports whether msg holds the parts of quote that lie between its "...", in that order: the runbook
// quotes a message with "..." where it has a value that differs from one call to the next.
func holdsInOrder(msg, quote string) bool {
	for _, part := range strings.Split(quote, "...") {
		i := strings.Index(msg, part)
		if i < 0 {
			return false
		}
		msg = msg[i+len(part):]
	}
	return true
}

// TestRunbookListsTheFingerprintFileAndHasAnEntryForEachRefusal: step 6 of the runbook lists tls.fingerprint among the
// files of the Controller, and its troubleshooting list has an entry for the refusal of a Controller whose fingerprint
// ranz cannot read or does not trust (AUD1-DT-14, #496) and one for the refusal of a certificate that is not the
// Controller's. Each entry is titled by the words of the message, as the code says them, and tells the reader what to
// give or set, and that the logins open no browser.
func TestRunbookListsTheFingerprintFileAndHasAnEntryForEachRefusal(t *testing.T) {
	lines := docLines(t, "first-test.md")

	// The files that the Controller made at its first start are the bullets that follow the line that says so
	var files []string
	for i, line := range lines {
		if !strings.HasSuffix(line, "At its first start the Controller made:") {
			continue
		}
		for _, l := range lines[i+1:] {
			if strings.HasPrefix(l, "- ") {
				files = append(files, l)
			} else if l != "" {
				break
			}
		}
		break
	}
	if len(files) == 0 {
		t.Fatal("the runbook has no list of the files that the Controller made at its first start")
	}
	listed := false
	for _, f := range files {
		listed = listed || strings.HasPrefix(f, "- `"+servercert.FingerprintFile+"`: ")
	}
	if !listed {
		t.Errorf("the files of the Controller in the runbook are %q, want %s among them", files, servercert.FingerprintFile)
	}

	// The entries of the troubleshooting list are the bullets of that section
	var entries []string
	inList := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "## "):
			inList = l == "## Troubleshooting"
		case inList && strings.HasPrefix(l, "- **"):
			entries = append(entries, l)
		}
	}
	const server = "https://127.0.0.1"
	for _, c := range []struct {
		refusal error
		quote   string   // what the runbook quotes of the message, with "..." for the values in it
		also    []string // what else the entry quotes of the message, in backticks
		remedy  string   // what the entry tells the reader to give or set
	}{
		{&unchecked{server: server, dir: "DIR", err: errors.New("the file is not there")},
			"ranz sends no token to " + server + " without checking who answers there", nil, "-tls-fingerprint"},
		// The same entry covers the refusal of a file that ranz does not trust (AUD1-DT-14, #496)
		{&unchecked{server: server, dir: "DIR", err: &controllercmd.UntrustedError{Path: "DIR", Why: "is owned by SOMEONE"}},
			"ranz sends no token to " + server + " without checking who answers there", []string{"does not trust that file"}, "-tls-fingerprint"},
		{&mismatch{server: server, file: "FILE", err: &api.FingerprintError{Got: "GOT", Want: "WANT"}},
			"ranz sent no token to " + server + ": what answers there has a certificate with the TLS fingerprint ..., and ... names ... for the Controller of this host", nil, "RANZ_SERVER"},
	} {
		if !holdsInOrder(c.refusal.Error(), c.quote) {
			t.Errorf("the runbook quotes %q, which the refusal does not say: %q", c.quote, c.refusal)
		}
		title := "- **`ranz` on PC A says `" + c.quote + "`.**"
		entry := ""
		for _, e := range entries {
			if strings.HasPrefix(e, title) {
				entry = e
			}
		}
		if entry == "" {
			t.Errorf("the troubleshooting list of the runbook has no entry that begins %q", title)
			continue
		}
		for _, want := range []string{c.remedy, "`ranz login` and `ranz node login`", "no browser"} {
			if !strings.Contains(entry, want) {
				t.Errorf("the entry %q does not say %q", title, want)
			}
		}
		for _, q := range c.also {
			if !strings.Contains(c.refusal.Error(), q) {
				t.Errorf("the runbook quotes %q, which the refusal does not say: %q", q, c.refusal)
			}
			if !strings.Contains(entry, "`"+q+"`") {
				t.Errorf("the entry %q does not quote %q", title, q)
			}
		}
	}
}

// TestThreatModelRowAP2NamesSDN38AndTheTestsOfTheBrowserLogin: the row AP-2 names SDN-38 (#231) for the scope below the
// role, as the ticket asks, and the tests that show what it says of a browser login that checks the Controller before
// it opens the browser. Every test and fuzz target that the row names as its evidence is in the code of the Controller,
// so that what the row says is shown by what it points at.
func TestThreatModelRowAP2NamesSDN38AndTheTestsOfTheBrowserLogin(t *testing.T) {
	row := ""
	for _, l := range docLines(t, "threat-model.md") {
		if strings.HasPrefix(l, "| AP-2 |") {
			row = l
		}
	}
	if row == "" {
		t.Fatal("the threat model has no row AP-2")
	}
	if !strings.Contains(row, "SDN-38 (#231)") || strings.Contains(row, "SDN-32 (#226) for a scope") {
		t.Errorf("the row AP-2 does not name SDN-38 (#231), and only it, for the scope below the role")
	}

	found := map[string]bool{}
	for _, m := range regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`").FindAllStringSubmatch(row, -1) {
		found[m[1]] = false
	}
	for _, name := range []string{"TestRanzLoginOpensNoBrowserBeforeItHasCheckedTheCertificate", "TestRanzNodeLoginOpensNoBrowserBeforeItHasCheckedTheCertificate"} {
		if _, ok := found[name]; !ok {
			t.Errorf("the row AP-2 does not name %s", name)
		}
	}
	// The code of the Controller is the directory two levels up from this package
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for name := range found {
			if strings.Contains(string(b), "func "+name+"(") {
				found[name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, ok := range found {
		if !ok {
			t.Errorf("the row AP-2 names %s as its evidence, which no test file of the Controller defines", name)
		}
	}
}
