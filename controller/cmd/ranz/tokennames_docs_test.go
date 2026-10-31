package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The docs of AUD1-DT-15-R1 (#561), its second criterion. The audit log names the API tokens: each call that changes something is
// recorded under token:NAME, and since AUD1-DT-15 (#497) so is a call with a token after its expiry. GET /api/v1/audit needs the role
// viewer, and ADR-0030 and ADR-0031 keep it so, while GET /api/v1/tokens needs admin, so a viewer reads the names of tokens that it cannot
// list. The decision of the ticket is to say so, in the rows AP-5 and AP-8 of the threat model, and to hold it with a conformance test of
// a viewer (TestAViewerReadsTheNamesOfTheTokensInTheAuditLog), and not to take the names out of what a viewer reads, which would be a
// rule in the Guard that no ADR has.

// threatRow returns the row id of the threats of docs/threat-model.md with its white space folded into single spaces, the table cells
// included.
func threatRow(t *testing.T, id string) string {
	t.Helper()
	for _, line := range docLines(t, "threat-model.md") {
		if strings.HasPrefix(line, "| "+id+" |") {
			return strings.Join(strings.Fields(line), " ")
		}
	}
	t.Fatalf("the threat model has no row %s", id)
	return ""
}

func TestDocsSayThatAViewerReadsTheNamesOfTheTokensInTheAuditLog(t *testing.T) {
	for _, row := range []struct {
		id   string
		want []string
	}{
		{"AP-5", []string{
			"and the audit log, which names the API tokens that acted (AP-8), and an operator changes every VRF",
		}},
		{"AP-8", []string{
			"The audit log names the API tokens, and a viewer reads it, since ADR-0030 and ADR-0031 keep `GET /api/v1/audit` with the viewer",
			"a call that changes something, and each of those three reads, is recorded under `token:NAME` (`user:NAME` for a user token)",
			"so is a call with the secret of a token after its expiry, as an `auth-failed` entry that says when the token ended and where the call came from",
			"So a viewer reads the name of every token that acted or whose secret was tried after its end, and can filter the log by it (`actor=token:NAME`)",
			"while `GET /api/v1/tokens` is the admin's and refuses a viewer with 403",
			"A name is no secret, and no secret of a token comes into the log",
		}},
	} {
		text := threatRow(t, row.id)
		for _, want := range row.want {
			if !strings.Contains(text, want) {
				t.Errorf("the row %s of the threat model does not say %q", row.id, want)
			}
		}
	}

	// The row rests on the two ADRs, which say that the audit log stays with the viewer: a change of either fails here until the row
	// follows it
	for _, adr := range []struct{ file, want string }{
		{"adr/0030-telemetry-and-events.md", "It needs the role viewer, since the API gives every read that role"},
		{"adr/0031-intent-api-revisions-explain-and-rbac.md", "`GET /api/v1/audit` and `GET /api/v1/audit/retention` stay with the viewer"},
	} {
		if !strings.Contains(pageText(t, adr.file), adr.want) {
			t.Errorf("docs/%s does not say %q, which the row AP-8 of the threat model rests on", adr.file, adr.want)
		}
	}

	// The row names the tests that show what it says of a viewer, and the code of the Controller defines them
	named := map[string]bool{"TestAViewerReadsTheNamesOfTheTokensInTheAuditLog": false, "TestDocsSayThatAViewerReadsTheNamesOfTheTokensInTheAuditLog": false}
	row := threatRow(t, "AP-8")
	for name := range named {
		if !strings.Contains(row, "`"+name+"`") {
			t.Errorf("the row AP-8 does not name %s as its evidence", name)
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
		for name := range named {
			if strings.Contains(string(b), "func "+name+"(") {
				named[name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, ok := range named {
		if !ok {
			t.Errorf("the row AP-8 names %s as its evidence, which no test file of the Controller defines", name)
		}
	}
}
