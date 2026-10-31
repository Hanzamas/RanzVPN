package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The script of the first test puts the admin source allowlist back in a finally (AUD1-DT-15-R1, #561). It takes the branch for an
// address that is not private by adding 203.0.113.77, which no host holds, to the list of the Controller, and then puts the list back.
// When the check of the list threw, its read back for one, the list kept the address, and a machine that keeps its data directory failed
// at its next run, since a list refuses an entry that is there twice. Only the job first test runs the script, and there nothing throws,
// so the way that fails is read here: the call that puts the list back is in the finally of the block that adds the address, and the
// read back that fails the step comes after it.
func TestTheFirstTestPutsTheAllowlistBackWhenItsCheckFails(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "scripts", "first-test.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	// The script is read with its white space folded into single spaces, since a checkout on Windows may hold it with CRLF line endings
	script := strings.Join(strings.Fields(string(b)), " ")
	const (
		add      = "Assert-AllowlistHolds '203.0.113.77'"
		finally  = "try { " + add + " } finally {"
		restore  = "Invoke-Ranz (@('admin-sources', 'set') + $before)"
		readBack = "$after = @(Get-Allowlist)"
	)

	for _, c := range []struct{ what, text string }{{"adds the address", add}, {"puts the list back", restore}, {"reads the list back", readBack}} {
		if n := strings.Count(script, c.text); n != 1 {
			t.Fatalf("the script %s %d times with %q, want once", c.what, n, c.text)
		}
	}
	tried := strings.Index(script, finally)
	if tried < 0 {
		t.Fatalf("the script does not add the address in a try that has a finally, so the list keeps the address when the check throws: want %q", finally)
	}
	back := strings.Index(script, restore)
	if back < tried || strings.Contains(script[tried+len(finally):back], "}") {
		t.Error("the script puts the list back outside the finally of the block that adds the address")
	}
	if read := strings.Index(script, readBack); read < back {
		t.Error("the script reads the list back before it has put it back, so the read back does not fail the step when the list is not as it was")
	}
}
