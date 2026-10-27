package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tool writes the plan of every scenario of tests/explain and of a scenario file named alone, and refuses what is
// not a scenario.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"-o", dir, "../../../tests/explain", "../../../tests/explain/broken/policy-drift.json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	for _, name := range []string{"policy", "leak", "nat", "leak-nat", "policy-drift"} {
		b, err := os.ReadFile(filepath.Join(dir, name+".plan"))
		if err != nil || !bytes.Contains(b, []byte("\nscenario "+name+"\n")) {
			t.Errorf("the plan of %s: %v", name, err)
		}
		if !strings.Contains(out.String(), name+": ") {
			t.Errorf("the output names no plan of %s: %s", name, out.String())
		}
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"nodes": {}, "intent": {"resources": []}, "packets": [{"name": "x", "from": "a", "to": "b", "expect": {}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		code int
		text string
	}{
		{[]string{dir}, 2, "usage: ranz-explainplan"},
		{[]string{"-o", dir}, 2, "usage: ranz-explainplan"},
		{[]string{"-o", dir, filepath.Join(dir, "missing")}, 1, "missing"},
		{[]string{"-o", dir, t.TempDir()}, 1, "no scenario file"},
		{[]string{"-o", dir, bad}, 1, `"a" is no Node`},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(c.args, &out, &errOut); code != c.code || !strings.Contains(errOut.String(), c.text) {
			t.Errorf("ranz-explainplan %v: exit code %d, %q; want %d with %q", c.args, code, errOut.String(), c.code, c.text)
		}
	}
}
