package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ranz acme refuses arguments that are wrong, and writes the answer of a run that failed: one line
// that starts with error.
func TestACMEArguments(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{
		{"-directory", "https://acme.test/dir", "-names", "a.test", "-state", t.TempDir()},
		{"-out", filepath.Join(t.TempDir(), "out"), "extra"},
		{"-renew-days", "many"},
	} {
		if code := runACME(context.Background(), args, &stderr); code != 2 {
			t.Errorf("ranz acme %q: exit code %d, want 2", args, code)
		}
	}
	if code := runACME(context.Background(), []string{"-h"}, &stderr); code != 0 {
		t.Errorf("ranz acme -h: exit code %d, want 0", code)
	}

	// A service that does not answer: the run fails, and its answer says why
	out := filepath.Join(t.TempDir(), "answer.out")
	args := []string{"-directory", "https://127.0.0.1:1/dir", "-names", "a.test, b.test", "-http-port", "5002", "-state", t.TempDir(), "-out", out}
	if code := runACME(context.Background(), args, &stderr); code != 1 {
		t.Errorf("ranz acme against no service: exit code %d, want 1", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if answer := string(b); !strings.HasPrefix(answer, "error acme: ") || strings.Count(answer, "\n") != 1 {
		t.Errorf("the answer is %q, want one line that starts with error", answer)
	}

	// An answer that cannot be written
	args = []string{"-directory", "https://127.0.0.1:1/dir", "-names", "a.test", "-state", t.TempDir(), "-out", filepath.Join(t.TempDir(), "no", "such", "dir", "out")}
	if code := runACME(context.Background(), args, &stderr); code != 1 {
		t.Errorf("ranz acme with an answer file that cannot be written: exit code %d, want 1", code)
	}
}
