package main

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
)

// The arguments: -version, and the exit code 2 for arguments that are wrong.
func TestArguments(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &out, io.Discard); code != 0 || !strings.HasPrefix(out.String(), "ranz-bgp") {
		t.Errorf("-version: exit code %d, output %q", code, out.String())
	}
	for _, args := range [][]string{
		{},
		{"-pipe", `\\.\pipe\x`, "extra"},
		{"-pipe", `\\.\pipe\x`, "-log-level", "loud"},
		{"-no-such-flag"},
	} {
		if code := run(context.Background(), args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
	}
	if runtime.GOOS != "windows" {
		if code := run(context.Background(), []string{"-pipe", `\\.\pipe\x`}, io.Discard, io.Discard); code != 1 {
			t.Errorf("-pipe off Windows: exit code %d, want 1", code)
		}
	}
}
