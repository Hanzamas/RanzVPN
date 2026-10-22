package bgpcmd

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
)

// The arguments: the exit code 2 for arguments that are wrong, which include -version, because the
// one version of ranz is what `ranz version` prints (ONE-1, #310), and the help of ranz bgp.
func TestArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-pipe", `\\.\pipe\x`, "extra"},
		{"-pipe", `\\.\pipe\x`, "-log-level", "loud"},
		{"-no-such-flag"},
		{"-version"},
	} {
		if code := run(context.Background(), args, io.Discard); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
	}
	var msg bytes.Buffer
	if code := run(context.Background(), nil, &msg); code != 2 || !strings.HasPrefix(msg.String(), "ranz bgp: -pipe is required") {
		t.Errorf("no arguments: exit code %d, message %q, want 2 and the message of ranz bgp", code, msg.String())
	}
	msg.Reset()
	if code := run(context.Background(), []string{"-h"}, &msg); code != 0 || !strings.Contains(msg.String(), "Usage of ranz bgp") {
		t.Errorf("-h: exit code %d, output %q, want 0 and the usage of ranz bgp", code, msg.String())
	}
	if runtime.GOOS != "windows" {
		if code := run(context.Background(), []string{"-pipe", `\\.\pipe\x`}, io.Discard); code != 1 {
			t.Errorf("-pipe off Windows: exit code %d, want 1", code)
		}
	}
}
