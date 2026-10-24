package bgpcmd

import (
	"bytes"
	"context"
	"errors"
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

// The limits of the log file reach the function that opens it: the ones that the node gives, or the
// limits of the node log without them. Limits that are negative are arguments that are wrong.
func TestLogFileLimits(t *testing.T) {
	var path string
	var days, megabytes int
	old := OpenLog
	t.Cleanup(func() { OpenLog = old })
	OpenLog = func(p string, d, m int) (io.WriteCloser, error) {
		path, days, megabytes = p, d, m
		return nil, errors.New("no log in this test")
	}
	args := []string{"-pipe", `\\.\pipe\x`, "-log", "ranz-bgp.log"}
	var msg bytes.Buffer
	if code := run(context.Background(), append(args, "-log-days", "7", "-log-mb", "64"), &msg); code != 1 || !strings.Contains(msg.String(), "no log in this test") {
		t.Errorf("-log-days 7 -log-mb 64: exit code %d, message %q, want 1 and the error of the log", code, msg.String())
	}
	if path != "ranz-bgp.log" || days != 7 || megabytes != 64 {
		t.Errorf("the log was opened as %q with %d days and %d MB, want ranz-bgp.log, 7 and 64", path, days, megabytes)
	}
	run(context.Background(), args, io.Discard)
	if days != defaultLogDays || megabytes != defaultLogMB {
		t.Errorf("without the flags the limits are %d days and %d MB, want %d and %d", days, megabytes, defaultLogDays, defaultLogMB)
	}
	for _, extra := range [][]string{{"-log-days", "-1"}, {"-log-mb", "-1"}} {
		msg.Reset()
		if code := run(context.Background(), append(args, extra...), &msg); code != 2 || !strings.Contains(msg.String(), "must not be negative") {
			t.Errorf("%q: exit code %d, message %q, want 2 and the reason", extra, code, msg.String())
		}
	}
}
