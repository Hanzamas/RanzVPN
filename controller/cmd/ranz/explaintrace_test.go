package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// ranz explain -trace ID prints the path of a traced packet (SDN-89, #388): a line for the trace with its ID, its ingress
// Node and when it was reported, then one for each Node that the packet crossed, the ingress Node first, with the VRF,
// the group that the packet carried with the tags of its set, and the verdict of the Node. The ID is decimal or 0x and
// hex; -trace all prints every trace, the newest first; -o json prints the answer of the API as it is. A trace ID that
// the controller holds no trace of is refused with 404, and a -trace that is no trace ID, or that comes with A and B, is
// the usage. The answers are those of a stand-in of the API.
func TestExplainTracePrintsThePath(t *testing.T) {
	ctx := context.Background()
	reported := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	path := controller.Trace{ID: 42, Ingress: "branch-1", Reported: reported, Steps: []controller.TraceStep{
		{Node: "branch-1", Ingress: true, VRF: "corp", Group: 3, Tags: []string{"web"}, Verdict: controller.TraceAllow},
		{Node: "db", VRF: "corp", Group: 3, Tags: []string{"web"}, Verdict: controller.TraceDeny},
	}}
	stranger := controller.Trace{ID: 7, Ingress: "eeeeeeeeeeeeeeee", Reported: reported, Steps: []controller.TraceStep{
		{Node: "db", VRF: "99", Verdict: controller.TraceDeny},
	}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer secret" {
			switch r.URL.Path {
			case "/api/v1/traces/42":
				json.NewEncoder(w).Encode(api.TraceList{Traces: []controller.Trace{path}})
				return
			case "/api/v1/traces":
				json.NewEncoder(w).Encode(api.TraceList{Traces: []controller.Trace{stranger, path}})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(api.Problem{Error: "no trace of the trace ID 9"})
	}))
	t.Cleanup(srv.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The stand-in is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	run := func(out, errOut *bytes.Buffer, args ...string) int {
		t.Helper()
		out.Reset()
		errOut.Reset()
		return runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprintOf(srv.Certificate())}, args...), out, errOut)
	}

	var out, errOut bytes.Buffer
	want := "trace 42 (0x0000002a) of branch-1, reported 2026-11-02T08:00:00Z: 2 Nodes\n" +
		"  branch-1  ingress  VRF corp  group 3 (web)  allowed\n" +
		"  db" + strings.Repeat(" ", 17) + "VRF corp  group 3 (web)  denied\n"
	// The ID as the usage says: decimal, also with a leading 0, or 0x and hex (SDN-89-R1, #630)
	for _, id := range []string{"42", "042", "0x2a"} {
		if code := run(&out, &errOut, "-trace", id); code != 0 {
			t.Fatalf("ranz explain -trace %s: exit code %d: %s", id, code, errOut.String())
		}
		if out.String() != want {
			t.Errorf("ranz explain -trace %s printed\n%s\nwant\n%s", id, out.String(), want)
		}
	}

	if code := run(&out, &errOut, "-trace", "all"); code != 0 {
		t.Fatalf("ranz explain -trace all: exit code %d: %s", code, errOut.String())
	}
	all := "trace 7 (0x00000007) of eeeeeeeeeeeeeeee, reported 2026-11-02T08:00:00Z: 1 Node\n" +
		"  db" + strings.Repeat(" ", 11) + "VRF 99  no group  denied\n" + want
	if out.String() != all {
		t.Errorf("ranz explain -trace all printed\n%s\nwant\n%s", out.String(), all)
	}

	if code := run(&out, &errOut, "-o", "json", "-trace", "42"); code != 0 {
		t.Fatalf("ranz explain -o json -trace 42: exit code %d: %s", code, errOut.String())
	}
	var list api.TraceList
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Traces) != 1 || !list.Traces[0].Reported.Equal(reported) ||
		!reflect.DeepEqual(list.Traces[0].Steps, path.Steps) || list.Traces[0].Ingress != "branch-1" {
		t.Errorf("ranz explain -o json -trace 42 gave %+v, %v, want %+v", list, err, path)
	}

	if code := run(&out, &errOut, "-trace", "9"); code != 1 || !strings.Contains(errOut.String(), "no trace of the trace ID 9 (404 Not Found)") {
		t.Errorf("ranz explain -trace 9: exit code %d, %q", code, errOut.String())
	}
	// ... and not binary, octal or with underscores, which the base 0 of strconv would read (SDN-89-R1, #630)
	for _, args := range [][]string{{"-trace", "zero"}, {"-trace", "0"}, {"-trace", "4294967296"}, {"-trace", "0b1"}, {"-trace", "1_0"}, {"-trace", "0o52"}} {
		if code := run(&out, &errOut, args...); code != 2 || !strings.Contains(errOut.String(), "-trace takes a trace ID") {
			t.Errorf("ranz explain %v: exit code %d, %q, want the refusal of the trace ID", args, code, errOut.String())
		}
	}
	for _, args := range [][]string{{"-trace", "42", "branch-1", "db"}, {"-trace", "42", "-port", "80"}, {"-trace", "42", "-listener", "front"}} {
		if code := run(&out, &errOut, args...); code != 2 {
			t.Errorf("ranz explain %v: exit code %d, want the usage", args, code)
		}
	}
}

// The trace ID of -trace is read as the usage says (SDN-89-R1, #630): hex after 0x, else decimal, from 1 to 4294967295.
// A leading 0 is decimal, not octal, so 042 is the trace 42; the binary, the octal and the underscores that the base 0 of
// strconv reads are no trace ID, nor is a sign, a space, or 0x without digits.
func TestParseTraceIDReadsTheUsage(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
	}{{"42", 42}, {"042", 42}, {"0x2a", 42}, {"0X2A", 42}, {"0x002a", 42}, {"1", 1}, {"4294967295", 4294967295}, {"0xffffffff", 4294967295}} {
		if got, ok := parseTraceID(c.in); !ok || got != c.want {
			t.Errorf("parseTraceID(%q) = %d, %v, want %d", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{"", "0", "00", "0x0", "0x", "0b1", "0B1", "0o52", "1_0", "0x_2a", "0x2_a", "+42", "-1", " 42", "42 ", "4294967296", "0x100000000", "2a", "x2a"} {
		if got, ok := parseTraceID(in); ok {
			t.Errorf("parseTraceID(%q) = %d, want no trace ID", in, got)
		}
	}
}
