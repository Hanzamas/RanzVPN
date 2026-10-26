package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
)

// auditServer answers GET /api/v1/audit with list, and records the query of each call.
func auditServer(t *testing.T, list api.AuditList) (*api.Client, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit" {
			http.NotFound(w, r)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		if err := show(w, list); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return &api.Client{URL: srv.URL, HTTP: srv.Client()}, &queries
}

// The table has a line for each record with what it says, and the page that follows when the answer
// is full; the flags go to the API as its filters.
func TestAuditTable(t *testing.T) {
	at := time.Date(2026, 10, 26, 1, 2, 3, 0, time.UTC)
	list := api.AuditList{Records: []audit.Record{
		{ID: 7, Time: at, Kind: audit.Enrolment, Actor: "node:pc-a", Source: "192.0.2.10", Outcome: audit.Success, Message: "the first control stream of the static key of this node"},
		{ID: 8, Time: at, Kind: audit.IntentChange, Actor: "token:admin", Source: audit.SourceLocal, Outcome: audit.Success, Action: "apply", Revision: 2},
	}, Next: 8}
	c, queries := auditServer(t, list)
	var out bytes.Buffer
	if err := do(context.Background(), c, []string{"get", "audit", "-kind", "enrolment", "-limit", "2", "-o", "table"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 1 || (*queries)[0] != "kind=enrolment&limit=2" {
		t.Errorf("the calls asked for %q", *queries)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ID") || !strings.Contains(lines[0], "WHAT") {
		t.Fatalf("the table is\n%s", out.String())
	}
	for i, want := range []string{"7 2026-10-26T01:02:03Z enrolment node:pc-a 192.0.2.10 success", "8 2026-10-26T01:02:03Z intent-change token:admin local success"} {
		if got := strings.Join(strings.Fields(lines[i+1])[:6], " "); got != want {
			t.Errorf("line %d starts with %q, want %q", i+1, got, want)
		}
	}
	if !strings.Contains(lines[1], "node:pc-a") || !strings.Contains(lines[1], "the first control stream") || !strings.Contains(lines[2], "apply; revision 2") {
		t.Errorf("the lines do not say what the records say:\n%s", out.String())
	}
	if lines[3] != "more records follow: ranz get audit -after 8, with the same filters" {
		t.Errorf("the last line is %q", lines[3])
	}

	// JSON is the answer as the API gives it, and a page that is not full names no next
	out.Reset()
	c, queries = auditServer(t, api.AuditList{Records: list.Records[:1]})
	if err := do(context.Background(), c, []string{"get", "audit"}, &out); err != nil {
		t.Fatal(err)
	}
	if (*queries)[0] != "limit=100" || !strings.Contains(out.String(), `"kind": "enrolment"`) || strings.Contains(out.String(), "next") {
		t.Errorf("ranz get audit asked for %q and printed\n%s", *queries, out.String())
	}
	out.Reset()
	if err := do(context.Background(), c, []string{"get", "audit", "-o", "table"}, &out); err != nil || strings.Contains(out.String(), "more records") {
		t.Errorf("a page that is not full: %v\n%s", err, out.String())
	}
}

// A filter that the API would refuse is refused with its words before any call, and arguments
// that ranz get audit does not take print the usage.
func TestAuditRefusesWrongFilters(t *testing.T) {
	c, queries := auditServer(t, api.AuditList{})
	for _, c2 := range []struct {
		args []string
		want string
	}{
		{[]string{"-kind", "everything"}, "the kind"},
		{[]string{"-since", "yesterday"}, "RFC 3339"},
		{[]string{"-limit", "0"}, "limit"},
		{[]string{"-after", "x"}, "record id"},
	} {
		err := do(context.Background(), c, append([]string{"get", "audit"}, c2.args...), &bytes.Buffer{})
		if !errors.Is(err, audit.ErrInvalid) || !strings.Contains(err.Error(), c2.want) {
			t.Errorf("ranz get audit %s: %v, want an error that says %q", strings.Join(c2.args, " "), err, c2.want)
		}
	}
	for _, args := range [][]string{{"get", "audit", "extra"}, {"get", "audit", "-o", "yaml"}, {"get", "audit", "-unknown", "1"}} {
		if err := do(context.Background(), c, args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
	if len(*queries) != 0 {
		t.Errorf("wrong filters made the calls %q", *queries)
	}
}
