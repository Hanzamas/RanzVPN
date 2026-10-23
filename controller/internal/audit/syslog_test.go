package audit

import (
	"strings"
	"testing"
	"time"
)

func TestSyslogFormat(t *testing.T) {
	r := Record{ID: 7, Time: time.Date(2026, 10, 23, 8, 0, 0, 123_000_000, time.UTC), Kind: Login, Actor: "node:branch-1", Source: "192.0.2.7", Outcome: Success}
	want := "<110>1 2026-10-23T08:00:00.123Z ctl-1 ranz-controller - login - kind=login id=7 actor=node:branch-1 source=192.0.2.7 outcome=success"
	if got := r.Syslog("ctl-1"); got != want {
		t.Errorf("the message is\n%s\nwant\n%s", got, want)
	}
}

// A failure is a warning, a value that holds a space, a quote or a line break is quoted so that the
// line stays one line, and a host name that is not printable ASCII is cleaned.
func TestSyslogQuotesAndWarns(t *testing.T) {
	r := Record{ID: 8, Time: time.Date(2026, 10, 23, 8, 0, 0, 0, time.FixedZone("UTC+7", 7*3600)), Kind: IntentChange, Actor: "token:admin", Source: SourceLocal,
		Outcome: Failure, Action: "apply", Revision: 4, Message: "a \"bad\" apply\nnext line"}
	got := r.Syslog("ctl 1é")
	want := `<108>1 2026-10-23T01:00:00.000Z ctl1 ranz-controller - intent-change - kind=intent-change id=8 actor=token:admin source=local outcome=failure action=apply revision=4 message="a \"bad\" apply\nnext line"`
	if got != want {
		t.Errorf("the message is\n%s\nwant\n%s", got, want)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("the message %q has a line break", got)
	}
	if got := (Record{Kind: Operation, Outcome: Success, Action: "PUT /api/v1/targets/slack", Actor: "a=b"}).Syslog(""); !strings.Contains(got, ` ranz-controller - operation - `) ||
		!strings.Contains(got, `action="PUT /api/v1/targets/slack"`) || !strings.Contains(got, `actor="a=b"`) || !strings.HasPrefix(got, "<110>1 0001-01-01T00:00:00.000Z - ") {
		t.Errorf("the message %q has no host name, or does not quote a value with a space or an equals sign", got)
	}
	if got := (Record{Kind: Login}).Syslog(strings.Repeat("h", 300)); !strings.Contains(got, " "+strings.Repeat("h", 255)+" ranz-controller ") {
		t.Errorf("a host name of 300 characters is not cut to 255 in %q", got)
	}
}
