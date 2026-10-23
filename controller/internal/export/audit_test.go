package export

import (
	"errors"
	"strings"
	"testing"
)

// auditKinds are the kinds of audit record, as internal/audit lists them, which this package cannot
// import.
var auditKinds = []string{"login", "logout", "auth-failed", "enrolment", "intent-change", "operation"}

func TestValidateAuditAcceptsTheKinds(t *testing.T) {
	for _, tg := range []Target{
		{Name: "siem", Kind: KindWebhook, URL: "https://siem.example.com/audit/T0/XXXX", Secret: "key", Types: []string{"auth-failed", "intent-change"}},
		{Name: "plain-http", Kind: KindWebhook, URL: "http://10.0.0.5:8080/audit"},
		{Name: "syslog-udp", Kind: KindSyslog, URL: "udp://192.0.2.10:514"},
		{Name: "syslog-tcp", Kind: KindSyslog, URL: "tcp://logs.example.com:601", Types: []string{"login", "logout"}},
		{Name: "syslog-tls", Kind: KindSyslog, URL: "tls://[2001:db8::10]:6514"},
		{Name: "a", Kind: KindWebhook, URL: "https://x.example"},
	} {
		if err := tg.ValidateAudit(auditKinds); err != nil {
			t.Errorf("%+v: %v", tg, err)
		}
	}
}

func TestValidateAuditRefusesWhatIsNotValid(t *testing.T) {
	hook := Target{Name: "siem", Kind: KindWebhook, URL: "https://siem.example.com/audit"}
	syslog := Target{Name: "logs", Kind: KindSyslog, URL: "udp://192.0.2.10:514"}
	with := func(base Target, f func(*Target)) Target {
		f(&base)
		return base
	}
	for _, c := range []struct {
		target Target
		want   string
	}{
		{with(hook, func(tg *Target) { tg.Name = "Bad_Name" }), "must be a DNS label"},
		{with(hook, func(tg *Target) { tg.Name = "" }), "must be a DNS label"},
		{with(hook, func(tg *Target) { tg.Kind = KindIPFIX }), `the kind of an audit target must be webhook or syslog, not "ipfix"`},
		{with(hook, func(tg *Target) { tg.Kind = "" }), "the kind of an audit target must be webhook or syslog"},
		{with(hook, func(tg *Target) { tg.URL = "ftp://siem.example.com/x" }), `scheme of the url must be [http https], not "ftp"`},
		{with(hook, func(tg *Target) { tg.URL = "https://user:pw@siem.example.com/x" }), "carries a user name or password"},
		{with(hook, func(tg *Target) { tg.Secret = strings.Repeat("s", maxSecret+1) }), "the secret is 257 bytes"},
		{with(hook, func(tg *Target) { tg.Types = []string{"node-down"} }), `the kind of audit record "node-down" is none of`},
		{with(hook, func(tg *Target) { tg.Types = []string{"login", "login"} }), `the kind of audit record "login" is listed twice`},
		{with(syslog, func(tg *Target) { tg.URL = "http://192.0.2.10:514" }), "scheme of the url must be [udp tcp tls]"},
		{with(syslog, func(tg *Target) { tg.URL = "udp://192.0.2.10" }), "needs a port, for example udp://192.0.2.10:514"},
		{with(syslog, func(tg *Target) { tg.Secret = "x" }), "a syslog target has no secret"},
	} {
		err := c.target.ValidateAudit(auditKinds)
		switch {
		case err == nil:
			t.Errorf("%+v is valid, want the problem %q", c.target, c.want)
		case !errors.Is(err, ErrInvalid):
			t.Errorf("%+v: %v does not wrap ErrInvalid", c.target, err)
		case !strings.Contains(err.Error(), c.want):
			t.Errorf("%+v: %q does not say %q", c.target, err, c.want)
		}
	}
}

// Every problem of an audit target is named at once, not only the first.
func TestValidateAuditNamesEveryProblem(t *testing.T) {
	err := Target{Name: "Bad", Kind: KindSyslog, URL: "http://host", Secret: "x", Types: []string{"node-up"}}.ValidateAudit(auditKinds)
	if err == nil {
		t.Fatal("the target is valid")
	}
	for _, want := range []string{"DNS label", "scheme of the url", "needs a port", "no secret", "is none of"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not name %q", err, want)
		}
	}
}

// The targets of events, metrics and flow records stay what they were: an audit kind is no kind of
// them, and the other way round.
func TestTheKindsOfAuditAndOfEventsAreApart(t *testing.T) {
	if err := (Target{Name: "logs", Kind: KindSyslog, URL: "udp://192.0.2.10:514"}).Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("a syslog target is valid as a target of events: %v", err)
	}
	if err := (Target{Name: "flows", Kind: KindIPFIX, URL: "udp://192.0.2.10:4739"}).ValidateAudit(auditKinds); !errors.Is(err, ErrInvalid) {
		t.Errorf("an IPFIX target is valid as an audit target: %v", err)
	}
}

// FuzzValidateAudit checks that ValidateAudit answers any audit target, from an operator's request,
// with nil or an error that wraps ErrInvalid, and that what it accepts is a webhook or a syslog
// receiver that can be shown without a secret.
func FuzzValidateAudit(f *testing.F) {
	f.Add("siem", "syslog", "udp://192.0.2.10:514", "", "login")
	f.Add("hook", "webhook", "https://siem.example.com/audit", "key", "auth-failed")
	f.Add("logs", "syslog", "tls://[::1]:6514", "k", "bogus")
	f.Add("", "", "", "", "")
	f.Add("a", "webhook", "https://u:p@h:99999/%zz", "k", "login")
	f.Fuzz(func(t *testing.T, name, kind, url, secret, typ string) {
		tg := Target{Name: name, Kind: kind, URL: url, Secret: secret}
		if typ != "" {
			tg.Types = []string{typ}
		}
		err := tg.ValidateAudit(auditKinds)
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v does not wrap ErrInvalid", tg, err)
		}
		if err == nil && (!nameRule.MatchString(tg.Name) || (kind != KindWebhook && kind != KindSyslog) || tg.Info().HasSecret != (secret != "")) {
			t.Fatalf("%+v is accepted, but its name, its kind or its info is wrong: %+v", tg, tg.Info())
		}
	})
}
