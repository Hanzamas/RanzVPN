package export

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

func TestValidateAcceptsTheKinds(t *testing.T) {
	for _, tg := range []Target{
		{Name: "slack", Kind: KindWebhook, URL: "https://hooks.example.com/services/T0/B0/XXXX", Secret: "key", Types: []string{event.NodeDown, event.GatewayFailover}},
		{Name: "plain-http", Kind: KindWebhook, URL: "http://10.0.0.5:8080/ranz"},
		{Name: "collector", Kind: KindOTLP, URL: "http://otel.example.com:4318", Secret: "token"},
		{Name: "otel-path", Kind: KindOTLP, URL: "https://otel.example.com/v1/metrics"},
		{Name: "flows", Kind: KindIPFIX, URL: "udp://192.0.2.10:4739"},
		{Name: "flows-tcp", Kind: KindIPFIX, URL: "tcp://[2001:db8::10]:4739"},
		{Name: "a", Kind: KindWebhook, URL: "https://x.example"},
	} {
		if err := tg.Validate(); err != nil {
			t.Errorf("%+v: %v", tg, err)
		}
	}
}

func TestValidateRefusesWhatIsNotValid(t *testing.T) {
	hook := Target{Name: "slack", Kind: KindWebhook, URL: "https://hooks.example.com/x"}
	with := func(f func(*Target)) Target {
		tg := hook
		f(&tg)
		return tg
	}
	for _, c := range []struct {
		target Target
		want   string
	}{
		{with(func(tg *Target) { tg.Name = "Bad_Name" }), "must be a DNS label"},
		{with(func(tg *Target) { tg.Name = "" }), "must be a DNS label"},
		{with(func(tg *Target) { tg.Name = "-lead" }), "must be a DNS label"},
		{with(func(tg *Target) { tg.Name = strings.Repeat("a", 64) }), "must be a DNS label"},
		{with(func(tg *Target) { tg.Kind = "email" }), "kind must be webhook, otlp or ipfix"},
		{with(func(tg *Target) { tg.Kind = "" }), "kind must be webhook, otlp or ipfix"},
		{with(func(tg *Target) { tg.URL = "ftp://hooks.example.com/x" }), `scheme of the url must be [http https], not "ftp"`},
		{with(func(tg *Target) { tg.URL = "hooks.example.com/x" }), "scheme of the url must be"},
		{with(func(tg *Target) { tg.URL = "https:///x" }), "names no host"},
		{with(func(tg *Target) { tg.URL = "https://user:pw@hooks.example.com/x" }), "carries a user name or password"},
		{with(func(tg *Target) { tg.URL = "https://hooks.example.com:99999/x" }), "is not between 1 and 65535"},
		{with(func(tg *Target) { tg.URL = "https://%zz" }), "does not parse"},
		{with(func(tg *Target) { tg.URL = "https://h.example/" + strings.Repeat("a", maxURL) }), "at most 2048"},
		{with(func(tg *Target) { tg.Secret = strings.Repeat("s", maxSecret+1) }), "the secret is 257 bytes"},
		{with(func(tg *Target) { tg.Types = []string{"node-up"} }), `the event type "node-up" is none of`},
		{with(func(tg *Target) { tg.Types = []string{event.NodeDown, event.NodeDown} }), `the event type "node-down" is listed twice`},
		{Target{Name: "flows", Kind: KindIPFIX, URL: "udp://192.0.2.10"}, "needs a port"},
		{Target{Name: "flows", Kind: KindIPFIX, URL: "http://192.0.2.10:4739"}, "scheme of the url must be [udp tcp]"},
		{Target{Name: "flows", Kind: KindIPFIX, URL: "udp://192.0.2.10:4739", Secret: "x"}, "an IPFIX target has no secret"},
		{Target{Name: "flows", Kind: KindIPFIX, URL: "udp://192.0.2.10:4739", Types: []string{event.NodeDown}}, "only a webhook has event types, and this target is ipfix"},
		{Target{Name: "otel", Kind: KindOTLP, URL: "http://otel.example.com", Types: []string{event.NodeDown}}, "only a webhook has event types"},
	} {
		err := c.target.Validate()
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

// Every problem of a target is named at once, not only the first.
func TestValidateNamesEveryProblem(t *testing.T) {
	err := Target{Name: "Bad", Kind: KindIPFIX, URL: "http://host", Secret: "x", Types: []string{"node-up"}}.Validate()
	if err == nil {
		t.Fatal("the target is valid")
	}
	for _, want := range []string{"DNS label", "scheme of the url", "needs a port", "no secret", "only a webhook"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not name %q", err, want)
		}
	}
}

func TestWants(t *testing.T) {
	all := Target{Kind: KindWebhook}
	some := Target{Kind: KindWebhook, Types: []string{event.NodeDown}}
	if !all.Wants(event.NodeDown) || !all.Wants("anything") {
		t.Error("a webhook without types does not want every event")
	}
	if !some.Wants(event.NodeDown) || some.Wants(event.GatewayFailover) {
		t.Error("a webhook with the type node-down wants another type, or not node-down")
	}
}

// The API shows a target without its secret and without the path and the query of its URL, which
// are often the token of a webhook.
func TestInfoShowsNoSecret(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"https://hooks.example.com/services/T0/B0/XXXX", "https://hooks.example.com/..."},
		{"https://hooks.example.com/?token=1", "https://hooks.example.com/..."},
		{"https://hooks.example.com:8443/", "https://hooks.example.com:8443"},
		{"https://hooks.example.com", "https://hooks.example.com"},
		{"udp://192.0.2.10:4739", "udp://192.0.2.10:4739"},
		{"%zz", ""},
	} {
		info := Target{Name: "x", Kind: KindWebhook, URL: c.url, Secret: "hmac-key", Types: []string{event.NodeDown}}.Info()
		if info.URL != c.want || !info.HasSecret || info.Name != "x" || info.Kind != KindWebhook || len(info.Types) != 1 {
			t.Errorf("the info of %q is %+v, want the URL %q and a secret that is not shown", c.url, info, c.want)
		}
	}
	if info := (Target{Name: "x", Kind: KindOTLP, URL: "http://o.example.com"}).Info(); info.HasSecret {
		t.Error("a target without a secret says it has one")
	}
}

// FuzzValidate checks that Validate answers any target, from an operator's request, with nil or an
// error that wraps ErrInvalid, and that what it accepts can be shown without a secret.
func FuzzValidate(f *testing.F) {
	f.Add("slack", "webhook", "https://hooks.example.com/x", "key", "node-down")
	f.Add("flows", "ipfix", "udp://192.0.2.10:4739", "", "")
	f.Add("otel", "otlp", "http://[::1]:4318", "token", "")
	f.Add("", "", "", "", "")
	f.Add("a", "webhook", "https://u:p@h:99999/%zz", "k", "node-up")
	f.Fuzz(func(t *testing.T, name, kind, url, secret, typ string) {
		tg := Target{Name: name, Kind: kind, URL: url, Secret: secret}
		if typ != "" {
			tg.Types = []string{typ}
		}
		err := tg.Validate()
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v does not wrap ErrInvalid", tg, err)
		}
		if err == nil && (!nameRule.MatchString(tg.Name) || tg.Info().HasSecret != (secret != "")) {
			t.Fatalf("%+v is accepted, but its name or its info is wrong: %+v", tg, tg.Info())
		}
	})
}
