package audit

import (
	"context"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// An audit target is checked when it is used (AUD1-DT-9, #457): a webhook or a syslog receiver on
// loopback that no admin lists gets no record, however the target came into the store, and gets them
// once a listed prefix holds it.
func TestExporterSendsOnlyWhereTheGuardAllows(t *testing.T) {
	deny := &export.Guard{Allowed: func(context.Context) ([]string, error) { return nil, nil }}
	allow := &export.Guard{Allowed: func(context.Context) ([]string, error) { return []string{"127.0.0.0/8"}, nil }}

	s := &memStore{}
	h := newHook(t)
	logs := newSyslogReceiver(t, "udp")
	s.add(Login)
	s.put(export.Target{Name: "siem", Kind: export.KindWebhook, URL: h.URL}, 0)
	s.put(export.Target{Name: "logs", Kind: export.KindSyslog, URL: "udp://" + logs.addr}, 0)

	x := NewExporter(s, nil, "ranz-controller/test", 0)
	x.SetGuard(deny)
	x.step(context.Background())
	if h.calls.Load() != 0 || s.deliveredTo("siem") != 0 || s.deliveredTo("logs") != 0 {
		t.Errorf("the guard let %d calls through to the webhook, and the targets were sent up to %d and %d, want none",
			h.calls.Load(), s.deliveredTo("siem"), s.deliveredTo("logs"))
	}

	x.SetGuard(allow)
	x.attempts = map[string]attempt{}
	x.step(context.Background())
	if len(h.records()) != 1 || s.deliveredTo("siem") != 1 || s.deliveredTo("logs") != 1 {
		t.Errorf("with the prefix listed the webhook got %d records and the targets were sent up to %d and %d, want 1 each",
			len(h.records()), s.deliveredTo("siem"), s.deliveredTo("logs"))
	}
}
