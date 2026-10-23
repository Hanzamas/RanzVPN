package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// auditIDs returns the ids of recs, in order.
func auditIDs(recs []audit.Record) []uint64 {
	out := []uint64{}
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

func sameAuditIDs(got []uint64, want ...uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestAuditLog checks the audit log of SDN-49 in the store: a record keeps what it says, a listing
// is oldest first and follows each condition of its filter and the page that it asks for, the
// retention removes the old records and the oldest beyond the maximum, and an id is never used twice,
// also after everything was removed.
func TestAuditLog(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if recs, err := st.Audit(ctx, audit.Filter{}); err != nil || len(recs) != 0 {
		t.Fatalf("a new store holds the audit records %+v, %v", recs, err)
	}
	base := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	add := func(kind, actor string, at time.Duration) {
		t.Helper()
		r := audit.Record{Time: base.Add(at), Kind: kind, Actor: actor, Source: "192.0.2.7", Outcome: audit.Success, Action: "apply", Revision: 3, Message: "a message"}
		if err := st.AddAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	add(audit.Login, "node:a", 0)
	add(audit.Logout, "node:a", time.Minute)
	add(audit.IntentChange, "token:admin", 2*time.Minute)
	add(audit.Login, "node:b", 3*time.Minute)

	all, err := st.Audit(ctx, audit.Filter{})
	if err != nil || !sameAuditIDs(auditIDs(all), 1, 2, 3, 4) {
		t.Fatalf("the records are %+v, %v, want the four, oldest first", all, err)
	}
	if r := all[2]; r.Kind != audit.IntentChange || r.Actor != "token:admin" || r.Source != "192.0.2.7" || r.Outcome != audit.Success || r.Action != "apply" ||
		r.Revision != 3 || r.Message != "a message" || !r.Time.Equal(base.Add(2*time.Minute)) {
		t.Errorf("the third record is %+v, want everything that was stored", r)
	}

	for _, c := range []struct {
		name string
		f    audit.Filter
		want []uint64
	}{
		{"kind", audit.Filter{Kind: audit.Login}, []uint64{1, 4}},
		{"actor", audit.Filter{Actor: "node:a"}, []uint64{1, 2}},
		{"since", audit.Filter{Since: base.Add(90 * time.Second)}, []uint64{3, 4}},
		{"until", audit.Filter{Until: base.Add(90 * time.Second)}, []uint64{1, 2}},
		{"since and until", audit.Filter{Since: base.Add(30 * time.Second), Until: base.Add(150 * time.Second)}, []uint64{2, 3}},
		{"after", audit.Filter{After: 2}, []uint64{3, 4}},
		{"limit", audit.Filter{Limit: 2}, []uint64{1, 2}},
		{"the next page", audit.Filter{After: 2, Limit: 1}, []uint64{3}},
		{"kind and after", audit.Filter{Kind: audit.Login, After: 1}, []uint64{4}},
		{"a limit out of bounds", audit.Filter{Limit: audit.MaxLimit + 1}, []uint64{1, 2, 3, 4}},
		{"nothing matches", audit.Filter{Actor: "node:c"}, []uint64{}},
	} {
		got, err := st.Audit(ctx, c.f)
		if err != nil || !sameAuditIDs(auditIDs(got), c.want...) {
			t.Errorf("%s: the records are %v, %v, want %v", c.name, auditIDs(got), err, c.want)
		}
	}

	// The retention removes the records made before a time, and then the oldest beyond a maximum
	if err := st.PruneAudit(ctx, base.Add(90*time.Second), 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Audit(ctx, audit.Filter{}); !sameAuditIDs(auditIDs(got), 3, 4) {
		t.Errorf("after removing what is older than 90 s the records are %v, want 3 and 4", auditIDs(got))
	}
	if err := st.PruneAudit(ctx, base.Add(-time.Hour), 5); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Audit(ctx, audit.Filter{}); !sameAuditIDs(auditIDs(got), 3, 4) {
		t.Errorf("a maximum above the number of records removed some: %v", auditIDs(got))
	}
	if err := st.PruneAudit(ctx, base.Add(-time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Audit(ctx, audit.Filter{}); !sameAuditIDs(auditIDs(got), 4) {
		t.Errorf("after a maximum of one record the records are %v, want 4, the newest", auditIDs(got))
	}

	// An id that was used is not used again, also when every record was removed
	if err := st.PruneAudit(ctx, base.Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	add(audit.Logout, "node:b", 4*time.Minute)
	if got, _ := st.Audit(ctx, audit.Filter{}); !sameAuditIDs(auditIDs(got), 5) {
		t.Errorf("the first record after everything was removed is %v, want 5 and not 1 again", auditIDs(got))
	}
}

// TestAuditTargets checks the audit targets in the store: a target keeps its secret and its types, a
// new one starts at the latest record, an update keeps what it was sent, what it was sent only moves
// forward, and the targets of events are not these.
func TestAuditTargets(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if ts, err := st.AuditTargets(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("a new store holds the audit targets %+v, %v", ts, err)
	}
	for range 3 {
		if err := st.AddAudit(ctx, audit.Record{Time: time.Unix(1760000000, 0).UTC(), Kind: audit.Login, Actor: "node:a", Source: "192.0.2.7", Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	hook := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/audit", Secret: "key", Types: []string{audit.AuthFailed}}
	if err := st.PutAuditTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	logs := export.Target{Name: "logs", Kind: export.KindSyslog, URL: "udp://192.0.2.10:514"}
	if err := st.PutAuditTarget(ctx, logs); err != nil {
		t.Fatal(err)
	}
	ts, err := st.AuditTargets(ctx)
	if err != nil || len(ts) != 2 || ts[0].Name != "logs" || ts[1].Name != "siem" {
		t.Fatalf("the audit targets are %+v, %v, want logs and siem", ts, err)
	}
	if got := ts[1]; got.Secret != "key" || got.URL != hook.URL || len(got.Types) != 1 || got.Types[0] != audit.AuthFailed || got.Kind != export.KindWebhook {
		t.Errorf("the target siem is %+v, want what was stored, with its secret and types", got)
	}
	if ts[0].Delivered != 3 || ts[1].Delivered != 3 {
		t.Errorf("a new target starts after the records of before it: it was sent up to %d and %d, want 3", ts[0].Delivered, ts[1].Delivered)
	}
	if others, err := st.Targets(ctx); err != nil || len(others) != 0 {
		t.Errorf("the targets of events hold %+v, %v, want none of the audit targets", others, err)
	}

	// The target is sent two more records, and a record that goes back changes nothing
	for _, id := range []uint64{5, 4} {
		if err := st.AuditDelivered(ctx, "siem", id); err != nil {
			t.Fatal(err)
		}
	}
	if ts, _ = st.AuditTargets(ctx); ts[0].Delivered != 3 || ts[1].Delivered != 5 {
		t.Errorf("what the targets were sent is %d and %d, want 3 and 5", ts[0].Delivered, ts[1].Delivered)
	}

	// An update replaces the target and keeps what it was sent
	hook.URL, hook.Secret, hook.Types = "https://siem.example.com/v2", "", nil
	if err := st.PutAuditTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if ts, _ = st.AuditTargets(ctx); len(ts) != 2 || ts[1].URL != hook.URL || ts[1].Secret != "" || len(ts[1].Types) != 0 || ts[1].Delivered != 5 {
		t.Errorf("after the update the target is %+v, want the new URL, no secret, no types, still sent up to 5", ts[1])
	}

	if err := st.DeleteAuditTarget(ctx, "siem"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAuditTarget(ctx, "siem"); err != nil {
		t.Errorf("deleting an audit target twice: %v", err)
	}
	if ts, _ = st.AuditTargets(ctx); len(ts) != 1 || ts[0].Name != "logs" {
		t.Errorf("after the delete the audit targets are %+v", ts)
	}
}

// TestAuditRetention checks the retention policy in the store: there is none until one is set, and a
// set one replaces the one before.
func TestAuditRetention(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if r, ok, err := st.AuditRetention(ctx); err != nil || ok {
		t.Fatalf("a new store holds the retention %+v (%v), %v, want none", r, ok, err)
	}
	for _, want := range []audit.Retention{{Days: 30, MaxRecords: 5000}, {Days: 90, MaxRecords: 100000}} {
		if err := st.SetAuditRetention(ctx, want); err != nil {
			t.Fatal(err)
		}
		if got, ok, err := st.AuditRetention(ctx); err != nil || !ok || got != want {
			t.Errorf("the retention is %+v (%v), %v, want %+v", got, ok, err, want)
		}
	}
}
