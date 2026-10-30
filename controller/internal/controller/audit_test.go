// Controller conformance for the audit log (SDN-49 #242, ADR-0030), with the harness and the node
// simulator of conformance_test.go: what the controller does makes each kind of audit record once,
// with its actor, its time, its source and its outcome; the records reach a webhook and a syslog
// receiver that an operator configured; the retention removes the old records; and the audit
// targets and the retention are managed through the API with the roles of the API. The API in these
// tests has the audit log on it as ranz-controller serves it (api.AuditRefusals and api.AuditCalls).
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newAuditHarness returns a harness whose controller looks for audit records to send, and for old
// ones to remove, every 50 ms.
func newAuditHarness(t *testing.T) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) {
		c.Audit = audit.Config{Poll: 50 * time.Millisecond, Prune: 50 * time.Millisecond}
	}}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	h.allowLoopback()
	return h
}

// allowLoopback lists the loopback addresses as target hosts, since the receivers of the tests listen
// there (AUD1-DT-9, #457): the targets refuse them otherwise. It writes the store, as an admin does
// through the API, but raises no event, which the tests that count events would see.
func (h *harness) allowLoopback() {
	h.t.Helper()
	if err := h.st.SetAdminDestinations(context.Background(), intent.Destinations{Targets: []string{"127.0.0.0/8", "::1/128"}}); err != nil {
		h.t.Fatal(err)
	}
}

// auditedAPI returns a client of the API of the controller of h as ranz-controller serves it, with
// the audit log on it, that calls with the token secret.
func (h *harness) auditedAPI(secret string) *api.Client {
	h.t.Helper()
	tokens := rbac.New(h.st)
	routes := api.AuditCalls(h.c, api.Routes(h.c, tokens, api.Status{}))
	srv := httptest.NewTLSServer(api.AuditRefusals(audit.NewLog(h.st, nil), api.Guard(tokens, routes)))
	h.t.Cleanup(srv.Close)
	c := api.NewClient(srv.URL)
	c.Token = secret
	return c
}

// waitAudit lists the audit log with the token of c until ok holds of its records, and returns them.
// It fails with the records it saw when ok does not hold within waitTimeout. The listing goes to the
// API of the harness, which has no audit log on it: the audited API records each read of the audit
// log as an access (AUD1-DT-13, #461), and a test that counts what it made would count those too.
func (h *harness) waitAudit(c *api.Client, what string, ok func([]audit.Record) bool) []audit.Record {
	h.t.Helper()
	reader := h.client(c.Token)
	deadline := time.Now().Add(waitTimeout)
	for {
		l, err := reader.Audit(context.Background(), audit.Filter{})
		if err != nil {
			h.t.Fatal(err)
		}
		if ok(l.Records) {
			return l.Records
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the audit log does not hold %s within %v:\n%s", what, waitTimeout, auditLines(l.Records))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// auditOfKind returns the records of kind kind.
func auditOfKind(recs []audit.Record, kind string) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// auditLines returns recs one line each, for the message of a test that fails.
func auditLines(recs []audit.Record) string {
	var b strings.Builder
	for _, r := range recs {
		fmt.Fprintf(&b, "%d %s %s %s %s %q revision %d %q\n", r.ID, r.Kind, r.Actor, r.Source, r.Outcome, r.Action, r.Revision, r.Message)
	}
	return b.String()
}

// checkAuditRecord checks that r has an id, a time between since and now, and the actor, the source,
// the outcome, the action and the revision that are given.
func checkAuditRecord(t *testing.T, r audit.Record, since time.Time, actor, source, outcome, action string, revision uint64) {
	t.Helper()
	if r.ID == 0 || r.Time.Before(since) || r.Time.After(time.Now().Add(time.Minute)) {
		t.Errorf("the %s record has the id %d and the time %v, want an id and a time since %v", r.Kind, r.ID, r.Time, since)
	}
	if r.Actor != actor || r.Source != source || r.Outcome != outcome || r.Action != action || r.Revision != revision {
		t.Errorf("the %s record is %+v, want the actor %q, the source %q, the outcome %q, the action %q and the revision %d",
			r.Kind, r, actor, source, outcome, action, revision)
	}
}

// TestAuditRecordsEachKindOnce is the first criterion of #242: a change of the intent, a node that
// opens its control stream for the first time, the end of that stream and a call with a token that
// is none of the controller's each make their record once, and so does a call that changes something
// but the intent and a read of the licence, and every record has its actor, its time, its source and
// its outcome.
func TestAuditRecordsEachKindOnce(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	since := time.Now().Add(-time.Second)

	// intent-change: an apply, with the revision it made
	res, err := admin.Apply(ctx, h.document("apply1.json"))
	if err != nil {
		t.Fatal(err)
	}
	// enrolment and login: the node opens its control stream, the first one of its static key
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	// logout: the stream ends
	b1.halt()
	// auth-failed: a call with a token that is none of the controller's
	if _, err := h.auditedAPI("ranz_NOTATOKEN").Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with a token that does not exist gave %v, want 401", err)
	}
	// operation: a call that changes something but the intent
	if _, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 90, MaxRecords: 100000}); err != nil {
		t.Fatal(err)
	}
	// access: a read of the licence (AUD1-DT-13, #461)
	if _, err := admin.Licence(ctx); err != nil {
		t.Fatal(err)
	}

	recs := h.waitAudit(admin, "a record of each kind", func(rs []audit.Record) bool {
		for _, k := range audit.Kinds {
			if len(auditOfKind(rs, k)) == 0 {
				return false
			}
		}
		return true
	})
	if len(recs) != len(audit.Kinds) {
		t.Fatalf("the audit log holds %d records, want one of each of the %d kinds:\n%s", len(recs), len(audit.Kinds), auditLines(recs))
	}
	for _, k := range audit.Kinds {
		if n := len(auditOfKind(recs, k)); n != 1 {
			t.Errorf("the audit log holds %d records of the kind %s, want 1:\n%s", n, k, auditLines(recs))
		}
	}
	node, caller := audit.ActorNode("branch-1"), audit.ActorToken(rbac.FirstAdmin)
	checkAuditRecord(t, auditOfKind(recs, audit.Enrolment)[0], since, node, "127.0.0.1", audit.Success, "", 0)
	checkAuditRecord(t, auditOfKind(recs, audit.Login)[0], since, node, "127.0.0.1", audit.Success, "", 0)
	checkAuditRecord(t, auditOfKind(recs, audit.Logout)[0], since, node, "127.0.0.1", audit.Success, "", 0)
	checkAuditRecord(t, auditOfKind(recs, audit.AuthFailed)[0], since, audit.ActorUnknown, "127.0.0.1", audit.Failure, "", 0)
	checkAuditRecord(t, auditOfKind(recs, audit.IntentChange)[0], since, caller, "127.0.0.1", audit.Success, "apply", res.Revision)
	checkAuditRecord(t, auditOfKind(recs, audit.Operation)[0], since, caller, "127.0.0.1", audit.Success, "PUT /api/v1/audit/retention", 0)
	checkAuditRecord(t, auditOfKind(recs, audit.Access)[0], since, caller, "127.0.0.1", audit.Success, "GET /api/v1/licence", 0)
	if m := auditOfKind(recs, audit.AuthFailed)[0].Message; !strings.Contains(m, "is not a token of this controller") {
		t.Errorf("the failed authentication says %q, want why the token was refused", m)
	}
}

// A node whose static key no Node resource holds is a failed authentication, with the key as its
// actor, so that an operator can write the Node resource for it. A node that reconnects makes a login
// and a logout again, and no second enrolment.
func TestAuditRecordsTheStreamsOfNodes(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	h.apply("apply1.json")

	stranger := h.sim("stranger", keyUnknown)
	stranger.refusal(t)
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	b1.halt()
	h.waitNode("branch-1", 1, false)
	b1.start(h)
	h.waitNode("branch-1", 1, true)
	b1.halt()

	recs := h.waitAudit(admin, "two logouts of branch-1", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Logout)) == 2 })
	if n := len(auditOfKind(recs, audit.Enrolment)); n != 1 {
		t.Errorf("a node that reconnects made %d enrolments, want 1:\n%s", n, auditLines(recs))
	}
	if n := len(auditOfKind(recs, audit.Login)); n != 2 {
		t.Errorf("a node that connected twice made %d logins, want 2:\n%s", n, auditLines(recs))
	}
	failed := auditOfKind(recs, audit.AuthFailed)
	if len(failed) != 1 {
		t.Fatalf("a node with a static key that no resource holds made %d failed authentications, want 1:\n%s", len(failed), auditLines(recs))
	}
	wantActor := "key:" + base64.StdEncoding.EncodeToString(keyUnknown.Public())
	if failed[0].Actor != wantActor || failed[0].Source != "127.0.0.1" || failed[0].Outcome != audit.Failure ||
		!strings.Contains(failed[0].Message, "no Node resource has the static key of this node") {
		t.Errorf("the failed authentication of the stranger is %+v, want the actor %q", failed[0], wantActor)
	}
}

// The refusals of the source restrictions of SDN-39 are failed authentications and enrolments in the
// audit log too: a node that a Network does not allow to enrol from its address is an enrolment with
// the outcome failure, which a later enrolment that is allowed follows, and a request from an address
// outside the admin source allowlist is a failed authentication of an actor that is not known.
func TestAuditRecordsTheRefusalsOfTheSourceRestrictions(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	h.apply("apply1.json")

	// corp-lan allows documentation addresses only; the node of the VRF comes from 127.0.0.1
	if _, err := h.api.Apply(ctx, corpLan(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	b1 := h.sim("branch-1", keyBranch1)
	b1.refusal(t)
	recs := h.waitAudit(admin, "the refused enrolment", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Enrolment)) == 1 })
	refused := auditOfKind(recs, audit.Enrolment)[0]
	if refused.Outcome != audit.Failure || refused.Actor != "node:branch-1" || refused.Source != "127.0.0.1" ||
		!strings.Contains(refused.Message, `which Network "corp-lan" does not allow to enrol`) {
		t.Errorf("the refused enrolment is %+v, want a failure of branch-1 from 127.0.0.1 that names the Network", refused)
	}
	if n := len(auditOfKind(recs, audit.Login)); n != 0 {
		t.Errorf("a node that was refused made %d logins", n)
	}

	// A Network that allows the address admits the node: its first Hello is an enrolment that succeeded
	if _, err := h.api.Apply(ctx, corpLan(t)); err != nil {
		t.Fatal(err)
	}
	b1.start(h)
	h.waitNode("branch-1", 1, true)
	recs = h.waitAudit(admin, "the enrolment that succeeded", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Enrolment)) == 2 })
	if second := auditOfKind(recs, audit.Enrolment)[1]; second.Outcome != audit.Success || second.Actor != "node:branch-1" {
		t.Errorf("the second enrolment is %+v, want the first Hello of the node, that succeeded", second)
	}

	// The admin source allowlist refuses a request from outside it: no token is looked at
	if _, err := h.api.SetAdminSources(ctx, []string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	web := api.NewSources(h.st, nil, 0).WithAudit(audit.NewLog(h.st, nil)).Restrict(h.port.HTTP)
	req := httptest.NewRequest(http.MethodGet, "https://ctl.example/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.9:40000"
	req.Header.Set("Authorization", "Bearer "+h.admin)
	w := httptest.NewRecorder()
	web.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request from outside the admin source allowlist was not refused: %d", w.Code)
	}
	recs = h.waitAudit(admin, "the refused request", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.AuthFailed)) == 1 })
	denied := auditOfKind(recs, audit.AuthFailed)[0]
	if denied.Outcome != audit.Failure || denied.Actor != audit.ActorUnknown || denied.Source != "198.51.100.9" ||
		!strings.Contains(denied.Message, "the address is outside the admin source allowlist") {
		t.Errorf("the refused request is %+v, want a failed authentication of an unknown actor from 198.51.100.9", denied)
	}
}

// Every revision of the intent has one record: an apply, a delete, a rollback, an apply that nobody
// confirms and the automatic rollback that follows it, with the revision each made, the token that
// asked for it, and the system for the automatic rollback. An apply that is refused is a record too,
// with no revision and the reason.
func TestAuditRecordsEveryRevision(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()

	bad := intent.Document{Resources: []intent.Resource{{Kind: intent.KindNode, Name: "Bad_Name"}}}
	if _, err := admin.Apply(ctx, bad); httpStatus(err) != http.StatusBadRequest {
		t.Fatalf("an apply of an invalid intent gave %v, want 400", err)
	}
	if _, err := admin.Apply(ctx, h.document("apply1.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Apply(ctx, h.document("apply2.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Delete(ctx, intent.KindNetwork, "corp-dmz"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Rollback(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ApplyConfirm(ctx, h.document("apply3.json"), controller.MinConfirm); err != nil {
		t.Fatal(err)
	}

	recs := h.waitAudit(admin, "the revisions 1 to 6", func(rs []audit.Record) bool {
		return len(auditOfKind(rs, audit.IntentChange)) == 7
	})
	changes := auditOfKind(recs, audit.IntentChange)
	failure := changes[0]
	if failure.Outcome != audit.Failure || failure.Action != "apply" || failure.Revision != 0 || failure.Actor != "token:admin" ||
		!strings.Contains(failure.Message, `Node "Bad_Name"`) {
		t.Errorf("the apply that was refused is %+v, want a failure with the reason and no revision", failure)
	}
	var want = []struct {
		action, actor, source, message string
	}{
		{"apply", "token:admin", "127.0.0.1", ""},
		{"apply", "token:admin", "127.0.0.1", ""},
		{"delete", "token:admin", "127.0.0.1", ""},
		{"rollback", "token:admin", "127.0.0.1", "restores revision 1"},
		{"apply", "token:admin", "127.0.0.1", ""},
		{"automatic-rollback", audit.ActorSystem, audit.SourceLocal, "reverts revision 5, which nobody confirmed in time"},
	}
	for i, w := range want {
		r := changes[i+1]
		if r.Revision != uint64(i+1) || r.Action != w.action || r.Actor != w.actor || r.Source != w.source || r.Outcome != audit.Success || r.Message != w.message {
			t.Errorf("the record of revision %d is %+v, want the action %q, the actor %q, the source %q and the message %q", i+1, r, w.action, w.actor, w.source, w.message)
		}
	}
	if len(recs) != 7 {
		t.Errorf("the audit log holds %d records, want the 7 of the intent and nothing else:\n%s", len(recs), auditLines(recs))
	}
}

// The first start of a controller makes its first revision, by the system, and is recorded.
func TestAuditRecordsTheFirstStart(t *testing.T) {
	h := newFirstStartHarness(t)
	recs := h.waitAudit(h.auditedAPI(h.admin), "the first start", func(rs []audit.Record) bool { return len(rs) == 1 })
	checkAuditRecord(t, recs[0], time.Now().Add(-time.Minute), audit.ActorSystem, audit.SourceLocal, audit.Success, "first-start", 1)
	if recs[0].Kind != audit.IntentChange {
		t.Errorf("the first start is recorded as %s, want %s", recs[0].Kind, audit.IntentChange)
	}
}

// auditHook is a test webhook for the audit log: an HTTP server that checks the signature of each
// call and keeps the record and the headers of it.
type auditHook struct {
	*httptest.Server
	mu      sync.Mutex
	records []audit.Record
	headers []http.Header
}

func newAuditHook(t *testing.T) *auditHook {
	h := &auditHook{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte("audit-key"))
		mac.Write(body)
		if r.Header.Get("X-Ranz-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var rec audit.Record
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.records = append(h.records, rec)
		h.headers = append(h.headers, r.Header.Clone())
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *auditHook) got() ([]audit.Record, []http.Header) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]audit.Record(nil), h.records...), append([]http.Header(nil), h.headers...)
}

// auditSyslog is a test syslog receiver over UDP: it keeps each datagram it is sent.
type auditSyslog struct {
	conn net.PacketConn
	mu   sync.Mutex
	msgs []string
}

func newAuditSyslog(t *testing.T) *auditSyslog {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &auditSyslog{conn: pc}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, string(buf[:n]))
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *auditSyslog) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

// TestAuditRecordsReachSyslogAndWebhookReceivers is the first half of the second criterion of #242:
// a webhook and a syslog receiver that an operator configured through the API get the records, each
// in the form of its kind, in the order they were made. The webhook was made first and gets every
// record, the syslog receiver the ones after the call that made it.
func TestAuditRecordsReachSyslogAndWebhookReceivers(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	hook := newAuditHook(t)
	logs := newAuditSyslog(t)

	if _, err := admin.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: hook.URL, Secret: "audit-key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.PutAuditTarget(ctx, export.Target{Name: "logs", Kind: export.KindSyslog, URL: "udp://" + logs.conn.LocalAddr().String()}); err != nil {
		t.Fatal(err)
	}
	// An apply, a failed authentication, and a node that joins and leaves
	if _, err := admin.Apply(ctx, h.document("apply1.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.auditedAPI("ranz_NOTATOKEN").Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with a token that does not exist gave %v, want 401", err)
	}
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	b1.halt()

	all := h.waitAudit(admin, "the logout of branch-1", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Logout)) == 1 })
	if len(all) != 7 || all[0].ID != 1 || all[0].Action != "PUT /api/v1/audit/targets/siem" || all[1].Action != "PUT /api/v1/audit/targets/logs" {
		t.Fatalf("the audit log holds\n%swant the two calls that made the targets, the apply, the failed authentication, and the enrolment, login and logout of the node", auditLines(all))
	}
	host, _ := os.Hostname()
	deadline := time.Now().Add(waitTimeout)
	for {
		recs, _ := hook.got()
		if len(recs) >= len(all) && len(logs.got()) >= len(all)-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within %v the webhook got %d of the %d records and the syslog receiver %d of the %d", waitTimeout, len(recs), len(all), len(logs.got()), len(all)-1)
		}
		time.Sleep(20 * time.Millisecond)
	}

	recs, headers := hook.got()
	for i, want := range all {
		got := recs[i]
		if got.ID != want.ID || got.Kind != want.Kind || got.Actor != want.Actor || got.Source != want.Source || got.Outcome != want.Outcome ||
			got.Action != want.Action || got.Revision != want.Revision || got.Message != want.Message || !got.Time.Equal(want.Time) {
			t.Errorf("the webhook got %+v as its record %d, want %+v", got, i+1, want)
		}
		if hd := headers[i]; hd.Get("X-Ranz-Audit") != want.Kind || hd.Get("X-Ranz-Audit-Id") != fmt.Sprint(want.ID) || hd.Get("Content-Type") != "application/json" {
			t.Errorf("the headers of the call for record %d are %v", want.ID, hd)
		}
	}
	msgs := logs.got()
	for i, want := range all[1:] {
		if wantMsg := want.Syslog(strings.ToLower(host)); msgs[i] != wantMsg {
			t.Errorf("the syslog receiver got\n%s\nas its message %d, want\n%s", msgs[i], i+1, wantMsg)
		}
	}
	// The message of a failed authentication, the third that the syslog receiver got, is a warning
	if m := msgs[2]; !strings.HasPrefix(m, "<108>1 ") || !strings.Contains(m, " - auth-failed - kind=auth-failed ") {
		t.Errorf("the message of the failed authentication is %q", m)
	}
}

// A webhook that wants some kinds of record is sent those only.
func TestAuditWebhookGetsTheKindsItWants(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	hook := newAuditHook(t)
	if _, err := admin.PutAuditTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: hook.URL, Secret: "audit-key",
		Types: []string{audit.AuthFailed, audit.IntentChange}}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Apply(ctx, h.document("apply1.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.auditedAPI("ranz_NOTATOKEN").Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a call with a token that does not exist gave %v, want 401", err)
	}
	if _, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 90, MaxRecords: 100000}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		recs, _ := hook.got()
		if len(recs) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the webhook got %d records within %v, want 2", len(recs), waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// What it does not want is skipped: it is not sent later either
	time.Sleep(4 * 50 * time.Millisecond)
	recs, _ := hook.got()
	if len(recs) != 2 || recs[0].Kind != audit.IntentChange || recs[1].Kind != audit.AuthFailed {
		t.Errorf("the webhook for failed authentications and changes of the intent got %+v, want the apply and the failed authentication", recs)
	}
}

// TestAuditRetentionRemovesOldRecords is the second half of the second criterion of #242: the old
// records are removed, by the policy in force, which is a year until an operator sets another.
func TestAuditRetentionRemovesOldRecords(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	now := time.Now().UTC()
	record := func(actor string, age time.Duration) {
		t.Helper()
		if err := h.c.RecordAudit(ctx, audit.Record{Time: now.Add(-age), Kind: audit.Login, Actor: actor, Source: "192.0.2.7", Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	has := func(recs []audit.Record, actor string) bool {
		for _, r := range recs {
			if r.Actor == actor {
				return true
			}
		}
		return false
	}

	if got, err := admin.AuditRetention(ctx); err != nil || got != audit.DefaultRetention {
		t.Fatalf("the retention of a new controller is %+v, %v, want %+v", got, err, audit.DefaultRetention)
	}
	record("node:ancient", 2*365*24*time.Hour)
	record("node:fresh", time.Hour)
	h.waitAudit(admin, "the record of two years ago gone and the fresh one kept", func(rs []audit.Record) bool {
		return !has(rs, "node:ancient") && has(rs, "node:fresh")
	})

	// An operator shortens the policy to a week
	if got, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 7, MaxRecords: 100000}); err != nil || got.Days != 7 {
		t.Fatalf("setting the retention gave %+v, %v", got, err)
	}
	record("node:month-old", 30*24*time.Hour)
	record("node:day-old", 24*time.Hour)
	recs := h.waitAudit(admin, "the record of a month ago gone", func(rs []audit.Record) bool { return !has(rs, "node:month-old") })
	if !has(recs, "node:day-old") || !has(recs, "node:fresh") || len(auditOfKind(recs, audit.Operation)) != 1 {
		t.Errorf("a policy of a week removed more than the records of before it:\n%s", auditLines(recs))
	}
	if got, err := admin.AuditRetention(ctx); err != nil || got.Days != 7 || got.MaxRecords != 100000 {
		t.Errorf("the retention is %+v, %v, want the one that was set", got, err)
	}
}

// A listing of the audit log goes through its pages with the id of the last record, and follows its
// filter. A record that is not valid is refused.
func TestAuditListingPagesAndFilters(t *testing.T) {
	h := newAuditHarness(t)
	// The API of the harness has no audit log on it: the audited API would record each listing as an
	// access (AUD1-DT-13, #461), which the next page would list
	admin := h.client(h.admin)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		kind := audit.Login
		if i%2 == 0 {
			kind = audit.Logout
		}
		if err := h.c.RecordAudit(ctx, audit.Record{Kind: kind, Actor: fmt.Sprintf("node:p%d", i), Source: "192.0.2.7", Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.c.RecordAudit(ctx, audit.Record{Kind: "reboot", Outcome: audit.Success}); !errors.Is(err, audit.ErrInvalid) {
		t.Errorf("a record of a kind that does not exist gave %v, want an error that wraps audit.ErrInvalid", err)
	}

	first, err := admin.Audit(ctx, audit.Filter{Limit: 2})
	if err != nil || len(first.Records) != 2 || first.Records[0].Actor != "node:p1" || first.Records[1].Actor != "node:p2" || first.Next != first.Records[1].ID {
		t.Fatalf("the first page is %+v, %v, want two records and the id of the second as the next", first, err)
	}
	second, err := admin.Audit(ctx, audit.Filter{Limit: 2, After: first.Next})
	if err != nil || len(second.Records) != 2 || second.Records[0].Actor != "node:p3" || second.Next != second.Records[1].ID {
		t.Fatalf("the second page is %+v, %v", second, err)
	}
	last, err := admin.Audit(ctx, audit.Filter{Limit: 2, After: second.Next})
	if err != nil || len(last.Records) != 1 || last.Records[0].Actor != "node:p5" || last.Next != 0 {
		t.Fatalf("the last page is %+v, %v, want one record and no next", last, err)
	}
	logouts, err := admin.Audit(ctx, audit.Filter{Kind: audit.Logout})
	if err != nil || len(logouts.Records) != 2 || logouts.Records[0].Actor != "node:p2" || logouts.Records[1].Actor != "node:p4" {
		t.Errorf("the logouts are %+v, %v", logouts, err)
	}
	one, err := admin.Audit(ctx, audit.Filter{Actor: "node:p3"})
	if err != nil || len(one.Records) != 1 || one.Records[0].Kind != audit.Login {
		t.Errorf("the records of node:p3 are %+v, %v", one, err)
	}
	if _, err := admin.Audit(ctx, audit.Filter{Kind: "reboot"}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a listing of a kind that does not exist gave %v, want 400", err)
	}
}

// The audit log and the retention are read by every role; the audit targets are read, and the targets
// and the retention changed, by an admin only (AUD1-DT-9, #457); a target that is not valid is
// refused, and the API shows no secret.
func TestAuditTargetsAndRetentionAreManagedThroughTheAPI(t *testing.T) {
	h := newAuditHarness(t)
	ctx := context.Background()
	viewer := h.auditedAPI(h.token("viewer-1", rbac.Viewer))
	operator := h.auditedAPI(h.token("operator-1", rbac.Operator))
	admin := h.auditedAPI(h.token("admin-2", rbac.Admin))
	target := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/audit/T0/XXXX", Secret: "s3cret-hmac-key", Types: []string{audit.AuthFailed}}

	// The calls on audit targets and the change of the retention need admin (AUD1-DT-9, #457): an
	// operator must not send the audit log where he pleases, nor shorten it
	for _, c := range []*api.Client{viewer, operator} {
		if _, err := c.PutAuditTarget(ctx, target); httpStatus(err) != http.StatusForbidden {
			t.Errorf("a role below admin made an audit target: %v", err)
		}
		if _, err := c.AuditTargets(ctx); httpStatus(err) != http.StatusForbidden {
			t.Errorf("a role below admin listed the audit targets: %v", err)
		}
		if _, err := c.DeleteAuditTarget(ctx, "siem"); httpStatus(err) != http.StatusForbidden {
			t.Errorf("a role below admin deleted an audit target: %v", err)
		}
		if _, err := c.SetAuditRetention(ctx, audit.Retention{Days: 30, MaxRecords: 5000}); httpStatus(err) != http.StatusForbidden {
			t.Errorf("a role below admin set the retention: %v", err)
		}
	}
	info, err := admin.PutAuditTarget(ctx, target)
	if err != nil || !info.HasSecret || info.URL != "https://siem.example.com/..." || len(info.Types) != 1 {
		t.Fatalf("an admin made the audit target and got %+v, %v, want it without its secret and the path of its URL", info, err)
	}
	if list, err := admin.AuditTargets(ctx); err != nil || len(list) != 1 || list[0].Name != "siem" || strings.Contains(asJSON(t, list), "s3cret") {
		t.Errorf("an admin lists the audit targets %+v, %v", list, err)
	}
	if others, err := operator.Targets(ctx); err != nil || len(others) != 0 {
		t.Errorf("the targets of events hold %+v, %v, want none of the audit targets", others, err)
	}

	for name, bad := range map[string]export.Target{
		"a kind of the events": {Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"},
		"a syslog secret":      {Name: "logs", Kind: export.KindSyslog, URL: "udp://192.0.2.10:514", Secret: "x"},
		"a kind of record":     {Name: "logs", Kind: export.KindSyslog, URL: "udp://192.0.2.10:514", Types: []string{"node-down"}},
	} {
		if _, err := admin.PutAuditTarget(ctx, bad); httpStatus(err) != http.StatusBadRequest {
			t.Errorf("%s: the audit target was answered with %v, want 400", name, err)
		}
	}
	if _, err := admin.DeleteAuditTarget(ctx, "gone"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("deleting an audit target that is not there gave %v, want 404", err)
	}
	if gone, err := admin.DeleteAuditTarget(ctx, "siem"); err != nil || gone.Name != "siem" {
		t.Errorf("deleting the audit target gave %+v, %v", gone, err)
	}
	if list, err := admin.AuditTargets(ctx); err != nil || len(list) != 0 {
		t.Errorf("after the delete an admin lists %+v, %v", list, err)
	}

	if _, err := admin.SetAuditRetention(ctx, audit.Retention{}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a retention of nothing was answered with %v, want 400", err)
	}
	if got, err := admin.SetAuditRetention(ctx, audit.Retention{Days: 30, MaxRecords: 5000}); err != nil || got.Days != 30 {
		t.Errorf("an admin set the retention and got %+v, %v", got, err)
	}
	if got, err := viewer.AuditRetention(ctx); err != nil || got != (audit.Retention{Days: 30, MaxRecords: 5000}) {
		t.Errorf("a viewer reads the retention %+v, %v", got, err)
	}

	// What the admin changed is in the audit log, under the admin: the failures too, and no call that
	// the Guard refused
	recs := h.waitAudit(viewer, "the eight operations of the admin", func(rs []audit.Record) bool { return len(auditOfKind(rs, audit.Operation)) == 8 })
	var rejected int
	for _, r := range auditOfKind(recs, audit.Operation) {
		if r.Actor != "token:admin-2" {
			t.Errorf("the operation %+v is not the admin's", r)
		}
		if r.Outcome == audit.Failure {
			rejected++
			if r.Message == "" {
				t.Errorf("the failed operation %+v says no reason", r)
			}
		}
	}
	if rejected != 5 {
		t.Errorf("%d operations of the admin failed, want 5 (the three targets that are not valid, the delete of one that is not there, and the retention of nothing):\n%s", rejected, auditLines(recs))
	}
}
