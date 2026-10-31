// The web UI against a controller and the node simulator (SDN-28 #204, the controller
// conformance seam of #176): the controller serves the API and the UI on one TLS port, as
// ranz-controller does, and a headless Chrome drives the pages (ADR-0038). Without rqlited
// (RQLITED) or a Chrome, the tests are skipped, except under CI, where they fail.
package webui_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
	"github.com/Hanzamas/RanzVPN/controller/internal/webui"
)

// waitTimeout bounds every wait for the controller, a node or a page.
const waitTimeout = 30 * time.Second

// pollInterval is how often a test checks a page for what it waits for.
const pollInterval = 50 * time.Millisecond

// action is an entry of ui/assets/actions.json.
type action struct {
	Name   string    `json:"name"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Role   rbac.Role `json:"role"`
}

// actions returns the action table of the UI, by name.
func actions(t *testing.T) map[string]action {
	t.Helper()
	b, err := os.ReadFile("ui/assets/actions.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Actions []action `json:"actions"`
	}
	if err := json.Unmarshal(b, &table); err != nil {
		t.Fatal(err)
	}
	out := map[string]action{}
	for _, a := range table.Actions {
		out[a.Name] = a
	}
	return out
}

// placeholder is a {wildcard} of a path pattern.
var placeholder = regexp.MustCompile(`\{[^}]*\}`)

// TestActionsAreAPIRoutes is the first criterion of SDN-28 against the API itself: every UI
// action is a route the API registered, with the same method and path pattern, so no action
// reaches anything but the public API. With the second criterion: the role the table gives
// each action is the role that the API's Guard asks for it (api.Needs), so the UI hides
// exactly what the API refuses.
func TestActionsAreAPIRoutes(t *testing.T) {
	h := newHarness(t)
	for _, a := range actions(t) {
		concrete := placeholder.ReplaceAllString(a.Path, "x")
		if api.IsLogin(concrete) {
			// The logins are served in front of the Guard, so they are no routes of it (TestLoginActionsAreServedByTheLogins)
			continue
		}
		_, pattern := h.routes.Handler(httptest.NewRequest(a.Method, concrete, nil))
		if want := a.Method + " " + a.Path; pattern != want {
			t.Errorf("the action %s calls %s %s, which the API answers with the route %q, not %q", a.Name, a.Method, concrete, pattern, want)
		}
		if need := api.Needs(a.Method, concrete); need != a.Role {
			t.Errorf("the action %s needs the role %s in the table, and the API asks for %s", a.Name, a.Role, need)
		}
	}
}

// TestRolesLimitTheUI is the second criterion of SDN-28 (#204): roles limit the UI the same way
// they limit the API. A viewer, an operator and an admin sign in and open every page; on each,
// every control of a UI action shows exactly when the role allows the role that the API asks for
// the action (TestActionsAreAPIRoutes ties the two together).
func TestRolesLimitTheUI(t *testing.T) {
	h := newHarness(t)
	table := actions(t)
	ctx := context.Background()
	nodeKey := newKey(t)
	if _, err := h.admin.Apply(ctx, document(nodeKey)); err != nil {
		t.Fatal(err)
	}
	// A revision that waits for its confirmation, so the Revisions page offers the confirmation.
	if _, err := h.admin.ApplyConfirm(ctx, labDocument(nodeKey), time.Hour); err != nil {
		t.Fatal(err)
	}
	secrets := map[rbac.Role]string{
		rbac.Viewer:   h.token(t, "viewer-1", rbac.Viewer),
		rbac.Operator: h.token(t, "operator-1", rbac.Operator),
		rbac.Admin:    h.secret,
	}
	pages := []struct{ path, page string }{
		{"/", "overview"},
		{"/vrfs", "vrfs"},
		{"/networks", "networks"},
		{"/nodes", "nodes"},
		{"/devices", "devices"},
		{"/intent", "intent"},
		{"/revisions", "revisions"},
		{"/revisions?revision=1&from=0&to=2", "revisions"},
		{"/events", "events"},
		{"/licence", "licence"},
		{"/diagnostics", "diagnostics"},
		{"/tokens", "tokens"},
	}
	// control is an element of a page with data-action, and whether it shows.
	type control struct {
		Action  string `json:"action"`
		Visible bool   `json:"visible"`
	}
	// One tab, signed in again for each role: the tab in use is never in the background, where
	// the browser slows its timers down.
	tab := newBrowser(t)
	for _, role := range rbac.Roles {
		h.signIn(t, tab, secrets[role])
		seen := map[string]bool{}
		for _, p := range pages {
			h.visit(t, tab, p.path, p.page)
			controls := run(t, tab, chromedp.Evaluate[[]control](`[...document.querySelectorAll('[data-action]')].map((e) => ({action: e.dataset.action, visible: e.checkVisibility()}))`))
			if len(controls) == 0 {
				t.Errorf("%s: %s has no control of a UI action", role, p.path)
			}
			for _, c := range controls {
				a, ok := table[c.Action]
				if !ok {
					t.Errorf("%s: %s has a control of the action %q, which is not in the table", role, p.path, c.Action)
					continue
				}
				if want := role.Allows(a.Role); c.Visible != want {
					t.Errorf("%s: %s shows a control of the action %s (needs %s): %v, want %v", role, p.path, a.Name, a.Role, c.Visible, want)
				}
				seen[a.Name] = true
			}
			if p.page == "diagnostics" && !role.Allows(rbac.Operator) {
				if notice := run(t, tab, chromedp.Text(chromedp.CSS("#operator-only"))); !strings.Contains(notice, "needs the role operator") {
					t.Errorf("%s: the Diagnostics page says %q", role, notice)
				}
			}
		}
		for _, name := range []string{"apply", "deleteResource", "confirmRevision", "rollback", "diff", "installLicence", "tokens", "createToken", "deleteToken", "diagnosticsBundle", "createDevice"} {
			if !seen[name] && (name != "deleteToken" || role == rbac.Admin) {
				t.Errorf("%s: no page has a control of the action %s", role, name)
			}
		}
		if role != rbac.Admin {
			notice := run(t, tab, chromedp.Text(chromedp.CSS("#admin-only")))
			if !strings.Contains(notice, "needs the role admin") {
				t.Errorf("%s: the API tokens page says %q", role, notice)
			}
		}
	}
}

// TestTheUIWorksThroughTheAPI drives each area of the UI: an operator applies Intent and rolls
// it back, a viewer sees the node that the node simulator runs with its Capabilities and the
// diff between two revisions, an admin makes and deletes an API token. Each change shows in the
// API. A call that the role of the token may not make gets the API's own refusal in the UI.
func TestTheUIWorksThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	nodeKey := newKey(t)
	viewer := h.token(t, "viewer-1", rbac.Viewer)
	operator := h.token(t, "operator-1", rbac.Operator)
	// One tab, signed in again for each role: the tab in use is never in the background, where
	// the browser slows its timers down.
	tab := newBrowser(t)

	h.signIn(t, tab, operator)
	h.visit(t, tab, "/intent", "intent")
	doc, err := json.Marshal(document(nodeKey))
	if err != nil {
		t.Fatal(err)
	}
	if got := h.act(t, tab, chromedp.SetValue(chromedp.CSS("#document"), string(doc)),
		chromedp.Click(chromedp.CSS(`#apply-form button[type="submit"]`))); !strings.Contains(got, "Applied as revision 1.") {
		t.Errorf("the apply says %q", got)
	}
	revs, err := h.admin.Revisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 || revs[0].Operation != intent.OpApply {
		t.Fatalf("after the apply of the UI, the revisions are %+v", revs)
	}

	node := &nodesim.Node{Key: nodeKey, Controller: h.ln.Addr().String(), ControllerKey: h.key.Public(),
		Capabilities: &controlpb.Capabilities{Sku: controlpb.Sku_SKU_PRO, Architecture: controlpb.Architecture_ARCHITECTURE_X64,
			HyperV: true, EgressTier: controlpb.EgressTier_EGRESS_TIER_WINNAT}}
	sctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- node.Serve(sctx) }()
	t.Cleanup(func() {
		stop()
		<-served
	})
	h.waitNode(t, "branch-1", 1)

	h.signIn(t, tab, viewer)
	h.visit(t, tab, "/nodes", "nodes")
	row := run(t, tab, chromedp.Text(chromedp.Search(`//tr[td[1][normalize-space()="branch-1"]]`)))
	for _, want := range []string{"corp", "yes", "Pro", "x64", "2, WinNAT", "443"} {
		if !strings.Contains(row, want) {
			t.Errorf("the row of branch-1 on the Nodes page has no %q: %q", want, row)
		}
	}

	h.signIn(t, tab, operator)
	h.visit(t, tab, "/intent", "intent")
	lab, err := json.Marshal(labDocument(nodeKey))
	if err != nil {
		t.Fatal(err)
	}
	if got := h.act(t, tab, chromedp.SetValue(chromedp.CSS("#document"), string(lab)),
		chromedp.Click(chromedp.CSS(`#apply-form button[type="submit"]`))); !strings.Contains(got, "Applied as revision 2.") {
		t.Errorf("the second apply says %q", got)
	}

	h.signIn(t, tab, viewer)
	h.visit(t, tab, "/revisions?from=1&to=2", "revisions")
	changes := run(t, tab, chromedp.Text(chromedp.CSS("#changes")))
	if !strings.Contains(changes, "added") || !strings.Contains(changes, "lab") {
		t.Errorf("the diff from 1 to 2 shows %q", changes)
	}

	h.signIn(t, tab, operator)
	h.visit(t, tab, "/revisions", "revisions")
	if got := h.act(t, tab, chromedp.Click(chromedp.Search(`//button[normalize-space()="Roll back to 1"]`)),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
		chromedp.Click(chromedp.CSS(`dialog[open] button[value="ok"]`))); !strings.Contains(got, "Rolled back to revision 1 as revision 3.") {
		t.Errorf("the rollback says %q", got)
	}
	rev, err := h.admin.Revision(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Operation != intent.OpRollback || rev.Restores == nil || *rev.Restores != 1 {
		t.Errorf("revision 3 is %+v, want the rollback to 1", rev)
	}

	h.signIn(t, tab, h.secret)
	h.visit(t, tab, "/tokens", "tokens")
	if got := h.act(t, tab, chromedp.SetValue(chromedp.CSS("#name"), "ui-made"),
		chromedp.SetValue(chromedp.CSS("#role"), "operator"),
		chromedp.Click(chromedp.CSS(`#create-form button[type="submit"]`))); !strings.Contains(got, "ui-made (operator) is made") {
		t.Errorf("making the token says %q", got)
	}
	secret := run(t, tab, chromedp.Text(chromedp.CSS("code.secret")))
	if tok, err := h.client(secret).Whoami(ctx); err != nil || tok != (rbac.Token{Name: "ui-made", Role: rbac.Operator}) {
		t.Errorf("the secret the UI showed is the token %+v, %v", tok, err)
	}
	if got := h.act(t, tab, chromedp.Click(chromedp.Search(`//tr[td[1][normalize-space()="ui-made"]]//button`)),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
		chromedp.Click(chromedp.CSS(`dialog[open] button[value="ok"]`))); !strings.Contains(got, "ui-made is deleted") {
		t.Errorf("deleting the token says %q", got)
	}
	if _, err := h.client(secret).Whoami(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the token the UI deleted still answers %v", err)
	}

	// A viewer's tab that calls an operator's action anyway gets the API's own refusal.
	h.signIn(t, tab, viewer)
	got := run(t, tab, chromedp.Evaluate[string](`import('/assets/api.js').then((m) => m.call('apply', {body: {resources: []}})).then(() => 'allowed', (e) => e.status + ' ' + e.message)`,
		chromedp.EvalAwaitPromise))
	_, err = h.client(viewer).Apply(ctx, intent.Document{Resources: []intent.Resource{}})
	var e *api.Error
	if !errors.As(err, &e) {
		t.Fatalf("the viewer's apply through the API gave %v", err)
	}
	if want := fmt.Sprintf("%d %s", e.Status, e.Message); got != want || e.Status != http.StatusForbidden {
		t.Errorf("the viewer's apply through the UI gave %q, and through the API %q", got, want)
	}
}

// TestTheUIPullsTheDiagnosticsBundle is the second criterion of SDN-54 (#247) through the web UI: an
// operator opens the Diagnostics page and takes the bundle with its button, and the archive that the
// button made holds the parts that the controller names and none of the secrets that the log of the
// controller holds. A viewer's page has no button and says why, and the call that a viewer's tab makes
// anyway gets the API's own refusal.
func TestTheUIPullsTheDiagnosticsBundle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	nodeKey := newKey(t)
	if _, err := h.admin.Apply(ctx, document(nodeKey)); err != nil {
		t.Fatal(err)
	}
	viewer := h.token(t, "viewer-1", rbac.Viewer)
	operator := h.token(t, "operator-1", rbac.Operator)
	tab := newBrowser(t)

	h.signIn(t, tab, operator)
	h.visit(t, tab, "/diagnostics", "diagnostics")
	// The page hands the archive to the browser as a Blob; keep the one that the click makes
	run(t, tab, chromedp.Evaluate[chromedp.Void](`(() => {
		window.pulled = null;
		const make = URL.createObjectURL.bind(URL);
		URL.createObjectURL = (blob) => { window.pulled = blob; return make(blob); };
	})()`))
	got := h.act(t, tab, chromedp.Click(chromedp.CSS("#bundle-button")))
	if !strings.Contains(got, "The diagnostics bundle ranz-controller-") || !strings.Contains(got, ".zip is made") {
		t.Errorf("the page says %q after the click", got)
	}
	encoded := run(t, tab, chromedp.Evaluate[string](`window.pulled.arrayBuffer().then((buffer) => {
		const bytes = new Uint8Array(buffer);
		let text = '';
		for (let i = 0; i < bytes.length; i += 0x8000) {
			text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
		}
		return btoa(text);
	})`, chromedp.EvalAwaitPromise))
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("what the button made is no ZIP archive: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
	}
	for _, name := range []string{bundle.ManifestName, "system.json", "controller/status.json", controller.DiagnosticsNodes, controller.DiagnosticsIntent,
		controller.DiagnosticsRevisions, controller.DiagnosticsEvents, controller.DiagnosticsLicence, controller.DiagnosticsIPAM,
		"controller/logs.json", "controller/logs/controller.log"} {
		if _, ok := files[name]; !ok {
			t.Errorf("the bundle that the button made has no part %s", name)
		}
	}
	if log := files["controller/logs/controller.log"]; !strings.Contains(log, "first start: the admin token is created") || !strings.Contains(log, "file=admin.token") {
		t.Errorf("the log of the bundle is\n%s", log)
	}
	if intentPart := files[controller.DiagnosticsIntent]; !strings.Contains(intentPart, "branch-1") || !strings.Contains(intentPart, "corp-lan") {
		t.Errorf("the intent of the bundle is\n%s", intentPart)
	}
	// The log on the disk does hold the secret of the admin token, so that its absence means something
	if disk, err := os.ReadFile(h.logPath); err != nil || !strings.Contains(string(disk), h.secret) {
		t.Fatalf("the log of the controller does not hold the secret that the test plants: %v", err)
	}
	for _, secret := range []string{h.secret, operator, viewer} {
		for name, content := range files {
			if strings.Contains(content, secret) {
				t.Errorf("the part %s of the bundle holds the secret of an API token", name)
			}
		}
	}

	h.signIn(t, tab, viewer)
	h.visit(t, tab, "/diagnostics", "diagnostics")
	if run(t, tab, chromedp.Evaluate[bool](`document.querySelector('#bundle-button').checkVisibility()`)) {
		t.Error("the Diagnostics page of a viewer shows the button that pulls the bundle")
	}
	refused := run(t, tab, chromedp.Evaluate[string](`import('/assets/api.js').then((m) => m.call('diagnosticsBundle', {blob: true})).then(() => 'allowed', (e) => e.status + ' ' + e.message)`,
		chromedp.EvalAwaitPromise))
	_, err = h.client(viewer).DiagnosticsBundle(ctx)
	var refusal *api.Error
	if !errors.As(err, &refusal) {
		t.Fatalf("the viewer's call for the bundle through the API gave %v", err)
	}
	if want := fmt.Sprintf("%d %s", refusal.Status, refusal.Message); refused != want || refusal.Status != http.StatusForbidden {
		t.Errorf("the viewer's call for the bundle through the UI gave %q, and through the API %q", refused, want)
	}
}

// harness is one controller on its own rqlite, with the control stream, the API and the web UI
// on one TLS port, as ranz-controller serves them.
type harness struct {
	key    *keys.Soft     // the controller's Noise static key
	routes *http.ServeMux // the API without its Guard
	ln     net.Listener
	admin  *api.Client // with the admin token
	secret string      // of the admin token
	// logPath is the log of the controller that the diagnostics bundle holds, with the secret in it.
	logPath string
	// sealer is the sealing key of the host, which a test makes stop opening what it sealed (devicekeysr1_test.go).
	sealer *shutSealer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	h := &harness{}
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	// The sealing key of the host, which seals the PresharedKey of a Device that a page makes (SDN-82)
	sealing, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	h.sealer = &shutSealer{Sealer: keys.NewSealer(sealing)}
	st.SetSealer(h.sealer, nil)
	c, err := controller.New(ctx, controller.Config{Store: st, Key: h.key})
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	tokens := rbac.New(st)
	if _, err := tokens.Bootstrap(ctx, func(secret string) error { h.secret = secret; return nil }); err != nil {
		t.Fatal(err)
	}
	if h.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	// The log of the controller, as the service writes it: it holds the secret of the admin token
	logLimits := logfile.LimitsOf(30, 1)
	h.logPath = filepath.Join(t.TempDir(), "controller.log")
	lw, err := logfile.New(h.logPath, logLimits)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(lw, "2026-10-24T10:00:00.000Z INFO first start: the admin token is created token=%s file=admin.token\n", h.secret)
	fmt.Fprintf(lw, "2026-10-24T10:00:01.000Z INFO the web UI is served on %s\n", h.ln.Addr())
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	h.routes = api.Routes(c, tokens, api.Status{ControlAddress: h.ln.Addr().String(), TLSFingerprint: keys.Fingerprint(cert),
		Diagnostics: &api.Diagnostics{LogFile: h.logPath, LogLimits: logLimits}})
	// The logins of users are in front of the Guard, as ranz-controller serves them (SDN-32, SDN-58)
	logins := api.Logins(c, tokens, func() api.Status { return api.Status{TLSFingerprint: keys.Fingerprint(cert)} })
	srv := &port.Server{
		TLS:     &tls.Config{Certificates: []tls.Certificate{cert}},
		Control: c.ServeStream,
		HTTP:    webui.Handler(api.WithLogins(logins, api.Guard(tokens, h.routes))),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(h.ln) }()
	t.Cleanup(func() {
		h.ln.Close()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
		srv.Close()
		c.Close()
		st.Close()
	})
	h.admin = h.client(h.secret)
	return h
}

// url returns the URL of path on the controller's TLS port.
func (h *harness) url(path string) string {
	return "https://" + h.ln.Addr().String() + path
}

// client returns a client of the API that calls with the token secret.
func (h *harness) client(secret string) *api.Client {
	c := api.NewClient(h.url(""))
	c.Token = secret
	return c
}

// token creates the API token name with role and returns its secret.
func (h *harness) token(t *testing.T, name string, role rbac.Role) string {
	t.Helper()
	tok, err := h.admin.CreateToken(context.Background(), name, role)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Secret
}

// newKey returns a new static key, for the simulated node branch-1.
func newKey(t *testing.T) *keys.Soft {
	t.Helper()
	k, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// document returns the Intent of the tests: the VRF corp with the Network corp-lan, and the
// Node branch-1 with the static key node in it.
func document(node *keys.Soft) intent.Document {
	return intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
		{Kind: intent.KindNetwork, Name: "corp-lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`)},
		{Kind: intent.KindNode, Name: "branch-1", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["corp"]}`, base64.StdEncoding.EncodeToString(node.Public())))},
	}}
}

// labDocument returns the Intent of document with the VRF lab added, which no node joins.
func labDocument(node *keys.Soft) intent.Document {
	doc := document(node)
	doc.Resources = append(doc.Resources, intent.Resource{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 99, "ula": "fd99:1:2::/48"}`)})
	return doc
}

// waitNode waits until the API reports node name connected, with generation gen acknowledged.
func (h *harness) waitNode(t *testing.T, name string, gen uint64) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		nodes, err := h.admin.Nodes(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nodes {
			if n.Name == name && n.Connected && n.Generation == gen && n.AckedGeneration == gen {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node %s did not acknowledge generation %d within %v: %+v", name, gen, waitTimeout, nodes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// signIn signs tab in with the token secret on the sign-in page, which goes on to the overview.
func (h *harness) signIn(t *testing.T, tab context.Context, secret string) {
	t.Helper()
	run(t, tab, chromedp.Steps(
		chromedp.Navigate(h.url("/sign-in")),
		chromedp.WaitVisible(chromedp.CSS("#token")),
		chromedp.SetValue(chromedp.CSS("#token"), secret),
		chromedp.Click(chromedp.CSS(`#sign-in button[type="submit"]`)),
		chromedp.WaitReady(chromedp.CSS(`html[data-page="overview"]`)),
	))
	h.settle(t, tab, "overview")
}

// visit opens the page at path, whose <html> has data-page page, and waits until it rendered.
func (h *harness) visit(t *testing.T, tab context.Context, path, page string) {
	t.Helper()
	run(t, tab, chromedp.Navigate(h.url(path)))
	h.settle(t, tab, page)
}

// settle waits until the page page rendered, and fails the test when it shows a problem instead.
func (h *harness) settle(t *testing.T, tab context.Context, page string) {
	t.Helper()
	state := run(t, tab, chromedp.Poll[string](fmt.Sprintf(`(() => {
		const html = document.documentElement;
		return html.dataset.page === %q && ['ready', 'error'].includes(html.dataset.state ?? '') ? html.dataset.state : null;
	})()`, page), chromedp.WithPollingInterval(pollInterval), chromedp.WithPollingTimeout(waitTimeout)))
	if state != "ready" {
		problem := run(t, tab, chromedp.Evaluate[string](`document.querySelector('ranz-problem')?.textContent ?? ''`))
		t.Fatalf("the page %s did not render: %s", page, problem)
	}
}

// act runs steps on the page in tab, which make a change through the API, and returns what the
// page then says in its #result. A problem that the page shows instead fails the test.
func (h *harness) act(t *testing.T, tab context.Context, steps ...chromedp.Action[chromedp.Void]) string {
	t.Helper()
	run(t, tab, chromedp.Evaluate[chromedp.Void](`document.querySelector('#result')?.replaceChildren();
		document.querySelector('ranz-problem')?.replaceChildren();`))
	run(t, tab, chromedp.Steps(steps...))
	// said is what the page says after the steps: its #result, or the problem it shows instead.
	type said struct {
		Result  string `json:"result"`
		Problem string `json:"problem"`
	}
	out := run(t, tab, chromedp.Poll[said](`(() => {
		const result = document.querySelector('#result')?.textContent ?? '';
		const problem = document.querySelector('ranz-problem')?.textContent ?? '';
		return result || problem ? {result, problem} : null;
	})()`, chromedp.WithPollingInterval(pollInterval), chromedp.WithPollingTimeout(waitTimeout)))
	if out.Problem != "" {
		t.Fatalf("the page shows the problem %q", out.Problem)
	}
	return out.Result
}

// newBrowser starts a headless Chrome, which ends with the test, and returns its tab. Without a
// Chrome on the host the test is skipped, except under CI.
func newBrowser(t *testing.T) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// The browser only ever opens the test's own controller on the loopback address.
		chromedp.NoSandbox,
		// The controller's certificate is self-signed until ACME.
		chromedp.Flag("ignore-certificate-errors", true),
	)
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancel)
	ctx, cancel := chromedp.NewContext(actx)
	t.Cleanup(cancel)
	// The first run starts the browser, without a timeout, which would stop the browser with it.
	if err := chromedp.Do(ctx); err != nil {
		if (errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found")) && os.Getenv("CI") == "" {
			t.Skip("no Chrome on this host: install one to run this test")
		}
		t.Fatal(err)
	}
	return ctx
}

// run runs the action in tab within waitTimeout and returns its value.
func run[T any](t *testing.T, tab context.Context, a chromedp.Action[T]) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(tab, waitTimeout)
	defer cancel()
	v, err := chromedp.Run(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// httpStatus returns the HTTP status of an error of the API: 200 for no error, 0 for an error
// that is not an answer of the API.
func httpStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var e *api.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}
