// The user portal in the web UI (SDN-58 #251), against a controller and the node simulator as the other tests of
// the UI run: a User signs in with its name and its password, sees its own devices and none of anybody else's,
// adds a device, removes it, makes a join token that enrols a device, revokes another, and signs out. The
// portal and the console keep their tokens apart, and every control of the portal is an action of the table.
package webui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/webui"
)

const (
	portalAlicePassword = "alice has a long password"
	portalBobPassword   = "bob keeps a long password too"
)

// TestThePortalPagesAreServed: each page of the portal, its scripts and its style are files of the UI at their
// own paths, with the security headers of every file, for GET and HEAD only.
func TestThePortalPagesAreServed(t *testing.T) {
	h := webui.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, c := range []struct{ path, contentType, contains string }{
		{"/portal", "text/html; charset=utf-8", `data-page="portal"`},
		{"/portal-sign-in", "text/html; charset=utf-8", `data-page="portal-sign-in"`},
		{"/portal-join", "text/html; charset=utf-8", `data-page="portal-join"`},
		{"/assets/portal.js", "text/javascript; charset=utf-8", "export async function start"},
		{"/assets/portal-devices.js", "text/javascript; charset=utf-8", "removeSelfDevice"},
		{"/assets/portal-join.js", "text/javascript; charset=utf-8", "makeJoinToken"},
		{"/assets/portal-sign-in.js", "text/javascript; charset=utf-8", "signIn"},
		{"/assets/portal.css", "text/css; charset=utf-8", "header.portal"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != c.contentType || !strings.Contains(w.Body.String(), c.contains) {
			t.Errorf("GET %s: %d, %q, want 200 and %q with %q", c.path, w.Code, w.Header().Get("Content-Type"), c.contentType, c.contains)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: the headers are %v", c.path, w.Header())
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, c.path, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: %d, want 405", c.path, w.Code)
		}
	}
}

// TestLoginActionsAreServedByTheLogins: the actions of the table that call the logins, which are in front of the
// Guard and so are no routes of its mux (TestActionsAreAPIRoutes skips them), are the sign-in, which needs no
// token, and the sign-out, which needs the token that it ends; and the logins do serve each.
func TestLoginActionsAreServedByTheLogins(t *testing.T) {
	h := newHarness(t)
	found := map[string]rbac.Role{}
	for _, a := range actions(t) {
		concrete := placeholder.ReplaceAllString(a.Path, "x")
		if !api.IsLogin(concrete) {
			continue
		}
		found[a.Name] = a.Role
		req, err := http.NewRequest(a.Method, h.url(concrete), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := h.client("").HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("the action %s calls %s %s, which the logins answer with %d", a.Name, a.Method, concrete, resp.StatusCode)
		}
	}
	if want := map[string]rbac.Role{"signIn": "public", "signOut": rbac.Self}; fmt.Sprint(found) != fmt.Sprint(want) {
		t.Errorf("the actions that call the logins are %v, want %v", found, want)
	}
}

// portalControl is an element of a page of the portal with data-action, and whether it shows.
type portalControl struct {
	Action  string `json:"action"`
	Visible bool   `json:"visible"`
}

// portalSignIn signs tab in to the portal as the User user with the password, on its sign-in page, which goes
// on to the page that My devices is.
func (h *harness) portalSignIn(t *testing.T, tab context.Context, user, password string) {
	t.Helper()
	run(t, tab, chromedp.Steps(
		chromedp.Navigate(h.url("/portal-sign-in")),
		chromedp.WaitVisible(chromedp.CSS("#user")),
		chromedp.SetValue(chromedp.CSS("#user"), user),
		chromedp.SetValue(chromedp.CSS("#password"), password),
		chromedp.Click(chromedp.CSS(`#sign-in button[type="submit"]`)),
		chromedp.WaitReady(chromedp.CSS(`html[data-page="portal"]`)),
	))
	h.settle(t, tab, "portal")
}

// problemOf waits until the page shows a problem and returns what it says.
func (h *harness) problemOf(t *testing.T, tab context.Context) string {
	t.Helper()
	return run(t, tab, chromedp.Poll[string](`(() => document.querySelector('ranz-problem')?.textContent || null)()`,
		chromedp.WithPollingInterval(pollInterval), chromedp.WithPollingTimeout(waitTimeout)))
}

// portalRows waits until the table with the selector table has want rows, and returns the text of each.
func portalRows(t *testing.T, tab context.Context, table string, want int) []string {
	t.Helper()
	return run(t, tab, chromedp.Poll[[]string](fmt.Sprintf(`(() => {
		const rows = [...document.querySelectorAll('%s tbody tr')].map((r) => r.textContent.trim());
		return rows.length === %d ? rows : null;
	})()`, table, want), chromedp.WithPollingInterval(pollInterval), chromedp.WithPollingTimeout(waitTimeout)))
}

// portalControls checks that each control of a UI action on the page that tab shows is an action of the table
// that the portal's token makes, that it shows, and that the page has each of the actions that want names.
func portalControls(t *testing.T, tab context.Context, page string, want ...string) {
	t.Helper()
	table := actions(t)
	controls := run(t, tab, chromedp.Evaluate[[]portalControl](`[...document.querySelectorAll('[data-action]')].map((e) => ({action: e.dataset.action, visible: e.checkVisibility()}))`))
	seen := map[string]bool{}
	for _, c := range controls {
		a, ok := table[c.Action]
		switch {
		case !ok:
			t.Errorf("%s has a control of the action %q, which is not in the table", page, c.Action)
		case a.Role != rbac.Self && a.Role != "public":
			t.Errorf("%s has a control of the action %s, which needs the role %s, and the portal's token holds none", page, a.Name, a.Role)
		case !c.Visible:
			t.Errorf("%s does not show its control of the action %s", page, a.Name)
		}
		seen[c.Action] = true
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("%s has no control of the action %s", page, name)
		}
	}
}

// portalKey returns the base64 of the public half of key, as ranz node key shows it.
func portalKey(key keys.Static) string {
	return base64.StdEncoding.EncodeToString(key.Public())
}

// portalDevices returns the names of the devices that the controller holds for the User user, the Nodes that name
// it as their owner, as the API of the console lists them.
func portalDevices(t *testing.T, h *harness, user string) []string {
	t.Helper()
	users, err := h.admin.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == user {
			names := make([]string, len(u.Devices))
			for i, d := range u.Devices {
				names[i] = d.Name
			}
			return names
		}
	}
	t.Fatalf("the controller holds no User %s", user)
	return nil
}

// TestAUserUsesThePortal drives the portal as the two criteria of SDN-58 (#251) ask for it: alice signs in and
// sees her laptop and nothing of the laptop of bob; she adds a phone, which the controller then holds as her
// device, and removes it; she makes a join token, and a device that presents it becomes her device; she revokes
// a second token, which then enrols nothing. What the controller refuses is shown in its own words. The portal
// and the console keep their tokens apart, and the sign-out ends the token at the controller.
func TestAUserUsesThePortal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	laptopKey, bobKey, phoneKey, nasKey := newKey(t), newKey(t), newKey(t), newKey(t)
	// VRF default, which a Node that names none joins, so a device that joins has an address of its Network
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: intent.DefaultVRF, Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lan", Spec: json.RawMessage(`{"vrf": "default", "ipv4Pool": "10.10.0.0/24"}`)},
		{Kind: intent.KindUser, Name: "alice", Spec: json.RawMessage(`{"displayName": "Alice", "maxDevices": 4}`)},
		{Kind: intent.KindUser, Name: "bob", Spec: json.RawMessage(`{}`)},
		{Kind: intent.KindNode, Name: "alice-laptop", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "owner": "alice"}`, portalKey(laptopKey)))},
		{Kind: intent.KindNode, Name: "bob-laptop", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "owner": "bob"}`, portalKey(bobKey)))},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	for user, password := range map[string]string{"alice": portalAlicePassword, "bob": portalBobPassword} {
		if _, err := h.admin.SetUserPassword(ctx, user, password); err != nil {
			t.Fatal(err)
		}
	}
	tab := newBrowser(t)

	// A page of the portal without a token goes to the sign-in, and a wrong password is refused in the words of
	// the controller, with the field emptied
	run(t, tab, chromedp.Navigate(h.url("/portal")))
	h.settle(t, tab, "portal-sign-in")
	portalControls(t, tab, "the sign-in", "signIn")
	run(t, tab, chromedp.Steps(
		chromedp.SetValue(chromedp.CSS("#user"), "alice"),
		chromedp.SetValue(chromedp.CSS("#password"), "not the password of alice"),
		chromedp.Click(chromedp.CSS(`#sign-in button[type="submit"]`)),
	))
	if refused := h.problemOf(t, tab); !strings.Contains(refused, "the user name or the password is wrong") {
		t.Errorf("a wrong password: the sign-in says %q", refused)
	}
	if left := run(t, tab, chromedp.Evaluate[string](`document.querySelector('#password').value`)); left != "" {
		t.Errorf("the password field still holds %q after a refusal", left)
	}

	// alice signs in, and the portal shows her, her laptop and nothing of bob
	h.portalSignIn(t, tab, "alice", portalAlicePassword)
	portalControls(t, tab, "My devices", "selfDevices", "addSelfDevice", "removeSelfDevice", "signOut")
	rows := portalRows(t, tab, "#devices", 1)
	if !strings.Contains(rows[0], "alice-laptop") || !strings.Contains(rows[0], "Offline") || !strings.Contains(rows[0], "10.10.0.") {
		t.Errorf("the row of the laptop of alice is %q, want its name, that it is offline and its address", rows[0])
	}
	if account := run(t, tab, chromedp.Text(chromedp.CSS("#account"))); !strings.Contains(account, "Alice") || !strings.Contains(account, "1 of 4") {
		t.Errorf("the account is %q, want the name of alice and her one device of four", account)
	}
	if page := strings.ToLower(run(t, tab, chromedp.Evaluate[string](`document.body.innerText`))); strings.Contains(page, "bob") {
		t.Errorf("the page of alice mentions bob:\n%s", page)
	}

	// She adds a phone by its static key; the controller holds it as her device, and the page lists it
	if got := h.act(t, tab, chromedp.SetValue(chromedp.CSS("#device-name"), "alice-phone"), chromedp.SetValue(chromedp.CSS("#device-key"), portalKey(phoneKey)),
		chromedp.Click(chromedp.CSS(`#add-form button[type="submit"]`))); !strings.Contains(got, "The device alice-phone is added") {
		t.Errorf("adding the phone says %q", got)
	}
	if rows := portalRows(t, tab, "#devices", 2); !strings.Contains(rows[1], "alice-phone") {
		t.Errorf("the rows after the add are %q", rows)
	}
	if devices := portalDevices(t, h, "alice"); !slices.Equal(devices, []string{"alice-laptop", "alice-phone"}) {
		t.Errorf("the controller holds the devices %v of alice, want her laptop and her phone", devices)
	}
	// What the controller refuses is shown as it says it: the key of the laptop of bob is no key of hers to add
	run(t, tab, chromedp.Steps(
		chromedp.SetValue(chromedp.CSS("#device-name"), "stolen"),
		chromedp.SetValue(chromedp.CSS("#device-key"), portalKey(bobKey)),
		chromedp.Click(chromedp.CSS(`#add-form button[type="submit"]`)),
	))
	if refused := h.problemOf(t, tab); !strings.Contains(refused, "is no device of User") {
		t.Errorf("adding the key of the laptop of bob: the page says %q", refused)
	}

	// She removes the phone, after the question; the controller no longer holds it
	if got := h.act(t, tab, chromedp.Click(chromedp.Search(`//tr[td[1][normalize-space()="alice-phone"]]//button`)),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
		chromedp.Click(chromedp.CSS(`dialog[open] button[value="ok"]`))); !strings.Contains(got, "The device alice-phone is removed") {
		t.Errorf("removing the phone says %q", got)
	}
	portalRows(t, tab, "#devices", 1)
	if devices := portalDevices(t, h, "alice"); !slices.Equal(devices, []string{"alice-laptop"}) {
		t.Errorf("the controller holds the devices %v of alice after the removal, want her laptop", devices)
	}

	// She makes a join token for a device without a browser; its secret shows once, with the command for it
	h.visit(t, tab, "/portal-join", "portal-join")
	portalControls(t, tab, "Join tokens", "makeJoinToken", "joinTokens", "signOut")
	if got := h.act(t, tab, chromedp.SetValue(chromedp.CSS("#join-name"), "alice-nas"), chromedp.Click(chromedp.CSS(`#make-form button[type="submit"]`))); !strings.Contains(got, "The join token is made") {
		t.Errorf("making the join token says %q", got)
	}
	secret := run(t, tab, chromedp.Text(chromedp.CSS("code.secret")))
	command := run(t, tab, chromedp.Text(chromedp.CSS("code.command")))
	if !controller.ValidJoinToken(secret) || command != fmt.Sprintf("echo %s | ranz node join -server %s", secret, h.url("")) {
		t.Errorf("the secret is %q and the command %q", secret, command)
	}
	if rows := portalRows(t, tab, "#tokens", 1); !strings.Contains(rows[0], "alice-nas") {
		t.Errorf("the join tokens that wait are %q", rows)
	}
	portalControls(t, tab, "Join tokens with a token that waits", "revokeJoinToken")

	// A device that presents the secret with its static key becomes a device of alice, in the networks of a
	// Node; the token is spent, and the portal lists the device
	lc := &login.Client{URL: h.url(""), HTTP: h.client("").HTTP}
	res, err := lc.Join(ctx, secret, login.Device{Key: nasKey.Public()})
	if err != nil || res.Node != "alice-nas" || res.User != "alice" || res.Controller == nil {
		t.Fatalf("the join with the token of the portal: %+v, %v", res, err)
	}
	if devices := portalDevices(t, h, "alice"); !slices.Equal(devices, []string{"alice-laptop", "alice-nas"}) {
		t.Errorf("the controller holds the devices %v of alice after the join, want her laptop and the device that joined", devices)
	}
	h.visit(t, tab, "/portal-join", "portal-join")
	if empty := run(t, tab, chromedp.Text(chromedp.CSS("#tokens"))); !strings.Contains(empty, "No join token waits") {
		t.Errorf("the join tokens that wait after the join are %q, want none", empty)
	}
	h.visit(t, tab, "/portal", "portal")
	if rows := portalRows(t, tab, "#devices", 2); !strings.Contains(rows[1], "alice-nas") || !strings.Contains(rows[1], "10.10.0.") {
		t.Errorf("the rows after the join are %q, want the device with an address of the network", rows)
	}

	// A token that she revokes enrols nothing
	h.visit(t, tab, "/portal-join", "portal-join")
	if got := h.act(t, tab, chromedp.Click(chromedp.CSS(`#make-form button[type="submit"]`))); !strings.Contains(got, "The join token is made") {
		t.Fatalf("making a second join token says %q", got)
	}
	spare := run(t, tab, chromedp.Text(chromedp.CSS("code.secret")))
	portalRows(t, tab, "#tokens", 1)
	if got := h.act(t, tab, chromedp.Click(chromedp.Search(`//tr//button[normalize-space()="Revoke"]`)),
		chromedp.WaitVisible(chromedp.CSS(`dialog[open] button[value="ok"]`)),
		chromedp.Click(chromedp.CSS(`dialog[open] button[value="ok"]`))); !strings.Contains(got, "The join token is revoked") {
		t.Errorf("revoking the join token says %q", got)
	}
	var refused *login.Error
	if _, err := lc.Join(ctx, spare, login.Device{Key: newKey(t).Public()}); !errors.As(err, &refused) || refused.Status != http.StatusUnauthorized {
		t.Errorf("the join with the token that was revoked: %v, want 401", err)
	}

	// The portal and the console keep their tokens apart: the console does not open with the token of the
	// portal, and signing in to the console does not take the portal away
	run(t, tab, chromedp.Navigate(h.url("/")))
	h.settle(t, tab, "sign-in")
	h.signIn(t, tab, h.secret)
	h.visit(t, tab, "/portal", "portal")
	if rows := portalRows(t, tab, "#devices", 2); !strings.Contains(rows[0], "alice-laptop") {
		t.Errorf("the portal after a sign-in to the console shows %q", rows)
	}

	// The sign-out ends the token at the controller, and the portal asks for a sign-in again
	selfSecret := run(t, tab, chromedp.Evaluate[string](`sessionStorage.getItem('ranz.selfToken')`))
	if _, err := h.client(selfSecret).Self(ctx); err != nil {
		t.Fatalf("the token of the portal before the sign-out: %v", err)
	}
	run(t, tab, chromedp.Click(chromedp.Search(`//header[@id="portal-header"]//button[normalize-space()="Sign out"]`)))
	h.settle(t, tab, "portal-sign-in")
	if _, err := h.client(selfSecret).Self(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the token of the portal after the sign-out: %v, want 401", err)
	}
	run(t, tab, chromedp.Navigate(h.url("/portal-join")))
	h.settle(t, tab, "portal-sign-in")

	// bob signs in to the same portal, and sees his laptop and nothing of the devices of alice
	h.portalSignIn(t, tab, "bob", portalBobPassword)
	if rows := portalRows(t, tab, "#devices", 1); !strings.Contains(rows[0], "bob-laptop") {
		t.Errorf("the device of bob is %q", rows)
	}
	if page := strings.ToLower(run(t, tab, chromedp.Evaluate[string](`document.body.innerText`))); strings.Contains(page, "alice") {
		t.Errorf("the page of bob mentions alice:\n%s", page)
	}
}
