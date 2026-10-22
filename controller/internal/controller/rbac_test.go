package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// labVRF is a VRF that no node joins, so applying and deleting it changes no node.
var labVRF = intent.Document{Resources: []intent.Resource{
	{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id": 99, "ula": "fd99:1:2::/48"}`)},
}}

// TestRolesAllowAndRefuseExactlyTheirActions is the first criterion of SDN-14 (#190): each role
// is allowed and refused exactly its actions. Every action of the API runs with each role, with
// no token and with a token the controller does not know. An allowed action succeeds; a refused
// one answers 403 Forbidden (401 Unauthorized without a known token) and changes nothing.
func TestRolesAllowAndRefuseExactlyTheirActions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("apply1.json")
	viewer := h.client(h.token("viewer-1", rbac.Viewer))
	operator := h.client(h.token("operator-1", rbac.Operator))
	var pending uint64 // the revision that waits for confirmation, for the confirm action
	businessKey, err := licence.Sign(testVendor, licence.Licence{ID: "business-1", Licensee: "Test", Tier: licence.Business, Nodes: 20, Expires: time.Now().Add(year)})
	if err != nil {
		t.Fatal(err)
	}

	actions := []struct {
		name  string
		need  rbac.Role
		setup func() // runs with the admin token before the action
		do    func(c *api.Client) error
	}{
		{"status", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Status(ctx); return err }},
		{"whoami", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Whoami(ctx); return err }},
		{"get resources", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Resources(ctx); return err }},
		{"get nodes", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Nodes(ctx); return err }},
		{"apply", rbac.Operator, func() { h.deleteIfThere(intent.KindVRF, "lab") },
			func(c *api.Client) error { _, err := c.Apply(ctx, labVRF); return err }},
		{"delete a resource", rbac.Operator, func() { h.applyDoc(labVRF) },
			func(c *api.Client) error { _, err := c.Delete(ctx, intent.KindVRF, "lab"); return err }},
		{"get revisions", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Revisions(ctx); return err }},
		{"get a revision", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Revision(ctx, 1); return err }},
		{"diff", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Diff(ctx); return err }},
		{"get events", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Events(ctx); return err }},
		{"rollback", rbac.Operator, nil, func(c *api.Client) error { _, err := c.Rollback(ctx, 1); return err }},
		{"confirm", rbac.Operator, func() {
			if pending == 0 {
				h.deleteIfThere(intent.KindVRF, "lab")
				res, err := h.api.ApplyConfirm(ctx, labVRF, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				pending = res.Revision
			}
		}, func(c *api.Client) error {
			_, err := c.Confirm(ctx, pending)
			if err == nil {
				pending = 0
			}
			return err
		}},
		{"get the licence", rbac.Viewer, nil, func(c *api.Client) error { _, err := c.Licence(ctx); return err }},
		{"install a licence key", rbac.Operator, nil, func(c *api.Client) error { _, err := c.SetLicence(ctx, businessKey); return err }},
		{"remove the licence key", rbac.Operator, nil, func(c *api.Client) error { _, err := c.RemoveLicence(ctx); return err }},
		{"list the tokens", rbac.Admin, nil, func(c *api.Client) error { _, err := c.Tokens(ctx); return err }},
		{"create a token", rbac.Admin, func() { h.deleteTokenIfThere("spare") },
			func(c *api.Client) error { _, err := c.CreateToken(ctx, "spare", rbac.Viewer); return err }},
		{"delete a token", rbac.Admin, func() { h.deleteTokenIfThere("spare"); h.token("spare", rbac.Operator) },
			func(c *api.Client) error { _, err := c.DeleteToken(ctx, "spare"); return err }},
	}
	callers := []struct {
		name string
		role rbac.Role // none for a caller without a known token
		c    *api.Client
	}{
		{"no token", "", h.client("")},
		{"an unknown token", "", h.client("ranz_NOTATOKENOFTHISCONTROLLER")},
		{"viewer", rbac.Viewer, viewer},
		{"operator", rbac.Operator, operator},
		{"admin", rbac.Admin, h.api},
	}
	for _, a := range actions {
		for _, who := range callers {
			if a.setup != nil {
				a.setup()
			}
			before := h.snapshot()
			err := a.do(who.c)
			if who.role.Allows(a.need) {
				if err != nil {
					t.Errorf("%s: %s was refused: %v", who.name, a.name, err)
				}
				continue
			}
			want := http.StatusForbidden
			if who.role == "" {
				want = http.StatusUnauthorized
			}
			var e *api.Error
			if !errors.As(err, &e) || e.Status != want {
				t.Errorf("%s: %s gave %v, want the status %d", who.name, a.name, err, want)
				continue
			}
			t.Logf("%s: %s: %d %s", who.name, a.name, e.Status, e.Message)
			if after := h.snapshot(); after != before {
				t.Errorf("%s: the refused %s changed the controller:\n--- after\n%s\n--- before\n%s", who.name, a.name, after, before)
			}
		}
	}

	for _, who := range callers[2:] {
		tok, err := who.c.Whoami(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Role != who.role {
			t.Errorf("whoami of the %s token gave %+v", who.name, tok)
		}
	}
}

// TestRolesAtTheNode checks the roles at the simulated node: the apply of an operator reaches
// the node, and the refused apply and delete of a viewer send it nothing, so the operator's next
// apply is the node's next generation, the one of TestSecondApplySendsDelta.
func TestRolesAtTheNode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	operator := h.client(h.token("operator-1", rbac.Operator))
	viewer := h.client(h.token("viewer-1", rbac.Viewer))

	res, err := operator.Apply(ctx, h.document("apply1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the operator's apply1.json changed %+v, want %+v", res.Nodes, want)
	}
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)

	if _, err := viewer.Apply(ctx, h.document("apply2.json")); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the viewer's apply gave %v, want 403", err)
	}
	if _, err := viewer.Delete(ctx, intent.KindNetwork, "corp-lan"); httpStatus(err) != http.StatusForbidden {
		t.Errorf("the viewer's delete gave %v, want 403", err)
	}
	res, err = operator.Apply(ctx, h.document("apply2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "branch-2", Generation: 1}}; !equalGenerations(res.Nodes, want) {
		t.Errorf("the operator's apply2.json changed %+v, want %+v", res.Nodes, want)
	}
	golden(t, "apply2-branch-1", b1.update(t))
	h.waitNode("branch-1", 2, true)
	h.checkState(b1)
}

// TestTokens checks the management of the tokens: names are unique, a bad name or role is
// refused, a deleted token stops working at once, and the controller always keeps an admin
// token.
func TestTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.api.DeleteToken(ctx, rbac.FirstAdmin); httpStatus(err) != http.StatusConflict {
		t.Errorf("deleting the only admin token gave %v, want 409", err)
	}
	root, err := h.api.CreateToken(ctx, "root", rbac.Admin)
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "root" || root.Role != rbac.Admin || root.Secret == "" {
		t.Errorf("the created token is %+v", root)
	}
	for _, c := range []struct {
		name string
		role rbac.Role
		want int
	}{
		{"root", rbac.Viewer, http.StatusConflict},
		{"Bad_Name", rbac.Viewer, http.StatusBadRequest},
		{"ops", "superuser", http.StatusBadRequest},
		{"ops", "", http.StatusBadRequest},
	} {
		if _, err := h.api.CreateToken(ctx, c.name, c.role); httpStatus(err) != c.want {
			t.Errorf("creating the token %q with the role %q gave %v, want %d", c.name, c.role, err, c.want)
		}
	}
	if _, err := h.api.DeleteToken(ctx, "nobody"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("deleting a token that does not exist gave %v, want 404", err)
	}

	byRoot := h.client(root.Secret)
	gone, err := byRoot.DeleteToken(ctx, rbac.FirstAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if gone != (rbac.Token{Name: rbac.FirstAdmin, Role: rbac.Admin}) {
		t.Errorf("the delete answered %+v", gone)
	}
	if _, err := h.api.Status(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("the deleted admin token gave %v, want 401", err)
	}
	if _, err := byRoot.DeleteToken(ctx, "root"); httpStatus(err) != http.StatusConflict {
		t.Errorf("deleting the last admin token gave %v, want 409", err)
	}
	tokens, err := byRoot.Tokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []rbac.Token{{Name: "root", Role: rbac.Admin}}; fmt.Sprint(tokens) != fmt.Sprint(want) {
		t.Errorf("the tokens are %+v, want %+v", tokens, want)
	}
}

// TestTheAPIAnswersOtherHosts checks that the API serves clients on other hosts, which the
// controller refused before it had roles: a request from an address that is not loopback gets
// what its token allows, and a request without a token gets 401 with the challenge of RFC 6750.
func TestTheAPIAnswersOtherHosts(t *testing.T) {
	h := newHarness(t)
	viewer := h.token("viewer-1", rbac.Viewer)
	for _, c := range []struct {
		remote, method, path, token string
		want                        int
	}{
		{"192.0.2.10:50000", http.MethodGet, "/api/v1/resources", viewer, http.StatusOK},
		{"[2001:db8::10]:50000", http.MethodGet, "/api/v1/nodes", viewer, http.StatusOK},
		{"192.0.2.10:50000", http.MethodPost, "/api/v1/apply", viewer, http.StatusForbidden},
		{"192.0.2.10:50000", http.MethodGet, "/api/v1/tokens", h.admin, http.StatusOK},
		{"192.0.2.10:50000", http.MethodGet, "/api/v1/status", "", http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(c.method, "https://ctl.example"+c.path, nil)
		r.RemoteAddr = c.remote
		if c.token != "" {
			r.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		h.port.HTTP.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s from %s got %d, want %d: %s", c.method, c.path, c.remote, w.Code, c.want, w.Body)
		}
		if c.want == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("the 401 of %s %s has no WWW-Authenticate challenge", c.method, c.path)
		}
	}
}

// token creates the token name with role through the API, with the admin token, and returns
// its secret.
func (h *harness) token(name string, role rbac.Role) string {
	h.t.Helper()
	tok, err := h.api.CreateToken(context.Background(), name, role)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.Secret
}

// document returns the intent document testdata/file, YAML or JSON.
func (h *harness) document(file string) intent.Document {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		h.t.Fatal(err)
	}
	doc, err := intent.ParseDocument(b)
	if err != nil {
		h.t.Fatalf("%s: %v", file, err)
	}
	return doc
}

// applyDoc applies doc with the admin token.
func (h *harness) applyDoc(doc intent.Document) {
	h.t.Helper()
	if _, err := h.api.Apply(context.Background(), doc); err != nil {
		h.t.Fatal(err)
	}
}

// deleteIfThere deletes the resource kind/name with the admin token, if it exists.
func (h *harness) deleteIfThere(kind, name string) {
	h.t.Helper()
	if _, err := h.api.Delete(context.Background(), kind, name); err != nil && httpStatus(err) != http.StatusNotFound {
		h.t.Fatal(err)
	}
}

// deleteTokenIfThere deletes the token name with the admin token, if it exists.
func (h *harness) deleteTokenIfThere(name string) {
	h.t.Helper()
	if _, err := h.api.DeleteToken(context.Background(), name); err != nil && httpStatus(err) != http.StatusNotFound {
		h.t.Fatal(err)
	}
}

// snapshot returns what an action can change, as the admin token reads it: the intent, the
// nodes, the tokens and the licence in force.
func (h *harness) snapshot() string {
	h.t.Helper()
	ctx := context.Background()
	nodes, err := h.api.Nodes(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	tokens, err := h.api.Tokens(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	lic, err := h.api.Licence(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	b, err := json.MarshalIndent(map[string]any{"nodes": nodes, "tokens": tokens, "licence": lic}, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	return h.resources() + "\n" + string(b)
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
