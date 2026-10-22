package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestAdminAccessFromOutsideTheAllowlistIsRefusedAndAudited is the first criterion of SDN-39
// (#232): the API and the web UI accept connections only from the admin source allowlist. A
// request from outside it is refused before anyone looks at its token, and recorded as an event; a
// loopback address always passes; only an admin reads or changes the allowlist; and a list that
// would lock the caller out is refused. The requests come from the addresses of the test, as
// TestTheAPIAnswersOtherHosts sends them.
func TestAdminAccessFromOutsideTheAllowlistIsRefusedAndAudited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	operator := h.client(h.token("operator-1", rbac.Operator))
	viewer := h.client(h.token("viewer-1", rbac.Viewer))
	sources := func(want ...string) {
		t.Helper()
		got, err := h.api.AdminSources(ctx)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("the admin source allowlist is %v (%v), want %v", got, err, want)
		}
	}

	sources()
	set, err := h.api.SetAdminSources(ctx, []string{"2001:db8::10", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.0/24", "2001:db8::10/128"}; fmt.Sprint(set) != fmt.Sprint(want) {
		t.Errorf("the allowlist that was set reads back as %v, want %v", set, want)
	}
	sources("192.0.2.0/24", "2001:db8::10/128")

	// The restriction stands in front of the API and the web UI, as ranz-controller wires it
	web := api.NewSources(h.st, nil, 0).Restrict(h.port.HTTP)
	get := func(remote, path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://ctl.example"+path, nil)
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		web.ServeHTTP(w, r)
		return w
	}
	for _, c := range []struct {
		remote string
		path   string
		token  string
		want   int
	}{
		{"192.0.2.77:40000", "/api/v1/status", h.admin, http.StatusOK},
		{"[2001:db8::10]:40000", "/api/v1/whoami", h.admin, http.StatusOK},
		{"127.0.0.1:40000", "/api/v1/status", h.admin, http.StatusOK},
		{"[::1]:40000", "/api/v1/status", h.admin, http.StatusOK},
		{"192.0.2.77:40000", "/api/v1/status", "", http.StatusUnauthorized},
		{"198.51.100.9:40000", "/api/v1/status", h.admin, http.StatusForbidden},
		{"198.51.100.9:40000", "/api/v1/status", "", http.StatusForbidden},
		{"[2001:db8::11]:40000", "/api/v1/tokens", h.admin, http.StatusForbidden},
		{"198.51.100.9:40000", "/sign-in", "", http.StatusForbidden},
	} {
		if w := get(c.remote, c.path, c.token); w.Code != c.want {
			t.Errorf("GET %s from %s got %d, want %d: %s", c.path, c.remote, w.Code, c.want, w.Body)
		}
	}

	// The refusals are audited: the change of the allowlist, and each source that was refused,
	// once however often it asked
	if got := h.sourceEvents(event.AdminSourcesChanged); len(got) != 1 ||
		!strings.Contains(got[0].Message, `set to 192.0.2.0/24, 2001:db8::10/128 by the API token "admin"`) {
		t.Errorf("the events of the change are %+v", got)
	}
	got := h.sourceEvents(event.AdminAccessRefused)
	if len(got) != 2 || !strings.HasPrefix(got[0].Message, `GET "/api/v1/status" from 198.51.100.9 was refused`) ||
		!strings.HasPrefix(got[1].Message, `GET "/api/v1/tokens" from 2001:db8::11 was refused`) ||
		!strings.HasSuffix(got[1].Message, "(refusals not recorded since the last record: 1)") {
		t.Errorf("the events of the refusals are %+v, want one for each source that was refused", got)
	}

	// Only an admin reads or changes the allowlist
	if _, err := operator.AdminSources(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator reading the allowlist gave %v, want 403", err)
	}
	if _, err := operator.SetAdminSources(ctx, nil); httpStatus(err) != http.StatusForbidden {
		t.Errorf("an operator changing the allowlist gave %v, want 403", err)
	}
	if _, err := viewer.AdminSources(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer reading the allowlist gave %v, want 403", err)
	}

	// A list with an entry that is wrong is refused and changes nothing
	for _, bad := range [][]string{{"nowhere"}, {"10.0.0.1/8"}, {"192.0.2.0/24", "192.0.2.0/24"}} {
		if _, err := h.api.SetAdminSources(ctx, bad); httpStatus(err) != http.StatusBadRequest {
			t.Errorf("the list %q gave %v, want 400", bad, err)
		}
	}
	sources("192.0.2.0/24", "2001:db8::10/128")

	// A list that does not hold the address of the call would lock the caller out; a loopback
	// address always passes, and an empty list removes the restriction
	put := func(remote string, prefixes ...string) *httptest.ResponseRecorder {
		b, err := json.Marshal(api.AdminSourceList{Prefixes: prefixes})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPut, "https://ctl.example/api/v1/admin-sources", bytes.NewReader(b))
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer "+h.admin)
		w := httptest.NewRecorder()
		h.port.HTTP.ServeHTTP(w, r)
		return w
	}
	if w := put("198.51.100.9:50000", "203.0.113.0/24"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "198.51.100.9") {
		t.Errorf("a list without the address of the call got %d: %s", w.Code, w.Body)
	}
	sources("192.0.2.0/24", "2001:db8::10/128")
	if w := put("198.51.100.9:50000", "203.0.113.0/24", "198.51.100.0/24"); w.Code != http.StatusOK {
		t.Errorf("a list with the address of the call got %d: %s", w.Code, w.Body)
	}
	sources("198.51.100.0/24", "203.0.113.0/24")
	if w := put("127.0.0.1:50000", "203.0.113.0/24"); w.Code != http.StatusOK {
		t.Errorf("a list without the address of a call from loopback got %d: %s", w.Code, w.Body)
	}
	sources("203.0.113.0/24")
	if w := get("198.51.100.9:40000", "/api/v1/status", h.admin); w.Code != http.StatusForbidden {
		t.Errorf("an address outside the new list got %d, want 403", w.Code)
	}
	if w := put("203.0.113.5:50000"); w.Code != http.StatusOK {
		t.Errorf("an empty list got %d: %s", w.Code, w.Body)
	}
	sources()
	if w := get("198.51.100.9:40000", "/api/v1/status", h.admin); w.Code != http.StatusOK {
		t.Errorf("an address with no restriction in force got %d, want 200", w.Code)
	}
	if got := h.sourceEvents(event.AdminSourcesChanged); len(got) != 4 || !strings.Contains(got[3].Message, "was removed") {
		t.Errorf("the events of the changes are %+v, want four, the last the removal", got)
	}
}

// TestEnrolmentFromOutsideTheSourcesOfANetworkIsRefused is the second criterion of SDN-39
// (#232): a Network can limit the source prefixes that its Nodes enrol from. A node that opens its
// control stream from an address outside them is refused, names the address and the Network, and
// gets no state; the refusal is recorded once however often the node tries again; a Network that
// is tightened refuses the stream of a node that it no longer allows at once; and one that is
// opened again admits the node. The simulated nodes come from loopback.
func TestEnrolmentFromOutsideTheSourcesOfANetworkIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("apply1.json")

	// corp-lan allows documentation addresses only; the node of the VRF comes from 127.0.0.1
	res, err := h.api.Apply(ctx, corpLan(t, "203.0.113.0/24", "2001:db8::/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 0 {
		t.Errorf("limiting the sources of a Network changed the desired state of %+v", res.Nodes)
	}
	b1 := h.sim("branch-1", keyBranch1)
	golden(t, "refuse-source", b1.refusal(t))
	nodes, err := h.api.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Connected || nodes[0].AckedGeneration != 0 || nodes[0].Capabilities != nil {
		t.Errorf("the node that was refused is %+v, want it unconnected, with nothing acknowledged and no Capabilities", nodes)
	}
	// It is recorded once, however often the node tries again
	b1.start(h)
	golden(t, "refuse-source", b1.refusal(t))
	got := h.sourceEvents(event.EnrolmentRefused)
	if len(got) != 1 || got[0].Message != `Node "branch-1" opened its control stream from 127.0.0.1, which Network "corp-lan" does not allow to enrol` {
		t.Errorf("the events of the refusals are %+v, want one", got)
	}

	// A Network that allows the address admits the node, with the state of apply1.json
	if _, err := h.api.Apply(ctx, corpLan(t, "127.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	b1.start(h)
	golden(t, "apply1-branch-1", b1.update(t))
	h.waitNode("branch-1", 1, true)
	h.checkState(b1)

	// Tightening the Network refuses the stream of the node at once
	if _, err := h.api.Apply(ctx, corpLan(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	golden(t, "refuse-source", b1.refusal(t))
	h.waitNode("branch-1", 1, false)

	// A Network with no source prefixes admits any address again
	if _, err := h.api.Apply(ctx, corpLan(t)); err != nil {
		t.Fatal(err)
	}
	b1.start(h)
	h.waitNode("branch-1", 1, true)
}

// corpLan returns the intent document that declares Network corp-lan of apply1.json again, with
// the source prefixes sources that its Nodes may enrol from. The desired state of the node of
// that VRF does not change.
func corpLan(t *testing.T, sources ...string) intent.Document {
	t.Helper()
	spec := map[string]any{"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"}
	if len(sources) > 0 {
		spec["enrolSources"] = sources
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return intent.Document{Resources: []intent.Resource{{Kind: intent.KindNetwork, Name: "corp-lan", Spec: json.RawMessage(b)}}}
}

// sourceEvents returns the events of the type typ that the API lists, oldest first.
func (h *harness) sourceEvents(typ string) []event.Event {
	h.t.Helper()
	evs, err := h.api.Events(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	var out []event.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}
