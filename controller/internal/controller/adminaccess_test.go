// The first install narrows who may reach the API (AUD1-DT-6, #454) in the controller conformance
// seam: ranz status says which sources are allowed and that the starter rule allows all traffic
// inside VRF default, and a Node enrols from an address outside the admin source allowlist, since
// its control stream is not behind it (ADR-0034).
package controller_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// TestStatusSaysWhoMayReachTheControllerAndWhatTheStarterRuleDoes: ranz status shows the admin
// source allowlist in force and how to change it, with no list shown as open, and the starter rule
// with how to narrow it for as long as the intent holds it.
func TestStatusSaysWhoMayReachTheControllerAndWhatTheStarterRuleDoes(t *testing.T) {
	h := newFirstStartHarness(t)
	ctx := context.Background()

	st, err := h.api.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.AdminAccess == nil || !st.AdminAccess.Open || len(st.AdminAccess.Sources) != 0 || !strings.Contains(st.AdminAccess.Note, "any address may reach the API") {
		t.Errorf("with no allowlist the status says %+v, want it open", st.AdminAccess)
	}
	if st.StarterRule == nil || st.StarterRule.Name != intent.StarterRule ||
		!strings.Contains(st.StarterRule.Note, "allows all traffic inside VRF default") ||
		!strings.Contains(st.StarterRule.Note, "ranz delete Policy default-allow-all") ||
		!strings.Contains(st.StarterRule.Note, "docs/first-test.md") {
		t.Errorf("the status says %+v about the starter rule", st.StarterRule)
	}

	if _, err := h.api.SetAdminSources(ctx, []string{"10.1.2.0/24", "127.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if st.AdminAccess == nil || st.AdminAccess.Open || strings.Join(st.AdminAccess.Sources, ",") != "10.1.2.0/24,127.0.0.0/8" ||
		!strings.Contains(st.AdminAccess.Note, "ranz admin-sources set") || !strings.Contains(st.AdminAccess.Note, "403") {
		t.Errorf("with an allowlist the status says %+v", st.AdminAccess)
	}

	// Once the rule is deleted the status stops saying that it allows all
	if _, err := h.api.Delete(ctx, intent.KindPolicy, intent.StarterRule); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil || st.StarterRule != nil {
		t.Errorf("after the starter rule was deleted the status says %+v (%v), want nothing", st.StarterRule, err)
	}
}

// TestANodeEnrolsFromAnAddressOutsideTheAdminAllowlist: the list holds a documentation prefix only,
// the web side refuses an address outside it, and a Node that comes from 127.0.0.1, which the list
// does not hold, still opens its control stream and gets its state: the mesh is unchanged.
func TestANodeEnrolsFromAnAddressOutsideTheAdminAllowlist(t *testing.T) {
	h := newFirstStartHarness(t)
	ctx := context.Background()
	if _, err := h.api.SetAdminSources(ctx, []string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	web := api.NewSources(h.st, nil, 0).Restrict(h.port.HTTP)
	r := httptest.NewRequest(http.MethodGet, "https://ctl.example/api/v1/status", nil)
	r.RemoteAddr = "198.51.100.9:40000"
	r.Header.Set("Authorization", "Bearer "+h.admin)
	w := httptest.NewRecorder()
	web.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("an address outside the allowlist got %d from the API, want 403", w.Code)
	}

	h.apply("apply-default.json")
	a := h.sim("node-a", keyBranch1)
	a.update(t)
	h.waitNode("node-a", 1, true)
}
