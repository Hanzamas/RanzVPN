package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// A token whose role is held for one Network passes the Guard for whoami and for the calls under the path of its
// Network, and for nothing else: not for a call of another Network, not for the calls of the whole API, and not
// for a path that climbs out of its own. A token of the whole API passes the check of the scope for every call.
func TestAScopedTokenPassesOnlyTheCallsOfItsNetwork(t *testing.T) {
	scoped := rbac.Token{Name: "ops", Role: rbac.Admin, Network: "branch-a"}
	global := rbac.Token{Name: "root", Role: rbac.Admin}
	for _, c := range []struct {
		method, path string
		pass         bool
	}{
		{http.MethodGet, "/api/v1/whoami", true},
		{http.MethodHead, "/api/v1/whoami", true},
		{http.MethodPost, "/api/v1/whoami", false},
		{http.MethodGet, "/api/v1/networks/branch-a", true},
		{http.MethodGet, "/api/v1/networks/branch-a/resources", true},
		{http.MethodPost, "/api/v1/networks/branch-a/apply", true},
		{http.MethodDelete, "/api/v1/networks/branch-a/resources/User/alice", true},
		{http.MethodPut, "/api/v1/networks/branch-a/users/alice/password", true},
		{http.MethodGet, "/api/v1/networks/branch-a/sessions", true},
		{http.MethodPost, "/api/v1/networks/branch-a/sessions/0123456789abcdef/disconnect", true},
		// Another Network, and a name that only starts like this one's
		{http.MethodGet, "/api/v1/networks/branch-b", false},
		{http.MethodPost, "/api/v1/networks/branch-b/apply", false},
		{http.MethodGet, "/api/v1/networks/branch-a-b", false},
		{http.MethodGet, "/api/v1/networks/branch-ab/resources", false},
		{http.MethodGet, "/api/v1/networks", false},
		{http.MethodGet, "/api/v1/networks/", false},
		// A path that climbs out of the Network's own is the path that it climbs to
		{http.MethodGet, "/api/v1/networks/branch-a/../branch-b/resources", false},
		{http.MethodGet, "/api/v1/networks/branch-a/../../tokens", false},
		{http.MethodPost, "/api/v1/networks/branch-a/../../apply", false},
		{http.MethodGet, "/api/v1/networks/branch-a%2f..%2fbranch-b", false},
		{http.MethodGet, "/api/v1/networks/branch-b/../branch-a/resources", true},
		{http.MethodGet, "//api/v1/networks/branch-a/resources", true},
		// Everything that is not a Network's
		{http.MethodPost, "/api/v1/apply", false},
		{http.MethodGet, "/api/v1/resources", false},
		{http.MethodGet, "/api/v1/nodes", false},
		{http.MethodGet, "/api/v1/status", false},
		{http.MethodGet, "/api/v1/tokens", false},
		{http.MethodPost, "/api/v1/tokens", false},
		{http.MethodPut, "/api/v1/tokens/delegations/branch-a", false},
		{http.MethodPut, "/api/v1/tokens/users/alice", false},
		{http.MethodPut, "/api/v1/admin-sources", false},
		{http.MethodGet, "/api/v1/operations/sessions", false},
		{http.MethodPost, "/api/v1/rollback", false},
		{http.MethodDelete, "/api/v1/resources/Network/branch-a", false},
		{http.MethodGet, "/api/v1/audit", false},
		{http.MethodGet, "/", false},
		{http.MethodGet, "/api/v1/self/devices", false},
	} {
		r := httptest.NewRequest(c.method, "https://ctl.example"+c.path, nil)
		refusal := scopeRefusal(scoped, r)
		if (refusal == "") != c.pass {
			t.Errorf("%s %s: the scoped token passes %v, want %v (%q)", c.method, c.path, refusal == "", c.pass, refusal)
		}
		if refusal != "" && (!strings.Contains(refusal, `"ops"`) || !strings.Contains(refusal, `Network "branch-a" only`) || !strings.Contains(refusal, "/api/v1/networks/branch-a")) {
			t.Errorf("%s %s: the refusal %q does not say whose token, which Network and what it calls", c.method, c.path, refusal)
		}
		if got := scopeRefusal(global, r); got != "" {
			t.Errorf("%s %s: a token of the whole API was refused for its scope: %q", c.method, c.path, got)
		}
	}
}

// The calls of a Network are under /api/v1/networks, and Needs gives them the role that any call gets from its
// method: a read is viewer and any other call operator. The calls that set who holds which role, and what a scoped
// role may do, are under the tokens, which only an admin reads or changes.
func TestTheRolesOfTheScopedCalls(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         rbac.Role
	}{
		{http.MethodGet, "/api/v1/networks/branch-a", rbac.Viewer},
		{http.MethodGet, "/api/v1/networks/branch-a/resources", rbac.Viewer},
		{http.MethodPost, "/api/v1/networks/branch-a/apply", rbac.Operator},
		{http.MethodDelete, "/api/v1/networks/branch-a/resources/User/alice", rbac.Operator},
		{http.MethodPut, "/api/v1/networks/branch-a/users/alice/password", rbac.Operator},
		{http.MethodPost, "/api/v1/networks/branch-a/sessions/abc/disconnect", rbac.Operator},
		{http.MethodGet, "/api/v1/tokens/delegations", rbac.Admin},
		{http.MethodPut, "/api/v1/tokens/delegations/branch-a", rbac.Admin},
		{http.MethodDelete, "/api/v1/tokens/delegations/branch-a", rbac.Admin},
		{http.MethodGet, "/api/v1/tokens/provider-groups", rbac.Admin},
		{http.MethodPut, "/api/v1/tokens/provider-groups/okta", rbac.Admin},
		{http.MethodDelete, "/api/v1/tokens/provider-groups/okta", rbac.Admin},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("Needs(%s, %s) is %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

// The registered routes make a mux: no two of their patterns conflict, which http.ServeMux reports by panicking
// when Routes builds it, and each path that holds a Network's name reaches the handler of its own pattern.
func TestTheRegisteredRoutesMakeAMux(t *testing.T) {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.HandleFunc(rt.Method+" "+rt.Pattern, func(http.ResponseWriter, *http.Request) {})
	}
	for _, c := range []struct{ method, path, pattern string }{
		{http.MethodGet, "/api/v1/networks/branch-a", "GET /api/v1/networks/{network}"},
		{http.MethodPost, "/api/v1/networks/branch-a/apply", "POST /api/v1/networks/{network}/apply"},
		{http.MethodDelete, "/api/v1/networks/branch-a/resources/User/alice", "DELETE /api/v1/networks/{network}/resources/{kind}/{name}"},
		{http.MethodPut, "/api/v1/networks/branch-a/users/alice/password", "PUT /api/v1/networks/{network}/users/{name}/password"},
		{http.MethodPut, "/api/v1/tokens/delegations/branch-a", "PUT /api/v1/tokens/delegations/{network}"},
		{http.MethodGet, "/api/v1/tokens/delegations", "GET /api/v1/tokens/delegations"},
		{http.MethodDelete, "/api/v1/tokens/provider-groups/okta", "DELETE /api/v1/tokens/provider-groups/{provider}"},
		// A token that is named like one of the paths under the tokens is still deleted and changed as a token is
		{http.MethodDelete, "/api/v1/tokens/delegations", "DELETE /api/v1/tokens/{name}"},
		{http.MethodPatch, "/api/v1/tokens/provider-groups", "PATCH /api/v1/tokens/{name}"},
	} {
		r := httptest.NewRequest(c.method, "https://ctl.example"+c.path, nil)
		if _, pattern := mux.Handler(r); pattern != c.pattern {
			t.Errorf("%s %s reaches the pattern %q, want %q", c.method, c.path, pattern, c.pattern)
		}
	}
}

// The reads of who holds which role and what it may do are audited as the reads of the tokens are.
func TestTheReadsOfDelegationsAndProviderGroupsAreAudited(t *testing.T) {
	for _, p := range []string{delegationsPath, providerGroupsPath} {
		found := false
		for _, a := range auditedReads {
			found = found || a == p
		}
		if !found {
			t.Errorf("a read of %s is not one of the audited reads %v", p, auditedReads)
		}
	}
}
