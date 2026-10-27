package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The fourth criterion of AUD1-DT-9 (#457): the admin destination lists, the calls on audit targets and
// the change of the audit retention need admin, and the reads of the audit log and of the retention
// stay with the viewer. TestRegisteredRolesMatchNeeds holds the routes to the same answers.
func TestNeedsAdminForTheAuditTargetsTheRetentionAndTheLists(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         rbac.Role
	}{
		{http.MethodGet, "/api/v1/admin-destinations", rbac.Admin},
		{http.MethodPut, "/api/v1/admin-destinations", rbac.Admin},
		{http.MethodGet, "/api/v1/audit/targets", rbac.Admin},
		{http.MethodPut, "/api/v1/audit/targets/siem", rbac.Admin},
		{http.MethodDelete, "/api/v1/audit/targets/siem", rbac.Admin},
		{http.MethodPut, "/api/v1/audit/targets/../targets/siem", rbac.Admin},
		{http.MethodPut, "/api/v1/audit/retention", rbac.Admin},
		{http.MethodPut, "/api/v1/audit/retention/", rbac.Admin},
		{http.MethodPost, "/api/v1/audit/retention", rbac.Admin},
		{http.MethodGet, "/api/v1/audit/retention", rbac.Viewer},
		{http.MethodGet, "/api/v1/audit", rbac.Viewer},
		{http.MethodGet, "/api/v1/targets", rbac.Viewer},
		{http.MethodPut, "/api/v1/targets/slack", rbac.Operator},
		{http.MethodPost, "/api/v1/apply", rbac.Operator},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

// The calls of the Client for the admin destination lists send the token and the lists, with a list
// that was left out as an empty one, and give what the API answers.
func TestAdminDestinationsClient(t *testing.T) {
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		var d intent.Destinations
		_ = json.NewDecoder(r.Body).Decode(&d)
		b, _ := json.Marshal(d)
		body = string(b)
		reply(w, http.StatusOK, intent.Destinations{Targets: []string{"10.0.0.0/8"}, Sensors: []string{}, UNCServers: []string{}})
	}))
	defer srv.Close()
	c := NewClient(srv.URL)

	got, err := c.AdminDestinations(context.Background())
	if err != nil || method != http.MethodGet || len(got.Targets) != 1 {
		t.Fatalf("AdminDestinations gave %+v, %v after a %s", got, err, method)
	}
	if _, err := c.SetAdminDestinations(context.Background(), intent.Destinations{Sensors: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if want := `{"targets":[],"sensors":["192.0.2.0/24"],"uncServers":[]}`; method != http.MethodPut || body != want {
		t.Errorf("SetAdminDestinations sent a %s with %s, want a PUT with %s", method, body, want)
	}
}
