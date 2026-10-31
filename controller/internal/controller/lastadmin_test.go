// Controller conformance for the last-admin guard of the API tokens (AUD1-DT-15, #497), with the harness of conformance_test.go and
// the API with a clock that the test moves (tokenlife_test.go): the controller keeps one admin token that has not expired, so the
// delete of the admin token that works is refused (409) while the only other admin token has expired.
package controller_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestAnExpiredAdminTokenDoesNotCountAsTheLastAdminToken is the first criterion of AUD1-DT-15 (#497): with one admin token that never
// expires, admin, and one admin token that has expired, ops, the delete of admin is refused as the last admin token that works, and
// so are the change of its role and the scoping of it. Nobody is left without a token that works, and the expired token is deleted as
// any is.
func TestAnExpiredAdminTokenDoesNotCountAsTheLastAdminToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	clk, srv := h.lifeAPI()
	admin := clientOf(srv, h.admin)

	ops, err := admin.CreateTokenRequest(ctx, api.TokenRequest{Name: "ops", Role: rbac.Admin, Expires: clk.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour)
	if _, err := clientOf(srv, ops.Secret).Status(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Fatalf("the admin token that expired gave %v, want 401", err)
	}
	if listed := findToken(t, admin, "ops"); !listed.Expired || listed.Role != rbac.Admin {
		t.Fatalf("ops is listed as %+v, want an admin token that has expired", listed)
	}

	// The delete of the first is refused as the last admin token that works, and the token still works
	_, err = admin.DeleteToken(ctx, rbac.FirstAdmin)
	if httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "the last token with the role admin that has not expired") {
		t.Errorf("deleting the admin token beside an admin token that expired gave %v, want 409 that names it the last one that has not expired", err)
	}
	if _, err := admin.SetTokenRole(ctx, rbac.FirstAdmin, rbac.Operator); httpStatus(err) != http.StatusConflict {
		t.Errorf("taking the role admin from it gave %v, want 409", err)
	}
	if who, err := admin.Whoami(ctx); err != nil || who.Name != rbac.FirstAdmin || who.Role != rbac.Admin {
		t.Errorf("after the refusals the admin token answers whoami as %+v, %v, want it still the admin token", who, err)
	}
	if _, err := admin.Tokens(ctx); err != nil {
		t.Errorf("after the refusals the admin token cannot manage the tokens: %v", err)
	}

	// The token that expired goes as any does, and then admin is the only admin token, which is still kept
	gone, err := admin.DeleteToken(ctx, "ops")
	if err != nil || gone.Name != "ops" || !gone.Expired {
		t.Fatalf("deleting the expired admin token gave %+v, %v", gone, err)
	}
	if _, err := admin.DeleteToken(ctx, rbac.FirstAdmin); httpStatus(err) != http.StatusConflict {
		t.Errorf("deleting the only admin token gave %v, want 409", err)
	}
}
