package cluster_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The member that leads serves the logins of users in front of its Guard, with the controller that it
// leads (SDN-32 #226, ADR-0031 amendment of 2026-10-28), as ranz controller serves them: a User that an
// admin gave an API role signs in with its password, a wrong password is the refusal of the login and
// not the one of the Guard, and the user token that the login gives is a token of the API of the member,
// with the role of the User, until the User signs out.
func TestLeaderServesTheLoginsOfUsers(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { admin = s; return nil }); err != nil {
		t.Fatal(err)
	}
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	vendor, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := cluster.Start(cluster.Config{Name: "a", Store: st, Tokens: tokens, Key: key, LicenceKeys: []ed25519.PublicKey{vendor}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	waitLeads(t, m)
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	c := api.NewClient(srv.URL)
	c.Token = admin

	// alice is a User of the intent, with a password and the API role operator
	const password = "correct horse battery staple"
	doc := intent.Document{Resources: []intent.Resource{{Kind: intent.KindUser, Name: "alice", Spec: json.RawMessage(`{"displayName": "Alice"}`)}}}
	if _, err := c.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetUserPassword(ctx, "alice", password); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetUserRole(ctx, "alice", rbac.Operator); err != nil {
		t.Fatal(err)
	}

	lc := &login.Client{URL: srv.URL}
	_, err = lc.SignIn(ctx, "alice", "not the password of alice")
	var le *login.Error
	if !errors.As(err, &le) || le.Status != http.StatusUnauthorized || !strings.Contains(le.Code, "the user name or the password is wrong") {
		t.Fatalf("a login with a wrong password: %v, want the refusal of the login, not the one of the Guard", err)
	}
	in, err := lc.SignIn(ctx, "alice", password)
	if err != nil {
		t.Fatal(err)
	}
	user := api.NewClient(srv.URL)
	user.Token = in.Secret
	if who, err := user.Whoami(ctx); err != nil || who != (rbac.Token{Name: "user:alice", Role: rbac.Operator, User: "alice"}) {
		t.Errorf("whoami with the user token: %+v, %v", who, err)
	}
	if out, err := lc.SignOut(ctx, in.Secret); err != nil || out.User != "alice" {
		t.Errorf("the logout: %+v, %v", out, err)
	}
	if _, err := user.Whoami(ctx); err == nil {
		t.Error("the user token still works after the logout")
	}
}
