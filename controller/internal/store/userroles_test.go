package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestUserRolesAndTokens checks the API roles of the users and their user tokens (SDN-32): a new store
// holds none; a token is stored only for a user that holds a role and is found with that role until
// its end; a token that ended is removed by the next one stored; the end of the tokens of a user is
// moved earlier and never later; and a delete of a role, of the roles of users or of the tokens of
// users takes the tokens along.
func TestUserRolesAndTokens(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()

	if rs, err := st.UserRoles(ctx); err != nil || rs == nil || len(rs) != 0 {
		t.Fatalf("a new store holds the roles %v (%v), want an empty list", rs, err)
	}
	if ok, err := st.AddUserToken(ctx, store.UserToken{Hash: "h0", Name: "alice", Expires: now.Add(time.Hour)}, now); err != nil || ok {
		t.Fatalf("a token of a user that holds no role was stored (%v, %v)", ok, err)
	}
	for name, role := range map[string]string{"carol": "viewer", "alice": "operator", "bob": "admin"} {
		if err := st.SetUserRole(ctx, name, role); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetUserRole(ctx, "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	rs, err := st.UserRoles(ctx)
	if err != nil || len(rs) != 3 || rs[0] != (store.UserRole{Name: "alice", Role: "admin"}) || rs[2].Name != "carol" {
		t.Fatalf("the roles are %+v (%v), want alice (admin), bob and carol", rs, err)
	}
	if role, ok, err := st.UserRole(ctx, "nobody"); err != nil || ok || role != "" {
		t.Errorf("the role of nobody is %q (%v, %v)", role, ok, err)
	}

	for _, tok := range []store.UserToken{
		{Hash: "h1", Name: "alice", Expires: now.Add(time.Hour)},
		{Hash: "h2", Name: "alice", Expires: now.Add(2 * time.Hour)},
		{Hash: "h3", Name: "bob", Expires: now.Add(-time.Minute)},
		{Hash: "h4", Name: "carol", Expires: now.Add(time.Hour)},
	} {
		if ok, err := st.AddUserToken(ctx, tok, now.Add(-time.Hour)); err != nil || !ok {
			t.Fatalf("storing the token %+v: %v, %v", tok, ok, err)
		}
	}
	if name, role, ok, err := st.UserTokenByHash(ctx, "h1", now); err != nil || !ok || name != "alice" || role != "admin" {
		t.Errorf("the token h1 is of %q with %q (%v, %v)", name, role, ok, err)
	}
	if _, _, ok, err := st.UserTokenByHash(ctx, "h3", now); err != nil || ok {
		t.Errorf("a token past its end was found (%v, %v)", ok, err)
	}
	// The next token stored removes the ones that ended
	if ok, err := st.AddUserToken(ctx, store.UserToken{Hash: "h5", Name: "bob", Expires: now.Add(time.Hour)}, now); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if name, ok, err := st.DeleteUserToken(ctx, "h3"); err != nil || ok || name != "" {
		t.Errorf("the token h3, which ended, was still there to delete: %q (%v, %v)", name, ok, err)
	}

	// The end of the tokens of alice moves earlier, never later
	if err := st.EndUserTokens(ctx, "alice", now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.EndUserTokens(ctx, "carol", now.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h2", now.Add(40*time.Minute)); ok {
		t.Error("a token of alice outlives the end that was set")
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h4", now.Add(90*time.Minute)); ok {
		t.Error("the end of a token of carol moved later")
	}

	// A logout deletes one token
	if name, ok, err := st.DeleteUserToken(ctx, "h1"); err != nil || !ok || name != "alice" {
		t.Errorf("the delete of the token h1: %q (%v, %v)", name, ok, err)
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h2", now); !ok {
		t.Error("the delete of one token of alice took the other")
	}
	// A delete of a role takes the tokens of the user along
	if ok, err := st.DeleteUserRole(ctx, "alice"); err != nil || !ok {
		t.Errorf("the delete of the role of alice: %v, %v", ok, err)
	}
	if ok, err := st.DeleteUserRole(ctx, "alice"); err != nil || ok {
		t.Errorf("a second delete of the role of alice: %v, %v", ok, err)
	}
	if err := st.SetUserRole(ctx, "alice", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h2", now); ok {
		t.Error("a token of alice came back with a new role")
	}
	// The tokens of users, and the roles of users with their tokens
	if err := st.DeleteUserTokens(ctx, []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h5", now); ok {
		t.Error("the tokens of bob outlived their delete")
	}
	if err := st.DeleteUserRoles(ctx, []string{"carol", "nobody"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserRoles(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserTokens(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if rs, err := st.UserRoles(ctx); err != nil || len(rs) != 2 || rs[0].Name != "alice" || rs[1].Name != "bob" {
		t.Errorf("the roles after the deletes are %+v (%v), want alice and bob", rs, err)
	}
	if err := st.SetUserRole(ctx, "carol", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.UserTokenByHash(ctx, "h4", now); ok {
		t.Error("a token of carol outlived the delete of her role")
	}
}
