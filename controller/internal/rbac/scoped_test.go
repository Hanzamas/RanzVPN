package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// A token that is held for one Network authenticates with the Network, lists with it, keeps it when its role
// changes, and is no admin token of the whole API: it does not count as the last one, and the last one cannot be
// scoped away.
func TestScopedTokens(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t))
	if _, err := tokens.Bootstrap(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	made, err := tokens.CreateGrant(ctx, "branch-ops", Grant{Role: Operator, Network: "branch-a"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Token{Name: "branch-ops", Role: Operator, Network: "branch-a"}); made.Token != want || made.Secret == "" {
		t.Errorf("the token that was made is %+v", made)
	}
	got, err := tokens.Authenticate(ctx, made.Secret)
	if err != nil || got.Role != Operator || got.Network != "branch-a" || got.Grant() != (Grant{Role: Operator, Network: "branch-a"}) {
		t.Errorf("the scoped token authenticates as %+v, %v", got, err)
	}
	list, err := tokens.List(ctx)
	if err != nil || len(list) != 2 || list[0].Name != FirstAdmin || list[0].Network != "" || list[1].Name != "branch-ops" || list[1].Network != "branch-a" {
		t.Errorf("the tokens are %+v, %v, want admin for the whole API and branch-ops for branch-a", list, err)
	}

	for _, c := range []struct {
		name string
		g    Grant
	}{{"a-bad", Grant{Role: Operator, Network: "Branch A"}}, {"b-bad", Grant{Role: "root", Network: "branch-a"}}, {"c-bad", Grant{Network: "branch-a"}}} {
		if _, err := tokens.CreateGrant(ctx, c.name, c.g, time.Time{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("CreateGrant(%+v) gave %v, want ErrInvalid", c.g, err)
		}
	}
	// CreateExpiring makes the token of the whole API as it did
	whole, err := tokens.CreateExpiring(ctx, "whole", Viewer, time.Time{})
	if err != nil || whole.Network != "" || whole.Role != Viewer {
		t.Errorf("CreateExpiring made %+v, %v", whole, err)
	}

	// A change of the role keeps the scope: it can never widen a token to the whole API
	if tok, err := tokens.SetRole(ctx, "branch-ops", Admin); err != nil || tok != (Token{Name: "branch-ops", Role: Admin, Network: "branch-a"}) {
		t.Errorf("SetRole of a scoped token gave %+v, %v, want the role admin for branch-a", tok, err)
	}
	if got, err := tokens.Authenticate(ctx, made.Secret); err != nil || got.Role != Admin || got.Network != "branch-a" {
		t.Errorf("the scoped token authenticates as %+v, %v after its role changed", got, err)
	}
	// SetGrant changes the scope: to another Network, to the whole API, and back
	if tok, err := tokens.SetGrant(ctx, "branch-ops", Grant{Role: Viewer, Network: "branch-b"}); err != nil || tok.Network != "branch-b" || tok.Role != Viewer {
		t.Errorf("SetGrant to branch-b gave %+v, %v", tok, err)
	}
	if tok, err := tokens.SetGrant(ctx, "branch-ops", Grant{Role: Operator}); err != nil || tok.Network != "" {
		t.Errorf("SetGrant to the whole API gave %+v, %v", tok, err)
	}
	if got, err := tokens.Authenticate(ctx, made.Secret); err != nil || got.Network != "" || got.Role != Operator {
		t.Errorf("the token authenticates as %+v, %v after it was given the whole API", got, err)
	}
	if _, err := tokens.SetGrant(ctx, "branch-ops", Grant{Role: Admin, Network: "Bad"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetGrant with a Network that is no name gave %v, want ErrInvalid", err)
	}
	if _, err := tokens.SetGrant(ctx, "nobody", Grant{Role: Viewer}); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetGrant of a token that does not exist gave %v, want ErrNotFound", err)
	}

	// An admin token for a Network is no admin token of the whole API: it does not keep the controller from
	// losing its last one, and the last one cannot be scoped away
	if _, err := tokens.SetGrant(ctx, "branch-ops", Grant{Role: Admin, Network: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Delete(ctx, FirstAdmin); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the last admin token beside an admin token for a Network gave %v, want ErrLastAdmin", err)
	}
	if _, err := tokens.SetGrant(ctx, FirstAdmin, Grant{Role: Admin, Network: "branch-a"}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("scoping the last admin token gave %v, want ErrLastAdmin", err)
	}
	if _, err := tokens.SetRole(ctx, FirstAdmin, Operator); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("taking the role from the last admin token gave %v, want ErrLastAdmin", err)
	}
	if gone, err := tokens.Delete(ctx, "branch-ops"); err != nil || gone.Network != "branch-a" {
		t.Errorf("deleting the admin token for a Network gave %+v, %v", gone, err)
	}

	// A stored role that does not parse authenticates nothing: it is no role of the whole API
	secret := secretPrefix + "NOTAROLE"
	for _, role := range []string{"admin@", "admin@Bad", "root@a"} {
		name := "stored-" + strings.NewReplacer("@", "-", "A", "a", "B", "b").Replace(role)
		if _, err := tokens.st.AddToken(ctx, store.Token{Name: name, Role: role, Hash: hash(secret + role)}); err != nil {
			t.Fatal(err)
		}
		if tok, err := tokens.Authenticate(ctx, secret+role); err == nil || errors.Is(err, ErrUnauthenticated) {
			t.Errorf("a token that is stored with the role %q authenticates as %+v (%v), want an error", role, tok, err)
		}
	}
}

// A User that holds a role for one Network gets user tokens of that Network, the list of the roles shows it, a
// change to the whole API replaces it, and the role goes with the tokens as it did.
func TestScopedUserRoles(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t))
	if ur, err := tokens.SetUserGrant(ctx, "alice", Grant{Role: Admin, Network: "branch-a"}); err != nil || ur != (UserRole{User: "alice", Role: Admin, Network: "branch-a"}) {
		t.Fatalf("SetUserGrant: %+v, %v", ur, err)
	}
	if _, err := tokens.SetUserRole(ctx, "bob", Viewer); err != nil {
		t.Fatal(err)
	}
	rs, err := tokens.UserRoles(ctx)
	if err != nil || len(rs) != 2 || rs[0] != (UserRole{User: "alice", Role: Admin, Network: "branch-a"}) || rs[1] != (UserRole{User: "bob", Role: Viewer}) {
		t.Errorf("the roles are %+v, %v", rs, err)
	}
	if role, ok, err := tokens.UserRole(ctx, "alice"); err != nil || !ok || role != Admin {
		t.Errorf("UserRole of a User with a role for a Network gave %q, %v, %v: the User holds the role", role, ok, err)
	}
	if g, ok, err := tokens.UserGrant(ctx, "alice"); err != nil || !ok || g != (Grant{Role: Admin, Network: "branch-a"}) {
		t.Errorf("UserGrant of alice gave %+v, %v, %v", g, ok, err)
	}
	for _, g := range []Grant{{Role: Admin, Network: "Bad Name"}, {Role: "root", Network: "a"}} {
		if _, err := tokens.SetUserGrant(ctx, "alice", g); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetUserGrant(%+v) gave %v, want ErrInvalid", g, err)
		}
	}

	tok, err := tokens.IssueUserToken(ctx, "alice", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := Token{Name: "user:alice", Role: Admin, Network: "branch-a", User: "alice"}
	if tok.Token != want {
		t.Errorf("the user token is %+v, want %+v", tok.Token, want)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("the user token authenticates as %+v, %v", got, err)
	}
	// The token carries the role that the User holds when it is used, the scope with it
	if _, err := tokens.SetUserGrant(ctx, "alice", Grant{Role: Viewer, Network: "branch-b"}); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got.Role != Viewer || got.Network != "branch-b" {
		t.Errorf("after the change the token authenticates as %+v, %v", got, err)
	}
	if _, err := tokens.SetUserRole(ctx, "alice", Operator); err != nil {
		t.Fatal(err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got.Role != Operator || got.Network != "" {
		t.Errorf("a role for the whole API replaces the scope: the token authenticates as %+v, %v", got, err)
	}
	if _, err := tokens.SetUserGrant(ctx, "alice", Grant{Role: Operator, Network: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	if ur, err := tokens.DeleteUserRole(ctx, "alice"); err != nil || ur != (UserRole{User: "alice", Role: Operator, Network: "branch-a"}) {
		t.Errorf("DeleteUserRole answered %+v, %v, want the role for branch-a that it took away", ur, err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token after the delete of the role: %v, want ErrUnauthenticated", err)
	}
}

// The groups of a provider that an admin mapped give a login the role of those groups, for the Network that the
// mapping names and for no other, and the user token that it gets carries exactly that.
func TestProviderGroupsGiveTheirScopeAndNoOther(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tokens := New(st)
	for _, m := range []GroupMapping{
		{Provider: "okta", Group: "net-a-admins", Role: Admin, Network: "branch-a"},
		{Provider: "okta", Group: "net-b-admins", Role: Admin, Network: "branch-b"},
		{Provider: "okta", Group: "net-a-viewers", Role: Viewer, Network: "branch-a"},
		{Provider: "okta", Group: "auditors", Role: Viewer},
		{Provider: "entra", Group: "net-a-admins", Role: Operator, Network: "branch-c"},
	} {
		got, err := tokens.SetGroupMapping(ctx, m)
		if err != nil || got != m {
			t.Fatalf("SetGroupMapping(%+v) gave %+v, %v", m, got, err)
		}
	}
	list, err := tokens.GroupMappings(ctx)
	if err != nil || len(list) != 5 || list[0].Provider != "entra" || list[1].Group != "auditors" || list[2].Group != "net-a-admins" {
		t.Errorf("the mappings are %+v, %v, want them by provider and group", list, err)
	}
	// A mapping that is set again replaces the one that the group had
	if _, err := tokens.SetGroupMapping(ctx, GroupMapping{Provider: "okta", Group: "net-a-viewers", Role: Operator, Network: "branch-a"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := tokens.GroupMappings(ctx); len(list) != 5 {
		t.Errorf("setting a mapping again made %d mappings, want 5", len(list))
	}
	if _, err := tokens.SetGroupMapping(ctx, GroupMapping{Provider: "okta", Group: "x", Role: "root"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a mapping to a role that is none gave %v, want ErrInvalid", err)
	}

	// The grants of the groups of a login: those of its provider, and those of the groups that it has
	grants := func(provider string, groups ...string) []Grant {
		t.Helper()
		g, err := tokens.GrantsFor(ctx, provider, groups)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	if g := grants("okta", "net-a-admins", "staff"); len(g) != 1 || g[0] != (Grant{Role: Admin, Network: "branch-a"}) {
		t.Errorf("the grants of net-a-admins and staff are %+v, want admin for branch-a", g)
	}
	if g := grants("entra", "net-a-admins"); len(g) != 1 || g[0] != (Grant{Role: Operator, Network: "branch-c"}) {
		t.Errorf("a group of another provider with the same name gave %+v, want the role of its own mapping", g)
	}
	if g := grants("okta", "staff", "everyone"); len(g) != 0 {
		t.Errorf("groups that no mapping names gave the grants %+v", g)
	}
	if g := grants("ldap", "net-a-admins"); len(g) != 0 {
		t.Errorf("a provider that has no mapping gave the grants %+v", g)
	}
	if g := grants("okta", "auditors", "net-a-viewers", "net-a-admins", "net-b-admins"); len(g) != 4 || g[0] != (Grant{Role: Viewer}) ||
		g[1] != (Grant{Role: Admin, Network: "branch-a"}) || g[2] != (Grant{Role: Operator, Network: "branch-a"}) || g[3] != (Grant{Role: Admin, Network: "branch-b"}) {
		t.Errorf("the grants of four groups are %+v, want the whole API first, then each Network, the greater role first", g)
	}

	// The token of a login that is in a group mapped to a role for one Network has that role for that Network
	expires := time.Now().Add(time.Hour)
	tok, err := tokens.IssueProviderToken(ctx, "alice", "okta", []string{"net-a-admins", "staff"}, "", expires)
	if err != nil {
		t.Fatal(err)
	}
	want := Token{Name: "user:alice", Role: Admin, Network: "branch-a", User: "alice"}
	if tok.Token != want || !strings.HasPrefix(tok.Secret, userTokenPrefix) {
		t.Errorf("the token of the login is %+v, want %+v", tok.Token, want)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != want {
		t.Errorf("the token authenticates as %+v, %v, want exactly %+v", got, err, want)
	}
	// It needs no role of the User in the table of the API roles, and does not make one
	if rs, err := tokens.UserRoles(ctx); err != nil || len(rs) != 0 {
		t.Errorf("a login through a provider made the roles %+v (%v)", rs, err)
	}
	// A logout ends it
	if _, err := tokens.RevokeUserToken(ctx, tok.Secret); err != nil {
		t.Errorf("the logout of a token that a provider's login made: %v", err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token after its logout: %v, want ErrUnauthenticated", err)
	}

	// Groups that give no role give no token, and groups of several Networks need the login to name one
	if _, err := tokens.IssueProviderToken(ctx, "alice", "okta", []string{"staff"}, "", expires); !errors.Is(err, ErrNoRole) {
		t.Errorf("a login whose groups give no role gave %v, want ErrNoRole", err)
	}
	both := []string{"net-a-admins", "net-b-admins"}
	if _, err := tokens.IssueProviderToken(ctx, "alice", "okta", both, "", expires); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("a login whose groups give roles for two Networks gave %v, want ErrAmbiguous", err)
	}
	tok, err = tokens.IssueProviderToken(ctx, "alice", "okta", both, "branch-b", expires)
	if err != nil || tok.Network != "branch-b" || tok.Role != Admin {
		t.Errorf("the login that names branch-b got %+v, %v, want admin for branch-b", tok.Token, err)
	}
	if _, err := tokens.IssueProviderToken(ctx, "alice", "okta", []string{"net-a-admins"}, "branch-b", expires); !errors.Is(err, ErrNoRole) {
		t.Errorf("a login that asks for a Network that its groups give no role for gave %v, want ErrNoRole", err)
	}
	// A role for the whole API, narrowed to the Network that the login asks for
	tok, err = tokens.IssueProviderToken(ctx, "bob", "okta", []string{"auditors"}, "branch-a", expires)
	if err != nil || tok.Network != "branch-a" || tok.Role != Viewer {
		t.Errorf("a role for the whole API, asked for branch-a, gave %+v, %v", tok.Token, err)
	}
	if _, err := tokens.IssueProviderToken(ctx, "Alice", "okta", both, "branch-a", expires); !errors.Is(err, ErrInvalid) {
		t.Errorf("a user that is no name gave %v, want ErrInvalid", err)
	}
	if _, err := tokens.IssueProviderToken(ctx, "alice", "okta", both, "Branch A", expires); !errors.Is(err, ErrInvalid) {
		t.Errorf("a Network that is no name gave %v, want ErrInvalid", err)
	}
	if _, err := tokens.IssueProviderToken(ctx, "alice", "okta", both, "branch-a", time.Now().Add(-time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a token that ended before it was made gave %v, want ErrInvalid", err)
	}

	// The tokens of a User end with the User, those of a provider's login too
	tok, err = tokens.IssueProviderToken(ctx, "carol", "okta", []string{"net-b-admins"}, "", expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserTokens(ctx, []string{"carol"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token of a User whose tokens were deleted: %v, want ErrUnauthenticated", err)
	}

	// A mapping is deleted, once; the tokens that it made stay until they end
	tok, err = tokens.IssueProviderToken(ctx, "dave", "okta", []string{"net-b-admins"}, "", expires)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := tokens.DeleteGroupMapping(ctx, "okta", "net-b-admins"); err != nil || m != (GroupMapping{Provider: "okta", Group: "net-b-admins", Role: Admin, Network: "branch-b"}) {
		t.Errorf("DeleteGroupMapping answered %+v, %v", m, err)
	}
	if _, err := tokens.DeleteGroupMapping(ctx, "okta", "net-b-admins"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second delete of the mapping gave %v, want ErrNotFound", err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got.Network != "branch-b" {
		t.Errorf("the token that the mapping made authenticates as %+v, %v", got, err)
	}
	if _, err := tokens.IssueProviderToken(ctx, "dave", "okta", []string{"net-b-admins"}, "", expires); !errors.Is(err, ErrNoRole) {
		t.Errorf("a login by the group of a mapping that was deleted gave %v, want ErrNoRole", err)
	}
}

// What was held for a Network that the intent no longer has goes with it, and only that: the tokens, the roles of
// users, the tokens that carry such a role, the mappings and the delegation of the Network; not those of the
// whole API, nor those of another Network, nor a Network whose name ends the same way.
func TestDeleteScopedAccess(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	tokens := New(st)
	expires := time.Now().Add(time.Hour)
	secrets := map[string]string{}
	for _, c := range []struct {
		name string
		g    Grant
	}{
		{"gone-admin", Grant{Role: Admin, Network: "branch-a"}}, {"gone-viewer", Grant{Role: Viewer, Network: "branch-a"}},
		{"other-network", Grant{Role: Admin, Network: "branch-b"}}, {"longer-name", Grant{Role: Admin, Network: "old-branch-a"}}, {"whole", Grant{Role: Operator}},
	} {
		tok, err := tokens.CreateGrant(ctx, c.name, c.g, expires)
		if err != nil {
			t.Fatal(err)
		}
		secrets[c.name] = tok.Secret
	}
	for _, c := range []struct {
		user string
		g    Grant
	}{{"alice", Grant{Role: Admin, Network: "branch-a"}}, {"bob", Grant{Role: Admin, Network: "branch-b"}}, {"carol", Grant{Role: Viewer}}} {
		if _, err := tokens.SetUserGrant(ctx, c.user, c.g); err != nil {
			t.Fatal(err)
		}
		tok, err := tokens.IssueUserToken(ctx, c.user, expires)
		if err != nil {
			t.Fatal(err)
		}
		secrets["user-"+c.user] = tok.Secret
	}
	for _, m := range []GroupMapping{{Provider: "okta", Group: "a", Role: Admin, Network: "branch-a"}, {Provider: "okta", Group: "b", Role: Admin, Network: "branch-b"}, {Provider: "okta", Group: "w", Role: Viewer}} {
		if _, err := tokens.SetGroupMapping(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ user, group string }{{"dave", "a"}, {"erin", "b"}, {"frank", "w"}} {
		tok, err := tokens.IssueProviderToken(ctx, c.user, "okta", []string{c.group}, "", expires)
		if err != nil {
			t.Fatal(err)
		}
		secrets["login-"+c.user] = tok.Secret
	}
	for _, n := range []string{"branch-a", "branch-b"} {
		if err := st.PutDelegation(ctx, store.Delegation{Network: n, Spec: `{"network":"` + n + `"}`}); err != nil {
			t.Fatal(err)
		}
	}

	if err := st.DeleteScopedAccess(ctx, "branch-a"); err != nil {
		t.Fatal(err)
	}
	gone := []string{"gone-admin", "gone-viewer", "user-alice", "login-dave"}
	kept := []string{"other-network", "longer-name", "whole", "user-bob", "user-carol", "login-erin", "login-frank"}
	for _, name := range gone {
		if _, err := tokens.Authenticate(ctx, secrets[name]); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s, held for the Network that was deleted, authenticates: %v", name, err)
		}
	}
	for _, name := range kept {
		if _, err := tokens.Authenticate(ctx, secrets[name]); err != nil {
			t.Errorf("%s, held for something else, was ended with the Network: %v", name, err)
		}
	}
	if rs, err := tokens.UserRoles(ctx); err != nil || len(rs) != 2 || rs[0].User != "bob" || rs[1].User != "carol" {
		t.Errorf("the roles of users after the delete are %+v, %v, want bob and carol", rs, err)
	}
	if ms, err := tokens.GroupMappings(ctx); err != nil || len(ms) != 2 || ms[0].Group != "b" || ms[1].Group != "w" {
		t.Errorf("the mappings after the delete are %+v, %v, want b and w", ms, err)
	}
	if ds, err := st.Delegations(ctx); err != nil || len(ds) != 1 || ds[0].Network != "branch-b" {
		t.Errorf("the delegations after the delete are %+v, %v, want the one of branch-b", ds, err)
	}
	if list, err := tokens.List(ctx); err != nil || len(list) != 3 {
		t.Errorf("the tokens after the delete are %+v, %v, want three", list, err)
	}
	// Doing it again, for a Network that holds nothing, is no error
	if err := st.DeleteScopedAccess(ctx, "branch-a"); err != nil {
		t.Errorf("deleting what is held for a Network that holds nothing: %v", err)
	}
}
