package rbac

import (
	"errors"
	"strings"
	"testing"
)

// The stored form of a role is the role, or the role, @ and the Network: ParseGrant reads it back, and refuses
// whatever would read as a role of the whole API when it is not one.
func TestParseGrant(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Grant
	}{
		{"viewer", Grant{Role: Viewer}},
		{"operator", Grant{Role: Operator}},
		{"admin", Grant{Role: Admin}},
		{"viewer@branch-a", Grant{Role: Viewer, Network: "branch-a"}},
		{"operator@a", Grant{Role: Operator, Network: "a"}},
		{"admin@lab-lan-2", Grant{Role: Admin, Network: "lab-lan-2"}},
	} {
		got, err := ParseGrant(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseGrant(%q) is %+v, %v, want %+v", c.in, got, err, c.want)
			continue
		}
		if got.String() != c.in || got.Scoped() != strings.Contains(c.in, "@") {
			t.Errorf("ParseGrant(%q) writes %q and is scoped %v", c.in, got.String(), got.Scoped())
		}
	}
	for _, in := range []string{
		"", "root", "Admin", "self", "@", "@branch-a", "admin@", "operator@@a", "admin@a@b", "admin@Branch", "admin@-a", "admin@a-", "viewer@a b",
		"viewer@" + strings.Repeat("a", 64), "admin@a\n", " admin",
	} {
		if g, err := ParseGrant(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseGrant(%q) is %+v, %v, want ErrInvalid", in, g, err)
		}
	}
	// A role of the whole API is never written with an @
	if got := (Grant{Role: Admin}).String(); got != "admin" {
		t.Errorf("the grant of admin for the whole API is written %q", got)
	}
}

// NewGrant takes a role and a Network as an API call gives them.
func TestNewGrant(t *testing.T) {
	if g, err := NewGrant(Operator, ""); err != nil || g != (Grant{Role: Operator}) {
		t.Errorf("NewGrant(operator, none) is %+v, %v", g, err)
	}
	if g, err := NewGrant(Viewer, "branch-a"); err != nil || g != (Grant{Role: Viewer, Network: "branch-a"}) {
		t.Errorf("NewGrant(viewer, branch-a) is %+v, %v", g, err)
	}
	for _, c := range []struct {
		role    Role
		network string
	}{{"", "a"}, {"root", ""}, {Admin, "Bad_Name"}, {Admin, "a@b"}, {Admin, strings.Repeat("a", 64)}} {
		if _, err := NewGrant(c.role, c.network); !errors.Is(err, ErrInvalid) {
			t.Errorf("NewGrant(%q, %q) gave %v, want ErrInvalid", c.role, c.network, err)
		}
	}
	tok := Token{Name: "ops", Role: Operator, Network: "branch-a"}
	if tok.Grant() != (Grant{Role: Operator, Network: "branch-a"}) {
		t.Errorf("the grant of %+v is %+v", tok, tok.Grant())
	}
}

// FuzzParseGrant checks that a text that ParseGrant takes is the stored form of what it returns, so that no
// text reads as a role that it is not.
func FuzzParseGrant(f *testing.F) {
	for _, s := range []string{"viewer", "operator@branch-a", "admin@", "", "admin@a@b", "root@x", "@a", "viewer@" + strings.Repeat("a", 64), "admin@a-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		g, err := ParseGrant(s)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("ParseGrant(%q) gave %v, which is no ErrInvalid", s, err)
			}
			return
		}
		if g.String() != s {
			t.Errorf("ParseGrant(%q) is %+v, which is written %q", s, g, g.String())
		}
		if _, err := ParseRole(string(g.Role)); err != nil {
			t.Errorf("ParseGrant(%q) took the role %q", s, g.Role)
		}
		if g.Network != "" && !nameRule.MatchString(g.Network) {
			t.Errorf("ParseGrant(%q) took the Network %q", s, g.Network)
		}
		if g.Scoped() != strings.Contains(s, scopeSeparator) {
			t.Errorf("ParseGrant(%q) is scoped %v", s, g.Scoped())
		}
	})
}

// A login takes the one grant that its groups give it: the role that allows most, held for the Network that it
// asks for, which narrows a role of the whole API and never widens one.
func TestSelect(t *testing.T) {
	global := func(r Role) Grant { return Grant{Role: r} }
	scoped := func(r Role, n string) Grant { return Grant{Role: r, Network: n} }
	for _, c := range []struct {
		name    string
		grants  []Grant
		network string
		want    Grant
		err     error
	}{
		{"one grant for the whole API", []Grant{global(Viewer)}, "", global(Viewer), nil},
		{"the greater of two for the whole API", []Grant{global(Viewer), global(Admin), global(Operator)}, "", global(Admin), nil},
		{"the whole API before a Network", []Grant{scoped(Admin, "a"), global(Viewer)}, "", global(Viewer), nil},
		{"one Network", []Grant{scoped(Viewer, "a"), scoped(Operator, "a")}, "", scoped(Operator, "a"), nil},
		{"several Networks, none named", []Grant{scoped(Admin, "a"), scoped(Admin, "b")}, "", Grant{}, ErrAmbiguous},
		{"several Networks, one named", []Grant{scoped(Viewer, "a"), scoped(Admin, "b")}, "b", scoped(Admin, "b"), nil},
		{"a Network that no group gives", []Grant{scoped(Admin, "a")}, "b", Grant{}, ErrNoRole},
		{"a role of the whole API, narrowed to a Network", []Grant{global(Admin)}, "a", scoped(Admin, "a"), nil},
		{"the whole API and the Network, the greater", []Grant{global(Viewer), scoped(Operator, "a")}, "a", scoped(Operator, "a"), nil},
		{"the whole API greater than the Network", []Grant{global(Admin), scoped(Viewer, "a")}, "a", scoped(Admin, "a"), nil},
		{"a Network that is not the one asked for, beside the whole API", []Grant{global(Viewer), scoped(Admin, "b")}, "a", scoped(Viewer, "a"), nil},
		{"no grant", nil, "", Grant{}, ErrNoRole},
		{"no grant, for a Network", nil, "a", Grant{}, ErrNoRole},
	} {
		got, err := Select(c.grants, c.network)
		if !errors.Is(err, c.err) || got != c.want {
			t.Errorf("%s: Select gave %+v, %v, want %+v, %v", c.name, got, err, c.want, c.err)
		}
	}
	// The refusal of groups for several Networks says which
	_, err := Select([]Grant{scoped(Admin, "b"), scoped(Admin, "a")}, "")
	if err == nil || !strings.Contains(err.Error(), "(a, b)") {
		t.Errorf("the refusal for several Networks is %v, want it to name them", err)
	}
}

// The name of a provider group is a text that is no longer than a name of the directory, and holds nothing that
// a log or a terminal would take for more than text.
func TestCheckMapping(t *testing.T) {
	ok := GroupMapping{Provider: "entra", Group: "CN=Branch A Admins,OU=Groups,DC=example,DC=com", Role: Admin, Network: "branch-a"}
	if g, err := checkMapping(ok); err != nil || g != (Grant{Role: Admin, Network: "branch-a"}) {
		t.Fatalf("checkMapping of a mapping that is right gave %+v, %v", g, err)
	}
	if _, err := checkMapping(GroupMapping{Provider: "okta", Group: "ünïcode groüp 日本語", Role: Viewer}); err != nil {
		t.Errorf("a group in UTF-8 was refused: %v", err)
	}
	for _, c := range []struct {
		name string
		m    GroupMapping
	}{
		{"no provider", GroupMapping{Group: "g", Role: Viewer}},
		{"a provider that is no name", GroupMapping{Provider: "Entra ID", Group: "g", Role: Viewer}},
		{"no group", GroupMapping{Provider: "entra", Role: Viewer}},
		{"a group that is too long", GroupMapping{Provider: "entra", Group: strings.Repeat("g", maxGroupName+1), Role: Viewer}},
		{"a group that is no UTF-8", GroupMapping{Provider: "entra", Group: "g\xff", Role: Viewer}},
		{"a group with a control character", GroupMapping{Provider: "entra", Group: "g\nadmin", Role: Viewer}},
		{"a role that is none", GroupMapping{Provider: "entra", Group: "g", Role: "root"}},
		{"a Network that is no name", GroupMapping{Provider: "entra", Group: "g", Role: Viewer, Network: "Branch A"}},
	} {
		if _, err := checkMapping(c.m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: checkMapping gave %v, want ErrInvalid", c.name, err)
		}
	}
	if _, err := checkMapping(GroupMapping{Provider: "entra", Group: strings.Repeat("g", maxGroupName), Role: Viewer}); err != nil {
		t.Errorf("a group of %d bytes was refused: %v", maxGroupName, err)
	}
}
