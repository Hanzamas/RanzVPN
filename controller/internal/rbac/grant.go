package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The roles scoped to one Network (SDN-38, #231; ADR-0031 amendment of 2026-10-29). A role of the API is held
// for the whole API, or for one Network: a Grant names the role and, for a scoped role, the Network. The Guard
// takes a scoped role as no role at all for any call that is not about its Network (internal/api, scoped.go),
// so a scope only ever narrows a role. What the Controller lets a scoped role change in its Network, and how
// much, is the delegation of the Network (internal/scope), which an admin sets; this package knows only who
// holds a role for which Network.
//
// The scope is part of the stored role, not a fact beside it: the tables hold role@network (for example
// operator@branch-a) where they held a role, so a token or a role is never stored without its scope, and
// one that a controller of an earlier release reads fails to parse and authenticates nothing, instead of
// holding its role for the whole API. The roles of the tokens that hold no scope are stored as they were.

// scopeSeparator separates the role from the Network in the stored form of a scoped role. A Network name is a
// DNS label, which holds no such character.
const scopeSeparator = "@"

// Grant is what a role is held for: the role, and for a scoped role the one Network.
type Grant struct {
	// Role is viewer, operator or admin.
	Role Role `json:"role"`
	// Network is the Network that the role is held for. Left out, the role is held for the whole API.
	Network string `json:"network,omitempty"`
}

// Scoped reports whether the role is held for one Network.
func (g Grant) Scoped() bool {
	return g.Network != ""
}

// String returns the stored form of the grant: the role, and for a scoped role @ and the Network.
func (g Grant) String() string {
	if g.Network == "" {
		return string(g.Role)
	}
	return string(g.Role) + scopeSeparator + g.Network
}

// NewGrant returns the grant of the role role for the Network network, which is empty for the whole API. It
// is an error that wraps ErrInvalid when the role is none of the three or the Network is no Network name.
func NewGrant(role Role, network string) (Grant, error) {
	if _, err := ParseRole(string(role)); err != nil {
		return Grant{}, err
	}
	if network != "" && !nameRule.MatchString(network) {
		return Grant{}, fmt.Errorf("%w: the Network name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, network)
	}
	return Grant{Role: role, Network: network}, nil
}

// ParseGrant returns the grant that the stored form s holds: a role, or a role, @ and a Network. A role that
// is none of the three, a Network that is no Network name and an @ with no Network are refused, with an error
// that wraps ErrInvalid, so a scoped role is never read as a role of the whole API.
func ParseGrant(s string) (Grant, error) {
	role, network, scoped := strings.Cut(s, scopeSeparator)
	if scoped && network == "" {
		return Grant{}, fmt.Errorf("%w: the role %q names no Network after the %s", ErrInvalid, s, scopeSeparator)
	}
	return NewGrant(Role(role), network)
}

// Grant returns the grant that the token holds.
func (t Token) Grant() Grant {
	return Grant{Role: t.Role, Network: t.Network}
}

// CreateGrant creates the token name with the grant g, which the controller refuses from the instant expires
// on, and returns it with its secret. The zero time makes a token that never expires. A scoped token is held
// for the Network of g only; the caller checks that the Network exists.
func (t *Tokens) CreateGrant(ctx context.Context, name string, g Grant, expires time.Time) (NewToken, error) {
	if !nameRule.MatchString(name) {
		return NewToken{}, fmt.Errorf("%w: the token name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	g, err := NewGrant(g.Role, g.Network)
	if err != nil {
		return NewToken{}, err
	}
	if !expires.IsZero() {
		expires = expires.UTC().Truncate(time.Second)
		if y := expires.Year(); y < 1 || y > 9999 {
			return NewToken{}, fmt.Errorf("%w: the expiry is outside the years 1 to 9999 (UTC)", ErrInvalid)
		}
		if !expires.After(t.now()) {
			return NewToken{}, fmt.Errorf("%w: the expiry %s is not in the future", ErrInvalid, expires.Format(time.RFC3339))
		}
	}
	secret := newSecret()
	ok, err := t.st.AddToken(ctx, store.Token{Name: name, Role: g.String(), Hash: hash(secret), Expires: expires})
	if err != nil {
		return NewToken{}, err
	}
	if !ok {
		return NewToken{}, fmt.Errorf("%w: a token named %q exists already", ErrExists, name)
	}
	return NewToken{Token: Token{Name: name, Role: g.Role, Network: g.Network, Expires: expires}, Secret: secret}, nil
}

// SetGrant gives the API token name the grant g in place, its secret unchanged, as SetRole gives it a role: its
// next call has the new role and the new scope. It refuses to take the role admin of the whole API from the
// last token that holds it (ErrLastAdmin), which includes scoping it, and returns the token as it is now.
func (t *Tokens) SetGrant(ctx context.Context, name string, g Grant) (Token, error) {
	g, err := NewGrant(g.Role, g.Network)
	if err != nil {
		return Token{}, err
	}
	return t.change(ctx, name, func(Grant) Grant { return g })
}

// UserGrant returns the grant that the User name holds, and false when it holds none.
func (t *Tokens) UserGrant(ctx context.Context, name string) (Grant, bool, error) {
	s, ok, err := t.st.UserRole(ctx, name)
	if err != nil || !ok {
		return Grant{}, false, err
	}
	g, err := ParseGrant(s)
	if err != nil {
		return Grant{}, false, fmt.Errorf("stored role of user %q: %w", name, err)
	}
	return g, true, nil
}

// SetUserGrant gives the User name the grant g, in place of the one it held: its user tokens carry the new
// role and the new scope from their next call on. The caller checks that the intent holds the User, and the
// Network.
func (t *Tokens) SetUserGrant(ctx context.Context, name string, g Grant) (UserRole, error) {
	if !nameRule.MatchString(name) {
		return UserRole{}, fmt.Errorf("%w: the user name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	g, err := NewGrant(g.Role, g.Network)
	if err != nil {
		return UserRole{}, err
	}
	if err := t.st.SetUserRole(ctx, name, g.String()); err != nil {
		return UserRole{}, err
	}
	return UserRole{User: name, Role: g.Role, Network: g.Network}, nil
}

// userTokenOfGrant returns the token of a user token of the User name, which holds the grant g: userTokenOf
// with the Network of the scope.
func userTokenOfGrant(name string, g Grant) Token {
	tok := userTokenOf(name, g.Role)
	tok.Network = g.Network
	return tok
}
