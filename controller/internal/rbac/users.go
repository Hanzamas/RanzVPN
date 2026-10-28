package rbac

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The API roles of users and the user tokens (SDN-32, #226; ADR-0031 amendment of 2026-10-28). A User
// of the intent holds no API role of its own (SDN-31). An admin gives one to a User (SetUserRole), and a
// login of that User (internal/login) gives it a user token: a bearer secret, as an API token is, that
// the Guard takes as a token of the role that the User holds when the token is used, until the token
// ends. Taking the role away ends the user tokens of the User at once, and so do a change of the intent
// that removes the User and a ban of the User (internal/controller). The store keeps only the SHA-256
// of a secret, as it does for an API token, and every member of a controller cluster knows the tokens.

// userTokenPrefix starts the secret of a user token. The secret of an API token is secretPrefix and
// the capitals of base32 (rand.Text), so the two never meet, and Authenticate knows where to look.
const userTokenPrefix = secretPrefix + "u_"

// ErrNoRole marks a User that holds no API role, which a login gives no user token.
var ErrNoRole = errors.New("the user holds no API role")

// UserRole is the API role that a User holds, as the API shows it.
type UserRole struct {
	User string `json:"user"`
	Role Role   `json:"role"`
}

// UserToken is a user token just made: its token, its secret, which the controller shows this once,
// and its end.
type UserToken struct {
	Token
	Secret  string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// Actor returns the actor of the audit log that t authenticates: the User of a user token
// (audit.ActorUser), the API token otherwise (audit.ActorToken).
func (t Token) Actor() string {
	if t.User != "" {
		return audit.ActorUser(t.User)
	}
	return audit.ActorToken(t.Name)
}

// userTokenOf returns the token of a user token of the User name, which holds role. Its name is the
// actor of the User, user:NAME, which no API token can have, so the name tells the two apart wherever
// a token is named.
func userTokenOf(name string, role Role) Token {
	return Token{Name: audit.ActorUser(name), Role: role, User: name}
}

// UserRoles returns the API role of every User that holds one, ordered by the name of the User.
func (t *Tokens) UserRoles(ctx context.Context) ([]UserRole, error) {
	rs, err := t.st.UserRoles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserRole, 0, len(rs))
	for _, r := range rs {
		role, err := ParseRole(r.Role)
		if err != nil {
			return nil, fmt.Errorf("stored role of user %q: %w", r.Name, err)
		}
		out = append(out, UserRole{User: r.Name, Role: role})
	}
	return out, nil
}

// UserRole returns the API role of the User name, and false when it holds none.
func (t *Tokens) UserRole(ctx context.Context, name string) (Role, bool, error) {
	s, ok, err := t.st.UserRole(ctx, name)
	if err != nil || !ok {
		return "", false, err
	}
	role, err := ParseRole(s)
	if err != nil {
		return "", false, fmt.Errorf("stored role of user %q: %w", name, err)
	}
	return role, true, nil
}

// SetUserRole gives the User name the API role role, in place of the one it held; its user tokens carry
// the new role from their next call on. The caller checks that the intent holds the User.
func (t *Tokens) SetUserRole(ctx context.Context, name string, role Role) (UserRole, error) {
	if !nameRule.MatchString(name) {
		return UserRole{}, fmt.Errorf("%w: the user name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	if _, err := ParseRole(string(role)); err != nil {
		return UserRole{}, err
	}
	if err := t.st.SetUserRole(ctx, name, string(role)); err != nil {
		return UserRole{}, err
	}
	return UserRole{User: name, Role: role}, nil
}

// DeleteUserRole takes the API role of the User name away, and with it every user token of the User,
// and returns the role that it held. A User that holds none is ErrNotFound.
func (t *Tokens) DeleteUserRole(ctx context.Context, name string) (UserRole, error) {
	role, ok, err := t.UserRole(ctx, name)
	if err != nil {
		return UserRole{}, err
	}
	if !ok {
		return UserRole{}, fmt.Errorf("%w: the user %q holds no API role", ErrNotFound, name)
	}
	deleted, err := t.st.DeleteUserRole(ctx, name)
	if err != nil {
		return UserRole{}, err
	}
	if !deleted {
		return UserRole{}, fmt.Errorf("%w: the user %q holds no API role", ErrNotFound, name)
	}
	return UserRole{User: name, Role: role}, nil
}

// IssueUserToken makes a user token of the User name that ends at expires, for a login of the User that
// the caller checked, and returns it with its secret. A User that holds no API role gets none
// (ErrNoRole). The token carries the role that the User holds when it is used, not the one of now.
func (t *Tokens) IssueUserToken(ctx context.Context, name string, expires time.Time) (UserToken, error) {
	role, ok, err := t.UserRole(ctx, name)
	if err != nil {
		return UserToken{}, err
	}
	if !ok {
		return UserToken{}, fmt.Errorf("%w: user %q", ErrNoRole, name)
	}
	secret := userTokenPrefix + rand.Text()
	// The insert checks the role again, in one statement, against a delete of it meanwhile
	added, err := t.st.AddUserToken(ctx, store.UserToken{Hash: hash(secret), Name: name, Expires: expires}, time.Now())
	if err != nil {
		return UserToken{}, err
	}
	if !added {
		return UserToken{}, fmt.Errorf("%w: user %q", ErrNoRole, name)
	}
	return UserToken{Token: userTokenOf(name, role), Secret: secret, Expires: expires.UTC()}, nil
}

// RevokeUserToken ends the user token whose secret is secret, as its holder does at a logout, and
// returns its token. A secret that is no user token of this controller, or one that ended, is
// ErrUnauthenticated.
func (t *Tokens) RevokeUserToken(ctx context.Context, secret string) (Token, error) {
	if !strings.HasPrefix(secret, userTokenPrefix) {
		return Token{}, ErrUnauthenticated
	}
	tok, err := t.authenticateUser(ctx, secret)
	if err != nil {
		return Token{}, err
	}
	_, deleted, err := t.st.DeleteUserToken(ctx, hash(secret))
	if err != nil {
		return Token{}, err
	}
	if !deleted {
		return Token{}, ErrUnauthenticated
	}
	return tok, nil
}

// authenticateUser returns the token of the user token whose secret is secret, or ErrUnauthenticated
// when there is none, when it ended, or when its User holds no API role any more.
func (t *Tokens) authenticateUser(ctx context.Context, secret string) (Token, error) {
	name, s, ok, err := t.st.UserTokenByHash(ctx, hash(secret), time.Now())
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, ErrUnauthenticated
	}
	role, err := ParseRole(s)
	if err != nil {
		return Token{}, fmt.Errorf("stored role of user %q: %w", name, err)
	}
	return userTokenOf(name, role), nil
}
