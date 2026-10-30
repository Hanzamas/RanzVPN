package rbac

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The self scope (SDN-58, #251, the user portal of the unified-management spec #224). A User signs in to
// the web UI of the portal with its password and a login that asks for the scope self (internal/login),
// and the login gives it a token of that scope: a bearer secret, as the user token of an API role is, that
// the Guard takes as a token of the role Self, which may make the self calls of its User, the calls under
// /api/v1/self, and no other call of the API. It needs no API role: the portal is for every User, and what
// it lets a User do is limited to the devices and the join tokens of that User. The store keeps only the
// SHA-256 of a secret, as it does for an API token, in a table of its own (self_tokens): the scope is fixed
// when the token is made, so a token of the self scope never becomes more when an admin gives the User an
// API role, and the token of a role never becomes a token of the scope. A change of the intent that
// removes the User, a ban of the User, an expiry that moves earlier and a logout end the token, as they
// end the user tokens of a role.

// Self is the role of a token of the self scope. It is no API role: ParseRole refuses it, so an admin
// cannot give it, and Roles does not list it. It is the lowest role that Allows orders, below viewer, so
// that a token of it allows no call that the three API roles ask for, and every token of a role allows the
// self calls: a call of /api/v1/self asks for Self and then for a token of a User (api.Needs, internal/api).
const Self Role = "self"

// selfTokenPrefix starts the secret of a token of the self scope. The secret of an API token is secretPrefix
// and the capitals of base32, and a user token has userTokenPrefix, so the three never meet and Authenticate
// knows where to look.
const selfTokenPrefix = secretPrefix + "s_"

// ranked are the roles that Allows orders, from the one allowed least to the one allowed most: Self, and
// then the three API roles.
var ranked = []Role{Self, Viewer, Operator, Admin}

// IssueSelfToken makes a token of the self scope for the User name that ends at expires, for a login of the
// User that the caller checked, and returns it with its secret, which the controller shows this once. Unlike
// IssueUserToken it asks for no API role of the User.
func (t *Tokens) IssueSelfToken(ctx context.Context, name string, expires time.Time) (UserToken, error) {
	secret := selfTokenPrefix + rand.Text()
	if err := t.st.AddSelfToken(ctx, store.UserToken{Hash: hash(secret), Name: name, Expires: expires}, time.Now()); err != nil {
		return UserToken{}, err
	}
	return UserToken{Token: userTokenOf(name, Self), Secret: secret, Expires: expires.UTC()}, nil
}

// authenticateSelf returns the token of the self token whose secret is secret, or ErrUnauthenticated when
// there is none or it ended.
func (t *Tokens) authenticateSelf(ctx context.Context, secret string) (Token, error) {
	name, ok, err := t.st.SelfTokenByHash(ctx, hash(secret), time.Now())
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, ErrUnauthenticated
	}
	return userTokenOf(name, Self), nil
}

// revokeSelfToken ends the token of the self scope whose secret is secret, as its holder does at a logout,
// and returns its token. A secret that is no such token of this controller, or one that ended, is
// ErrUnauthenticated.
func (t *Tokens) revokeSelfToken(ctx context.Context, secret string) (Token, error) {
	tok, err := t.authenticateSelf(ctx, secret)
	if err != nil {
		return Token{}, err
	}
	_, deleted, err := t.st.DeleteSelfToken(ctx, hash(secret))
	if err != nil {
		return Token{}, err
	}
	if !deleted {
		return Token{}, ErrUnauthenticated
	}
	return tok, nil
}
