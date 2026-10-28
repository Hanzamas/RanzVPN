// Package rbac is the access control of the controller's API (#176 "Intent API, explain and
// RBAC", ADR-0031 decision 9): three global roles, each allowed what the roles below it are. A
// viewer reads the status, the Intent and the nodes; an operator also applies Intent and deletes
// resources; an admin also manages the API tokens, so only an admin changes who holds which role.
//
// A caller holds a role through an API token, a bearer secret (RFC 6750) that the controller
// shows once, when it creates the token, and keeps only as its SHA-256 in rqlite beside the
// Intent: every member of a controller cluster knows a token, and a deleted one stops working at
// once. The first start of a controller creates the admin token FirstAdmin (Bootstrap), and a
// local administrator of its host a new one when every admin secret is lost (Recover). Logins
// of users (SDN-32, #226) and roles scoped to one Network (SDN-38, #231) come later and grant
// the same roles.
package rbac

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// Role is one of the three global roles.
type Role string

const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Admin    Role = "admin"
)

// Roles are the roles from the one allowed least to the one allowed most.
var Roles = []Role{Viewer, Operator, Admin}

// FirstAdmin is the name of the admin token that Bootstrap creates.
const FirstAdmin = "admin"

// secretPrefix starts every token secret, so a secret is recognisable where it leaks, for
// example to a secret scanner, as the tokens of GitHub and GitLab are.
const secretPrefix = "ranz_"

var (
	// ErrUnauthenticated marks a secret that is not the secret of any token.
	ErrUnauthenticated = errors.New("no token has this secret")
	// ErrInvalid marks a token request with a bad name or role.
	ErrInvalid = errors.New("invalid token request")
	// ErrNotFound marks a delete of a token that does not exist.
	ErrNotFound = errors.New("no such token")
	// ErrExists marks the creation of a token whose name is taken.
	ErrExists = errors.New("the token exists")
	// ErrLastAdmin marks the delete of the last admin token, which would leave the controller
	// without anyone who may manage the tokens.
	ErrLastAdmin = errors.New("the last admin token")
)

// nameRule is the rule of resource names (internal/intent) for token names too.
var nameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseRole returns the role named s.
func ParseRole(s string) (Role, error) {
	for _, r := range Roles {
		if string(r) == s {
			return r, nil
		}
	}
	return "", fmt.Errorf("%w: the role must be %s, %s or %s, not %q", ErrInvalid, Viewer, Operator, Admin, s)
}

// Allows reports whether r may do what need may do: a role may do everything the roles below
// it may.
func (r Role) Allows(need Role) bool {
	return need.rank() > 0 && r.rank() >= need.rank()
}

func (r Role) rank() int {
	for i, x := range Roles {
		if x == r {
			return i + 1
		}
	}
	return 0
}

// Token is an API token as the API shows it: its name and its role, never its secret.
type Token struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
	// User is the User whose login made the token, a user token (users.go; SDN-32), and empty for an
	// API token.
	User string `json:"user,omitempty"`
}

// NewToken is a token just created, with its secret, which the controller shows this once.
type NewToken struct {
	Token
	Secret string `json:"token"`
}

// Tokens are the API tokens of a controller, in its store.
type Tokens struct {
	st *store.Store
}

// New returns the tokens in st.
func New(st *store.Store) *Tokens {
	return &Tokens{st: st}
}

// Authenticate returns the token whose secret is secret, an API token or a user token, or
// ErrUnauthenticated.
func (t *Tokens) Authenticate(ctx context.Context, secret string) (Token, error) {
	if !strings.HasPrefix(secret, secretPrefix) {
		return Token{}, ErrUnauthenticated
	}
	if strings.HasPrefix(secret, userTokenPrefix) {
		// A user token of a login (users.go; SDN-32)
		return t.authenticateUser(ctx, secret)
	}
	st, ok, err := t.st.TokenByHash(ctx, hash(secret))
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, ErrUnauthenticated
	}
	return token(st)
}

// List returns every token, ordered by name.
func (t *Tokens) List(ctx context.Context) ([]Token, error) {
	sts, err := t.st.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	out := []Token{}
	for _, st := range sts {
		tok, err := token(st)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	return out, nil
}

// Create creates the token name with role and returns it with its secret.
func (t *Tokens) Create(ctx context.Context, name string, role Role) (NewToken, error) {
	if !nameRule.MatchString(name) {
		return NewToken{}, fmt.Errorf("%w: the token name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	if _, err := ParseRole(string(role)); err != nil {
		return NewToken{}, err
	}
	secret := newSecret()
	ok, err := t.st.AddToken(ctx, store.Token{Name: name, Role: string(role), Hash: hash(secret)})
	if err != nil {
		return NewToken{}, err
	}
	if !ok {
		return NewToken{}, fmt.Errorf("%w: a token named %q exists already", ErrExists, name)
	}
	return NewToken{Token: Token{Name: name, Role: role}, Secret: secret}, nil
}

// Delete deletes the token name and returns it. It refuses to delete the last admin token.
func (t *Tokens) Delete(ctx context.Context, name string) (Token, error) {
	sts, err := t.st.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	var gone *store.Token
	for i := range sts {
		if sts[i].Name == name {
			gone = &sts[i]
		}
	}
	if gone == nil {
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	ok, err := t.st.DeleteToken(ctx, name, string(Admin))
	if err != nil {
		return Token{}, err
	}
	if !ok {
		if gone.Role == string(Admin) {
			return Token{}, fmt.Errorf("%w: %q is the last token with the role %s, and the controller keeps one; create another admin token first", ErrLastAdmin, name, Admin)
		}
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return token(*gone)
}

// Bootstrap creates the admin token FirstAdmin when the store holds no token at all, which is
// the first start of a controller, and hands its secret to save, which keeps it where the
// operator finds it. It reports whether it created the token. When save fails, it deletes the
// token again, so the controller never holds an admin token that nobody knows.
func (t *Tokens) Bootstrap(ctx context.Context, save func(secret string) error) (bool, error) {
	secret := newSecret()
	ok, err := t.st.AddFirstToken(ctx, store.Token{Name: FirstAdmin, Role: string(Admin), Hash: hash(secret)})
	if err != nil || !ok {
		return false, err
	}
	if err := save(secret); err != nil {
		if _, derr := t.st.DeleteToken(ctx, FirstAdmin, ""); derr != nil {
			return false, fmt.Errorf("%w; deleting the token again: %w", err, derr)
		}
		return false, err
	}
	return true, nil
}

// Recover creates the admin token name for a local administrator of the controller's host who
// lost the secret of every admin token (`ranz-controller reset-admin`), and hands its secret to
// save, as Bootstrap does. The admin tokens that exist stay; the new one may delete them. When
// save fails, it deletes the token again.
func (t *Tokens) Recover(ctx context.Context, name string, save func(secret string) error) (NewToken, error) {
	tok, err := t.Create(ctx, name, Admin)
	if err != nil {
		return NewToken{}, err
	}
	if err := save(tok.Secret); err != nil {
		if _, derr := t.st.DeleteToken(ctx, name, ""); derr != nil {
			return NewToken{}, fmt.Errorf("%w; deleting the token again: %w", err, derr)
		}
		return NewToken{}, err
	}
	return tok, nil
}

func token(st store.Token) (Token, error) {
	role, err := ParseRole(st.Role)
	if err != nil {
		return Token{}, fmt.Errorf("stored token %q: %w", st.Name, err)
	}
	return Token{Name: st.Name, Role: role}, nil
}

// newSecret returns a new token secret: secretPrefix and the base32 text of crypto/rand.Text,
// which holds at least 128 random bits.
func newSecret() string {
	return secretPrefix + rand.Text()
}

// hash is the form in which the store keeps a secret: the hex SHA-256 of it. A secret has at
// least 128 random bits, so a fast hash is enough; a password hash would only slow down every
// API call.
func hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
