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
//
// A token has a life (AUD1-DT-13, #461): it may be made with an expiry (CreateExpiring), from
// which the controller refuses its secret (ErrExpired) while an admin can still list and delete
// it, and the controller keeps the last use of each token, at most once in UseInterval, which the
// list shows.
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
	"sync"
	"time"

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

// UseInterval is how often the last use of a token is stored: a token that is used again within
// it keeps the use that was stored, so a busy token costs the store one write a minute and its
// last use is right to the minute.
const UseInterval = time.Minute

// maxUsed bounds the tokens that Tokens remembers a store of the last use for; past it, the ones
// that are due again are forgotten.
const maxUsed = 1024

var (
	// ErrUnauthenticated marks a secret that is not the secret of a token that works: no token has
	// it, or the token that had it was deleted or has expired (ErrExpired).
	ErrUnauthenticated = errors.New("no token has this secret")
	// ErrExpired marks the secret of a token that has expired. It is an ErrUnauthenticated as well,
	// so that a caller that does not tell the two apart refuses it all the same.
	ErrExpired = fmt.Errorf("%w (the token has expired)", ErrUnauthenticated)
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
	// The roles that Allows orders: the three API roles, and the role Self of the self scope below them
	for i, x := range ranked {
		if x == r {
			return i + 1
		}
	}
	return 0
}

// Token is an API token as the API shows it: its name, its role and its life, never its secret.
type Token struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
	// User is the User whose login made the token, a user token (users.go; SDN-32), and empty for an
	// API token.
	User string `json:"user,omitempty"`
	// Expires is the instant, an RFC 3339 time, from which the controller refuses the secret of the
	// API token. Left out, the token never expires. A user token has its own end (UserToken), which
	// the store checks, so this stays empty for it.
	Expires time.Time `json:"expires,omitzero"`
	// Expired says that Expires has passed: the token is refused (401), still listed, and an admin
	// can still delete it.
	Expired bool `json:"expired,omitempty"`
	// LastUsed is when the API token last authenticated a call, right to the minute (UseInterval).
	// Left out, the token was never used, and a user token keeps no use.
	LastUsed time.Time `json:"lastUsed,omitzero"`
}

// ExpiredAt reports whether the token has expired at the instant now: it has an expiry, and now is
// not before it.
func (t Token) ExpiredAt(now time.Time) bool {
	return !t.Expires.IsZero() && !now.Before(t.Expires)
}

// NewToken is a token just created, with its secret, which the controller shows this once.
type NewToken struct {
	Token
	Secret string `json:"token"`
}

// Tokens are the API tokens of a controller, in its store.
type Tokens struct {
	st  *store.Store
	now func() time.Time

	mu sync.Mutex
	// used holds, for the hash of each token, when this member last tried to store its use, so that
	// a burst of calls with one token stores it once.
	used map[string]time.Time
}

// New returns the tokens in st.
func New(st *store.Store) *Tokens {
	return &Tokens{st: st, now: time.Now, used: map[string]time.Time{}}
}

// WithClock makes t read the time from now, which a test sets: the expiry of an API token and the
// minute between two stores of its use go by it. It returns t.
func (t *Tokens) WithClock(now func() time.Time) *Tokens {
	t.now = now
	return t
}

// Authenticate returns the token whose secret is secret, an API token or a user token,
// ErrUnauthenticated when no token has it, and ErrExpired, with the token, when the API token has
// expired. An API token that is accepted has its use stored, at most once in UseInterval; the token
// that Authenticate returns is as the store held it before this use. A user token has its own end,
// which the store checks (users.go), and no use of it is stored.
func (t *Tokens) Authenticate(ctx context.Context, secret string) (Token, error) {
	if !strings.HasPrefix(secret, secretPrefix) {
		return Token{}, ErrUnauthenticated
	}
	if strings.HasPrefix(secret, userTokenPrefix) {
		// A user token of a login (users.go; SDN-32)
		return t.authenticateUser(ctx, secret)
	}
	if strings.HasPrefix(secret, selfTokenPrefix) {
		// A token of the self scope of a login for the portal (self.go; SDN-58)
		return t.authenticateSelf(ctx, secret)
	}
	st, ok, err := t.st.TokenByHash(ctx, hash(secret))
	if err != nil {
		return Token{}, err
	}
	if !ok {
		return Token{}, ErrUnauthenticated
	}
	now := t.now()
	tok, err := token(st, now)
	if err != nil {
		return Token{}, err
	}
	if tok.Expired {
		return tok, fmt.Errorf("%w: token %q expired at %s", ErrExpired, tok.Name, tok.Expires.Format(time.RFC3339))
	}
	t.use(ctx, st, now)
	return tok, nil
}

// use stores that the token st was used at now, unless its use was stored less than UseInterval ago,
// by the store of any member or by this one. A use that cannot be stored is no reason to refuse
// the call, and the next call after the interval tries again.
func (t *Tokens) use(ctx context.Context, st store.Token, now time.Time) {
	if !st.LastUsed.IsZero() && now.Sub(st.LastUsed) < UseInterval {
		return
	}
	if !t.attempt(st.Hash, now) {
		return
	}
	_ = t.st.TouchToken(ctx, st.Hash, now, UseInterval)
}

// attempt reports whether this member may store the use of the token with the hash h at now, which
// it may once in UseInterval, and remembers that it tries.
func (t *Tokens) attempt(h string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at, ok := t.used[h]; ok && now.Sub(at) < UseInterval {
		return false
	}
	t.used[h] = now
	if len(t.used) > maxUsed {
		for k, at := range t.used {
			if now.Sub(at) >= UseInterval {
				delete(t.used, k)
			}
		}
	}
	return true
}

// List returns every token, ordered by name, with its life.
func (t *Tokens) List(ctx context.Context) ([]Token, error) {
	sts, err := t.st.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	now := t.now()
	out := []Token{}
	for _, st := range sts {
		tok, err := token(st, now)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	return out, nil
}

// Create creates the token name with role, which never expires, and returns it with its secret.
func (t *Tokens) Create(ctx context.Context, name string, role Role) (NewToken, error) {
	return t.CreateExpiring(ctx, name, role, time.Time{})
}

// CreateExpiring creates the token name with role, which the controller refuses from the instant
// expires on, and returns it with its secret. The zero time makes a token that never expires. An
// expiry is kept in UTC to the second, and is refused unless it is in the future and in the years 1
// to 9999.
func (t *Tokens) CreateExpiring(ctx context.Context, name string, role Role, expires time.Time) (NewToken, error) {
	if !nameRule.MatchString(name) {
		return NewToken{}, fmt.Errorf("%w: the token name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	if _, err := ParseRole(string(role)); err != nil {
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
	ok, err := t.st.AddToken(ctx, store.Token{Name: name, Role: string(role), Hash: hash(secret), Expires: expires})
	if err != nil {
		return NewToken{}, err
	}
	if !ok {
		return NewToken{}, fmt.Errorf("%w: a token named %q exists already", ErrExists, name)
	}
	return NewToken{Token: Token{Name: name, Role: role, Expires: expires}, Secret: secret}, nil
}

// Delete deletes the token name, whether it has expired or not, and returns it. It refuses to delete
// the last admin token.
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
	return token(*gone, t.now())
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

// token returns the stored token st as the API shows it at the instant now.
func token(st store.Token, now time.Time) (Token, error) {
	role, err := ParseRole(st.Role)
	if err != nil {
		return Token{}, fmt.Errorf("stored token %q: %w", st.Name, err)
	}
	tok := Token{Name: st.Name, Role: role, Expires: st.Expires, LastUsed: st.LastUsed}
	tok.Expired = tok.ExpiredAt(now)
	return tok, nil
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
