package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The join tokens (SDN-58 #251, ADR-0031 amendment of 2026-10-29). A User makes a join token in the portal
// for a device of its own that cannot sign in itself, such as a Node without a browser, and gives the secret
// to that device, which presents it with its static key to the joins of the logins (internal/login, POST
// /api/v1/login/join). The Controller enrols the device as a Node that the User owns (EnrolDevice), in the
// VRFs that a Node with no VRF of its own gets (VRF default, ADR-0034), with the tags of the Groups of the
// User, so the policy that is written for them reaches it, and the token is spent. A join token is one use,
// lasts JoinTokenLife and is the User's alone: a User lists and revokes its own, and the store keeps only the
// SHA-256 of the secret, outside the intent (internal/store, jointokens.go). The device is enrolled as the
// User, under the actor user:NAME of the audit log, whatever its source address, and the enrolment is refused
// for a User that has expired or that an operator banned, and for a device above the maximum devices of the
// User, as the enrolment of a login is.

const (
	// JoinTokenLife is how long a join token lasts from the moment that its User makes it.
	JoinTokenLife = 24 * time.Hour
	// MaxJoinTokens is the most join tokens that one User may have waiting for a device.
	MaxJoinTokens = 16
	// JoinTokenPrefix starts the secret of a join token. The secret of an API token is "ranz_" and the capitals
	// of base32, and the tokens of a login have "ranz_u_" and "ranz_s_", so none of them is taken for another.
	JoinTokenPrefix = "ranz_j_"
	// The shortest and the longest text after the prefix: crypto/rand.Text gives 26 characters of base32.
	minJoinText = 26
	maxJoinText = 64
)

// ErrBadJoinToken marks a join with a secret that is no join token of this controller, or one that was used
// or has ended: one error for the three, so that a join says nothing of which tokens exist.
var ErrBadJoinToken = errors.New("the join token is not one of this controller, or it was used or it ended")

// deviceNameRule is the rule of the names of resources (intent), which the name of a Node is one of.
var deviceNameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// checkDeviceName refuses a name for the Node of a device that is no name of a resource, with an error that wraps
// intent.ErrInvalid. The empty name is the one that the controller draws. The name is checked before anything else
// is, so a name that is no name is refused whichever key comes with it, also one that a Node of the User holds
// already, whose enrolment is otherwise made again with no revision (EnrolDevice).
func checkDeviceName(name string) error {
	if name != "" && !deviceNameRule.MatchString(name) {
		return badRequestf("the name of the device must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen")
	}
	return nil
}

// JoinTokenInfo is a join token as its User sees it in the portal: never its secret.
type JoinTokenInfo struct {
	// ID names the token in the list of its User and in the revocation of it.
	ID string `json:"id"`
	// Name is the name that the Node of the device takes, left out for a name that the controller draws.
	Name string `json:"name,omitempty"`
	// Created is when the User made the token, and Expires when it ends.
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// NewJoinToken is a join token just made, with its secret, which the controller shows this once.
type NewJoinToken struct {
	JoinTokenInfo
	// Token is the secret of the join token, which the device presents.
	Token string `json:"token"`
}

// ValidJoinToken reports whether secret has the form of the secret of a join token: the prefix and between
// 26 and 64 characters of the base32 alphabet that crypto/rand.Text writes, capitals and the digits 2 to 7.
func ValidJoinToken(secret string) bool {
	text, ok := strings.CutPrefix(secret, JoinTokenPrefix)
	if !ok || len(text) < minJoinText || len(text) > maxJoinText {
		return false
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; !('A' <= c && c <= 'Z' || '2' <= c && c <= '7') {
			return false
		}
	}
	return true
}

// joinHash is the form in which the store keeps the secret of a join token: the hex SHA-256 of it, as for the
// API tokens, since a secret has at least 128 random bits.
func joinHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// joinInfo returns the join token t as its User sees it.
func joinInfo(t store.JoinToken) JoinTokenInfo {
	return JoinTokenInfo{ID: t.ID, Name: t.Name, Created: t.Created, Expires: t.Expires}
}

// MakeJoinToken makes a join token for a device of the User user (POST /api/v1/self/join-tokens), which
// takes the name name when it joins, or a name that the controller draws when name is empty, and returns it
// with its secret, which nobody can read again. An error that wraps intent.ErrInvalid is a name that is no
// name of a resource, one that wraps ErrConflict a User that has MaxJoinTokens waiting already, and one that
// wraps ErrUserExpired or ErrUserBanned a User that may not act now.
func (c *Controller) MakeJoinToken(ctx context.Context, user, name string) (NewJoinToken, error) {
	if err := checkDeviceName(name); err != nil {
		return NewJoinToken{}, err
	}
	if err := c.validUser(user); err != nil {
		return NewJoinToken{}, err
	}
	var id [8]byte
	_, _ = rand.Read(id[:])
	secret := JoinTokenPrefix + rand.Text()
	now := c.keyNow()
	t := store.JoinToken{Hash: joinHash(secret), ID: hex.EncodeToString(id[:]), Owner: user, Name: name, Created: now, Expires: now.Add(JoinTokenLife)}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	ok, err := c.store.AddJoinToken(sctx, t, now, MaxJoinTokens)
	if err != nil {
		return NewJoinToken{}, err
	}
	if !ok {
		return NewJoinToken{}, fmt.Errorf("%w: User %q has %d join tokens waiting already: a device uses one, or its User revokes one, first", ErrConflict, user, MaxJoinTokens)
	}
	c.log.Info("join token made", "user", user, "id", t.ID, "device", name)
	return NewJoinToken{JoinTokenInfo: joinInfo(t), Token: secret}, nil
}

// JoinTokens returns the join tokens of the User user that wait for a device, oldest first, without their
// secrets (GET /api/v1/self/join-tokens). An error that wraps intent.ErrNotFound is a User that the intent
// does not hold.
func (c *Controller) JoinTokens(ctx context.Context, user string) ([]JoinTokenInfo, error) {
	if !c.holdsUser(user) {
		return nil, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(user, maxSubject))
	}
	ts, err := c.store.JoinTokens(ctx, user, c.keyNow())
	if err != nil {
		return nil, err
	}
	out := make([]JoinTokenInfo, len(ts))
	for i, t := range ts {
		out[i] = joinInfo(t)
	}
	return out, nil
}

// RevokeJoinToken deletes the join token of the User user that has the id id, so that no device joins with
// it (DELETE /api/v1/self/join-tokens/{id}), and returns it. A token that no device is using and that the User
// has not made is not found: an error that wraps intent.ErrNotFound.
func (c *Controller) RevokeJoinToken(ctx context.Context, user, id string) (JoinTokenInfo, error) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	t, ok, err := c.store.DeleteJoinToken(sctx, user, id)
	if err != nil {
		return JoinTokenInfo{}, err
	}
	if !ok {
		return JoinTokenInfo{}, fmt.Errorf("%w: User %q has no join token %q", intent.ErrNotFound, user, clip(id, maxSubject))
	}
	c.log.Info("join token revoked", "user", user, "id", id)
	return joinInfo(t), nil
}

// JoinDevice enrols the device whose static key is key as a device of the User that made the join token
// whose secret is secret (POST /api/v1/login/join), as one revision of the intent under the actor of that
// User, and spends the token. The Node is named name, or the name that the token carries, or, with neither,
// the first of user-1, user-2 and so on that no Node has. The token is taken first, so two devices cannot
// join with one, and given back when the enrolment is refused, so that its User can try again once the
// reason is gone. The Enrolment names the User whenever the token was valid, also for an error.
//
// ErrBadJoinToken is a secret that no join token has, one that was used or ended, or one that is not of the
// form of a join token. For a valid token, the errors are those of EnrolDevice, and one that wraps
// ErrUserExpired or ErrUserBanned is a User that may not act now.
func (c *Controller) JoinDevice(ctx context.Context, secret, name string, key []byte) (Enrolment, error) {
	if !ValidJoinToken(secret) {
		return Enrolment{}, ErrBadJoinToken
	}
	hash := joinHash(secret)
	tok, ok, err := c.store.ClaimJoinToken(ctx, hash, c.keyNow())
	if err != nil {
		return Enrolment{}, err
	}
	if !ok {
		return Enrolment{}, ErrBadJoinToken
	}
	e, err := c.joinEnrol(ctx, tok, name, key)
	// The token is the User's until a device is enrolled with it, whatever happened to the request of ctx
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err != nil {
		if rerr := c.store.ReleaseJoinToken(sctx, hash); rerr != nil {
			c.log.Warn("giving back a join token after a refused enrolment", "user", tok.Owner, "id", tok.ID, "err", rerr)
		}
		return Enrolment{User: tok.Owner}, err
	}
	if ferr := c.store.FinishJoinToken(sctx, hash); ferr != nil {
		c.log.Warn("deleting a join token that enrolled a device", "user", tok.Owner, "id", tok.ID, "err", ferr)
	}
	c.log.Info("device joined with a join token", "user", tok.Owner, "id", tok.ID, "node", e.Node, "revision", e.Revision)
	return e, nil
}

// joinEnrol enrols the device with the key key for the User of the join token tok that JoinDevice took: the
// User must be able to act now, and the revision is made under its actor.
func (c *Controller) joinEnrol(ctx context.Context, tok store.JoinToken, name string, key []byte) (Enrolment, error) {
	if err := c.validUser(tok.Owner); err != nil {
		return Enrolment{}, err
	}
	if name == "" {
		name = tok.Name
	}
	origin, _ := audit.FromContext(ctx)
	origin.Actor = audit.ActorUser(tok.Owner)
	return c.EnrolDevice(audit.NewContext(ctx, origin), tok.Owner, name, key)
}
