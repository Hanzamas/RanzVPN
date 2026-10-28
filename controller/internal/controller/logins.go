package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The logins of users (SDN-32 #226, ADR-0031 amendment of 2026-10-28): what the logins of
// internal/login ask of the controller. A login checks the password of a User (AuthenticateUser,
// users.go) and gives the User either a user token for the API (internal/rbac) or the enrolment of the
// device that asked for the login: the Node resource of the static key of the device, owned by the
// User, as one revision of the intent (EnrolDevice). The maximum devices of the User and every other
// rule of the intent hold for that revision as they hold for an apply, so an enrolment meets the same
// refusal as `ranz apply` (intent.User.MaxDevices). The user tokens follow their User: a change of the
// intent that removes the User deletes them with its API role, one that moves its expiry earlier ends
// them then, and a ban ends them at once.

// Enrolment is what the enrolment of a device gives it: the Node resource that holds its static key,
// owned by the User whose login asked for it, and the revision of the intent that made it, or the one
// in force when a Node of the User held the key already.
type Enrolment struct {
	Node     string `json:"node"`
	User     string `json:"user"`
	Revision uint64 `json:"revision"`
}

// errEnrolled stops the apply of an enrolment whose static key a Node of the same User holds already.
var errEnrolled = errors.New("the device is enrolled already")

// maxEnrolTries bounds the tries of an enrolment whose drawn name another change took meanwhile.
const maxEnrolTries = 3

// HoldsUser reports whether the intent holds the User name.
func (c *Controller) HoldsUser(name string) bool {
	return c.holdsUser(name)
}

// EnrolDevice makes the Node resource of the device whose static key is key, owned by the User user,
// as one revision of the intent, after a login of the User that the caller checked. The Node is named
// name, or, when name is empty, the first of user-1, user-2 and so on that no Node has. It names no
// VRF, so it joins VRF default when the intent holds it (ADR-0034). The revision is recorded in the
// audit log under the origin of ctx (audit.NewContext). A key that a Node of the User holds already is
// the enrolment of that Node, and makes no revision. The errors are those of an apply: one that wraps
// intent.ErrInvalid is a device that the intent refuses, such as one above the maximum devices of the
// User, and one that wraps ErrConflict a name or a key that another Node holds.
func (c *Controller) EnrolDevice(ctx context.Context, user, name string, key []byte) (Enrolment, error) {
	if len(key) != intent.KeySize {
		return Enrolment{}, fmt.Errorf("%w: the static key of the device is %d bytes long, not %d", intent.ErrInvalid, len(key), intent.KeySize)
	}
	spec, err := json.Marshal(intent.Node{PublicKey: base64.StdEncoding.EncodeToString(key), Owner: user})
	if err != nil {
		return Enrolment{}, err
	}
	for try := 1; ; try++ {
		node := name
		if node == "" {
			node = c.freeDeviceName(user)
		}
		var held string
		taken := false
		// Checked under the lock of the apply, against the intent that it changes, so that no other
		// change slips in between: an apply of a Node of a name that exists would replace that Node
		check := func(in intent.Intent) error {
			if _, ok := in.Users[user]; !ok {
				return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, user)
			}
			for _, n := range slices.Sorted(maps.Keys(in.Nodes)) {
				k, err := intent.ParseKey(in.Nodes[n].PublicKey)
				if err != nil || !bytes.Equal(k, key) {
					continue
				}
				if in.Nodes[n].Owner != user {
					return fmt.Errorf("%w: the static key of the device is the key of a Node that is no device of User %q", ErrConflict, user)
				}
				held = n
				return errEnrolled
			}
			if _, ok := in.Nodes[node]; ok {
				taken = true
				return fmt.Errorf("%w: a Node named %q exists", ErrConflict, node)
			}
			return nil
		}
		doc := intent.Document{Resources: []intent.Resource{{Kind: intent.KindNode, Name: node, Spec: spec}}}
		res, err := c.ApplyConfirm(withPrecondition(ctx, check), doc, 0)
		switch {
		case errors.Is(err, errEnrolled):
			// The device authenticates again, so its key lives for another period (nodekeys.go; SDN-56)
			if err := c.refreshKey(ctx, held, user); err != nil {
				return Enrolment{}, err
			}
			return Enrolment{Node: held, User: user, Revision: c.LatestRevision()}, nil
		case taken && name == "" && try < maxEnrolTries:
			// Another change took the name that was drawn: draw the next one
			continue
		case err != nil:
			return Enrolment{}, err
		}
		c.log.Info("device enrolled", "user", user, "node", node, "revision", res.Revision)
		return Enrolment{Node: node, User: user, Revision: res.Revision}, nil
	}
}

// freeDeviceName returns the first of user-1, user-2 and so on that no Node of the intent has, the
// name of the User cut so that the whole is a name.
func (c *Controller) freeDeviceName(user string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 1; ; i++ {
		suffix := "-" + strconv.Itoa(i)
		base := user
		if len(base)+len(suffix) > 63 {
			base = strings.TrimRight(base[:63-len(suffix)], "-")
		}
		if _, ok := c.intent.Nodes[base+suffix]; !ok {
			return base + suffix
		}
	}
}

// preconditionKey carries a condition on the intent in force in the context of an apply, which
// ApplyConfirm checks under its lock before it changes anything (withPrecondition).
type preconditionKey struct{}

// withPrecondition returns ctx with check in it: ApplyConfirm runs check on the intent in force, under
// its lock, and makes no change when it fails, with its error.
func withPrecondition(ctx context.Context, check func(intent.Intent) error) context.Context {
	return context.WithValue(ctx, preconditionKey{}, check)
}

// checkPrecondition runs the condition that ctx carries (withPrecondition) on in, the intent in force;
// a context with none passes. c.mu is held.
func checkPrecondition(ctx context.Context, in intent.Intent) error {
	if check, ok := ctx.Value(preconditionKey{}).(func(intent.Intent) error); ok {
		return check(in)
	}
	return nil
}

// dropUserAccess deletes the API role and the user tokens of each User that the intent next no longer
// holds, so that a User made again under the name starts with neither, as it starts with no password,
// and ends the user tokens of each User whose expiry next moves earlier at that expiry, so that no token
// outlives its User. dropPasswords calls it once the change is stored, before next becomes the intent.
// A failure is logged: a User that the intent does not hold cannot log in anyway. c.mu is held.
func (c *Controller) dropUserAccess(ctx context.Context, next intent.Intent) {
	var gone []string
	for _, name := range slices.Sorted(maps.Keys(c.intent.Users)) {
		u, ok := next.Users[name]
		if !ok {
			gone = append(gone, name)
			continue
		}
		if was := c.intent.Users[name].Expires; !u.Expires.IsZero() && (was.IsZero() || u.Expires.Before(was)) {
			if err := c.store.EndUserTokens(ctx, name, u.Expires); err != nil {
				c.log.Warn("ending the user tokens of a user whose expiry moved earlier", "user", name, "err", err)
			}
		}
	}
	if len(gone) == 0 {
		return
	}
	if err := c.store.DeleteUserRoles(ctx, gone); err != nil {
		c.log.Warn("deleting the API roles and the user tokens of removed users", "users", gone, "err", err)
	}
}

// endUserTokens deletes the user tokens of the User user, which an operator banned (bans.go): a banned
// user calls the API no more than its devices reach the overlay. A failure is logged.
func (c *Controller) endUserTokens(ctx context.Context, user string) {
	if err := c.store.DeleteUserTokens(ctx, []string{user}); err != nil {
		c.log.Warn("deleting the user tokens of a banned user", "user", user, "err", err)
	}
}
