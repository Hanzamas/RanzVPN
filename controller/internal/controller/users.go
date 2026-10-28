package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/password"
)

// The users and the groups (SDN-31 #225, ADR-0031 amendment of 2026-10-25). The Users and the Groups
// are resources of the intent, applied like any other (internal/intent, user.go). What the intent
// cannot hold is here: the password of a User, kept as a PBKDF2 hash in the store (internal/password,
// internal/store) and never in the intent, and what a login of a User asks of both. The logins of
// SDN-32 (#226), the self-service portal (#251) and the Devices of #374 build on AuthenticateUser,
// ChangeUserPassword and the devices that a User has.

var (
	// ErrBadCredentials marks a login with a name that no User has, with a User that has no password,
	// or with a wrong password: one error for the three, so that a login does not tell which names
	// exist.
	ErrBadCredentials = errors.New("the user name or the password is wrong")
	// ErrUserExpired marks a login of a User that has expired, with the right password.
	ErrUserExpired = errors.New("the user has expired")
	// ErrSavedPassword marks a login with the right password of a User that may not save its
	// password, which the client took from its own storage.
	ErrSavedPassword = errors.New("the user may not save the password")
	// ErrPasswordFixed marks a change of a password by a User that may not change it.
	ErrPasswordFixed = errors.New("the user may not change the password")
)

// UserInfo is a User as the API lists it: its spec, and what the controller derives for it.
type UserInfo struct {
	// Name is the name of the User resource.
	Name string `json:"name"`
	intent.User
	// HasPassword says whether the user has a password: a user without one cannot authenticate.
	HasPassword bool `json:"hasPassword"`
	// Expired says whether the user has expired now.
	Expired bool `json:"expired"`
	// Devices are the devices of the user, the Nodes that name it as their owner.
	Devices []intent.DeviceRef `json:"devices"`
}

// GroupInfo is a Group as the API lists it: its spec and its members.
type GroupInfo struct {
	// Name is the name of the Group resource, which is also its tag.
	Name string `json:"name"`
	intent.Group
	// Members are the names of the users that belong to the group.
	Members []string `json:"members"`
}

// Login is what a client presents to authenticate a User.
type Login struct {
	// User is the name of the User.
	User string
	// Password is the password that the client sends.
	Password string
	// Saved says that the client took the password from its own storage, and did not have a person
	// type it. The controller refuses such a login of a User that may not save its password.
	Saved bool
}

// Account is a User that authenticated: its name and its spec as the intent holds them, and the
// devices that it has. What a login makes of it, a session or the enrolment of a device, is up to
// the caller; NoSavedPassword tells a client that asked not to keep the password.
type Account struct {
	// Name is the name of the User resource.
	Name string `json:"name"`
	intent.User
	// Devices are the devices that the user has now: at its maximum, no device is admitted.
	Devices []intent.DeviceRef `json:"devices"`
}

// Users returns the Users of the intent, ordered by name, with what the controller derives for each
// of them (GET /api/v1/users).
func (c *Controller) Users(ctx context.Context) ([]UserInfo, error) {
	names, err := c.store.UsersWithPassword(ctx)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(names))
	for _, name := range names {
		have[name] = true
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []UserInfo{}
	for _, name := range slices.Sorted(maps.Keys(c.intent.Users)) {
		u := c.intent.Users[name].Clone()
		devices := c.intent.DevicesOf(name)
		if devices == nil {
			devices = []intent.DeviceRef{}
		}
		out = append(out, UserInfo{Name: name, User: u, HasPassword: have[name], Expired: u.ExpiredAt(now), Devices: devices})
	}
	return out, nil
}

// Groups returns the Groups of the intent, ordered by name, each with its members (GET
// /api/v1/groups).
func (c *Controller) Groups() []GroupInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []GroupInfo{}
	for _, name := range slices.Sorted(maps.Keys(c.intent.Groups)) {
		members := c.intent.Members(name)
		if members == nil {
			members = []string{}
		}
		out = append(out, GroupInfo{Name: name, Group: c.intent.Groups[name], Members: members})
	}
	return out
}

// SetUserPassword sets the password of the User name to secret, which an administrator may do
// whatever the User's own choice to change it says. The password is kept as a PBKDF2 hash, outside the
// intent. An error that wraps password.ErrInvalid is a password that the rules refuse, and one that
// wraps intent.ErrNotFound a User that the intent does not hold.
func (c *Controller) SetUserPassword(ctx context.Context, name, secret string) error {
	if err := password.Check(secret); err != nil {
		return err
	}
	if !c.holdsUser(name) {
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, name)
	}
	// The derivation takes about a tenth of a second: it runs without the lock of the controller
	hash, err := password.Hash(secret)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A change of the intent that removed the User meanwhile took its password along (dropPasswords),
	// and must not find a new one here
	if _, ok := c.intent.Users[name]; !ok {
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, name)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.SetUserPassword(sctx, name, hash); err != nil {
		return err
	}
	c.log.Info("user password set", "user", name)
	return nil
}

// ChangeUserPassword changes the password of the User name from current to next, as the User does
// it: current must be the password, the User must not have expired, and the User must be one that may
// change its password (intent.User.MayChangePassword), else the error wraps ErrPasswordFixed. The
// errors of AuthenticateUser and SetUserPassword are the others.
func (c *Controller) ChangeUserPassword(ctx context.Context, name, current, next string) error {
	acct, err := c.AuthenticateUser(ctx, Login{User: name, Password: current})
	if err != nil {
		return err
	}
	if !acct.CanChangePassword() {
		return fmt.Errorf("%w: the password of User %q is the one that an administrator set", ErrPasswordFixed, name)
	}
	return c.SetUserPassword(ctx, name, next)
}

// AuthenticateUser checks the login l of a User and returns the Account of the User that it
// proves. The password is checked first, against the hash of the store, with the work of a
// derivation also for a name that no User has, so a refusal and its time say nothing about which
// names exist; only the holder of the password learns why the login fails after that:
//
//   - ErrBadCredentials: no such User, a User without a password, or a wrong password.
//   - ErrUserExpired: the User has expired (intent.User.Expires): it cannot authenticate any more.
//   - ErrUserBanned: an operator banned the User (SDN-50, bans.go): it cannot authenticate until the
//     ban is lifted.
//   - ErrSavedPassword: the User may not save its password, and the client says that it took it
//     from its own storage (Login.Saved).
//
// A device is admitted by the intent, not by this call: the Nodes of a User are its devices, and an
// intent that holds more of them than the User's maximum is refused when it is applied
// (intent.User.MaxDevices).
func (c *Controller) AuthenticateUser(ctx context.Context, l Login) (Account, error) {
	c.mu.Lock()
	user, known := c.intent.Users[l.User]
	user = user.Clone()
	devices := c.intent.DevicesOf(l.User)
	c.mu.Unlock()

	verified, derived := false, false
	if known {
		hash, have, err := c.store.UserPassword(ctx, l.User)
		if err != nil {
			return Account{}, err
		}
		if have {
			derived = true
			if verified, err = password.Verify(l.Password, hash); err != nil {
				return Account{}, fmt.Errorf("the stored password of User %q: %w", l.User, err)
			}
		}
	}
	if !derived {
		password.Decoy(l.Password)
	}
	if !verified {
		return Account{}, ErrBadCredentials
	}
	if user.ExpiredAt(time.Now()) {
		return Account{}, fmt.Errorf("%w: User %q expired at %s", ErrUserExpired, l.User, user.Expires.Format(time.RFC3339))
	}
	if c.isBanned(l.User) {
		// An operator banned the user (bans.go; SDN-50)
		return Account{}, fmt.Errorf("%w: User %q", ErrUserBanned, l.User)
	}
	if l.Saved && user.NoSavedPassword {
		return Account{}, fmt.Errorf("%w: User %q must have its password typed at each login", ErrSavedPassword, l.User)
	}
	if devices == nil {
		devices = []intent.DeviceRef{}
	}
	return Account{Name: l.User, User: user, Devices: devices}, nil
}

// holdsUser reports whether the intent holds the User name.
func (c *Controller) holdsUser(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.intent.Users[name]
	return ok
}

// dropPasswords deletes the password of each User that the intent next no longer holds. The passwords
// are no part of the intent, so nothing else takes them away: a rollback, an import or an automatic
// rollback that removes a User would leave its hash behind, and a User created later under the same
// name would get the old password. commit calls it once the change is stored, before it makes next the
// intent. A failure is logged: the Users that the intent does not hold cannot authenticate anyway.
func (c *Controller) dropPasswords(ctx context.Context, next intent.Intent) {
	// The API roles and the user tokens follow the Users too (logins.go; SDN-32)
	c.dropUserAccess(ctx, next)
	var gone []string
	for name := range c.intent.Users {
		if _, ok := next.Users[name]; !ok {
			gone = append(gone, name)
		}
	}
	if len(gone) == 0 {
		return
	}
	slices.Sort(gone)
	if err := c.store.DeleteUserPasswords(ctx, gone); err != nil {
		c.log.Warn("deleting the passwords of removed users", "users", gone, "err", err)
	}
}
