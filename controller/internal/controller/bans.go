package controller

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The bans of users (SDN-50 #243, ADR-0031 amendment of 2026-10-27). An operator bans a User to stop an
// incident: every device of the user is cut off at once, and none gets in again until an operator lifts
// the ban. A ban is no intent, so it is kept in the store beside it (table user_bans), and a revision, a
// rollback or an import does not change it.
//
// The desired state of every Node that does not belong to a banned user is compiled as if the Nodes of
// the banned users were not in the intent (compileStates), so the other Nodes get a new generation that
// has no Peer for them, and they take no packet of theirs; the control streams of those Nodes are
// refused (BanUser ends the ones that are open, serveConn refuses the ones that open later). The Nodes
// of the banned users keep a desired state and its generations, so that the next generation that one
// gets, after the ban is lifted, comes after the ones that it applied, as the generations of a Node
// that is never banned do.

// MaxBanReason is the longest reason of a ban, in bytes.
const MaxBanReason = 256

// ErrUserBanned marks a login of a User that an operator banned, with the right password.
var ErrUserBanned = errors.New("the user is banned")

// BanResult is the answer to a ban: the ban, and the sessions that it ended.
type BanResult struct {
	store.Ban
	// Disconnected are the sessions of the Nodes of the user that the ban ended, as they were when they
	// ended.
	Disconnected []Session `json:"disconnected"`
}

// bannedOwner returns the ban of the user that owns the Node name, if there is one. c.mu is held.
func (c *Controller) bannedOwner(name string) (store.Ban, bool) {
	owner := c.intent.Nodes[name].Owner
	if owner == "" {
		return store.Ban{}, false
	}
	b, ok := c.live.bans[owner]
	return b, ok
}

// isBanned reports whether the user user is banned.
func (c *Controller) isBanned(user string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.live.bans[user]
	return ok
}

// compileStates compiles the desired state of every Node of in, which a licence may have capped
// already. The state of a Node of a banned user is what it is without the ban; the state of every other
// Node is compiled from the intent without the Nodes of the banned users, so it has no Peer for them,
// no Relay and no route that leads to one of them. The Nodes that the life of their keys holds back, holds,
// those whose key ended and those that wait for approval, are left out the same way (nodekeys.go; SDN-56).
// c.mu is held.
func (c *Controller) compileStates(in intent.Intent, holds map[string]keyHold) (map[string]desired.State, error) {
	banned := withheld(in.NodesOwnedBy(slices.Sorted(maps.Keys(c.live.bans))), holds)
	if len(banned) == 0 {
		return desired.Compile(in)
	}
	states, err := desired.Compile(in.Without(banned))
	if err != nil {
		return nil, err
	}
	whole, err := desired.Compile(in)
	if err != nil {
		return nil, err
	}
	for _, name := range banned {
		if st, ok := whole[name]; ok {
			states[name] = st
		}
	}
	return states, nil
}

// refuseBanned ends the control stream conn of the node name, whose user ban banned: it records the
// refusal as a failed authentication and sends the Refuse with the reason REFUSE_REASON_OPERATOR.
func (c *Controller) refuseBanned(conn *control.Conn, name string, ban store.Ban, remote net.Addr) {
	c.log.Warn("node refused: its user is banned", "node", name, "user", ban.User, "remote", remote.String())
	c.auditNode(audit.AuthFailed, audit.ActorNode(name), audit.Failure, fmt.Sprintf("user %s, the owner of the node, is banned", ban.User), remote)
	writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_OPERATOR, "%s", banReason(ban)))
}

// banReason is the message of the Refuse for a Node of a banned user: who is banned, and why, if the
// operator said.
func banReason(ban store.Ban) string {
	if ban.Reason == "" {
		return fmt.Sprintf("User %q is banned", ban.User)
	}
	return fmt.Sprintf("User %q is banned: %s", ban.User, ban.Reason)
}

// checkBanReason refuses a reason that is longer than MaxBanReason, is no UTF-8 or holds a control
// character, with an error that wraps intent.ErrInvalid.
func checkBanReason(reason string) error {
	switch {
	case len(reason) > MaxBanReason:
		return badRequestf("the reason of a ban has %d bytes, and at most %d are allowed", len(reason), MaxBanReason)
	case !utf8.ValidString(reason):
		return badRequestf("the reason of a ban is no UTF-8 text")
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return badRequestf("the reason of a ban holds a control character, %U", r)
		}
	}
	return nil
}

// Bans returns the banned users, ordered by name (GET /api/v1/operations/bans). The call is recorded
// in the audit log.
func (c *Controller) Bans(ctx context.Context) []store.Ban {
	c.mu.Lock()
	out := make([]store.Ban, 0, len(c.live.bans))
	for _, user := range slices.Sorted(maps.Keys(c.live.bans)) {
		out = append(out, c.live.bans[user])
	}
	c.mu.Unlock()
	c.auditOperation(ctx, "ban-list", "bans", nil, fmt.Sprintf("bans listed: %d", len(out)))
	return out
}

// BanUser bans the user user for reason (PUT /api/v1/operations/bans/{name}), which may be empty: every
// Node that the user owns loses its control stream at once, and the other Nodes get a generation
// without it as a Peer. A user that is banned already is left as it is, with its first ban. An error that
// wraps intent.ErrNotFound is a user that the intent does not hold, and one that wraps intent.ErrInvalid
// a reason that is not valid. The call is recorded in the audit log.
func (c *Controller) BanUser(ctx context.Context, user, reason string) (BanResult, error) {
	res, err := c.banUser(ctx, user, reason)
	message := fmt.Sprintf("sessions ended: %d", len(res.Disconnected))
	if reason != "" {
		message += "; reason: " + reason
	}
	c.auditOperation(ctx, "user-ban", "user "+clip(user, maxSubject), err, message)
	return res, err
}

func (c *Controller) banUser(ctx context.Context, user, reason string) (BanResult, error) {
	if err := checkBanReason(reason); err != nil {
		return BanResult{}, err
	}
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.intent.Users[user]; !ok {
		return BanResult{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(user, maxSubject))
	}
	if b, ok := c.live.bans[user]; ok {
		return BanResult{Ban: b, Disconnected: []Session{}}, nil
	}
	origin, _ := audit.FromContext(ctx)
	ban := store.Ban{User: user, Since: time.Now().UTC().Truncate(time.Millisecond), By: cmp.Or(origin.Actor, audit.ActorSystem), Reason: reason}
	c.live.bans[user] = ban
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		delete(c.live.bans, user)
		return BanResult{}, err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.AddBan(sctx, ban); err != nil {
		delete(c.live.bans, user)
		return BanResult{}, err
	}
	if _, err := c.commit(sctx, c.intent, cp, store.Changes{}); err != nil {
		delete(c.live.bans, user)
		if derr := c.store.DeleteBans(sctx, []string{user}); derr != nil {
			c.log.Warn("taking back the ban of a user that the change of the states refused", "user", user, "err", derr)
		}
		return BanResult{}, err
	}
	ended := c.endSessions(snaps, func(name string) bool { return c.intent.Nodes[name].Owner == user }, "%s", banReason(ban))
	// The user tokens of the user end with its sessions (logins.go; SDN-32)
	c.endUserTokens(sctx, user)
	c.log.Warn("user banned", "user", user, "by", ban.By, "sessions", len(ended))
	return BanResult{Ban: ban, Disconnected: ended}, nil
}

// UnbanUser lifts the ban of the user user (DELETE /api/v1/operations/bans/{name}) and returns it:
// the Nodes of the user get their place among the Peers of the other Nodes back, and open their
// control streams again by themselves, at the next try of each. An error that wraps intent.ErrNotFound
// is a user that is not banned. The call is recorded in the audit log.
func (c *Controller) UnbanUser(ctx context.Context, user string) (store.Ban, error) {
	ban, err := c.unbanUser(ctx, user)
	c.auditOperation(ctx, "user-unban", "user "+clip(user, maxSubject), err, fmt.Sprintf("banned since %s by %s", ban.Since.Format(time.RFC3339), ban.By))
	return ban, err
}

func (c *Controller) unbanUser(ctx context.Context, user string) (store.Ban, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ban, ok := c.live.bans[user]
	if !ok {
		return store.Ban{}, fmt.Errorf("%w: user %q is not banned", intent.ErrNotFound, clip(user, maxSubject))
	}
	delete(c.live.bans, user)
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		c.live.bans[user] = ban
		return store.Ban{}, err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.DeleteBans(sctx, []string{user}); err != nil {
		c.live.bans[user] = ban
		return store.Ban{}, err
	}
	if _, err := c.commit(sctx, c.intent, cp, store.Changes{}); err != nil {
		c.live.bans[user] = ban
		if aerr := c.store.AddBan(sctx, ban); aerr != nil {
			c.log.Warn("putting back the ban of a user that the change of the states refused to lift", "user", user, "err", aerr)
		}
		return store.Ban{}, err
	}
	c.log.Info("user unbanned", "user", user)
	return ban, nil
}

// dropBans deletes the ban of each User that the intent next no longer holds, so that a User made
// again under the name starts with none, as it starts with no password (dropPasswords). commit calls it
// once the change is stored, before it makes next the intent. A failure is logged: the ban stays, and
// the user that it names is none that the intent holds. c.mu is held.
func (c *Controller) dropBans(ctx context.Context, next intent.Intent) {
	var gone []string
	for user := range c.live.bans {
		if _, ok := next.Users[user]; !ok {
			gone = append(gone, user)
		}
	}
	if len(gone) == 0 {
		return
	}
	slices.Sort(gone)
	if err := c.store.DeleteBans(ctx, gone); err != nil {
		c.log.Warn("deleting the bans of removed users", "users", gone, "err", err)
		return
	}
	for _, user := range gone {
		delete(c.live.bans, user)
	}
}
