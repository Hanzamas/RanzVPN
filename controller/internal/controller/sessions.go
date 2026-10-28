package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// The sessions (SDN-50 #243, ADR-0031 amendment of 2026-10-27). A session is the control stream of a
// node, from the moment the controller accepted it until it ends: it is who is connected now. The
// operator lists them (Sessions) and ends one (Disconnect) or every one of a user (DisconnectUser): the
// controller sends the node a Refuse with the reason REFUSE_REASON_OPERATOR and closes the stream, at
// once, and the node is no longer Connected. A node dials again after the delay of a refused stream,
// so a disconnect alone does not keep a node off; a ban does (bans.go).

// operatorMessage is the message of the Refuse that ends a session on the order of an operator.
const operatorMessage = "an operator disconnected this session"

// Session is one control stream of a node, as an operator sees it.
type Session struct {
	// ID names the session to Disconnect. It is made when the stream is accepted, so a node that dials
	// again has another one.
	ID string `json:"id"`
	// Node is the name of the Node resource.
	Node string `json:"node"`
	// User is the owner of the Node: the User whose device it is. It is left out for a Node with no owner.
	User string `json:"user,omitempty"`
	// Source is the address that the stream came from, without its port.
	Source string `json:"source"`
	// Since is when the controller accepted the stream.
	Since time.Time `json:"since"`
	// VRFs are the VRFs that the node is a member of, ordered.
	VRFs []string `json:"vrfs"`
	// Addresses are the addresses of the node in the Networks of its VRFs: the IPv4 ones, then the IPv6
	// ones, each by the name of its Network.
	Addresses []string `json:"addresses"`
	// Generation is the generation of the desired state of the node, AckedGeneration the one that it
	// acknowledged last.
	Generation      uint64 `json:"generation"`
	AckedGeneration uint64 `json:"ackedGeneration"`
	// Operations says that the node reports the Capability operations: it answers the requests for
	// the tables of its L2 Networks (tables.go).
	Operations bool `json:"operations,omitempty"`
	// The traffic of the node in all its VRFs since it started, as its last summary of Telemetry said:
	// Tx went from its host into the overlay, Rx came from the overlay to its host. All of it is 0 and
	// TrafficReported is left out until the node reported a summary.
	TxPackets       uint64    `json:"txPackets"`
	TxBytes         uint64    `json:"txBytes"`
	RxPackets       uint64    `json:"rxPackets"`
	RxBytes         uint64    `json:"rxBytes"`
	TrafficReported time.Time `json:"trafficReported,omitzero"`
}

// trafficSnapshot returns the counters that the nodes reported last, by the name of the node.
func (c *Controller) trafficSnapshot() map[string]telemetry.NodeSnapshot {
	out := map[string]telemetry.NodeSnapshot{}
	for _, s := range c.tel.hub.Snapshot(nil) {
		out[s.Node] = s
	}
	return out
}

// sessionOf returns the session of the node name, which has a control stream, with the traffic that
// snaps holds of it. c.mu is held.
func (c *Controller) sessionOf(name string, n *node, snaps map[string]telemetry.NodeSnapshot) Session {
	in := c.intent.Nodes[name]
	s := Session{ID: n.stream.live.id, Node: name, User: in.Owner, Source: n.stream.live.source, Since: n.stream.live.since,
		VRFs: []string{}, Addresses: nodeAddresses(in), Generation: n.gen, AckedGeneration: n.ackedGen}
	for k := range n.state {
		if k.Kind == controlpb.Kind_KIND_VRF {
			s.VRFs = append(s.VRFs, k.Name)
		}
	}
	slices.Sort(s.VRFs)
	// Apply validated the key.
	key, _ := intent.ParseKey(in.PublicKey)
	s.Operations = c.caps[string(key)].GetOperations()
	if snap, ok := snaps[name]; ok {
		for _, v := range snap.VRFs {
			s.TxPackets += v.TxPackets
			s.TxBytes += v.TxBytes
			s.RxPackets += v.RxPackets
			s.RxBytes += v.RxBytes
		}
		s.TrafficReported = snap.ReportedAt.UTC()
	}
	return s
}

// nodeAddresses returns the addresses of the node n in the Networks of its VRFs: the IPv4 ones, then the
// IPv6 ones, each in the order of the names of the Networks.
func nodeAddresses(n intent.Node) []string {
	out := []string{}
	for _, network := range slices.Sorted(maps.Keys(n.Addresses)) {
		out = append(out, n.Addresses[network])
	}
	for _, network := range slices.Sorted(maps.Keys(n.IPv6Addresses)) {
		out = append(out, n.IPv6Addresses[network])
	}
	return out
}

// Sessions returns the sessions, ordered by the name of the node (GET /api/v1/operations/sessions):
// those of the node node and those of the user user, when they are given. The call is an operation,
// so it is recorded in the audit log.
func (c *Controller) Sessions(ctx context.Context, user, node string) []Session {
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	out := []Session{}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		n := c.nodes[name]
		if n.stream == nil || (node != "" && name != node) || (user != "" && c.intent.Nodes[name].Owner != user) {
			continue
		}
		out = append(out, c.sessionOf(name, n, snaps))
	}
	c.mu.Unlock()
	subject := "sessions"
	if user != "" {
		subject += " of user " + user
	}
	if node != "" {
		subject += " of node " + node
	}
	c.auditOperation(ctx, "session-list", subject, nil, fmt.Sprintf("sessions listed: %d", len(out)))
	return out
}

// endSessions ends the session of each node that has a control stream and that match holds of, with
// the Refuse that has the reason REFUSE_REASON_OPERATOR and the message that format and args make:
// the node is detached from its stream at once, and the stream is closed after the Refuse. It returns
// the sessions that it ended, ordered by the name of the node. c.mu is held.
func (c *Controller) endSessions(snaps map[string]telemetry.NodeSnapshot, match func(name string) bool, format string, args ...any) []Session {
	out := []Session{}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		n := c.nodes[name]
		if n.stream == nil || !match(name) {
			continue
		}
		out = append(out, c.sessionOf(name, n, snaps))
		c.refuse(n.stream, controlpb.RefuseReason_REFUSE_REASON_OPERATOR, format, args...)
	}
	return out
}

// Disconnect ends the session id at once (POST /api/v1/operations/sessions/{id}/disconnect) and
// returns it, as it was when it ended. An error that wraps intent.ErrNotFound is a session that does
// not exist, or that ended already. The node is not kept off: it dials again after the delay of a
// refused stream, unless its user is banned. The call is recorded in the audit log.
func (c *Controller) Disconnect(ctx context.Context, id string) (Session, error) {
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	var ended []Session
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		if n := c.nodes[name]; n.stream != nil && n.stream.live.id == id {
			ended = c.endSessions(snaps, func(other string) bool { return other == name }, operatorMessage)
			break
		}
	}
	c.mu.Unlock()
	if len(ended) == 0 {
		err := fmt.Errorf("%w: session %q", intent.ErrNotFound, clip(id, maxSubject))
		c.auditOperation(ctx, "session-disconnect", "session "+clip(id, maxSubject), err, "")
		return Session{}, err
	}
	s := ended[0]
	c.nodeLost(s.Node)
	c.auditOperation(ctx, "session-disconnect", "session "+s.ID, nil, sessionMessage(s))
	return s, nil
}

// DisconnectUser ends every session of the nodes that the user user owns at once (POST
// /api/v1/operations/users/{name}/disconnect) and returns them: none when the user has no node that
// is connected. An error that wraps intent.ErrNotFound is a user that the intent does not hold. The
// call is recorded in the audit log.
func (c *Controller) DisconnectUser(ctx context.Context, user string) ([]Session, error) {
	snaps := c.trafficSnapshot()
	c.mu.Lock()
	var ended []Session
	_, known := c.intent.Users[user]
	if known {
		ended = c.endSessions(snaps, func(name string) bool { return c.intent.Nodes[name].Owner == user }, operatorMessage)
	}
	c.mu.Unlock()
	if !known {
		err := fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(user, maxSubject))
		c.auditOperation(ctx, "user-disconnect", "user "+clip(user, maxSubject), err, "")
		return nil, err
	}
	nodes := make([]string, len(ended))
	for i, s := range ended {
		c.nodeLost(s.Node)
		nodes[i] = s.Node
	}
	c.auditOperation(ctx, "user-disconnect", "user "+user, nil, fmt.Sprintf("sessions ended: %d (%s)", len(ended), strings.Join(nodes, ", ")))
	return ended, nil
}

// sessionMessage describes the session s for the audit log: its node, its user and where it came from.
func sessionMessage(s Session) string {
	if s.User == "" {
		return fmt.Sprintf("node %s, from %s", s.Node, s.Source)
	}
	return fmt.Sprintf("node %s of user %s, from %s", s.Node, s.User, s.Source)
}
