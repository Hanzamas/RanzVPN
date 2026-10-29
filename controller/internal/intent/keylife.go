package intent

import (
	"fmt"
	"slices"
	"time"
)

// The key life of the Nodes and the approval mode of the Networks (SDN-56 #249, ADR-0031 amendment of
// 2026-10-28). The static key of a Node expires: it lives for the key lifetime of the Networks of the Node
// from the last time that the Node authenticated, and a re-authentication of its User gives it another
// period. An admin marks a server or a gateway nonExpiring, since no user logs in for it again, and its key
// lives for good. A Node that has an owner is the device of a User, whose login refreshes its key, so the
// mark is refused on it (SDN-56-R1 #515): taking the mark off would be a refresh that the operator refuses
// for such a Node. A Network admits its new Nodes at once (approval auto, the default) or holds each of them
// until an admin approves it (approval manual).
//
// The intent holds this policy and nothing of its outcome. When each key ends, and which Node an admin
// approved, are kept by the controller beside the intent (internal/controller, nodekeys.go), so that a
// revision, a rollback or an import does not give an expired key another life, and does not approve a Node.

// The approval modes of a Network.
const (
	// ApprovalAuto admits a new Node of the Network at once. It is the mode of a Network that sets none.
	ApprovalAuto = "auto"
	// ApprovalManual holds a new Node of the Network until an admin approves it.
	ApprovalManual = "manual"
)

const (
	// DefaultKeyLifetimeDays is how many days the key of a Node lives from its last authentication in a
	// Network that sets none: 90.
	DefaultKeyLifetimeDays = 90
	// MaxKeyLifetimeDays is the most days that a Network may set as its key lifetime: ten years.
	MaxKeyLifetimeDays = 3650
)

// ApprovalNeeded returns the Network that holds the Node node for approval: the first Network, in name
// order, of a VRF of the Node whose approval mode is manual. It reports false when no Network does, or when
// the intent has no such Node.
func (in Intent) ApprovalNeeded(node string) (string, bool) {
	n, ok := in.Nodes[node]
	if !ok {
		return "", false
	}
	for _, name := range sortedNames(in.Networks) {
		if nw := in.Networks[name]; nw.Approval == ApprovalManual && slices.Contains(n.VRFs, nw.VRF) {
			return name, true
		}
	}
	return "", false
}

// KeyLifetime returns how long the key of the Node node lives from its last authentication: the shortest
// key lifetime of the Networks of its VRFs, where a Network that sets none counts DefaultKeyLifetimeDays. A
// Node of no Network, and a Node that the intent does not hold, get the default.
func (in Intent) KeyLifetime(node string) time.Duration {
	days := uint32(0)
	if n, ok := in.Nodes[node]; ok {
		for _, nw := range in.Networks {
			if !slices.Contains(n.VRFs, nw.VRF) {
				continue
			}
			d := nw.KeyLifetimeDays
			if d == 0 {
				d = DefaultKeyLifetimeDays
			}
			if days == 0 || d < days {
				days = d
			}
		}
	}
	if days == 0 {
		days = DefaultKeyLifetimeDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// validateKeyLife checks the approval mode and the key lifetime of each Network of a completed intent: the
// mode is auto or manual, and the lifetime is at most MaxKeyLifetimeDays. It checks the mark nonExpiring of
// each Node too: a Node that has an owner is not marked, since the key of a device of a User lives by the
// login of its User.
func (in Intent) validateKeyLife() []error {
	var problems []error
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		if n.Approval != "" && n.Approval != ApprovalAuto && n.Approval != ApprovalManual {
			problems = append(problems, fmt.Errorf("Network %q: the approval must be %s or %s, not %q", name, ApprovalAuto, ApprovalManual, n.Approval))
		}
		if n.KeyLifetimeDays > MaxKeyLifetimeDays {
			problems = append(problems, fmt.Errorf("Network %q: keyLifetimeDays %d is more than %d", name, n.KeyLifetimeDays, MaxKeyLifetimeDays))
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		if n := in.Nodes[name]; n.NonExpiring && n.Owner != "" {
			problems = append(problems, fmt.Errorf("Node %q: nonExpiring is for a Node that has no owner: the key of a device of User %q lives by the login of its User, who refreshes it", name, n.Owner))
		}
	}
	return problems
}
