// Package event is what the controller reports to operators (ADR-0030 decision 5): one Event
// for each condition, kept in the store with the change that raised it and listed by the API.
// The event feed (internal/telemetry, SDN-16 #192) delivers each one to the webhooks and counts it
// for the metrics.
package event

import "time"

// The types of an event.
const (
	// AutomaticRollback: an apply with a confirmation time was not confirmed in time, and the
	// controller rolled it back (ADR-0031 decision 4).
	AutomaticRollback = "automatic-rollback"
	// NodeDown: a node that had a control stream has had none for the grace period of the controller
	// (controller.Config.NodeDownAfter).
	NodeDown = "node-down"
	// GatewayFailover: a node moved its traffic from one gateway to another. The node reports it in
	// its telemetry (SDN-19, #195, makes the node detect it); Subject is the gateway it moved to.
	GatewayFailover = "gateway-failover"
	// PoolNearExhaustion: a change of the intent took a pool of a Network to the percentage of its
	// addresses in use that the Network sets as its threshold, so the controller reports the pool
	// before it runs out (ADR-0028 decision 2, ADR-0030 decision 5).
	PoolNearExhaustion = "ipam-pool-near-exhaustion"
)

// Types lists the types of event, in the order that the metrics list them.
var Types = []string{AutomaticRollback, NodeDown, GatewayFailover, PoolNearExhaustion, SessionFlap}

// Event is one thing that happened.
type Event struct {
	ID      uint64    `json:"id"` // given by the store, in the order of the events
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	// Revision is the revision the event made: for AutomaticRollback, the rollback; for
	// PoolNearExhaustion, the change that took the pool to its threshold.
	Revision uint64 `json:"revision,omitempty"`
	// Reverts is the revision that an AutomaticRollback undid.
	Reverts uint64 `json:"reverts,omitempty"`
	// Node is the node the event is about, for NodeDown and GatewayFailover, and the node that
	// reported it for SessionFlap.
	Node string `json:"node,omitempty"`
	// Subject is what else the event is about: the gateway of a GatewayFailover, the peer of a
	// SessionFlap.
	Subject string `json:"subject,omitempty"`
}
