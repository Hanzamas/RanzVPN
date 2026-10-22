// Package event is what the controller reports to operators (ADR-0030 decision 5): one Event
// for each condition, kept in the store with the change that raised it and listed by the API.
// The event feed (internal/telemetry, SDN-16 #192) delivers each one to the webhooks and counts it
// for the metrics.
package event

import "time"

// AutomaticRollback: an apply with a confirmation time was not confirmed in time, and the
// controller rolled it back (ADR-0031 decision 4).
const AutomaticRollback = "automatic-rollback"

// NodeDown: a node that had a control stream has had none for the grace period of the controller
// (controller.Config.NodeDownAfter).
const NodeDown = "node-down"

// GatewayFailover: a node moved its traffic from one gateway to another. The node reports it in its
// telemetry (SDN-19, #195, makes the node detect it); Subject is the gateway it moved to.
const GatewayFailover = "gateway-failover"

// PoolNearExhaustion: an IPAM pool reached its alert threshold (ADR-0028 decision 2). SDN-10
// (#186) raises it with controller.Raise; Subject is the Network of the pool.
const PoolNearExhaustion = "ipam-pool-near-exhaustion"

// Types lists the types of event, in the order that the metrics list them.
var Types = []string{AutomaticRollback, NodeDown, GatewayFailover, PoolNearExhaustion}

// Event is one thing that happened.
type Event struct {
	ID      uint64    `json:"id"` // given by the store, in the order of the events
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	// Revision is the revision the event made: for AutomaticRollback, the rollback.
	Revision uint64 `json:"revision,omitempty"`
	// Reverts is the revision that an AutomaticRollback undid.
	Reverts uint64 `json:"reverts,omitempty"`
	// Node is the node the event is about, for NodeDown and GatewayFailover.
	Node string `json:"node,omitempty"`
	// Subject is what else the event is about: the gateway of a GatewayFailover, the Network of a
	// PoolNearExhaustion.
	Subject string `json:"subject,omitempty"`
}
