package event

// The types of the events that the life of a node key raises (SDN-56-R1, #515; ADR-0030 amendment of 2026-10-29), beside the
// ones of event.go, access.go, certificate.go and session.go. The controller says what comes before it does: a key that ends
// takes its Node off the overlay, and every Node that existed when the first start gave the Nodes their lives ends on the
// same day. Node is the Node resource, Subject the User that owns it, left out for a Node that has none, and Message says
// what is the matter and who ends it. Each is raised once for each key and state, and `ranz get events`, a webhook target
// that names the type and the metric ranz_events_total{type="node-key-expiring"} have it as they have any Event.
const (
	// NodeKeyExpiring: the key of a Node ends within 14 days. The controller raises it when the key enters that span and
	// again when 3 days are left, and names the end in the message. A key that has no end, the key of a Node that is marked
	// nonExpiring, raises none.
	NodeKeyExpiring = "node-key-expiring"
	// NodeKeyEnded: the key of a Node ended. The Node is held back from then on: its control stream is refused, and the
	// desired state of every other Node leaves it out, until its User logs in again or an operator refreshes the key.
	NodeKeyEnded = "node-key-ended"
	// NodeWaiting: a Network that holds new Nodes for approval holds a new Node. It is held back until an operator approves it
	// (ranz node-key approve).
	NodeWaiting = "node-waiting"
)
