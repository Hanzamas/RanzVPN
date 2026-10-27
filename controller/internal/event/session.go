package event

// The type of the event that a node raises when two holders of one key replace the session of one of
// its peers again and again (NS-12 of docs/threat-model.md, AUD1-DT-11 #459), beside the ones of
// event.go, access.go and certificate.go.
const (
	// SessionFlap: a node counted the replacements of the session of one peer in a window and found
	// them above its limit. A new handshake of a key closes the session that the node holds for it,
	// so a thief and the real Node, two holders of one key, can keep each other off by taking turns.
	// The node reports it in its telemetry: Node is the node that reported it, Subject the peer whose
	// session was replaced, and Message says how often and from which source addresses the sessions
	// came, so that two addresses show two holders. The operator deletes the Node resource of the
	// peer and makes a new key for it (ADR-0030, the amendment of AUD1-DT-11).
	SessionFlap = "session-flap"
)
