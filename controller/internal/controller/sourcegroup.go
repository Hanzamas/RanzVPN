package controller

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The source groups (SDN-87 #386, desired/sourcegroup.go). A Node that reports the Capability tags in
// its Hello carries the source group of its packets to its peers and judges theirs by the one they
// carry. The controller puts the source groups into the desired states of those Nodes when it compiles
// the intent (withSourceGroups), from the Capabilities that each Node reported last, so a Node whose
// Capability tags changes changes the states of its peers too: its Hello recompiles the intent
// (tagsChanged), which gives the Nodes whose state changed their next Generation, the Node itself
// before the Hello is answered. A Node that does not report the Capability, as a Node of an older
// release does not, keeps the state it had, and its peers send it no record of frame version 1.

// withSourceGroups puts the source groups into states, which in compiled to, for the Nodes that report
// the Capability tags. c.mu is held.
func (c *Controller) withSourceGroups(in intent.Intent, states map[string]desired.State) {
	desired.SourceGroups(in, states, func(node string) bool {
		n, ok := in.Nodes[node]
		if !ok {
			return false
		}
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		return c.caps[string(k)].GetTags()
	})
}

// tagsChanged recompiles the intent when the Capabilities caps that the Node name reported in its Hello
// changed its Capability tags, which before was: the source groups of its state and of the states of its
// peers change with it. c.mu is held, and the Capabilities of the Node are recorded already.
func (c *Controller) tagsChanged(name string, before bool, caps *controlpb.Capabilities) {
	if caps.GetTags() == before {
		return
	}
	cp, err := c.compile(c.intent, c.lic)
	if err == nil {
		_, err = c.commit(context.Background(), c.intent, cp, store.Changes{})
	}
	if err != nil {
		c.log.Error("applying the Capability tags of a node", "node", name, "tags", caps.GetTags(), "err", err)
		return
	}
	c.log.Info("node capability tags changed", "node", name, "tags", caps.GetTags())
}
