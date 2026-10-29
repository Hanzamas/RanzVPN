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
//
// The numbers of the groups are the controller's own (desired.NumberGroups): a group ID or a bit of the
// tag set, once given in a VRF, never goes to another set of tags or tag, as a Node may still hold a
// Generation that uses it. The controller keeps them in its store (table source_groups), loads them at
// start, before the first compilation, and gives the new sets of tags and tags of a compilation the next
// numbers, which commit stores before the states that use them (saveGroupNumbers). So the numbers
// survive a restart and a new leader, and no state that a Node gets holds a number that the store does
// not hold. An intent exported and imported into another controller gives the groups the numbers of that
// controller.
//
// What a Node may assert in a VRF changes with the intent, though, and the Generations of two Nodes go in
// at different times. So each group of a Node carries its group generation in the VRF, the Generation of
// its state from which on it may assert what it asserts there, in its NodeConfig and in its Peer object
// at the other Nodes, and its claims name it: a Node takes the claim of a group that the sender may not
// assert by its state for an unknown group only when the claim names the group generation that its state
// gives the sender, and judges the packet by the map of address to group otherwise. The group generation
// comes from the Generations that the store holds with the states, so it survives a restart too.

// groupState is what the controller keeps for the source groups beside the intent.
type groupState struct {
	// numbers are the numbers of the source groups that the store holds, by VRF id. Controller.mu guards them, as it
	// does the intent that they are compiled with.
	numbers desired.GroupNumbers
}

// loadGroupNumbers reads the numbers of the source groups from the store.
func (c *Controller) loadGroupNumbers(ctx context.Context) error {
	stored, err := c.store.SourceGroups(ctx)
	if err != nil {
		return err
	}
	numbers := desired.GroupNumbers{}
	for id, v := range stored {
		numbers[id] = desired.VrfGroupNumbers{Groups: v.Groups, Bits: v.Bits}
	}
	c.groups.numbers = numbers
	return nil
}

// withSourceGroups puts the source groups into states, which in compiled to, for the Nodes that report
// the Capability tags, with the numbers that the controller gave and those that the sets of tags and the
// tags of in that have none take now, which it returns for commit to store. Each group of a Node carries
// the group generation of the Node in its VRF, which the claims of the Node name (desired.GroupGenerations):
// the Generation that commit gives its state, the one after the Generation of its state now, when the
// groups that it may assert there change, and the one of its state now otherwise. c.mu is held.
func (c *Controller) withSourceGroups(in intent.Intent, states map[string]desired.State) desired.GroupNumbers {
	added := desired.NumberGroups(in, c.groups.numbers)
	desired.SourceGroups(in, states, c.groups.numbers.With(added), func(node string) bool {
		n, ok := in.Nodes[node]
		if !ok {
			return false
		}
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		return c.caps[string(k)].GetTags()
	})
	gens := map[string]map[uint32]uint64{}
	for name, st := range states {
		var prev desired.State
		next := uint64(1)
		if n := c.nodes[name]; n != nil {
			prev, next = n.state, n.gen+1
		}
		gens[name] = desired.GroupGenerations(st, prev, name, next)
	}
	desired.WithGroupGenerations(states, gens)
	return added
}

// saveGroupNumbers stores the numbers of the source groups that a compilation gave (withSourceGroups),
// before the states that use them, and makes them the controller's. commit calls it before it stores
// the states, and stores none when it fails, so no Node gets a number that the store does not hold. A
// write that fails may have gone in all the same: the controller then reads the numbers of the store
// again, so that the next compilation gives none of them to another set or tag. c.mu is held.
func (c *Controller) saveGroupNumbers(ctx context.Context, added desired.GroupNumbers) error {
	if len(added) == 0 {
		return nil
	}
	rows := map[uint32]store.SourceGroupNumbers{}
	for id, v := range added {
		rows[id] = store.SourceGroupNumbers{Groups: v.Groups, Bits: v.Bits}
	}
	if err := c.store.AddSourceGroups(ctx, rows); err != nil {
		if lerr := c.loadGroupNumbers(ctx); lerr != nil {
			c.log.Warn("reading the numbers of the source groups again", "err", lerr)
		}
		return err
	}
	c.groups.numbers = c.groups.numbers.With(added)
	for id, v := range added {
		c.log.Info("source group numbers given", "vrf", id, "numbers", v.String())
	}
	return nil
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
