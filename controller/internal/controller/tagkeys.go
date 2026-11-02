package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The keys of the tag mode hmac (SDN-88 #387, spec #385). In that mode a Node of a VRF sends and takes the
// source group of a link of kind geneve only with a MAC under a key of the VRF (Cedar/NodeTagMac.c). The
// controller makes the keys:
//
//   - A VRF that a compilation finds in the mode without a key gets its first key, which its Nodes send
//     with at once (withTagKeys): commit makes it, 32 random bytes, seals it and stores it before the
//     states that name it (saveTagKeys), so no Node gets the ID of a key that the store does not hold.
//   - The controller keeps each key sealed, as it keeps the PresharedKeys of the Devices (devicekeys.go):
//     to the Sealing key of its store, a key of the key storage provider on Windows, or the Cluster key of
//     a cluster, under the label tag_keys:VRF:ID (table tag_keys). It holds the keys in clear in memory
//     only, from its start (loadTagKeys) or from the making of each.
//   - The states that the controller stores and compares hold the ID of each key and whether the Nodes
//     send with it, never the key (desired.WithTagKeys), and so do the acknowledgements. Only the Update
//     that a stream sends its Node holds the keys, in clear inside the authenticated control stream, as
//     the Generation of the Node (openTagKeys). No log line, audit record, API answer or diagnostics
//     bundle holds a key: the log names the VRF and the ID of a key.
//   - Two keys are active at once. An operator rotates the key of a VRF (RotateTagKey): its Nodes get a
//     new key beside the one that they send with, and once every Node whose state holds the new key
//     acknowledged a Generation that holds it (advanceTagKeys), the next Generation makes it the key to
//     send with. The older key stays until the next rotation, which drops it. So no Node sends with a key
//     that another Node of the VRF does not hold, whichever gets its Generation first, and no packet of an
//     open flow loses its source group. A Node that the controller cannot reach holds the switch back
//     until it acknowledged, as it may still forward on the Generation that it holds.
//   - A VRF that leaves the mode, or the intent, loses its keys (dropTagKeys). A key that does not open
//     at the start, as one of a backup of another host does not, is replaced by a new key of the next ID,
//     which the Nodes send with at once: they judge the claims of the Nodes that still send with the old
//     one by the map of address to group until all run the new one.
//   - A controller without a sealing key keeps no key: a VRF in the mode has none then, so its Nodes send
//     no source group on its links and judge every claim of them by the map, which the log says.

// tagKeySize is the size of a key of the tag mode hmac.
const tagKeySize = 32

// tagKey is a key of the tag mode hmac of a VRF that the controller holds.
type tagKey struct {
	id     uint32
	key    []byte // in clear, in memory only
	sealed string // the base64 of the key sealed, as the store holds it
	send   bool   // the Nodes of the VRF send with it
}

// tagKeys is what the controller keeps of the keys of the tag mode hmac. Controller.mu guards it.
type tagKeys struct {
	// sealer seals and opens the keys: the Sealer of the store, which is the Cluster key for a member of a
	// cluster, nil for a store that was given none
	sealer store.Sealer
	// keys are the keys of each VRF in the mode, by VRF id, in the order of their IDs, 2 at most
	keys map[uint32][]tagKey
	// last is the largest ID of a key that each VRF had, so that a key that replaces one takes the next ID
	last map[uint32]uint32
	// unkeyed are the VRFs in the mode that the last compilation could give no key, so that the log says
	// it once
	unkeyed []string
}

// TagKeyRotation is the answer to the rotation of the key of the tag mode hmac of a VRF: the ID of the
// new key, the Nodes whose desired state the rotation changed, with their new generations, and the
// Nodes that the switch to the new key waits for: their Nodes send with it once each of these
// acknowledged it.
type TagKeyRotation struct {
	VRF   string           `json:"vrf"`
	KeyID uint32           `json:"keyId"`
	Nodes []NodeGeneration `json:"nodes"`
	Waits []string         `json:"waits"`
}

// tagKeyLabel is the label that the sealed key id of the VRF vrf carries, so that a sealed key that is
// moved to another row does not open there.
func tagKeyLabel(vrf, id uint32) string {
	return fmt.Sprintf("tag_keys:%d:%d", vrf, id)
}

// hmacVRFs returns the ids of the VRFs of in whose tag mode is hmac.
func hmacVRFs(in intent.Intent) map[uint32]bool {
	out := map[uint32]bool{}
	modes := in.VRFTagModes()
	for name, v := range in.VRFs {
		if modes[name] == intent.TagModeHMAC {
			out[v.ID] = true
		}
	}
	return out
}

// storedTagKeys returns keys as the rows of the store.
func storedTagKeys(keys []tagKey) []store.TagKey {
	var out []store.TagKey
	for _, k := range keys {
		out = append(out, store.TagKey{ID: k.id, Sealed: k.sealed, Send: k.send})
	}
	return out
}

// loadTagKeys takes the Sealer of the store and opens the keys that the store holds of the VRFs of in
// that are in the tag mode hmac, which the first compile puts into the states. The rows of another VRF
// are dropped. A VRF a key of which does not open keeps none, so that the first compile gives it a new
// one, and the log says so with the VRF and the ID of the key. New calls it before it compiles.
func (c *Controller) loadTagKeys(ctx context.Context, in intent.Intent) error {
	c.tkeys = tagKeys{sealer: c.store.Sealer(), keys: map[uint32][]tagKey{}, last: map[uint32]uint32{}}
	rows, err := c.store.TagKeys(ctx)
	if err != nil {
		return err
	}
	keep := hmacVRFs(in)
	var gone []uint32
	for _, vrf := range slices.Sorted(maps.Keys(rows)) {
		for _, r := range rows[vrf] {
			c.tkeys.last[vrf] = max(c.tkeys.last[vrf], r.ID)
		}
		if !keep[vrf] {
			gone = append(gone, vrf)
			continue
		}
		var keys []tagKey
		for _, r := range rows[vrf] {
			k, err := c.openTagKey(vrf, r)
			if err != nil {
				c.log.Warn("a key of the tag mode hmac does not open with the sealing key of this host, or with the Cluster key for a member of a cluster, so the VRF gets a new key: its nodes judge the claims of the nodes that still send with the old one by the map of address to group until all run the new one",
					"vrf", vrf, "keyID", r.ID, "err", err)
				keys = nil
				break
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 && len(keys) <= 2 {
			c.tkeys.keys[vrf] = keys
		}
	}
	if len(gone) > 0 {
		if err := c.store.DeleteTagKeys(ctx, gone); err != nil {
			c.log.Warn("deleting the keys of the tag mode hmac of VRFs that are not in the mode", "vrfs", gone, "err", err)
		}
	}
	return nil
}

// openTagKey opens the row r of a key of the VRF vrf.
func (c *Controller) openTagKey(vrf uint32, r store.TagKey) (tagKey, error) {
	if c.tkeys.sealer == nil {
		return tagKey{}, errNoSealer
	}
	blob, err := base64.StdEncoding.DecodeString(r.Sealed)
	if err != nil {
		return tagKey{}, err
	}
	key, err := c.tkeys.sealer.Open(tagKeyLabel(vrf, r.ID), blob)
	if err != nil {
		return tagKey{}, err
	}
	if len(key) != tagKeySize {
		clear(key)
		return tagKey{}, fmt.Errorf("the key has %d bytes, not %d", len(key), tagKeySize)
	}
	return tagKey{id: r.ID, key: key, sealed: r.Sealed, send: r.Send}, nil
}

// makeTagKey makes the key id of the VRF vrf: 32 random bytes, sealed and opened again, so that a key that
// no Node could be given is found now. Either failure wraps ErrConflict, as a controller without a sealing
// key does.
func (c *Controller) makeTagKey(vrf, id uint32) (tagKey, error) {
	if c.tkeys.sealer == nil {
		return tagKey{}, fmt.Errorf("%w: the controller cannot keep a key of the tag mode hmac, since it has no sealing key: neither the sealing key of its host nor the Cluster key of a cluster (ADR-0026)", ErrConflict)
	}
	key := make([]byte, tagKeySize)
	if _, err := io.ReadFull(c.random, key); err != nil {
		return tagKey{}, fmt.Errorf("making a key of the tag mode hmac of VRF %d: %w", vrf, err)
	}
	label := tagKeyLabel(vrf, id)
	sealed, err := c.tkeys.sealer.Seal(label, key)
	if err != nil {
		clear(key)
		return tagKey{}, fmt.Errorf("%w: the controller cannot seal a key of the tag mode hmac of VRF %d now: %w", ErrConflict, vrf, err)
	}
	back, err := c.tkeys.sealer.Open(label, sealed)
	opens := err == nil && bytes.Equal(back, key)
	clear(back)
	if !opens {
		clear(key)
		return tagKey{}, fmt.Errorf("%w: the controller cannot open the key of the tag mode hmac of VRF %d that it sealed: its sealing key does not answer (%v)", ErrConflict, vrf, err)
	}
	return tagKey{id: id, key: key, sealed: base64.StdEncoding.EncodeToString(sealed)}, nil
}

// withTagKeys puts the IDs of the keys of each VRF of in in the tag mode hmac into the Vrf objects of the
// states of the Nodes that report the Capability tags (desired.WithTagKeys), and returns the VRFs that
// need a first key, with its ID, which commit makes and stores before the states (saveTagKeys): their
// Nodes send with it at once. A controller without a sealing key gives such a VRF none, and says so
// once. c.mu is held.
func (c *Controller) withTagKeys(in intent.Intent, states map[string]desired.State) map[uint32]uint32 {
	need := map[uint32]uint32{}
	lists := map[uint32][]*controlpb.TagKey{}
	var unkeyed []string
	modes := in.VRFTagModes()
	for _, name := range slices.Sorted(maps.Keys(in.VRFs)) {
		if modes[name] != intent.TagModeHMAC {
			continue
		}
		id := in.VRFs[name].ID
		keys := c.tkeys.keys[id]
		if len(keys) == 0 {
			if c.tkeys.sealer == nil {
				unkeyed = append(unkeyed, name)
				continue
			}
			need[id] = c.tkeys.last[id] + 1
			keys = []tagKey{{id: need[id], send: true}}
		}
		for _, k := range keys {
			lists[id] = append(lists[id], &controlpb.TagKey{Id: k.id, Send: k.send})
		}
	}
	if len(unkeyed) > 0 && !slices.Equal(unkeyed, c.tkeys.unkeyed) {
		c.log.Warn("VRFs in the tag mode hmac have no key, since the controller has no sealing key: their nodes send no source group on their links and judge every claim of them by the map of address to group",
			"vrfs", unkeyed)
	}
	c.tkeys.unkeyed = unkeyed
	desired.WithTagKeys(states, lists, func(node string) bool {
		n, ok := in.Nodes[node]
		if !ok {
			return false
		}
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		return c.caps[string(k)].GetTags()
	})
	return need
}

// saveTagKeys makes the first key of each VRF of need, with its ID, stores it sealed and makes it the
// controller's: commit calls it before it stores the states that name it, and stores none when it fails.
// c.mu is held.
func (c *Controller) saveTagKeys(ctx context.Context, need map[uint32]uint32) error {
	for _, vrf := range slices.Sorted(maps.Keys(need)) {
		k, err := c.makeTagKey(vrf, need[vrf])
		if err != nil {
			return err
		}
		k.send = true
		if err := c.store.SetTagKeys(ctx, vrf, storedTagKeys([]tagKey{k})); err != nil {
			clear(k.key)
			return err
		}
		c.tkeys.keys[vrf] = []tagKey{k}
		c.tkeys.last[vrf] = k.id
		c.log.Info("tag key made: the nodes of the VRF in the tag mode hmac send with it", "vrf", vrf, "keyID", k.id)
	}
	return nil
}

// dropTagKeys deletes the keys of each VRF that next does not hold in the tag mode hmac. commit calls it
// once the change is stored. A failure is logged: no state holds the keys any more, and the next start
// drops the rows (loadTagKeys). c.mu is held.
func (c *Controller) dropTagKeys(ctx context.Context, next intent.Intent) {
	if len(c.tkeys.keys) == 0 {
		return
	}
	keep := hmacVRFs(next)
	var gone []uint32
	for id := range c.tkeys.keys {
		if !keep[id] {
			gone = append(gone, id)
		}
	}
	if len(gone) == 0 {
		return
	}
	slices.Sort(gone)
	for _, id := range gone {
		for _, k := range c.tkeys.keys[id] {
			clear(k.key)
		}
		delete(c.tkeys.keys, id)
	}
	if err := c.store.DeleteTagKeys(ctx, gone); err != nil {
		c.log.Warn("deleting the keys of the tag mode hmac of VRFs that left the mode", "vrfs", gone, "err", err)
	}
	c.log.Info("tag keys dropped: the VRFs left the tag mode hmac", "vrfs", gone)
}

// openTagKeys returns u with each Vrf object that names keys of the tag mode hmac replaced by a copy that
// holds the keys: the states hold their IDs alone. A key that the controller does not hold is sent
// without its bytes, and the Node does not take it. c.mu is held.
func (c *Controller) openTagKeys(u *controlpb.Update) *controlpb.Update {
	for i, o := range u.GetSet() {
		v := o.GetVrf()
		if v == nil || len(v.GetTagKeys()) == 0 {
			continue
		}
		clone, ok := proto.Clone(v).(*controlpb.Vrf)
		if !ok {
			continue
		}
		for _, t := range clone.GetTagKeys() {
			for _, k := range c.tkeys.keys[v.GetId()] {
				if k.id == t.GetId() {
					t.Key = bytes.Clone(k.key)
				}
			}
		}
		u.Set[i] = &controlpb.Object{Kind: &controlpb.Object_Vrf{Vrf: clone}}
	}
	return u
}

// holdsTagKey reports whether the state st holds the key id in the Vrf object of the VRF vrf.
func holdsTagKey(st desired.State, vrf, id uint32) bool {
	for k, o := range st {
		if k.Kind != controlpb.Kind_KIND_VRF || o.GetVrf().GetId() != vrf {
			continue
		}
		for _, t := range o.GetVrf().GetTagKeys() {
			if t.GetId() == id {
				return true
			}
		}
	}
	return false
}

// tagKeyWaits returns the Nodes, in name order, whose desired state holds the key id of the VRF vrf and
// that have not acknowledged a state that holds it: the Nodes that the switch to the key waits for.
// c.mu is held.
func (c *Controller) tagKeyWaits(vrf, id uint32) []string {
	waits := []string{}
	for name, n := range c.nodes {
		if holdsTagKey(n.state, vrf, id) && !holdsTagKey(n.acked, vrf, id) {
			waits = append(waits, name)
		}
	}
	slices.Sort(waits)
	return waits
}

// advanceTagKeys makes the new key of each VRF whose rotation no Node waits for any more the key that its
// Nodes send with: once every Node whose state holds it acknowledged a Generation that holds it, so that
// every Node of the VRF takes a MAC of it. The next Generation of each of its Nodes says so. saveAck calls
// it after each acknowledgement, and New after its first commit, as the acknowledgements may all be in
// before a restart. c.mu is held.
func (c *Controller) advanceTagKeys() {
	if c.closed {
		return
	}
	var ready []uint32
	for _, vrf := range slices.Sorted(maps.Keys(c.tkeys.keys)) {
		keys := c.tkeys.keys[vrf]
		if len(keys) == 2 && !keys[1].send && len(c.tagKeyWaits(vrf, keys[1].id)) == 0 {
			ready = append(ready, vrf)
		}
	}
	if len(ready) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	for _, vrf := range ready {
		keys := slices.Clone(c.tkeys.keys[vrf])
		keys[0].send, keys[1].send = false, true
		if err := c.store.SetTagKeys(ctx, vrf, storedTagKeys(keys)); err != nil {
			c.log.Error("making the new key of the tag mode hmac the one to send with", "vrf", vrf, "keyID", keys[1].id, "err", err)
			return
		}
		c.tkeys.keys[vrf] = keys
		c.log.Info("tag key in use: every node of the VRF acknowledged it, so they send with it", "vrf", vrf, "keyID", keys[1].id)
	}
	cp, err := c.compile(c.intent, c.lic)
	if err == nil {
		_, err = c.commit(ctx, c.intent, cp, store.Changes{})
	}
	if err != nil {
		c.log.Error("giving the nodes the new key of the tag mode hmac to send with", "vrfs", ready, "err", err)
	}
}

// RotateTagKey gives the VRF vrf in the tag mode hmac a new key: its Nodes get it beside the key that they
// send with, and send with it once each Node whose state holds it acknowledged it (advanceTagKeys). The
// key that they sent with before stays until the next rotation. An error wraps intent.ErrNotFound for a
// VRF that the intent does not hold, and ErrConflict for a VRF in another tag mode, one without a key, as
// the controller cannot seal one, and one whose last rotation its Nodes do not all run yet.
func (c *Controller) RotateTagKey(ctx context.Context, vrf string) (TagKeyRotation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.intent.VRFs[vrf]
	if !ok {
		return TagKeyRotation{}, fmt.Errorf("%w: VRF %q", intent.ErrNotFound, vrf)
	}
	if mode := c.intent.VRFTagMode(vrf); mode != intent.TagModeHMAC {
		return TagKeyRotation{}, fmt.Errorf("%w: VRF %q is in the tag mode %s: only a VRF in the tag mode %s has a key", ErrConflict, vrf, mode, intent.TagModeHMAC)
	}
	keys := c.tkeys.keys[v.ID]
	if len(keys) == 0 {
		return TagKeyRotation{}, fmt.Errorf("%w: VRF %q has no key of the tag mode hmac to rotate, since the controller has no sealing key", ErrConflict, vrf)
	}
	cur := keys[len(keys)-1]
	if !cur.send {
		return TagKeyRotation{}, fmt.Errorf("%w: the key %d of VRF %q is not in use yet: its nodes send with it once %s acknowledged it, and it can be rotated then",
			ErrConflict, cur.id, vrf, strings.Join(c.tagKeyWaits(v.ID, cur.id), ", "))
	}
	next, err := c.makeTagKey(v.ID, cur.id+1)
	if err != nil {
		return TagKeyRotation{}, err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	list := []tagKey{cur, next}
	if err := c.store.SetTagKeys(sctx, v.ID, storedTagKeys(list)); err != nil {
		clear(next.key)
		return TagKeyRotation{}, err
	}
	for _, k := range keys[:len(keys)-1] {
		clear(k.key)
	}
	c.tkeys.keys[v.ID] = list
	c.tkeys.last[v.ID] = next.id
	c.log.Info("tag key rotated: the nodes of the VRF get the new key beside the one that they send with", "vrf", vrf, "keyID", next.id)

	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		return TagKeyRotation{}, err
	}
	res, err := c.commit(ctx, c.intent, cp, store.Changes{})
	if err != nil {
		return TagKeyRotation{}, err
	}
	out := TagKeyRotation{VRF: vrf, KeyID: next.id, Nodes: res, Waits: c.tagKeyWaits(v.ID, next.id)}
	// No Node to wait for: the key is in use at once
	c.advanceTagKeys()
	return out, nil
}
