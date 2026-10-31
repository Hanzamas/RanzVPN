package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The static keys of the Nodes of the tests of the lives of the keys (SDN-56): the public keys of the fixed keys 1 and
// 97 of the conformance tests.
const (
	lifeAlice = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	lifeFiles = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
)

// lifeIntent has two Nodes in one Network: alice-laptop, a device of alice whose key lives the 90 days of the default,
// and files, a server marked nonExpiring. bob is a User with no device.
const lifeIntent = `{"resources": [
	{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
	{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
	{"kind": "User", "name": "alice", "spec": {}},
	{"kind": "User", "name": "bob", "spec": {}},
	{"kind": "Node", "name": "alice-laptop", "spec": {"publicKey": "` + lifeAlice + `", "vrfs": ["corp"], "owner": "alice", "addresses": {"corp-lan": "10.10.0.1"}}},
	{"kind": "Node", "name": "files", "spec": {"publicKey": "` + lifeFiles + `", "vrfs": ["corp"], "addresses": {"corp-lan": "10.10.0.3"}, "nonExpiring": true}}
]}`

// stepClock is the clock of the lives of the keys of a controller from newLifeController, which a test moves.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the time of the clock.
func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the clock forward by d.
func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newLifeController returns a controller on a store of its own, with the clock clk and the intent lifeIntent applied. It
// looks at the lives of the keys every hour, so in a test it does so only when the test calls sweepKeys.
func newLifeController(t *testing.T, clk *stepClock) *Controller {
	t.Helper()
	rq := rqlitetest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(ctx, Config{Store: st, Key: key, Now: clk.Now, KeyCheck: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	doc, err := intent.ParseDocument([]byte(lifeIntent))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	return c
}

// A commit notes as held back the Nodes that its compile held back, and reads the clock no second time: a key that ends
// after the compile read the clock, while the change is committed, is in states that still have its Node as a Peer, so the
// commit does not note its Node as held, and the next look at the keys compiles the states again without it. Noted as held
// at the commit, the Node would stay a Peer of the others, since each look would find the holds of the states in force
// unchanged (SDN-56).
func TestACommitNotesTheHoldsOfItsCompile(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Millisecond)
	clk := &stepClock{now: start}
	c := newLifeController(t, clk)
	peer := desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: "alice-laptop"}

	// A millisecond before the key of alice-laptop ends, the states are compiled; the key ends before they are committed
	clk.advance(90*24*time.Hour - time.Millisecond)
	c.mu.Lock()
	cp, err := c.compile(c.intent, c.lic)
	if err == nil {
		clk.advance(time.Millisecond)
		_, err = c.commit(context.Background(), c.intent, cp, store.Changes{})
	}
	_, peered := c.nodes["files"].state[peer]
	noted := len(c.keyLife.applied)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !peered || noted != 0 {
		t.Fatalf("after the commit files has alice-laptop as a Peer: %v, and %d nodes are noted as held back; want the Peer and none, as the compile held back none", peered, noted)
	}

	// The next look at the keys finds the key of alice-laptop ended, and gives files a state without it
	c.sweepKeys()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, peered = c.nodes["files"].state[peer]
	if h, held := c.keyLife.applied["alice-laptop"]; peered || !held || h.reason != KeyExpired {
		t.Errorf("after the next look files has alice-laptop as a Peer: %v, and the hold of alice-laptop is %+v (noted: %v); want no Peer and the key expired", peered, h, held)
	}
}

// The refresh of a key renews the key that the device presented: refreshKey checks again, under the lock, that the Node
// that the enrolment found still holds that key as a device of that User, since a change of the intent can give the Node
// another key or another owner, or remove it, between the two; a refresh that it refuses renews nothing (SDN-56).
func TestARefreshRenewsOnlyTheKeyThatTheUserPresented(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Millisecond)
	clk := &stepClock{now: start}
	c := newLifeController(t, clk)
	ctx := context.Background()
	alice, err := intent.ParseKey(lifeAlice)
	if err != nil {
		t.Fatal(err)
	}
	files, err := intent.ParseKey(lifeFiles)
	if err != nil {
		t.Fatal(err)
	}
	life := func() store.NodeKey {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.keyLife.life[string(alice)]
	}

	clk.advance(10 * 24 * time.Hour)
	for _, r := range []struct {
		what, node, user string
		key              []byte
		want             error
	}{
		{"a key that the node does not hold", "alice-laptop", "alice", files, ErrConflict},
		{"a user that does not own the node", "alice-laptop", "bob", alice, ErrConflict},
		{"a node that the intent does not hold", "alice-phone", "alice", alice, intent.ErrNotFound},
	} {
		if err := c.refreshKey(ctx, r.node, r.user, r.key); !errors.Is(err, r.want) {
			t.Errorf("a refresh with %s gave %v, want %v", r.what, err, r.want)
		}
	}
	if k := life(); !k.Refreshed.Equal(start) || !k.Expires.Equal(start.Add(90*24*time.Hour)) {
		t.Errorf("the life of the key of alice-laptop is %+v after the refreshes that were refused, want it as the apply made it", k)
	}

	// The device of alice that presents its own key refreshes it: the key lives 90 days from now
	if err := c.refreshKey(ctx, "alice-laptop", "alice", alice); err != nil {
		t.Fatal(err)
	}
	if k, now := life(), start.Add(10*24*time.Hour); !k.Refreshed.Equal(now) || !k.Expires.Equal(now.Add(90*24*time.Hour)) {
		t.Errorf("the life of the key of alice-laptop is %+v after alice refreshed it on day 10, want it to end on day 100", k)
	}
}
