// Package clusterkey keeps the Cluster key of a member of a controller cluster (AUD1-DT-16 #501,
// ADR-0026 amendment of 2026-10-29): the key that seals the secrets of the export and audit targets of a
// cluster, where a single Controller seals them with the Sealing key of its host (internal/keys).
//
// The Sealing key of a member is a key of its own host's key storage that never leaves it, so no two
// members have one in common, and what one member sealed with it the next leader could not open. A
// cluster has one Cluster key instead: an X25519 key that the first member of the cluster makes, which
// seals a secret as a Sealing key does (keys.Sealer). The store holds it only as copies, one in the row
// of each member, sealed to the public half of that member's Sealing key under the label of the row, so
// that only that member opens it (internal/store, cluster_key_copies). A member publishes the public half
// of its Sealing key in its row when it starts; a member that holds the Cluster key gives a copy to
// every row that has none; and a member opens its copy with its own key and holds the Cluster key in
// memory, never in the store or in the log.
//
// The store names the key of the cluster (cluster_key), and a member holds a key only while the store
// names it. A member that holds none keeps no secret: Seal refuses one, so no secret is kept in clear,
// and Open opens none, so the targets are sent without their secrets until the member holds the key. A
// copy that its member's key does not open is removed, so that a member that holds the key gives
// another. When no row has held a copy for LostAfter, no member can get the key any more: the member that
// sees it makes a new one, and the secrets that the old key sealed are lost.
package clusterkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The defaults of a Config.
const (
	// DefaultPoll is how often a member reads the Cluster key in the store, as often as it reads the
	// certificate of the Controller (internal/servercert).
	DefaultPoll = 2 * time.Second
	// DefaultWait bounds the wait of Start for a copy: a member that holds the key gives one within a
	// poll.
	DefaultWait = 10 * time.Second
	// DefaultLostAfter is how long no row may hold a copy before the Cluster key is lost: a member that
	// holds the key writes its own copy again within a poll.
	DefaultLostAfter = time.Minute
)

// resealEvery is how often a member that holds the Cluster key seals the secrets of the targets that
// are in clear, after it did so when it came to hold the key.
const resealEvery = time.Minute

// startPoll is how often Start reads the store while it waits for a copy.
const startPoll = 250 * time.Millisecond

// keyLen is the length of an X25519 public key: a row whose key has another length holds no key.
const keyLen = 32

// ErrNoKey is what Seal and Open fail with while the member holds no Cluster key.
var ErrNoKey = errors.New("clusterkey: this member of the controller cluster does not hold the Cluster key yet, so it keeps no secret of a target: try again in a few seconds, once a member that holds the key has given it a copy")

// Config is what a Keeper runs with.
type Config struct {
	// Store is the store of the member, whose Sealer the Keeper is (store.SetSealer).
	Store *store.Store
	// Member is the name of the member, unique in the cluster: the name of its row.
	Member string
	// Sealing is the member's Sealing key (keys.LoadSealer), which opens its copy.
	Sealing *keys.Sealer
	// Log is discarded when it is nil.
	Log *slog.Logger
	// Poll, Wait and LostAfter are DefaultPoll, DefaultWait and DefaultLostAfter when they are 0.
	Poll, Wait, LostAfter time.Duration
}

// Keeper keeps the Cluster key of one member: it is the store.Sealer of the member's store.
type Keeper struct {
	cfg    Config
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}

	// Used by step only.
	noCopy   time.Time // since when no row holds a copy, zero while one does
	resealed time.Time // when the member last sealed the secrets that are in clear, zero for not yet
	cleared  bool      // the member said that it removed a copy that did not open, and holds no key since

	mu  sync.Mutex
	key *held // the Cluster key while the member holds it
}

// held is the Cluster key as a member holds it.
type held struct {
	key    *keys.Soft
	sealer *keys.Sealer
	public []byte
}

func newHeld(key *keys.Soft) *held {
	return &held{key: key, sealer: keys.NewSealer(key), public: key.Public()}
}

// New returns the Keeper of cfg, which holds no key until Start.
func New(cfg Config) *Keeper {
	if cfg.Poll <= 0 {
		cfg.Poll = DefaultPoll
	}
	if cfg.Wait <= 0 {
		cfg.Wait = DefaultWait
	}
	if cfg.LostAfter <= 0 {
		cfg.LostAfter = DefaultLostAfter
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Keeper{cfg: cfg, log: log}
}

// Start publishes the public half of the member's Sealing key in its row and waits, up to the Wait of the
// Config, until the member holds the Cluster key: the key that its copy opens, or a key that it makes
// when the cluster has none. A member that holds no key by then says so in its log, which is no error.
// From then on the Keeper reads the store every Poll until ctx ends or Close: it gives a copy to every
// member that has none, holds the key once its own copy comes, and seals the secrets that are in clear.
func (k *Keeper) Start(ctx context.Context) error {
	if err := k.cfg.Store.PublishSealingKey(ctx, k.cfg.Member, k.cfg.Sealing.Public()); err != nil {
		return fmt.Errorf("clusterkey: %w", err)
	}
	deadline := time.Now().Add(k.cfg.Wait)
	for {
		k.step(ctx, true)
		if k.Holds() || ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(startPoll):
		}
	}
	if !k.Holds() {
		k.log.Warn("this member does not hold the Cluster key yet, so it keeps no secret of a target: it refuses a target with a secret, and sends to the targets without their secrets, until a member that holds the key gives it a copy")
	}
	lctx, cancel := context.WithCancel(ctx)
	k.cancel, k.done = cancel, make(chan struct{})
	go k.loop(lctx)
	return nil
}

// Close stops the Keeper from reading the store, and waits until it stopped. The member keeps the key
// that it holds.
func (k *Keeper) Close() {
	if k.cancel != nil {
		k.cancel()
		<-k.done
	}
}

// Holds reports whether the member holds the Cluster key.
func (k *Keeper) Holds() bool {
	return k.current() != nil
}

// Seal seals plain under label with the Cluster key, as keys.Sealer.Seal does with a Sealing key. It
// fails with ErrNoKey while the member holds no key, so that a secret is never kept in clear.
func (k *Keeper) Seal(label string, plain []byte) ([]byte, error) {
	h := k.current()
	if h == nil {
		return nil, ErrNoKey
	}
	return h.sealer.Seal(label, plain)
}

// Open opens what Seal sealed under label with the Cluster key, as keys.Sealer.Open does. It fails with
// ErrNoKey while the member holds no key, and with keys.ErrNotSealed for what the Cluster key did not
// seal under label.
func (k *Keeper) Open(label string, sealed []byte) ([]byte, error) {
	h := k.current()
	if h == nil {
		return nil, ErrNoKey
	}
	return h.sealer.Open(label, sealed)
}

func (k *Keeper) current() *held {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.key
}

func (k *Keeper) loop(ctx context.Context) {
	defer close(k.done)
	t := time.NewTicker(k.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			k.step(ctx, false)
		}
	}
}

// step reads the Cluster key in the store and does what the member does about it. starting is true while
// Start waits: a member that starts and finds no key at all makes one at once. A member that runs waits
// LostAfter for that, as for a lost key, so that a moment without the key, as the load of a restore has
// one, makes no second key.
func (k *Keeper) step(ctx context.Context, starting bool) {
	ck, err := k.cfg.Store.ClusterKey(ctx)
	if err != nil {
		if ctx.Err() == nil {
			k.log.Debug("reading the Cluster key", "err", err)
		}
		return
	}
	own := k.cfg.Sealing.Public()
	i := slices.IndexFunc(ck.Copies, func(c store.ClusterKeyCopy) bool { return c.Member == k.cfg.Member })
	if i < 0 || !bytes.Equal(ck.Copies[i].Sealing, own) {
		// The row of the member is gone, or holds another key: a writer of the store changed it, or a
		// restore loads the rows of another store at this moment
		if err := k.cfg.Store.PublishSealingKey(ctx, k.cfg.Member, own); err != nil {
			if ctx.Err() == nil {
				k.log.Debug("publishing the sealing key of this member", "err", err)
			}
			return
		}
		mine := store.ClusterKeyCopy{Member: k.cfg.Member, Sealing: own}
		if i < 0 {
			ck.Copies, i = append(ck.Copies, mine), len(ck.Copies)
		} else {
			ck.Copies[i] = mine
		}
	}
	h := k.current()
	switch {
	case h != nil && ck.Public == nil:
		// A writer of the store removed the key that this member holds: it is the cluster's key, so it
		// goes back, with the copy of this member, and the next step goes on from there
		wrapped, err := wrap(h, k.cfg.Member, own)
		if err == nil {
			_, err = k.cfg.Store.MakeClusterKey(ctx, nil, h.public, k.cfg.Member, own, wrapped)
		}
		if err != nil && ctx.Err() == nil {
			k.log.Debug("writing the Cluster key back", "err", err)
		}
		return
	case h != nil && !bytes.Equal(h.public, ck.Public):
		k.drop()
		h = nil
	}
	if h == nil {
		if h = k.acquire(ctx, ck, i, starting); h == nil {
			return
		}
	}
	k.give(ctx, h, ck)
	k.reseal(ctx)
}

// acquire returns the Cluster key that the member holds from now on, nil while it holds none: the key that
// the copy in its row, ck.Copies[i], opens, or a key that it makes in the place of none or of a lost one.
func (k *Keeper) acquire(ctx context.Context, ck store.ClusterKey, i int, starting bool) *held {
	mine := &ck.Copies[i]
	if len(mine.Copy) > 0 {
		h, opened := k.openCopy(ck, *mine)
		if h != nil {
			k.hold(h)
			k.log.Info("this member holds the Cluster key: its copy opens with the sealing key of this member")
			return h
		}
		if !opened {
			// A copy that does not open is of no use to anyone: it goes, so that a member that holds the
			// key gives another
			if err := k.cfg.Store.ClearClusterKeyCopy(ctx, k.cfg.Member, mine.Sealing); err != nil {
				if ctx.Err() == nil {
					k.log.Debug("removing the copy of the Cluster key of this member", "err", err)
				}
				return nil
			}
			if !k.cleared {
				k.cleared = true
				k.log.Warn("the copy of the Cluster key in the row of this member does not open with its sealing key: it is removed, so that a member that holds the key gives it another")
			}
			mine.Copy = nil
		}
	}
	if ck.Public != nil && slices.ContainsFunc(ck.Copies, func(c store.ClusterKeyCopy) bool { return len(c.Copy) > 0 }) {
		// A member has a copy, so a member that holds the key gives this member one
		k.noCopy = time.Time{}
		return nil
	}
	if ck.Public == nil && starting {
		return k.makeKey(ctx, nil)
	}
	now := time.Now()
	if k.noCopy.IsZero() {
		k.noCopy = now
	}
	if now.Sub(k.noCopy) < k.cfg.LostAfter {
		return nil
	}
	return k.makeKey(ctx, ck.Public)
}

// openCopy returns the Cluster key that the copy mine holds, when the sealing key of the member opens it
// under the label of its row and it is the key that ck names, and nil otherwise; opened reports that the
// copy opened, as a copy of a key that the store does not name opens. The copy is what anyone who can
// write to the store may put there.
func (k *Keeper) openCopy(ck store.ClusterKey, mine store.ClusterKeyCopy) (h *held, opened bool) {
	priv, err := k.cfg.Sealing.Open(copyLabel(k.cfg.Member), mine.Copy)
	if err != nil {
		return nil, false
	}
	key, err := keys.NewSoft(priv)
	if err != nil {
		return nil, false
	}
	if !bytes.Equal(key.Public(), ck.Public) {
		return nil, true
	}
	return newHeld(key), true
}

// makeKey makes a new Cluster key in the place of old, nil when the store holds none, with the copy of
// this member, and holds it; nil when the store held another key by then, as when another member made one
// first.
func (k *Keeper) makeKey(ctx context.Context, old []byte) *held {
	key, err := keys.GenerateSoft()
	if err != nil {
		k.log.Warn("making a Cluster key", "err", err)
		return nil
	}
	h := newHeld(key)
	own := k.cfg.Sealing.Public()
	wrapped, err := wrap(h, k.cfg.Member, own)
	if err != nil {
		k.log.Warn("making a Cluster key", "err", err)
		return nil
	}
	made, err := k.cfg.Store.MakeClusterKey(ctx, old, h.public, k.cfg.Member, own, wrapped)
	if err != nil {
		if ctx.Err() == nil {
			k.log.Debug("making a Cluster key", "err", err)
		}
		return nil
	}
	if !made {
		return nil
	}
	k.hold(h)
	if old == nil {
		k.log.Info("this member holds the Cluster key: it made it, since the cluster had none")
	} else {
		k.log.Warn("the Cluster key was lost, so this member holds a new one: no member had a copy of the old key, and the secrets that it sealed cannot be opened, so the targets are sent without them until each is put again",
			"lostAfter", k.cfg.LostAfter)
	}
	return h
}

// hold makes h the key that the member holds.
func (k *Keeper) hold(h *held) {
	k.mu.Lock()
	k.key = h
	k.mu.Unlock()
	k.noCopy, k.resealed, k.cleared = time.Time{}, time.Time{}, false
}

// drop ends the hold of the key that the member held: the store names another one.
func (k *Keeper) drop() {
	k.mu.Lock()
	k.key = nil
	k.mu.Unlock()
	k.log.Warn("the Cluster key in the store is not the one that this member held, so it holds none until its copy of that key opens: it keeps no secret of a target meanwhile")
}

// give gives a copy of the Cluster key h to every member whose row has none, this member's own included.
func (k *Keeper) give(ctx context.Context, h *held, ck store.ClusterKey) {
	for _, c := range ck.Copies {
		if len(c.Copy) > 0 || len(c.Sealing) != keyLen {
			continue
		}
		wrapped, err := wrap(h, c.Member, c.Sealing)
		if err != nil {
			// A key that is none, which only a writer of the store puts in a row
			k.log.Debug("giving a copy of the Cluster key", "member", c.Member, "err", err)
			continue
		}
		gave, err := k.cfg.Store.PutClusterKeyCopy(ctx, h.public, c.Member, c.Sealing, wrapped)
		if err != nil {
			if ctx.Err() == nil {
				k.log.Debug("giving a copy of the Cluster key", "member", c.Member, "err", err)
			}
			continue
		}
		if gave && c.Member != k.cfg.Member {
			k.log.Info("gave a copy of the Cluster key to a member of the cluster", "member", c.Member)
		}
	}
}

// reseal seals the secrets of the targets that are in clear with the Cluster key: at once when the member
// has come to hold the key, and then every resealEvery. An earlier release kept them in clear, and so does
// a member of one during a rolling upgrade, and a backup of one that is restored.
func (k *Keeper) reseal(ctx context.Context) {
	if !k.resealed.IsZero() && time.Since(k.resealed) < resealEvery {
		return
	}
	n, err := k.cfg.Store.SealTargetSecrets(ctx)
	if err != nil {
		if ctx.Err() == nil {
			k.log.Warn("sealing the secrets of the targets that are in clear", "err", err)
		}
		return
	}
	k.resealed = time.Now()
	if n > 0 {
		k.log.Info("sealed the secrets of the targets that were in clear, with the Cluster key", "targets", n)
	}
}

// wrap returns the copy of the Cluster key h for the row of member, whose Sealing key has the public half
// sealing: the private half of h, sealed to sealing under the label of the row.
func wrap(h *held, member string, sealing []byte) ([]byte, error) {
	return keys.SealTo(sealing, copyLabel(member), h.key.Private())
}

// copyLabel is the label of the copy in the row of member, so that a copy opens in its own row only.
func copyLabel(member string) string {
	return "cluster_key_copies:" + member
}
