package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// Revisions (ADR-0031 decisions 2 to 4). Every apply, delete and rollback makes the next
// revision, which the store keeps with its whole intent in the same transaction as the change
// itself. A rollback is a new revision too, so the history only grows and a rollback can be
// rolled back. An apply with a confirmation time waits for `ranz confirm` until its deadline;
// meanwhile the controller refuses every other change but a rollback, so the revision to return
// to is always the one before it. At the deadline the controller restores that one as an
// automatic rollback and records an AutomaticRollback event in the same transaction. The wait
// is in the store as well, so it survives a restart of the controller.

const (
	// MinConfirm and MaxConfirm bound the confirmation time of an apply.
	MinConfirm = time.Second
	MaxConfirm = 24 * time.Hour
	// retryRollback is the wait before an automatic rollback that the store failed is tried
	// again.
	retryRollback = 5 * time.Second
)

var (
	// ErrNoRevision marks a revision that does not exist.
	ErrNoRevision = errors.New("no such revision")
	// ErrConflict marks a change that the controller cannot take now: any change but a
	// rollback while a revision waits for confirmation, or the confirmation of a revision that
	// does not wait for one.
	ErrConflict = errors.New("conflict")
	// ErrBadConfirm marks a confirmation time outside MinConfirm and MaxConfirm.
	ErrBadConfirm = errors.New("bad confirmation time")
)

// Rollback makes the intent of revision target the intent again, as the next revision
// (`ranz rollback`); revision 0 is the empty intent. Each node gets the generation that the
// restored intent compiles to for it. A rollback while a revision waits for confirmation ends
// the wait: that revision is cancelled.
func (c *Controller) Rollback(ctx context.Context, target uint64) (ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ch store.Changes
	if c.pending != nil {
		ch.UpdateRevisions = []intent.Revision{settled(*c.pending, intent.ConfirmCancelled)}
	}
	res, err := c.restore(ctx, target, c.nextRevision(intent.OpRollback), ch)
	if err != nil {
		return ApplyResult{}, err
	}
	if c.pending != nil {
		c.log.Info("confirmation cancelled by a rollback", "revision", c.pending.ID)
		c.settle()
	}
	c.log.Info("intent rolled back", "revision", res.Revision, "restores", target, "changed", len(res.Nodes))
	return res, nil
}

// Confirm confirms revision id, which an apply with a confirmation time made, so that the
// controller keeps it (`ranz confirm`). It returns the revision without its resources.
func (c *Controller) Confirm(ctx context.Context, id uint64) (intent.Revision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil || c.pending.ID != id {
		r, err := c.Revision(ctx, id)
		if err != nil {
			return intent.Revision{}, err
		}
		state := "no confirmation time"
		if r.Confirm != nil {
			state = r.Confirm.State
		}
		return intent.Revision{}, fmt.Errorf("%w: revision %d does not wait for confirmation (%s)", ErrConflict, id, state)
	}
	r := settled(*c.pending, intent.ConfirmConfirmed)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.Commit(sctx, store.Changes{UpdateRevisions: []intent.Revision{r}}); err != nil {
		return intent.Revision{}, err
	}
	c.settle()
	c.log.Info("revision confirmed", "revision", id)
	return r, nil
}

// Revisions returns every revision, oldest first, without their resources.
func (c *Controller) Revisions(ctx context.Context) ([]intent.Revision, error) {
	return c.store.Revisions(ctx)
}

// Revision returns revision id with its resources.
func (c *Controller) Revision(ctx context.Context, id uint64) (intent.Revision, error) {
	r, ok, err := c.store.Revision(ctx, id)
	if err != nil {
		return intent.Revision{}, err
	}
	if !ok {
		return intent.Revision{}, fmt.Errorf("%w: %d", ErrNoRevision, id)
	}
	return r, nil
}

// LatestRevision returns the number of the latest revision, 0 before the first.
func (c *Controller) LatestRevision() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revision
}

// Diff returns how the intent of revision to differs from the intent of revision from
// (`ranz diff`); revision 0 is the empty intent.
func (c *Controller) Diff(ctx context.Context, from, to uint64) ([]intent.Change, error) {
	a, err := c.intentAt(ctx, from)
	if err != nil {
		return nil, err
	}
	b, err := c.intentAt(ctx, to)
	if err != nil {
		return nil, err
	}
	return intent.Diff(a, b), nil
}

// Events returns every event, oldest first.
func (c *Controller) Events(ctx context.Context) ([]event.Event, error) {
	return c.store.Events(ctx)
}

// change makes next, which compiles to cp, the intent as revision rev, which nextRevision made,
// together with the further changes of ch. c.mu is held.
func (c *Controller) change(ctx context.Context, next intent.Intent, cp compiled, rev intent.Revision, ch store.Changes) (ApplyResult, error) {
	rev.Resources = next.Resources()
	ch.AddRevision = &rev
	nodes, err := c.commit(ctx, next, cp, ch)
	if err != nil {
		return ApplyResult{}, err
	}
	c.revision = rev.ID
	return ApplyResult{Revision: rev.ID, Nodes: nodes}, nil
}

// restore makes the intent of revision target the intent again as revision rev, together with
// the further changes of ch. A rollback is checked like an apply: what the licence in force does
// not allow is refused with an error that wraps licence.ErrRefused (ADR-0036), an intent that a
// node cannot honour with one that wraps capability.ErrMissing (ADR-0033), and a rollback to
// Controller resources that the schema version the controller runs as does not know (SDN-17). An
// automatic rollback is not checked: it returns to the intent before an unconfirmed apply, and
// nothing may keep that apply. c.mu is held.
func (c *Controller) restore(ctx context.Context, target uint64, rev intent.Revision, ch store.Changes) (ApplyResult, error) {
	if target > c.revision {
		return ApplyResult{}, fmt.Errorf("%w: %d, the latest revision is %d", ErrNoRevision, target, c.revision)
	}
	rs, err := c.intentAt(ctx, target)
	if err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.FromResources(rs)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("revision %d: %w", target, err)
	}
	cp, err := c.compile(next, c.lic)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("revision %d: %w", target, err)
	}
	if rev.Operation == intent.OpRollback {
		if err := c.checkCluster(ctx, cp.force); err != nil {
			return ApplyResult{}, err
		}
		if err := c.checkCap(next, cp.force, "rollback"); err != nil {
			return ApplyResult{}, err
		}
		if err := c.known(rs); err != nil {
			return ApplyResult{}, fmt.Errorf("revision %d: %w", target, err)
		}
		if err := c.honoured(next, cp.states); err != nil {
			c.log.Warn("rollback refused: capability", "revision", target, "err", err)
			return ApplyResult{}, err
		}
	}
	rev.Restores = &target
	return c.change(ctx, next, cp, rev, ch)
}

// intentAt returns the resources of revision id: none for revision 0.
func (c *Controller) intentAt(ctx context.Context, id uint64) ([]intent.Resource, error) {
	if id == 0 {
		return nil, nil
	}
	r, err := c.Revision(ctx, id)
	if err != nil {
		return nil, err
	}
	return r.Resources, nil
}

// nextRevision returns the revision after the latest one, made now by op. c.mu is held.
func (c *Controller) nextRevision(op string) intent.Revision {
	return intent.Revision{ID: c.revision + 1, Time: time.Now().UTC().Truncate(time.Millisecond), Operation: op}
}

// await makes rev, which waits for confirmation, the pending revision, and has the controller
// roll it back after d unless a confirmation or a rollback comes first. c.mu is held.
func (c *Controller) await(rev intent.Revision, d time.Duration) {
	rev.Resources = nil
	c.pending = &rev
	id := rev.ID
	c.timer = time.AfterFunc(d, func() { c.expire(id) })
}

// expire rolls back revision id, whose deadline passed with no confirmation: the intent of the
// revision before it comes back as an automatic rollback, and an AutomaticRollback event is
// recorded with it (ADR-0031 decision 4, ADR-0030 decision 5). When the store fails, it tries
// again after retryRollback, so that a failed write cannot keep the unconfirmed change.
func (c *Controller) expire(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.pending == nil || c.pending.ID != id {
		return
	}
	// While a revision waits, no other revision can follow it, so the one before it is id-1.
	p := *c.pending
	rev := c.nextRevision(intent.OpAutomaticRollback)
	rev.Reverts = id
	msg := fmt.Sprintf("revision %d was not confirmed by %s: revision %d restores revision %d", id, p.Confirm.Deadline.Format(time.RFC3339), rev.ID, id-1)
	ev := event.Event{Time: rev.Time, Type: event.AutomaticRollback, Message: msg, Revision: rev.ID, Reverts: id}
	ch := store.Changes{UpdateRevisions: []intent.Revision{settled(p, intent.ConfirmRolledBack)}, AddEvents: []event.Event{ev}}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	res, err := c.restore(ctx, id-1, rev, ch)
	if err != nil {
		c.log.Error("automatic rollback failed, trying again", "revision", id, "retry", retryRollback, "err", err)
		c.timer = time.AfterFunc(retryRollback, func() { c.expire(id) })
		return
	}
	c.settle()
	c.tel.feed.Poke()
	c.log.Warn("automatic rollback: "+msg, "revision", res.Revision, "reverts", id, "changed", len(res.Nodes))
}

// settle ends the wait for the confirmation of the pending revision. c.mu is held.
func (c *Controller) settle() {
	if c.timer != nil {
		c.timer.Stop()
	}
	c.pending, c.timer = nil, nil
}

// unconfirmed returns an ErrConflict error while a revision waits for confirmation: only a
// confirmation or a rollback may follow it. c.mu is held.
func (c *Controller) unconfirmed() error {
	if c.pending == nil {
		return nil
	}
	return fmt.Errorf("%w: revision %d waits for confirmation until %s: confirm it (ranz confirm %d) or roll back",
		ErrConflict, c.pending.ID, c.pending.Confirm.Deadline.Format(time.RFC3339), c.pending.ID)
}

// settled returns r, which waits for confirmation, with its confirmation in state.
func settled(r intent.Revision, state string) intent.Revision {
	r.Confirm = &intent.Confirmation{Deadline: r.Confirm.Deadline, State: state}
	return r
}
