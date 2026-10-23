package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The audit log (SDN-49 #242, ADR-0030). The controller adds a record for each revision of the intent
// (auditRevision, which change calls once the revision is stored: one record for each revision,
// whoever made it, with the actor and the source of the API call that did, or the system for the
// first start and the automatic rollback), and for what happens on the control streams of the nodes:
// the first Hello of a static key is an enrolment, an accepted stream a login, its end a logout, and
// a static key that no Node resource holds a failed authentication. The calls of the API that change
// anything else, and the calls that fail, are recorded by the API itself (internal/api AuditCalls
// and AuditRefusals) through RecordAudit. The leader also runs what sends the log to the audit
// targets (audit.Exporter) and what removes the old records (audit.Retain).

// auditState is what the controller keeps for the audit log.
type auditState struct {
	log *audit.Log
	cfg audit.Config

	// Started by startAudit, once the store is loaded
	exporter *audit.Exporter
	cancel   context.CancelFunc
	done     chan struct{}
}

func newAuditState(cfg Config, st *store.Store, log *slog.Logger) *auditState {
	return &auditState{log: audit.NewLog(st, log), cfg: cfg.Audit}
}

// startAudit starts the exporter of the audit targets and the removal of the old records. New calls
// it last, so that nothing runs for a controller that did not start.
func (c *Controller) startAudit() {
	a := c.aud
	a.exporter = audit.NewExporter(c.store, c.log, "ranz-controller/"+c.version, a.cfg.Poll)
	a.exporter.Start()
	prune := a.cfg.Prune
	if prune <= 0 {
		prune = audit.DefaultPrune
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel, a.done = cancel, make(chan struct{})
	go func() {
		defer close(a.done)
		audit.Retain(ctx, c.store, prune, c.log)
	}()
}

// stopAudit stops the exporter and the removal of the old records. Close calls it once the control
// streams ended.
func (c *Controller) stopAudit() {
	a := c.aud
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
	if a.exporter != nil {
		a.exporter.Stop()
	}
}

// RecordAudit adds r to the audit log. What the controller does itself it records without this; the
// calls of the API that change anything but the intent come here, with the origin of the call in ctx
// (audit.NewContext), and so can a feature that has an audit record of its own to make: the logins of
// users (SDN-32), the live operations (SDN-50). A record without an actor or a source gets the ones
// of the origin in ctx, and the system and local when there is none. The exporter looks at the log
// at once. An error that wraps audit.ErrInvalid is a record that is not valid.
func (c *Controller) RecordAudit(ctx context.Context, r audit.Record) error {
	if err := c.aud.log.Record(ctx, r); err != nil {
		return err
	}
	c.aud.exporter.Poke()
	return nil
}

// auditRevision records the revision rev that change just made: one intent-change for each
// revision, with the revision that it made. The time of the record is the time of the revision.
func (c *Controller) auditRevision(ctx context.Context, rev intent.Revision) {
	r := audit.Record{Time: rev.Time, Kind: audit.IntentChange, Outcome: audit.Success, Action: rev.Operation, Revision: rev.ID}
	switch {
	case rev.Reverts != 0:
		r.Message = fmt.Sprintf("reverts revision %d, which nobody confirmed in time", rev.Reverts)
	case rev.Restores != nil:
		r.Message = fmt.Sprintf("restores revision %d", *rev.Restores)
	}
	// RecordAudit logs what it could not store: the change is made and stays
	_ = c.RecordAudit(ctx, r)
}

// auditNode records an event of the control stream of a node that came from the address remote.
func (c *Controller) auditNode(kind, actor, outcome, message string, remote net.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	_ = c.RecordAudit(ctx, audit.Record{Kind: kind, Actor: actor, Source: audit.Host(remote.String()), Outcome: outcome, Message: message})
}

// AuditRecords returns the records of the audit log that match f, the oldest first (GET
// /api/v1/audit).
func (c *Controller) AuditRecords(ctx context.Context, f audit.Filter) ([]audit.Record, error) {
	return c.store.Audit(ctx, f)
}

// AuditTargets returns the audit targets, ordered by name, with their secrets.
func (c *Controller) AuditTargets(ctx context.Context) ([]export.Target, error) {
	stored, err := c.store.AuditTargets(ctx)
	if err != nil {
		return nil, err
	}
	return plain(stored), nil
}

// PutAuditTarget stores the audit target t, which replaces the one of its name. An error that wraps
// export.ErrInvalid is a target that is not valid.
func (c *Controller) PutAuditTarget(ctx context.Context, t export.Target) error {
	if err := t.ValidateAudit(audit.Kinds); err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.PutAuditTarget(sctx, t); err != nil {
		return err
	}
	c.aud.exporter.Poke()
	return nil
}

// DeleteAuditTarget deletes the audit target name and returns it. There is none of that name when
// the error wraps intent.ErrNotFound.
func (c *Controller) DeleteAuditTarget(ctx context.Context, name string) (export.Target, error) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	stored, err := c.store.AuditTargets(sctx)
	if err != nil {
		return export.Target{}, err
	}
	for _, s := range stored {
		if s.Name != name {
			continue
		}
		if err := c.store.DeleteAuditTarget(sctx, name); err != nil {
			return export.Target{}, err
		}
		return s.Target, nil
	}
	return export.Target{}, fmt.Errorf("%w: audit target %q", intent.ErrNotFound, name)
}

// AuditRetention returns the retention policy of the audit log: the one that an operator set, and
// audit.DefaultRetention until then.
func (c *Controller) AuditRetention(ctx context.Context) (audit.Retention, error) {
	r, ok, err := c.store.AuditRetention(ctx)
	if err != nil {
		return audit.Retention{}, err
	}
	if !ok {
		return audit.DefaultRetention, nil
	}
	return r, nil
}

// SetAuditRetention sets the retention policy of the audit log. An error that wraps audit.ErrInvalid
// is a policy that is not valid. The next removal of old records follows it.
func (c *Controller) SetAuditRetention(ctx context.Context, r audit.Retention) error {
	if err := r.Validate(); err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	return c.store.SetAuditRetention(sctx, r)
}
