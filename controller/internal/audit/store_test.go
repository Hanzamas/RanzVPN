package audit

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// memStore is the Store of the audit log in memory, for the tests of this package. The store
// itself, in rqlite, is tested in internal/store.
type memStore struct {
	mu        sync.Mutex
	next      uint64
	records   []Record
	targets   []export.Stored
	retention *Retention
	prunes    []prune
	err       error // every call fails with it while it is set
	// failRead and failDelivered make the listing of the records and the record of a delivery fail
	failRead      error
	failDelivered error
}

// prune is one call of PruneAudit.
type prune struct {
	before time.Time
	keep   int
}

// add stores a record of the kind kind, from the actor ActorSystem and now, and returns its id.
func (s *memStore) add(kind string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.records = append(s.records, Record{ID: s.next, Time: time.Unix(1760000000, 0).UTC(), Kind: kind, Actor: ActorSystem, Source: SourceLocal, Outcome: Success})
	return s.next
}

// put stores the target t, which was sent every record up to delivered.
func (s *memStore) put(t export.Target, delivered uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append(s.targets, export.Stored{Target: t, Delivered: delivered})
}

// deliveredTo returns the id of the last record that the target name was sent.
func (s *memStore) deliveredTo(name string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		if t.Name == name {
			return t.Delivered
		}
	}
	return 0
}

// all returns the records that are stored.
func (s *memStore) all() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records)
}

// pruned returns the calls of PruneAudit.
func (s *memStore) pruned() []prune {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.prunes)
}

func (s *memStore) AddAudit(_ context.Context, r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.next++
	r.ID = s.next
	s.records = append(s.records, r)
	return nil
}

func (s *memStore) Audit(_ context.Context, f Filter) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.failRead != nil {
		return nil, s.failRead
	}
	var out []Record
	for _, r := range s.records {
		if r.ID <= f.After || (f.Kind != "" && r.Kind != f.Kind) || (f.Actor != "" && r.Actor != f.Actor) ||
			(!f.Since.IsZero() && r.Time.Before(f.Since)) || (!f.Until.IsZero() && r.Time.After(f.Until)) {
			continue
		}
		if f.Limit > 0 && len(out) == f.Limit {
			break
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *memStore) PruneAudit(_ context.Context, before time.Time, keep int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.prunes = append(s.prunes, prune{before: before, keep: keep})
	var kept []Record
	for _, r := range s.records {
		if !r.Time.Before(before) {
			kept = append(kept, r)
		}
	}
	if keep > 0 && len(kept) > keep {
		kept = kept[len(kept)-keep:]
	}
	s.records = kept
	return nil
}

func (s *memStore) AuditRetention(context.Context) (Retention, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return Retention{}, false, s.err
	}
	if s.retention == nil {
		return Retention{}, false, nil
	}
	return *s.retention, true, nil
}

func (s *memStore) SetAuditRetention(_ context.Context, r Retention) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.retention = &r
	return nil
}

func (s *memStore) AuditTargets(context.Context) ([]export.Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.targets), nil
}

func (s *memStore) PutAuditTarget(_ context.Context, t export.Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	for i := range s.targets {
		if s.targets[i].Name == t.Name {
			s.targets[i].Target = t
			return nil
		}
	}
	s.targets = append(s.targets, export.Stored{Target: t, Delivered: s.next})
	return nil
}

func (s *memStore) DeleteAuditTarget(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.targets = slices.DeleteFunc(s.targets, func(t export.Stored) bool { return t.Name == name })
	return nil
}

func (s *memStore) AuditDelivered(_ context.Context, name string, id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.failDelivered != nil {
		return s.failDelivered
	}
	for i := range s.targets {
		if s.targets[i].Name == name && s.targets[i].Delivered < id {
			s.targets[i].Delivered = id
		}
	}
	return nil
}
