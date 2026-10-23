package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// DefaultPrune is how often the leader removes the records past the retention policy.
const DefaultPrune = time.Hour

// The bounds of a retention policy.
const (
	minDays    = 1
	maxDays    = 3650
	minRecords = 1000
	maxRecords = 100_000_000
)

// Retention is how long the audit log keeps its records (SDN-49 #242): a record is removed once it
// is older than Days days, and the oldest records are removed when the log holds more than
// MaxRecords. The limit on the number of records is what keeps a flood of failed authentications
// from filling the disk. An operator sets it through the API; until then DefaultRetention is in force.
type Retention struct {
	Days       int `json:"days"`
	MaxRecords int `json:"maxRecords"`
}

// DefaultRetention is the retention policy of a controller that none was set for: a year, and two
// million records.
var DefaultRetention = Retention{Days: 365, MaxRecords: 2_000_000}

// Validate checks r. The error wraps ErrInvalid and names every problem.
func (r Retention) Validate() error {
	var problems []error
	if r.Days < minDays || r.Days > maxDays {
		problems = append(problems, fmt.Errorf("days is %d, and must be from %d to %d", r.Days, minDays, maxDays))
	}
	if r.MaxRecords < minRecords || r.MaxRecords > maxRecords {
		problems = append(problems, fmt.Errorf("maxRecords is %d, and must be from %d to %d", r.MaxRecords, minRecords, maxRecords))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(problems...))
	}
	return nil
}

// Prune removes the records of s that are past its retention policy as of now: the older ones, and
// the oldest of any beyond the maximum number.
func Prune(ctx context.Context, s Store, now time.Time) error {
	r, ok, err := s.AuditRetention(ctx)
	if err != nil {
		return err
	}
	if !ok {
		r = DefaultRetention
	}
	return s.PruneAudit(ctx, now.Add(-time.Duration(r.Days)*24*time.Hour), r.MaxRecords)
}

// Retain runs Prune on s once and then every `every` until ctx ends. A failure is logged to log, and
// the next round tries again.
func Retain(ctx context.Context, s Store, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, storeTimeout)
		err := Prune(pctx, s, time.Now())
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Warn("audit log: removing the records past their retention failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
