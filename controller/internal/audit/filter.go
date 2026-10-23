package audit

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// The page size of a listing of the audit log.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Filter says which records a listing of the audit log returns, oldest first: those that match
// every field that is set, at most Limit of them.
type Filter struct {
	// Kind is one of Kinds; all kinds when empty.
	Kind string
	// Actor is the exact actor, for example token:admin; all actors when empty.
	Actor string
	// Since and Until bound the time of the records, both inclusive, when they are not zero.
	Since time.Time
	Until time.Time
	// After is the id of the last record of the page before: only later records are returned.
	After uint64
	// Limit is how many records at most: DefaultLimit when it is 0 in a request, and it is at most
	// MaxLimit.
	Limit int
}

// ParseFilter returns the filter that the query of a call of the API asks for: kind, actor, since
// and until (a time in RFC 3339), after (a record id) and limit (1 to MaxLimit, DefaultLimit when
// it is left out). The error wraps ErrInvalid and names every parameter that is not valid.
func ParseFilter(q url.Values) (Filter, error) {
	f := Filter{Kind: q.Get("kind"), Actor: q.Get("actor"), Limit: DefaultLimit}
	var problems []error
	if f.Kind != "" && !slices.Contains(Kinds, f.Kind) {
		problems = append(problems, fmt.Errorf("the kind %q is none of %v", f.Kind, Kinds))
	}
	if len(f.Actor) > maxActor {
		problems = append(problems, fmt.Errorf("the actor is %d bytes, at most %d", len(f.Actor), maxActor))
	}
	for _, p := range []struct {
		name string
		to   *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		s := q.Get(p.name)
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, s)
		// A year that RFC 3339 has no four digits for, once the offset is applied, is no time of it
		if err != nil || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
			problems = append(problems, fmt.Errorf("%s %q is not a time in RFC 3339 (years 1 to 9999), for example 2026-10-23T08:00:00Z", p.name, s))
			continue
		}
		*p.to = t.UTC()
	}
	if s := q.Get("after"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			problems = append(problems, fmt.Errorf("after %q is not a record id", s))
		}
		f.After = n
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxLimit {
			problems = append(problems, fmt.Errorf("limit %q is not a number from 1 to %d", s, MaxLimit))
		} else {
			f.Limit = n
		}
	}
	if len(problems) > 0 {
		return Filter{}, fmt.Errorf("%w: %w", ErrInvalid, errors.Join(problems...))
	}
	return f, nil
}

// Query returns f as the query that ParseFilter reads: the parameters that f sets.
func (f Filter) Query() url.Values {
	q := url.Values{}
	if f.Kind != "" {
		q.Set("kind", f.Kind)
	}
	if f.Actor != "" {
		q.Set("actor", f.Actor)
	}
	if !f.Since.IsZero() {
		q.Set("since", f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		q.Set("until", f.Until.UTC().Format(time.RFC3339Nano))
	}
	if f.After != 0 {
		q.Set("after", strconv.FormatUint(f.After, 10))
	}
	if f.Limit != 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	return q
}
