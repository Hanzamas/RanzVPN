package audit

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseFilter(t *testing.T) {
	got, err := ParseFilter(url.Values{})
	if err != nil || got.Kind != "" || got.Actor != "" || !got.Since.IsZero() || !got.Until.IsZero() || got.After != 0 || got.Limit != DefaultLimit {
		t.Errorf("an empty query gives %+v, %v, want no condition and the default limit", got, err)
	}

	q, err := url.ParseQuery("kind=login&actor=token:admin&since=2026-10-23T08:00:00%2B07:00&until=2026-10-24T00:00:00.5Z&after=12&limit=5")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParseFilter(q)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != Login || got.Actor != "token:admin" || got.After != 12 || got.Limit != 5 ||
		!got.Since.Equal(time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)) || !got.Until.Equal(time.Date(2026, 10, 24, 0, 0, 0, 500_000_000, time.UTC)) {
		t.Errorf("the query gives %+v", got)
	}
}

func TestParseFilterNamesEveryProblem(t *testing.T) {
	for _, c := range []struct{ query, want string }{
		{"kind=reboot", `the kind "reboot" is none of`},
		{"actor=" + strings.Repeat("a", maxActor+1), "the actor is 129 bytes, at most 128"},
		{"since=yesterday", `since "yesterday" is not a time in RFC 3339`},
		{"until=2026-10-23", `until "2026-10-23" is not a time in RFC 3339`},
		{"after=-1", `after "-1" is not a record id`},
		{"after=x", `after "x" is not a record id`},
		{"limit=0", `limit "0" is not a number from 1 to 1000`},
		{"limit=1001", `limit "1001" is not a number from 1 to 1000`},
		{"limit=many", `limit "many" is not a number from 1 to 1000`},
	} {
		q, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseFilter(q); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one that wraps ErrInvalid and says %q", c.query, err, c.want)
		}
	}
	_, err := ParseFilter(url.Values{"kind": {"reboot"}, "limit": {"0"}, "after": {"x"}})
	if err == nil || !strings.Contains(err.Error(), "is none of") || !strings.Contains(err.Error(), "from 1 to 1000") || !strings.Contains(err.Error(), "record id") {
		t.Errorf("three bad parameters give %v, want all three named", err)
	}
}

func TestFilterQueryIsWhatParseFilterReads(t *testing.T) {
	f := Filter{Kind: AuthFailed, Actor: "unknown", Since: time.Date(2026, 10, 23, 1, 2, 3, 400_000_000, time.UTC),
		Until: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), After: 7, Limit: 50}
	got, err := ParseFilter(f.Query())
	if err != nil || got.Kind != f.Kind || got.Actor != f.Actor || !got.Since.Equal(f.Since) || !got.Until.Equal(f.Until) || got.After != f.After || got.Limit != f.Limit {
		t.Errorf("the query %v of %+v reads back as %+v, %v", f.Query(), f, got, err)
	}
	if q := (Filter{}).Query(); len(q) != 0 {
		t.Errorf("a filter with no condition has the query %v", q)
	}
}

// FuzzParseFilter checks that ParseFilter answers any query of a request with a filter that stays
// in its bounds and reads back from its own query, or with an error that wraps ErrInvalid.
func FuzzParseFilter(f *testing.F) {
	f.Add("kind=login&limit=5")
	f.Add("since=2026-10-23T08:00:00Z&until=2026-10-24T08:00:00.5%2B07:00&after=9")
	f.Add("kind=%ff&actor=%00&limit=-1")
	f.Add("after=18446744073709551615&limit=1000")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		got, err := ParseFilter(q)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%q: %v does not wrap ErrInvalid", raw, err)
			}
			return
		}
		if got.Limit < 1 || got.Limit > MaxLimit || (got.Kind != "" && !slices.Contains(Kinds, got.Kind)) || len(got.Actor) > maxActor {
			t.Fatalf("%q is accepted as the filter %+v, which is out of its bounds", raw, got)
		}
		again, err := ParseFilter(got.Query())
		if err != nil || again.Kind != got.Kind || again.Actor != got.Actor || again.After != got.After || again.Limit != got.Limit ||
			!again.Since.Equal(got.Since) || !again.Until.Equal(got.Until) {
			t.Fatalf("%q gives %+v, whose own query gives %+v, %v", raw, got, again, err)
		}
	})
}
