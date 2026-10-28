package rbac

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Tests of the life of a token (AUD1-DT-13, #461): its expiry and its last use. A clock that a test
// moves stands in for the time, so that nothing waits.

// clock is a time that a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock returns a clock at a whole second, which is how the store keeps a time.
func newClock() *clock {
	return &clock{now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// find returns the token name of the list of tokens, and fails when it is not there.
func find(t *testing.T, tokens *Tokens, name string) Token {
	t.Helper()
	ts, err := tokens.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range ts {
		if tok.Name == name {
			return tok
		}
	}
	t.Fatalf("the list of tokens has no %q: %+v", name, ts)
	return Token{}
}

// A token with an expiry works until then and is refused from then on, with an error that is an
// ErrUnauthenticated too; the list shows it as expired, and an admin deletes it. A token with no
// expiry never expires.
func TestAnExpiredTokenIsRefusedAndStaysListedAndDeletable(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)

	expires := clk.Now().Add(time.Hour)
	ci, err := tokens.CreateExpiring(ctx, "ci", Operator, expires)
	if err != nil {
		t.Fatal(err)
	}
	forever, err := tokens.Create(ctx, "forever", Viewer)
	if err != nil {
		t.Fatal(err)
	}
	if !ci.Expires.Equal(expires) || ci.Expired || !forever.Expires.IsZero() {
		t.Errorf("the created tokens are %+v and %+v, want the first to expire at %v and the second never", ci.Token, forever.Token, expires)
	}

	clk.Advance(time.Hour - time.Second)
	got, err := tokens.Authenticate(ctx, ci.Secret)
	if err != nil || got.Name != "ci" || got.Role != Operator || got.Expired || !got.Expires.Equal(expires) {
		t.Fatalf("a second before its expiry the token authenticates as %+v, %v", got, err)
	}
	if listed := find(t, tokens, "ci"); listed.Expired || !listed.Expires.Equal(expires) {
		t.Errorf("a second before its expiry the list has %+v", listed)
	}

	// From the instant of the expiry on
	clk.Advance(time.Second)
	got, err = tokens.Authenticate(ctx, ci.Secret)
	if !errors.Is(err, ErrExpired) || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("at its expiry the token authenticates with %v, want ErrExpired, which is an ErrUnauthenticated", err)
	}
	if got.Name != "ci" || !got.Expired || !got.Expires.Equal(expires) {
		t.Errorf("the refusal names the token %+v, want ci with its expiry and Expired", got)
	}
	if listed := find(t, tokens, "ci"); !listed.Expired || !listed.Expires.Equal(expires) || listed.Role != Operator {
		t.Errorf("the list shows the expired token as %+v, want it expired and with its role", listed)
	}

	// A century later the token with no expiry works
	clk.Advance(100 * 365 * 24 * time.Hour)
	if got, err := tokens.Authenticate(ctx, forever.Secret); err != nil || got.Expired || !got.Expires.IsZero() {
		t.Errorf("a token with no expiry a century later authenticates as %+v, %v", got, err)
	}

	// An admin deletes the expired token; it is then an unknown secret, not an expired one
	gone, err := tokens.Delete(ctx, "ci")
	if err != nil || gone.Name != "ci" || !gone.Expired {
		t.Fatalf("deleting the expired token gave %+v, %v", gone, err)
	}
	if _, err := tokens.Authenticate(ctx, ci.Secret); !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrExpired) {
		t.Errorf("the deleted token authenticates with %v, want ErrUnauthenticated and not ErrExpired", err)
	}
	if _, err := tokens.Delete(ctx, "ci"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting it again gave %v, want ErrNotFound", err)
	}
}

// An expiry is kept in UTC to the second, and is refused unless it is in the future and in the years
// of RFC 3339.
func TestAnExpiryIsChecked(t *testing.T) {
	ctx := context.Background()
	tokens := New(openStore(t)).WithClock(newClock().Now)
	now := newClock().Now()

	for name, expires := range map[string]time.Time{
		"now":             now,
		"the past":        now.Add(-time.Hour),
		"before 1 CE":     time.Date(0, 12, 31, 0, 0, 0, 0, time.UTC).Add(-time.Hour),
		"after year 9999": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if _, err := tokens.CreateExpiring(ctx, "late", Viewer, expires); !errors.Is(err, ErrInvalid) {
			t.Errorf("an expiry of %s gave %v, want ErrInvalid", name, err)
		}
	}
	if ts, err := tokens.List(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("the tokens that were refused left %+v, %v", ts, err)
	}

	// A time in another zone and with a fraction of a second is kept as UTC to the second
	zone := time.FixedZone("UTC+9", 9*3600)
	tok, err := tokens.CreateExpiring(ctx, "later", Viewer, time.Date(2026, 10, 27, 23, 0, 0, 999_000_000, zone))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC); !tok.Expires.Equal(want) || tok.Expires.Location() != time.UTC {
		t.Errorf("the expiry is %v, want %v in UTC", tok.Expires, want)
	}
	if listed := find(t, tokens, "later"); !listed.Expires.Equal(tok.Expires) {
		t.Errorf("the list has the expiry %v, want %v", listed.Expires, tok.Expires)
	}
	if _, err := tokens.CreateExpiring(ctx, "later", Viewer, now.Add(time.Hour)); !errors.Is(err, ErrExists) {
		t.Errorf("a second token of the name gave %v, want ErrExists", err)
	}
	if listed := find(t, tokens, "later"); !listed.Expires.Equal(tok.Expires) {
		t.Errorf("the refused token changed the expiry of the one that exists to %v", listed.Expires)
	}
}

// The last use of a token is stored at the first use and not again within UseInterval, however often
// the token is used and from whichever member; the next use after the interval moves it. A call that
// is refused is no use.
func TestTheLastUseIsStoredOnceInUseInterval(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)
	other := New(st).WithClock(clk.Now) // another member of a cluster, on the same store

	reader, err := tokens.Create(ctx, "reader", Viewer)
	if err != nil {
		t.Fatal(err)
	}
	if listed := find(t, tokens, "reader"); !listed.LastUsed.IsZero() {
		t.Fatalf("a token that was never used has the last use %v", listed.LastUsed)
	}
	if _, err := tokens.Authenticate(ctx, "ranz_NOTASECRETOFTHISCONTROLLER"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if listed := find(t, tokens, "reader"); !listed.LastUsed.IsZero() {
		t.Fatalf("a call with another secret gave the token the last use %v", listed.LastUsed)
	}

	first := clk.Now()
	if _, err := tokens.Authenticate(ctx, reader.Secret); err != nil {
		t.Fatal(err)
	}
	if listed := find(t, tokens, "reader"); !listed.LastUsed.Equal(first) {
		t.Fatalf("the first use is stored as %v, want %v", listed.LastUsed, first)
	}

	// Within the interval, from this member and from another, nothing moves
	for _, d := range []time.Duration{10 * time.Second, 20 * time.Second, 29 * time.Second} {
		clk.Advance(d)
		for _, m := range []*Tokens{tokens, other} {
			if _, err := m.Authenticate(ctx, reader.Secret); err != nil {
				t.Fatal(err)
			}
		}
		if listed := find(t, tokens, "reader"); !listed.LastUsed.Equal(first) {
			t.Fatalf("a use %v after the first moved the last use to %v, want it kept at %v", clk.Now().Sub(first), listed.LastUsed, first)
		}
	}

	// After the interval the next use is stored; the list is the same for every member
	clk.Advance(2 * time.Second)
	second := clk.Now()
	if second.Sub(first) < UseInterval {
		t.Fatalf("the test moved the clock %v, less than %v", second.Sub(first), UseInterval)
	}
	if _, err := other.Authenticate(ctx, reader.Secret); err != nil {
		t.Fatal(err)
	}
	if listed := find(t, tokens, "reader"); !listed.LastUsed.Equal(second) {
		t.Errorf("a use %v after the first is stored as %v, want %v", second.Sub(first), listed.LastUsed, second)
	}

	// The token that a call gets is the one that was stored before the call
	clk.Advance(UseInterval)
	got, err := tokens.Authenticate(ctx, reader.Secret)
	if err != nil || !got.LastUsed.Equal(second) {
		t.Errorf("the token of a call is %+v, %v, want the last use of before the call, %v", got, err, second)
	}
}

// The store keeps the use once in the interval by itself, whoever asks, and makes no row for a token
// that is gone.
func TestTouchTokenKeepsTheIntervalInTheStore(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)
	tok, err := tokens.Create(ctx, "reader", Viewer)
	if err != nil {
		t.Fatal(err)
	}
	h := hash(tok.Secret)
	t0 := clk.Now()

	for _, c := range []struct {
		after time.Duration
		want  time.Duration // the stored use, as an offset from t0
	}{
		{0, 0},
		{59 * time.Second, 0},
		{UseInterval, UseInterval},
		{UseInterval + time.Second, UseInterval},
		{2 * UseInterval, 2 * UseInterval},
	} {
		if err := st.TouchToken(ctx, h, t0.Add(c.after), UseInterval); err != nil {
			t.Fatal(err)
		}
		if got := find(t, tokens, "reader").LastUsed; !got.Equal(t0.Add(c.want)) {
			t.Errorf("a touch %v after the first stored the use %v after it, want %v", c.after, got.Sub(t0), c.want)
		}
	}

	if _, err := tokens.Delete(ctx, "reader"); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchToken(ctx, h, t0.Add(time.Hour), UseInterval); err != nil {
		t.Fatal(err)
	}
	// The name is free, and its new token has no life of the old one: no expiry and no use
	if _, err := tokens.Create(ctx, "reader", Viewer); err != nil {
		t.Fatal(err)
	}
	if listed := find(t, tokens, "reader"); !listed.Expires.IsZero() || !listed.LastUsed.IsZero() {
		t.Errorf("a token made again under the name has the life %+v of the one before", listed)
	}
}

// The life of a token goes with it: a token made again under the name of a deleted one has the
// expiry and the use of neither, and a refused delete of the last admin keeps what the token had.
func TestTheLifeOfATokenGoesWithIt(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)

	expires := clk.Now().Add(24 * time.Hour)
	root, err := tokens.CreateExpiring(ctx, "root", Admin, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Authenticate(ctx, root.Secret); err != nil {
		t.Fatal(err)
	}
	before := find(t, tokens, "root")
	if !before.Expires.Equal(expires) || !before.LastUsed.Equal(clk.Now()) {
		t.Fatalf("the token has %+v, want the expiry %v and the use %v", before, expires, clk.Now())
	}
	// It is the last admin token, so the delete is refused and its life stays
	if _, err := tokens.Delete(ctx, "root"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting the last admin token gave %v, want ErrLastAdmin", err)
	}
	if after := find(t, tokens, "root"); !after.Expires.Equal(expires) || !after.LastUsed.Equal(before.LastUsed) {
		t.Errorf("the refused delete changed the life of the token to %+v", after)
	}

	if _, err := tokens.Create(ctx, "spare", Admin); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Delete(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Create(ctx, "root", Viewer); err != nil {
		t.Fatal(err)
	}
	if again := find(t, tokens, "root"); !again.Expires.IsZero() || again.Expired || !again.LastUsed.IsZero() || again.Role != Viewer {
		t.Errorf("a token made again under the name has %+v, want no expiry and no use", again)
	}
}

// Tokens are used by many calls at once: the stored use is the same whoever won, and the race
// detector finds nothing.
func TestTokensAreUsedConcurrently(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	clk := newClock()
	tokens := New(st).WithClock(clk.Now)
	tok, err := tokens.Create(ctx, "busy", Operator)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if _, err := tokens.Authenticate(ctx, tok.Secret); err != nil {
					t.Error(err)
					return
				}
				_, _ = tokens.List(ctx)
			}
		}()
	}
	wg.Wait()
	if got := find(t, tokens, "busy").LastUsed; !got.Equal(clk.Now()) {
		t.Errorf("the last use is %v, want %v", got, clk.Now())
	}
}

// A member tries to store the use of a token once in UseInterval, and what it remembers of the
// tokens does not grow without end: the ones that are due again are forgotten.
func TestAMemberTriesOnceInUseIntervalAndForgets(t *testing.T) {
	tokens := New(nil)
	now := newClock().Now()
	if !tokens.attempt("a", now) || tokens.attempt("a", now.Add(UseInterval-time.Second)) || !tokens.attempt("a", now.Add(UseInterval)) {
		t.Error("a member did not try at the first use, and once in the interval after it")
	}
	if !tokens.attempt("b", now) {
		t.Error("a member did not try for another token")
	}
	for i := range maxUsed {
		tokens.used[fmt.Sprint("old-", i)] = now.Add(-time.Hour)
	}
	if !tokens.attempt("fresh", now) {
		t.Fatal("a member did not try for a token it never tried for")
	}
	if n := len(tokens.used); n != 3 {
		t.Errorf("%d tokens are remembered after the old ones were due again, want the 3 that were tried within the interval: %v", n, tokens.used)
	}
}
