package event

import (
	"fmt"
	"testing"
	"time"
)

var epoch = time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)

// A key passes once in a window, no more than Limit keys pass in a window, and a refusal that
// does not pass is counted for the next one that does. A key that passed is held back for a
// window from its own pass, not from the start of the window of the others.
func TestThrottle(t *testing.T) {
	th := &Throttle{Window: time.Minute, Limit: 3}
	for _, c := range []struct {
		key     string
		second  int
		ok      bool
		skipped int
	}{
		{"a", 0, true, 0},
		{"a", 1, false, 0},
		{"a", 30, false, 0},
		{"b", 31, true, 2},
		{"c", 32, true, 0},
		{"d", 33, false, 0},
		{"a", 59, false, 0},
		{"d", 60, true, 2},
		{"a", 61, true, 0},
		{"b", 62, false, 0},
		{"b", 91, true, 1},
		{"e", 92, false, 0},
		{"e", 120, true, 1},
	} {
		skipped, ok := th.Take(c.key, epoch.Add(time.Duration(c.second)*time.Second))
		if ok != c.ok || skipped != c.skipped {
			t.Errorf("%q at %d s: passed %v after %d skipped, want %v after %d", c.key, c.second, ok, skipped, c.ok, c.skipped)
		}
	}
}

// The zero value passes DefaultThrottleLimit keys in a window of DefaultThrottleWindow, and its
// table holds the keys of two windows at most, however many keys are refused.
func TestThrottleDefaults(t *testing.T) {
	var th Throttle
	passed := 0
	for i := 0; i < 2*DefaultThrottleLimit; i++ {
		if _, ok := th.Take(fmt.Sprint(i), epoch); ok {
			passed++
		}
	}
	if passed != DefaultThrottleLimit {
		t.Errorf("%d keys passed in one window, want %d", passed, DefaultThrottleLimit)
	}
	if skipped, ok := th.Take("0", epoch.Add(DefaultThrottleWindow)); !ok || skipped != DefaultThrottleLimit {
		t.Errorf("after the window a key passed %v and reported %d skipped, want true and %d", ok, skipped, DefaultThrottleLimit)
	}

	for w := 2; w < 12; w++ {
		for i := 0; i < 100; i++ {
			th.Take(fmt.Sprintf("%d-%d", w, i), epoch.Add(time.Duration(w)*DefaultThrottleWindow))
		}
	}
	if n := len(th.last); n > 2*DefaultThrottleLimit {
		t.Errorf("the table holds %d keys, want %d at most", n, 2*DefaultThrottleLimit)
	}
}
