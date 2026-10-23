package event

import (
	"sync"
	"time"
)

const (
	// DefaultThrottleWindow is how long a Throttle passes a key once, and the span in which it
	// passes DefaultThrottleLimit keys at most.
	DefaultThrottleWindow = time.Minute
	// DefaultThrottleLimit is the most keys that a Throttle passes in one window.
	DefaultThrottleLimit = 30
)

// Throttle decides for which of the refusals that a source restriction makes an event is
// recorded (SDN-39, #232). Each event is a write through the Raft log of the store, so a client
// that is refused again and again must not make one per refusal: the same key, the source address
// of the refusal, passes once in a window, and no more than Limit keys pass in a window. A refusal
// that does not pass is counted, and the next one that passes reports the count. The zero value is
// ready for use.
type Throttle struct {
	Window time.Duration // DefaultThrottleWindow when it is 0
	Limit  int           // DefaultThrottleLimit when it is 0

	mu      sync.Mutex
	start   time.Time            // the start of the window that count belongs to
	count   int                  // the keys passed since start
	last    map[string]time.Time // when each key passed last, for the keys of this window and the one before
	skipped int                  // the refusals that did not pass since the last one that did
}

// Take reports whether an event is recorded for a refusal of key at time now (ok), and how many
// refusals did not pass since the last one that did (skipped). A refusal that does not pass is
// counted for the next one that does.
func (t *Throttle) Take(key string, now time.Time) (skipped int, ok bool) {
	window, limit := t.Window, t.Limit
	if window == 0 {
		window = DefaultThrottleWindow
	}
	if limit == 0 {
		limit = DefaultThrottleLimit
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.start) >= window {
		t.start, t.count = now, 0
		for k, at := range t.last {
			if now.Sub(at) >= window {
				delete(t.last, k)
			}
		}
	}
	if at, seen := t.last[key]; (seen && now.Sub(at) < window) || t.count >= limit {
		t.skipped++
		return 0, false
	}
	if t.last == nil {
		t.last = map[string]time.Time{}
	}
	t.last[key] = now
	t.count++
	skipped, t.skipped = t.skipped, 0
	return skipped, true
}
