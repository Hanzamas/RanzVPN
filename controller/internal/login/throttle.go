package login

import (
	"net/netip"
	"sync"
	"time"
)

// The throttle of failed logins (threat model G-5). A login with a wrong password costs the
// controller a derivation of 600000 iterations (internal/password), and a caller that guesses gets one
// guess for each. So a failure takes one try from the name that the login gave, whether a User has it
// or not, and one from the source it came from, and each name and each source gets one try back in
// each tryBack. A login for a name or from a source that has no try left is refused at once, without a
// check of the password, until a try is back; the refusal says how long to wait and is recorded in the
// audit log. The same throttle counts the user codes of the device page that no device waits with.

const (
	// tries is the number of failed logins in a row that one name or one source may make.
	tries = 5
	// tryBack is how long it takes for one try to come back.
	tryBack = time.Minute
	// maxKeys bounds the names and the sources that the throttle remembers.
	maxKeys = 8192
)

// limiter holds the tries that each name and each source used.
type limiter struct {
	mu   sync.Mutex
	keys map[string]bucket
}

// bucket is the tries that one key used, as of the instant at.
type bucket struct {
	used float64
	at   time.Time
}

func newLimiter() *limiter {
	return &limiter{keys: map[string]bucket{}}
}

// usedAt returns how many tries b has used at now, the ones that came back since b.at taken off.
func (b bucket) usedAt(now time.Time) float64 {
	return max(b.used-float64(now.Sub(b.at))/float64(tryBack), 0)
}

// wait returns how long a login with the keys has to wait from now: 0 when each key has a try left.
func (l *limiter) wait(now time.Time, keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	var longest time.Duration
	for _, k := range keys {
		b, ok := l.keys[k]
		if !ok {
			continue
		}
		if over := b.usedAt(now) - (tries - 1); over > 0 {
			longest = max(longest, time.Duration(over*float64(tryBack)))
		}
	}
	return longest
}

// fail takes one try from each of the keys at now. A key that the throttle cannot remember, because it
// remembers maxKeys that still miss a try, is not counted.
func (l *limiter) fail(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		b, ok := l.keys[k]
		if !ok && len(l.keys) >= maxKeys {
			l.forget(now)
			if len(l.keys) >= maxKeys {
				continue
			}
		}
		l.keys[k] = bucket{used: min(b.usedAt(now)+1, tries), at: now}
	}
}

// forget drops the keys whose tries all came back. l.mu is held.
func (l *limiter) forget(now time.Time) {
	for k, b := range l.keys {
		if b.usedAt(now) == 0 {
			delete(l.keys, k)
		}
	}
}

// nameKey returns the key of the throttle of the name that a login gave. A name that no User can have
// shares one key with every other such name, so that a caller cannot make the throttle remember as many
// names as it sends.
func nameKey(name string) string {
	if !nameRule.MatchString(name) {
		return "name ?"
	}
	return "name " + name
}

// sourceKey returns the key of the throttle of the address host that a login came from: the address,
// or the /64 of an IPv6 address, which one host may hold whole.
func sourceKey(host string) string {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return "source " + host
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return "source " + p.String()
		}
	}
	return "source " + a.String()
}
