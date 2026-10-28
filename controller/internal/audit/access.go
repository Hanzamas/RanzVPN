package audit

import (
	"sync"
	"time"
)

// A read of the API tokens, the audit log or the licence is recorded as an Access (AUD1-DT-13, #461), so
// that the log says who looked at what a viewer is shown and an admin keeps secret from it. A read
// changes nothing and a caller can repeat it as often as it likes, so the Log records the reads of one
// token once a minute for each thing that it reads: the log shows that the token read it, and when
// it began, and a caller that polls cannot push the records of changes out of the retention policy.
const (
	// accessEvery is how long a read that was recorded stands for the same read by the same actor.
	accessEvery = time.Minute
	// maxAccess bounds the pairs of actor and action that an accessThrottle remembers.
	maxAccess = 4096
)

// accessThrottle remembers when each read was last recorded. Its zero value is ready for use.
type accessThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time // for each actor and action, when its last read was recorded
}

// allow reports whether the read action of actor at now is to be recorded, and remembers that it
// was. When the memory is full of reads that were recorded lately, a read of another pair is not.
func (t *accessThrottle) allow(actor, action string, now time.Time) bool {
	key := actor + "\x00" + action
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.last[key]; ok && now.Sub(last) < accessEvery {
		return false
	}
	if t.last == nil {
		t.last = map[string]time.Time{}
	}
	if len(t.last) >= maxAccess {
		for k, last := range t.last {
			if now.Sub(last) >= accessEvery {
				delete(t.last, k)
			}
		}
		if len(t.last) >= maxAccess {
			return false
		}
	}
	t.last[key] = now
	return true
}
