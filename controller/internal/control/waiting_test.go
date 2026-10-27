package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// textAddr is a network address that is no IP address, as the one of a pipe is.
type textAddr string

func (a textAddr) Network() string { return "test" }
func (a textAddr) String() string  { return string(a) }

// tcp returns the address of a TCP peer, "host:port" with the host an IP address.
func tcp(addr string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))
}

// idle checks that nothing waits in w.
func idle(t *testing.T, w *Waiting) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.total != 0 || len(w.bySource) != 0 {
		t.Errorf("%d streams wait for %d sources, want none", w.total, len(w.bySource))
	}
}

// At most a stated number of streams wait for a Hello, in all and for one source, and the next are
// refused and counted: the third criterion of #450.
func TestWaitingCaps(t *testing.T) {
	w := NewWaiting(5, 2)
	enter := func(remote string) func() {
		t.Helper()
		leave, err := w.Enter(tcp(remote))
		if err != nil {
			t.Fatalf("a stream from %s was refused: %v", remote, err)
		}
		return leave
	}
	var leaves []func()
	leaves = append(leaves, enter("192.0.2.1:1000"), enter("192.0.2.1:1001"))
	if _, err := w.Enter(tcp("192.0.2.1:1002")); !errors.Is(err, ErrWaitingSource) {
		t.Errorf("a third stream of one source: %v, want ErrWaitingSource", err)
	}
	leaves = append(leaves, enter("192.0.2.2:1000"), enter("192.0.2.2:1001"), enter("192.0.2.3:1000"))
	if _, err := w.Enter(tcp("192.0.2.4:1000")); !errors.Is(err, ErrWaitingFull) {
		t.Errorf("a sixth stream in all: %v, want ErrWaitingFull", err)
	}
	if full, source := w.Refused(); full != 1 || source != 1 {
		t.Errorf("the refusals are %d in all and %d for a source, want 1 and 1", full, source)
	}

	// A stream that leaves gives its place back, once however many times it calls
	leaves[0]()
	leaves[0]()
	leaves = append(leaves, enter("192.0.2.1:1003"))
	if _, err := w.Enter(tcp("192.0.2.1:1004")); !errors.Is(err, ErrWaitingFull) {
		t.Errorf("a stream that leaves twice gave back two places: %v, want ErrWaitingFull", err)
	}
	for _, leave := range leaves {
		leave()
	}
	idle(t, w)
}

// A stream is counted for its IPv4 address, or for the /64 of its IPv6 address, whatever its port and
// its zone, and a remote that is no IP address is one source of its own.
func TestWaitingSources(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"192.0.2.1:1", "192.0.2.1:2", true},
		{"192.0.2.1:1", "192.0.2.2:1", false},
		{"[::ffff:192.0.2.1]:1", "192.0.2.1:2", true},
		{"[2001:db8:1:2::1]:1", "[2001:db8:1:2:ffff::9]:2", true},
		{"[2001:db8:1:2::1]:1", "[2001:db8:1:3::1]:1", false},
		{"[fe80::1%eth0]:1", "[fe80::2%eth1]:1", true},
	} {
		if same := sourceOf(tcp(c.a)) == sourceOf(tcp(c.b)); same != c.same {
			t.Errorf("%s and %s are one source: %v, want %v", c.a, c.b, same, c.same)
		}
	}
	none := netip.Addr{}
	if sourceOf(textAddr("pipe")) != none || sourceOf(nil) != none || sourceOf(tcp("192.0.2.1:1")) == none {
		t.Error("a remote that is no IP address is not the source of its own")
	}

	w := NewWaiting(10, 1)
	leave, err := w.Enter(textAddr("pipe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Enter(textAddr("another pipe")); !errors.Is(err, ErrWaitingSource) {
		t.Errorf("a second stream of a remote that is no IP address: %v, want ErrWaitingSource", err)
	}
	leave()
	idle(t, w)
}

// The count holds when streams come and go on many goroutines.
func TestWaitingConcurrent(t *testing.T) {
	w := NewWaiting(MaxWaiting, MaxWaitingPerSource)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			remote := tcp(fmt.Sprintf("192.0.2.%d:1000", i+1))
			for j := 0; j < 200; j++ {
				leave, err := w.Enter(remote)
				if err != nil {
					t.Errorf("a stream was refused with 1 of %d waiting: %v", MaxWaitingPerSource, err)
					return
				}
				leave()
				leave()
			}
		}()
	}
	wg.Wait()
	idle(t, w)
	if full, source := w.Refused(); full != 0 || source != 0 {
		t.Errorf("the refusals are %d in all and %d for a source, want none", full, source)
	}
}
