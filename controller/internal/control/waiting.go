package control

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// The cap on the streams that wait for a Hello (CS-4 of docs/threat-model.md, AUD1-DT-2 #450). A
// stream waits from the moment that the controller takes its TLS connection until its Hello is read:
// the Noise handshake and the Hello, which have 10 s each at most. It holds a goroutine, a TLS
// connection and what its peer sent, and the controller knows no node by it yet, so no key and no
// token stand behind it. At most MaxWaiting streams wait at once, and MaxWaitingPerSource for one
// source: an IPv4 address, or the /64 that an IPv6 address is in. The next stream is closed at once and
// counted (Waiting.Refused). A node sends its Hello within a round trip of its handshake, so a site
// with many nodes behind one address meets the caps only when a great many of them connect in the same
// moment, and a node that was closed tries again.
const (
	// MaxWaiting is the most streams that wait for a Hello at once, in all.
	MaxWaiting = 1024
	// MaxWaitingPerSource is the most that wait at once for one source.
	MaxWaitingPerSource = 64
)

var (
	// ErrWaitingFull is why Enter refuses a stream when the most that may wait in all wait already.
	ErrWaitingFull = errors.New("control: too many streams wait for a Hello")
	// ErrWaitingSource is why Enter refuses a stream when the most that may wait for its source wait
	// already.
	ErrWaitingSource = errors.New("control: too many streams of one source wait for a Hello")
)

// Waiting counts the streams of a controller that wait for a Hello, and refuses the ones that are over
// the caps. It is safe for concurrent use.
type Waiting struct {
	limit     int
	perSource int

	mu            sync.Mutex
	total         int
	bySource      map[netip.Addr]int
	refusedFull   uint64
	refusedSource uint64
}

// NewWaiting returns a Waiting that lets limit streams wait in all and perSource for one source.
func NewWaiting(limit, perSource int) *Waiting {
	return &Waiting{limit: limit, perSource: perSource, bySource: map[netip.Addr]int{}}
}

// Enter counts a stream from remote that waits for its Hello. It returns the function that the stream
// calls once its Hello is read, or once it ends, whichever comes first; a call after the first does
// nothing. When too many wait already it counts the stream as refused and returns ErrWaitingFull, or
// ErrWaitingSource when the cap of its source is the one that is met: the caller closes the stream.
func (w *Waiting) Enter(remote net.Addr) (leave func(), err error) {
	src := sourceOf(remote)
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.total >= w.limit:
		w.refusedFull++
		return nil, ErrWaitingFull
	case w.bySource[src] >= w.perSource:
		w.refusedSource++
		return nil, ErrWaitingSource
	}
	w.total++
	w.bySource[src]++
	return sync.OnceFunc(func() { w.release(src) }), nil
}

// release takes back the place that Enter gave to a stream of the source src.
func (w *Waiting) release(src netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total--
	if n := w.bySource[src] - 1; n > 0 {
		w.bySource[src] = n
	} else {
		delete(w.bySource, src)
	}
}

// Refused returns how many streams Enter refused since the start: for the cap in all, and for the cap
// of one source.
func (w *Waiting) Refused() (full, source uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.refusedFull, w.refusedSource
}

// SourceOf is sourceOf for the other limits of the TLS port that count a source the same way (internal/port,
// AUD1-DT-3 #451).
func SourceOf(remote net.Addr) netip.Addr {
	return sourceOf(remote)
}

// sourceOf returns the source that a stream from remote counts for: its IPv4 address, or the /64 of its
// IPv6 address, which any address of the /64 stands for. A remote that is no IP address has the invalid
// address, a source of its own.
func sourceOf(remote net.Addr) netip.Addr {
	if remote == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}
	}
	a := ap.Addr().Unmap().WithZone("")
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return a
}
