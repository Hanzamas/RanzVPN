package mimic

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
)

// drainTimeout is how long a stream waits for its other direction once one direction ended, so that
// the last bytes that the other end sends reach the node before the stream closes.
const drainTimeout = 5 * time.Second

// pump copies between the pipe of the node and the outer connection until both directions ended, or
// until the second one did not end within drainTimeout of the first, or until stop is closed; then it
// closes both. The end of one direction is passed on as far as the connection can: the end of what the
// node writes becomes the close_notify of the TLS session, so the other end reads what is left and
// then the end.
func pump(pipe, outer net.Conn, stop <-chan struct{}) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(outer, pipe)
		if cw, ok := outer.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(pipe, outer)
		// The pipe has no half close: when the other end is done, so is the stream
		pipe.Close()
		done <- struct{}{}
	}()

	ended := 0
	var timer *time.Timer
	var drain <-chan time.Time
wait:
	for ended < 2 {
		select {
		case <-done:
			ended++
			// The wait for the second direction starts with the end of the first
			if ended == 1 {
				timer = time.NewTimer(drainTimeout)
				drain = timer.C
			}
		case <-drain:
			break wait
		case <-stop:
			break wait
		}
	}
	if timer != nil {
		timer.Stop()
	}
	pipe.Close()
	outer.Close()
	// Both directions end now that their connections are closed
	for ; ended < 2; ended++ {
		<-done
	}
}

// readLine reads one line of at most max bytes from r, a byte at a time so that it never reads past
// the end of the line, and returns it without its newline.
func readLine(r io.Reader, max int) (string, error) {
	var line []byte
	var b [1]byte
	for len(line) <= max {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
	return "", errors.New("the line is longer than the protocol allows")
}

// oneLine makes the text of an error fit the one line that tells it to the node.
func oneLine(err error) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// tracker keeps the connections that a role has open, so that the end of the role closes them.
type tracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (t *tracker) add(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns == nil {
		t.conns = map[net.Conn]struct{}{}
	}
	t.conns[c] = struct{}{}
}

func (t *tracker) remove(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, c)
}

func (t *tracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c := range t.conns {
		c.Close()
	}
}
