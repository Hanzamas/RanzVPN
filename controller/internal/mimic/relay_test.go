package mimic

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// The relay between the pipe of the node and the outer connection, with no TLS in between: what the
// node writes comes out of the outer connection in frames, what the other end sends in frames comes
// out of the pipe, and the stream ends when both ends are done.
func TestPumpCarriesBothDirectionsAndEnds(t *testing.T) {
	node, pipe := net.Pipe()
	peer, outer := net.Pipe()
	defer node.Close()
	defer peer.Close()

	ended := make(chan struct{})
	go func() {
		pump(slog.New(slog.DiscardHandler), pipe, newFrameConn(outer, shape{}), make(chan struct{}))
		close(ended)
	}()

	// What the node writes is read by the other end as frames
	go node.Write([]byte("from the node"))
	peer.SetReadDeadline(time.Now().Add(testTimeout))
	got := make([]byte, len("from the node"))
	if _, err := io.ReadFull(&frameReader{r: peer}, got); err != nil || string(got) != "from the node" {
		t.Fatalf("the other end read %q, %v", got, err)
	}

	// What the other end writes in frames is read by the node as bytes
	go newFrameWriter(peer, shape{}).Write([]byte("from the peer"))
	node.SetReadDeadline(time.Now().Add(testTimeout))
	got = make([]byte, len("from the peer"))
	if _, err := io.ReadFull(node, got); err != nil || string(got) != "from the peer" {
		t.Fatalf("the node read %q, %v", got, err)
	}

	// Both ends are done: the stream ends
	node.Close()
	peer.Close()
	select {
	case <-ended:
	case <-time.After(testTimeout):
		t.Fatal("the stream did not end when both ends were done")
	}
}
