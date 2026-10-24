package mimic

import (
	"net"
	"slices"
	"testing"
	"time"
)

// Traffic-shape padding (ADR-0023): what an observer of the TCP connection sees, the size of each TLS
// record that carries the inner stream and the time between them, is what the link chose, and not
// what the writes of the node were.

// recordOverhead is what a TLS 1.3 record adds to a frame: the header of 5 bytes, the inner content
// type of 1 and the 16 bytes that the AEAD adds.
const recordOverhead = 5 + 1 + 16

// applicationRecords are the writes that the tap saw after the first n, which are the records that
// carry the stream: the handshake is over by then.
func applicationRecords(t *testing.T, tp *tap, n int) []tapWrite {
	t.Helper()
	all := tp.all()
	if len(all) < n {
		t.Fatalf("the tap saw %d writes, fewer than the %d of the handshake", len(all), n)
	}
	return all[n:]
}

func TestPaddingShapesTheSizeAndTheTimingOnTheWire(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})

	dial := func(padding Padding) (*tap, net.Conn, net.Conn) {
		t.Helper()
		taps := make(chan *tap, 4)
		link := linkTo(srv.ready.Listen, public)
		link.Padding = padding
		_, pipe := runClient(t, Options{dialOuter: tapDialer(taps)}, link)
		conn, _, err := dialLink(pipe, srv.ready.Listen)
		if err != nil {
			t.Fatal(err)
		}
		st := data.next(t)
		t.Cleanup(func() {
			conn.Close()
			st.conn.Close()
		})
		return <-taps, conn, st.conn
	}

	// With the sizes of the link and a gap between the frames, every record is one of the sizes and no
	// two come closer than the gap
	const gap = 20 * time.Millisecond
	sizes := []int{300, 1200}
	tp, conn, node := dial(Padding{Sizes: sizes, MinGapMs: int(gap / time.Millisecond)})
	handshake := len(tp.all())
	exchange(t, conn, node, 5000)
	records := applicationRecords(t, tp, handshake)
	if len(records) < 4 {
		t.Fatalf("5000 bytes went out in %d records, want at least 4 of at most %d bytes", len(records), sizes[1])
	}
	for i, r := range records {
		if r.data[0] != 0x17 {
			t.Errorf("record %d is of the type %d, not application data", i, r.data[0])
		}
		if size := len(r.data) - recordOverhead; !slices.Contains(sizes, size) {
			t.Errorf("record %d carries a frame of %d bytes, which is none of %v", i, size, sizes)
		}
		// The clocks of two goroutines and the cost of one write are a few milliseconds at most
		if i > 0 {
			if d := r.at.Sub(records[i-1].at); d < gap-5*time.Millisecond {
				t.Errorf("record %d came %v after the one before it, want %v at least", i, d, gap)
			}
		}
	}

	// Without padding the same stream goes out in frames of the sizes of the writes of the node
	tp, conn, node = dial(Padding{})
	handshake = len(tp.all())
	exchange(t, conn, node, 5000)
	plain := applicationRecords(t, tp, handshake)
	if len(plain) == 0 {
		t.Fatal("the stream went out in no record")
	}
	shaped := true
	for _, r := range plain {
		shaped = shaped && slices.Contains(sizes, len(r.data)-recordOverhead)
	}
	if shaped {
		t.Errorf("a link without padding sent frames of the sizes %v only", sizes)
	}
}

// The server shapes what it sends to its clients with its own settings, and the client reads the
// frames whatever the padding of the other end was.
func TestServerPaddingCarriesTheStream(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	s := borrowSettings(private, site.addr)
	s.Padding = Padding{Profile: ProfileShape}
	srv, data := runServer(t, s, Options{skipDetect: true})
	link := linkTo(srv.ready.Listen, public)
	link.Padding = Padding{Profile: ProfileSize}
	_, pipe := runClient(t, Options{}, link)

	conn, _, err := dialLink(pipe, srv.ready.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	exchange(t, conn, st.conn, 100000)
	exchange(t, st.conn, conn, 100000)
}
