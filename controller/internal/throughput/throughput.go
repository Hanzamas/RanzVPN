// Package throughput is the traffic test of ranz (SDN-53, #246): `ranz test throughput` measures
// the rate that two nodes reach over the overlay, as the commands TrafficServer and TrafficClient
// of vpncmd measured it between two computers. A server listens on one node. A client on another
// opens several TCP connections to it, which carry data in both directions or in one for a span of
// time, and the receiving end of each connection counts what arrives. The test runs on the TCP
// stack of the host, so between two nodes it measures the path that the traffic of a node takes:
// the overlay adapter, the data plane and the transport.
//
// One connection carries one stream. The server greets the client, the client says which way the
// data flows and for how long, and the sender sends frames, each a 4-byte big-endian length and
// that many bytes, until it has sent for the span; a frame of length zero ends the stream. For a
// download the client receives. For an upload the server receives, and it answers the end of the
// stream with a Report: the bytes that it received and the time they took. The rate of a stream is
// what its receiver counted over the time from its first data to its last, so the data that the
// buffers of the sender still hold when the span ends does not add to the rate.
package throughput

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"
)

const (
	// DefaultPort is the port of a test server whose address names none: the port of the
	// TrafficServer command of vpncmd.
	DefaultPort = 9821
	// DefaultConnections is the number of connections of a test that asks for none.
	DefaultConnections = 32
	// MaxConnections is the most connections that a test opens.
	MaxConnections = 32
	// DefaultSpan is the span of a test that asks for none.
	DefaultSpan = 15 * time.Second
	// MaxSpan is the longest span that a server serves.
	MaxSpan = 10 * time.Minute
	// MaxPayload is the largest payload of a frame.
	MaxPayload = 64 * 1024
	// Greeting is what the server sends first on each connection, so that a client that reached
	// another service finds out.
	Greeting = "RANZ-THROUGHPUT/1\n"
)

const (
	// frameHeader is the size of the length that starts a frame.
	frameHeader = 4
	// requestSize is the size of a request: the direction, three bytes that are zero and the span
	// in milliseconds.
	requestSize = 8
	// reportSize is the size of a report: the bytes and the nanoseconds.
	reportSize = 16
	// grace is how long a transfer may run past its span before the one that waits for it gives
	// up: the data that the buffers of a slow link still hold, and the connections that open late.
	grace = 30 * time.Second
	// setupTimeout bounds the greeting of a connection.
	setupTimeout = 10 * time.Second
)

// Direction is the way the data of a test flows, from the point of view of the client.
type Direction int

const (
	// Full carries data both ways: the connections alternate between download and upload.
	Full Direction = iota
	// Download carries data from the server to the client.
	Download
	// Upload carries data from the client to the server.
	Upload
)

// String returns the name of the direction as the command line gives it.
func (d Direction) String() string {
	switch d {
	case Full:
		return "full"
	case Download:
		return "download"
	case Upload:
		return "upload"
	}
	return fmt.Sprintf("Direction(%d)", int(d))
}

// Request is what the client says to the server after the greeting: which way the data of the
// connection flows, and for how long its sender sends.
type Request struct {
	Direction Direction
	Span      time.Duration
}

// Write writes the request, whose Direction is Download or Upload.
func (r Request) Write(w io.Writer) error {
	var b [requestSize]byte
	switch r.Direction {
	case Download:
		b[0] = 'D'
	case Upload:
		b[0] = 'U'
	default:
		return fmt.Errorf("throughput: a connection cannot carry the direction %v", r.Direction)
	}
	ms := r.Span.Milliseconds()
	if ms <= 0 || r.Span > MaxSpan {
		return fmt.Errorf("throughput: a span of %v is not between 1 ms and %v", r.Span, MaxSpan)
	}
	binary.BigEndian.PutUint32(b[4:], uint32(ms))
	_, err := w.Write(b[:])
	return err
}

// ReadRequest reads the request of a client: what a peer says is checked, and an error says what
// is wrong with it.
func ReadRequest(r io.Reader) (Request, error) {
	var b [requestSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Request{}, err
	}
	var req Request
	switch b[0] {
	case 'D':
		req.Direction = Download
	case 'U':
		req.Direction = Upload
	default:
		return Request{}, fmt.Errorf("throughput: the byte %#x of a request is no direction", b[0])
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return Request{}, errors.New("throughput: the reserved bytes of a request are not zero")
	}
	ms := binary.BigEndian.Uint32(b[4:])
	req.Span = time.Duration(ms) * time.Millisecond
	if ms == 0 || req.Span > MaxSpan {
		return Request{}, fmt.Errorf("throughput: a span of %d ms is not between 1 ms and %v", ms, MaxSpan)
	}
	return req, nil
}

// Report is what the server answers to the end of an upload: the bytes of payload that it received
// and the time from its first data to its last.
type Report struct {
	Bytes   uint64
	Elapsed time.Duration
}

// Write writes the report.
func (r Report) Write(w io.Writer) error {
	var b [reportSize]byte
	binary.BigEndian.PutUint64(b[:8], r.Bytes)
	binary.BigEndian.PutUint64(b[8:], uint64(max(r.Elapsed, 0)))
	_, err := w.Write(b[:])
	return err
}

// ReadReport reads the report of a server.
func ReadReport(r io.Reader) (Report, error) {
	var b [reportSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Report{}, err
	}
	ns := binary.BigEndian.Uint64(b[8:])
	if ns > math.MaxInt64 {
		return Report{}, fmt.Errorf("throughput: %d ns in a report is no time", ns)
	}
	return Report{Bytes: binary.BigEndian.Uint64(b[:8]), Elapsed: time.Duration(ns)}, nil
}

// Receiver counts the payload of the frames of a stream that arrives in pieces of any size. The
// zero value is ready for use.
type Receiver struct {
	header    [frameHeader]byte
	headerLen int
	remaining int
	bytes     uint64
	done      bool
}

// Input takes the next piece of the stream, and reports whether the stream has ended with its end
// frame. Data after the end frame, and a frame larger than MaxPayload, are errors.
func (r *Receiver) Input(p []byte) (bool, error) {
	for len(p) > 0 {
		if r.done {
			return true, errors.New("throughput: data after the end of the stream")
		}
		if r.remaining > 0 {
			n := min(len(p), r.remaining)
			r.remaining -= n
			r.bytes += uint64(n)
			p = p[n:]
			continue
		}
		n := copy(r.header[r.headerLen:], p)
		r.headerLen += n
		p = p[n:]
		if r.headerLen < frameHeader {
			continue
		}
		r.headerLen = 0
		size := binary.BigEndian.Uint32(r.header[:])
		if size > MaxPayload {
			return false, fmt.Errorf("throughput: a frame of %d bytes is larger than %d", size, MaxPayload)
		}
		if size == 0 {
			r.done = true
			continue
		}
		r.remaining = int(size)
	}
	return r.done, nil
}

// Bytes returns the bytes of payload counted so far.
func (r *Receiver) Bytes() uint64 {
	return r.bytes
}

// endFrame is the frame that ends a stream: a length of zero.
var endFrame [frameHeader]byte

// dataFrame returns the frame that senders send, MaxPayload bytes of random data, which they
// share: nothing writes to it. Random data does not shrink on a link that compresses.
var dataFrame = sync.OnceValue(func() []byte {
	b := make([]byte, frameHeader+MaxPayload)
	binary.BigEndian.PutUint32(b, MaxPayload)
	rand.Read(b[frameHeader:])
	return b
})

// stats is what the receiver of a stream saw: the bytes of payload, and when the first and the
// last of them arrived.
type stats struct {
	bytes       uint64
	first, last time.Time
}

// elapsed returns the time from the first data to the last.
func (s stats) elapsed() time.Duration {
	if s.bytes == 0 {
		return 0
	}
	return s.last.Sub(s.first)
}

// receive reads the stream on conn up to its end frame, for limit at most, and counts it.
func receive(conn net.Conn, limit time.Duration) (stats, error) {
	var (
		rcv Receiver
		st  stats
	)
	if err := conn.SetReadDeadline(time.Now().Add(limit)); err != nil {
		return st, err
	}
	buf := make([]byte, MaxPayload)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			now := time.Now()
			before := rcv.Bytes()
			done, ierr := rcv.Input(buf[:n])
			st.bytes = rcv.Bytes()
			if st.bytes > before {
				if before == 0 {
					st.first = now
				}
				st.last = now
			}
			if ierr != nil {
				return st, ierr
			}
			if done {
				return st, nil
			}
		}
		if err != nil {
			return st, fmt.Errorf("throughput: the stream ended early: %w", err)
		}
	}
}

// send writes frames of data to conn for span, and then the end frame.
func send(conn net.Conn, span time.Duration) error {
	end := time.Now().Add(span)
	if err := conn.SetWriteDeadline(end.Add(grace)); err != nil {
		return err
	}
	frame := dataFrame()
	for time.Now().Before(end) {
		if _, err := conn.Write(frame); err != nil {
			return err
		}
	}
	_, err := conn.Write(endFrame[:])
	return err
}
