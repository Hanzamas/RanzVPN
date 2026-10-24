package mimic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"time"
)

// Between the two sidecars, the inner stream travels in frames, inside the TLS session that
// REALITY and uTLS made. A frame is a header of 4 bytes, the length of its payload and the length
// of its padding (2 bytes each, big-endian), then the payload, then the padding. The receiver gives
// the payload to the node and drops the padding. Both ends always frame; what they pad and when
// they send is the choice of each end for what it sends (Padding), and the other end needs to know
// nothing of it.
//
// A frame, header and padding included, is at most MaxFrame bytes: one TLS record, so what an
// observer of the TCP stream sees is the size of the frames the sidecar chose, not those of the
// writes of the node. The padding is zero: the TLS session encrypts it with the payload.

const (
	frameHeader = 4

	// MaxFrame is the size of the largest frame, which is the largest plaintext of one TLS record.
	MaxFrame = 16384
)

var errFrameTooLong = errors.New("a frame is longer than the protocol allows")

// The padding profiles. A profile is a set of Padding values that the settings can name; the
// explicit values of the settings come after it and win.
const (
	// ProfileOff sends each payload in frames of its own size, at once. The default.
	ProfileOff = "off"
	// ProfileSize pads each frame up to the next size of defaultSizes, so that the sizes of what an
	// observer sees are a few steps and no longer follow the writes of the node.
	ProfileSize = "size"
	// ProfileShape pads like ProfileSize and spaces the frames at least shapeMinGap apart, plus a
	// random part of up to shapeJitter, so that the rhythm of the stream is not that of its
	// writes. The spacing limits the rate to about MaxFrame in 3 ms, 40 Mbit/s: the profile is for
	// the links that need to look like web traffic more than they need to be fast.
	ProfileShape = "shape"
)

var defaultSizes = []int{256, 512, 1024, 2048, 4096, 8192, MaxFrame}

const (
	shapeMinGap = 1 * time.Millisecond
	shapeJitter = 4 * time.Millisecond

	maxSizes   = 16
	minLargest = 64
	maxGapMs   = 5000
)

// Padding is what a sidecar does to the frames it sends: their sizes and their timing.
type Padding struct {
	// Profile is ProfileOff (the default), ProfileSize or ProfileShape.
	Profile string `json:"profile,omitempty"`
	// Sizes are the sizes that a frame is padded up to, in bytes, ascending, each from 5 to MaxFrame;
	// a payload that does not fit the largest one goes in more frames. They replace the sizes of the
	// profile.
	Sizes []int `json:"sizes,omitempty"`
	// MinGapMs is the least time between two frames, in ms, and JitterMs the most that a random part
	// adds to it. They replace those of the profile.
	MinGapMs int `json:"min_gap_ms,omitempty"`
	JitterMs int `json:"jitter_ms,omitempty"`
}

// shape is Padding, checked.
type shape struct {
	sizes  []int         // the sizes of the frames, ascending; none: a frame is as large as its payload
	minGap time.Duration // the least time between two frames
	jitter time.Duration // the most that a random part adds to it
}

// resolve checks the padding and gives its shape.
func (p Padding) resolve() (shape, error) {
	var s shape
	switch p.Profile {
	case "", ProfileOff:
	case ProfileSize:
		s.sizes = defaultSizes
	case ProfileShape:
		s.sizes = defaultSizes
		s.minGap, s.jitter = shapeMinGap, shapeJitter
	default:
		return s, fmt.Errorf("profile %q is none of %q, %q and %q", p.Profile, ProfileOff, ProfileSize, ProfileShape)
	}

	if len(p.Sizes) != 0 {
		if len(p.Sizes) > maxSizes {
			return s, fmt.Errorf("%d sizes, at most %d", len(p.Sizes), maxSizes)
		}
		prev := frameHeader
		for _, n := range p.Sizes {
			if n <= prev || n > MaxFrame {
				return s, fmt.Errorf("size %d is not above the one before it (and the header of %d bytes) and at most %d", n, frameHeader, MaxFrame)
			}
			prev = n
		}
		if p.Sizes[len(p.Sizes)-1] < minLargest {
			return s, fmt.Errorf("the largest size is %d, at least %d are needed", p.Sizes[len(p.Sizes)-1], minLargest)
		}
		s.sizes = append([]int(nil), p.Sizes...)
	}

	for _, g := range []struct {
		name string
		ms   int
		to   *time.Duration
	}{{"min_gap_ms", p.MinGapMs, &s.minGap}, {"jitter_ms", p.JitterMs, &s.jitter}} {
		if g.ms < 0 || g.ms > maxGapMs {
			return s, fmt.Errorf("%s %d is not from 0 to %d", g.name, g.ms, maxGapMs)
		}
		if g.ms != 0 {
			*g.to = time.Duration(g.ms) * time.Millisecond
		}
	}
	return s, nil
}

// frameSize is the size of the frame that holds n bytes, header included: the next size of the
// shape that is at least n, or n.
func (s shape) frameSize(n int) int {
	for _, size := range s.sizes {
		if size >= n {
			return size
		}
	}
	return n
}

// maxPayload is the largest payload of one frame.
func (s shape) maxPayload() int {
	if n := len(s.sizes); n > 0 {
		return s.sizes[n-1] - frameHeader
	}
	return MaxFrame - frameHeader
}

// frameWriter writes the payloads it is given as frames. It serves one writer at a time.
type frameWriter struct {
	w     io.Writer
	shape shape
	last  time.Time // when the last frame was due
	buf   []byte
}

func newFrameWriter(w io.Writer, s shape) *frameWriter {
	return &frameWriter{w: w, shape: s, buf: make([]byte, MaxFrame)}
}

// Write cuts p into frames, pads each to a size of the shape and writes it to w, one write for
// each frame, at the pace of the shape. It returns the bytes of p that went out.
func (f *frameWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), f.shape.maxPayload())
		size := f.shape.frameSize(frameHeader + n)
		f.pace()

		frame := f.buf[:size]
		binary.BigEndian.PutUint16(frame[0:2], uint16(n))
		binary.BigEndian.PutUint16(frame[2:4], uint16(size-frameHeader-n))
		copy(frame[frameHeader:], p[:n])
		clear(frame[frameHeader+n:])
		if _, err := f.w.Write(frame); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// pace waits until the next frame may go: the gap after the frame before it, which is the least
// gap of the shape and a random part of up to its jitter.
func (f *frameWriter) pace() {
	if f.shape.minGap == 0 && f.shape.jitter == 0 {
		return
	}
	gap := f.shape.minGap
	if f.shape.jitter > 0 {
		gap += rand.N(f.shape.jitter)
	}
	if !f.last.IsZero() {
		if wait := time.Until(f.last.Add(gap)); wait > 0 {
			time.Sleep(wait)
		}
	}
	f.last = time.Now()
}

// frameReader reads the payloads of the frames of r as one stream.
type frameReader struct {
	r    io.Reader
	hdr  [frameHeader]byte
	left int // the payload bytes of the current frame that the caller did not take yet
	pad  int // the padding bytes that follow them
}

// Read gives payload bytes of the current frame, and the next frame once it is used up; the padding
// of a frame is read and dropped before the frame after it. io.EOF comes only between two frames:
// an end inside a frame is io.ErrUnexpectedEOF, and a frame longer than MaxFrame is an error.
func (f *frameReader) Read(p []byte) (int, error) {
	for f.left == 0 {
		if f.pad > 0 {
			if _, err := io.CopyN(io.Discard, f.r, int64(f.pad)); err != nil {
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			f.pad = 0
		}
		if _, err := io.ReadFull(f.r, f.hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(f.hdr[0:2]))
		pad := int(binary.BigEndian.Uint16(f.hdr[2:4]))
		if frameHeader+n+pad > MaxFrame {
			return 0, errFrameTooLong
		}
		f.left, f.pad = n, pad
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > f.left {
		p = p[:f.left]
	}
	n, err := f.r.Read(p)
	f.left -= n
	if f.left > 0 && errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// closeWriter is a connection that can end its writing side and go on reading.
type closeWriter interface {
	CloseWrite() error
}

// frameConn is the outer connection, the TLS session, with the frames on it: what the node writes
// goes out in frames and what it reads comes from the frames.
type frameConn struct {
	net.Conn
	r *frameReader
	w *frameWriter
}

func newFrameConn(c net.Conn, s shape) *frameConn {
	return &frameConn{Conn: c, r: &frameReader{r: c}, w: newFrameWriter(c, s)}
}

func (c *frameConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *frameConn) Write(p []byte) (int, error) {
	return c.w.Write(p)
}

// CloseWrite ends the writing side of the TLS session, which sends close_notify, when it can.
func (c *frameConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
