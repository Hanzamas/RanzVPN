package mimic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// The frames that carry the inner stream between the two sidecars, and the padding that shapes
// them: the sizes of what an observer of the TCP stream sees and the time between the frames.

// recorder keeps what is written to it, one entry for each Write and the time of each.
type recorder struct {
	writes [][]byte
	times  []time.Time
}

func (r *recorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	r.times = append(r.times, time.Now())
	return len(p), nil
}

func mustResolve(t *testing.T, p Padding) shape {
	t.Helper()
	s, err := p.resolve()
	if err != nil {
		t.Fatalf("%+v: %v", p, err)
	}
	return s
}

func TestFramesCarryTheStream(t *testing.T) {
	paddings := []Padding{
		{},
		{Profile: ProfileSize},
		{Profile: ProfileShape},
		{Sizes: []int{100, 5000}},
		{Sizes: []int{MaxFrame}},
	}
	for _, p := range paddings {
		var rec recorder
		fw := newFrameWriter(&rec, mustResolve(t, p))
		var want bytes.Buffer
		for _, n := range []int{1, 100, 4000, MaxFrame - frameHeader, MaxFrame - frameHeader + 1, 40000} {
			b := make([]byte, n)
			rand.Read(b)
			want.Write(b)
			if got, err := fw.Write(b); err != nil || got != n {
				t.Fatalf("%+v: Write of %d bytes returned %d, %v", p, n, got, err)
			}
		}

		var wire bytes.Buffer
		for _, w := range rec.writes {
			if len(w) > MaxFrame {
				t.Fatalf("%+v: a frame of %d bytes, more than %d", p, len(w), MaxFrame)
			}
			wire.Write(w)
		}
		got, err := io.ReadAll(&frameReader{r: &wire})
		if err != nil || !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%+v: %d bytes came out, %v, and not the %d that went in", p, len(got), err, want.Len())
		}
	}
}

// A reader that gets one byte at a time, and a caller that asks for one byte at a time, still see
// the stream: the frames do not depend on how the bytes arrive.
func TestFramesSurviveSmallReads(t *testing.T) {
	var rec recorder
	fw := newFrameWriter(&rec, mustResolve(t, Padding{Profile: ProfileSize}))
	data := make([]byte, 3000)
	rand.Read(data)
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	for _, w := range rec.writes {
		wire.Write(w)
	}
	got, err := io.ReadAll(iotest.OneByteReader(&frameReader{r: iotest.OneByteReader(&wire)}))
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("%d bytes came out, %v, and not the %d that went in", len(got), err, len(data))
	}
}

// With no padding a frame is as large as its payload and the header; with a profile or sizes, every
// frame is one of the sizes, whatever the writes of the node were.
func TestPaddingShapesTheSizesOfTheFrames(t *testing.T) {
	var rec recorder
	fw := newFrameWriter(&rec, mustResolve(t, Padding{}))
	for _, n := range []int{1, 100, 4000} {
		fw.Write(make([]byte, n))
	}
	for i, n := range []int{1, 100, 4000} {
		if len(rec.writes[i]) != frameHeader+n {
			t.Errorf("without padding, a write of %d bytes made a frame of %d bytes", n, len(rec.writes[i]))
		}
	}

	allowed := map[int]bool{}
	for _, size := range defaultSizes {
		allowed[size] = true
	}
	rec = recorder{}
	fw = newFrameWriter(&rec, mustResolve(t, Padding{Profile: ProfileSize}))
	for _, n := range []int{1, 100, 252, 253, 300, 5000, 17000, 70000} {
		fw.Write(make([]byte, n))
	}
	for _, w := range rec.writes {
		if !allowed[len(w)] {
			t.Errorf("a frame of %d bytes is none of the sizes of the profile", len(w))
		}
	}
	// 252 bytes and the header are 256 bytes: the first size, with no padding
	if got := len(rec.writes[2]); got != 256 {
		t.Errorf("a payload of 252 bytes made a frame of %d bytes, want 256", got)
	}
	if got := len(rec.writes[3]); got != 512 {
		t.Errorf("a payload of 253 bytes made a frame of %d bytes, want 512", got)
	}

	// The sizes of the settings replace those of the profile; a payload that does not fit the
	// largest goes in more frames
	rec = recorder{}
	fw = newFrameWriter(&rec, mustResolve(t, Padding{Profile: ProfileSize, Sizes: []int{100, 500}}))
	fw.Write(make([]byte, 1000))
	var sizes []int
	for _, w := range rec.writes {
		sizes = append(sizes, len(w))
	}
	if len(sizes) != 3 || sizes[0] != 500 || sizes[1] != 500 || sizes[2] != 100 {
		t.Errorf("1000 bytes went out in frames of %v, want 500, 500 and 100", sizes)
	}
}

func TestPaddingBytesAreZero(t *testing.T) {
	var rec recorder
	fw := newFrameWriter(&rec, mustResolve(t, Padding{Sizes: []int{300}}))
	fw.Write([]byte("hello"))
	frame := rec.writes[0]
	if len(frame) != 300 || string(frame[frameHeader:frameHeader+5]) != "hello" {
		t.Fatalf("the frame is %d bytes: %q", len(frame), frame[:16])
	}
	if !bytes.Equal(frame[frameHeader+5:], make([]byte, 300-frameHeader-5)) {
		t.Error("the padding of a frame is not zero")
	}
}

// The frames of a profile that spaces them are never closer than the least gap: the timing of the
// stream is not that of the writes of the node.
func TestPaddingSpacesTheFrames(t *testing.T) {
	const gap = 20 * time.Millisecond
	var rec recorder
	fw := newFrameWriter(&rec, mustResolve(t, Padding{Sizes: []int{512}, MinGapMs: int(gap / time.Millisecond)}))
	// One write that takes six frames
	if _, err := fw.Write(make([]byte, 6*(512-frameHeader))); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 6 {
		t.Fatalf("%d frames, want 6", len(rec.writes))
	}
	// The clocks of two goroutines and the cost of one Write are a few milliseconds at most
	for i := 1; i < len(rec.times); i++ {
		if d := rec.times[i].Sub(rec.times[i-1]); d < gap-5*time.Millisecond {
			t.Errorf("frame %d came %v after the one before it, want %v at least", i, d, gap)
		}
	}

	// A jitter lengthens the gaps and never shortens them
	rec = recorder{}
	fw = newFrameWriter(&rec, mustResolve(t, Padding{Sizes: []int{512}, MinGapMs: 10, JitterMs: 10}))
	if _, err := fw.Write(make([]byte, 5*(512-frameHeader))); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(rec.times); i++ {
		if d := rec.times[i].Sub(rec.times[i-1]); d < 10*time.Millisecond-5*time.Millisecond {
			t.Errorf("frame %d came %v after the one before it, want 10ms at least", i, d)
		}
	}
}

func TestFrameReaderRefuses(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"a frame that is too long", []byte{0x40, 0x00, 0x00, 0x00}, errFrameTooLong},
		{"a payload and padding that are too long together", []byte{0x20, 0x00, 0x20, 0x00}, errFrameTooLong},
		{"a header that is cut", []byte{0x00, 0x05}, io.ErrUnexpectedEOF},
		{"a payload that is cut", []byte{0x00, 0x0a, 0x00, 0x00, 'a', 'b', 'c'}, io.ErrUnexpectedEOF},
		{"padding that is cut", []byte{0x00, 0x01, 0x00, 0x05, 'a', 0, 0}, io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := io.ReadAll(&frameReader{r: bytes.NewReader(c.in)})
			if !errors.Is(err, c.want) {
				t.Errorf("reading %x: %v, want %v", c.in, err, c.want)
			}
		})
	}

	// The end of the stream between two frames is the end of the stream
	if got, err := io.ReadAll(&frameReader{r: bytes.NewReader(nil)}); err != nil || len(got) != 0 {
		t.Errorf("an empty stream: %q, %v", got, err)
	}
	// A frame with no payload is padding alone, and the stream goes on after it
	in := []byte{0x00, 0x00, 0x00, 0x03, 9, 9, 9, 0x00, 0x02, 0x00, 0x00, 'o', 'k'}
	if got, err := io.ReadAll(&frameReader{r: bytes.NewReader(in)}); err != nil || string(got) != "ok" {
		t.Errorf("a frame of padding alone and one of 2 bytes: %q, %v", got, err)
	}
	// A read of no bytes reads nothing
	fr := &frameReader{r: bytes.NewReader(in)}
	if n, err := fr.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = %d, %v", n, err)
	}
}

func TestPaddingRefuses(t *testing.T) {
	cases := []struct {
		name string
		p    Padding
		want string
	}{
		{"a profile that does not exist", Padding{Profile: "fast"}, "profile"},
		{"too many sizes", Padding{Sizes: make([]int, maxSizes+1)}, "at most 16"},
		{"sizes that fall", Padding{Sizes: []int{500, 100}}, "not above"},
		{"a size that is the header", Padding{Sizes: []int{frameHeader, 500}}, "not above"},
		{"a size above a TLS record", Padding{Sizes: []int{100, MaxFrame + 1}}, "at most"},
		{"sizes that are all small", Padding{Sizes: []int{10, 20}}, "at least 64"},
		{"a negative gap", Padding{MinGapMs: -1}, "min_gap_ms"},
		{"a gap of minutes", Padding{MinGapMs: maxGapMs + 1}, "min_gap_ms"},
		{"a negative jitter", Padding{JitterMs: -1}, "jitter_ms"},
		{"a jitter of minutes", Padding{JitterMs: maxGapMs + 1}, "jitter_ms"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.p.resolve(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("resolve = %v, want an error with %q", err, c.want)
			}
		})
	}
}

func TestPaddingProfiles(t *testing.T) {
	if s := mustResolve(t, Padding{Profile: ProfileOff}); len(s.sizes) != 0 || s.minGap != 0 || s.jitter != 0 {
		t.Errorf("the off profile is %+v", s)
	}
	if s := mustResolve(t, Padding{Profile: ProfileSize}); len(s.sizes) != len(defaultSizes) || s.minGap != 0 {
		t.Errorf("the size profile is %+v", s)
	}
	s := mustResolve(t, Padding{Profile: ProfileShape})
	if len(s.sizes) != len(defaultSizes) || s.minGap != shapeMinGap || s.jitter != shapeJitter {
		t.Errorf("the shape profile is %+v", s)
	}
	// What the settings name wins over the profile
	s = mustResolve(t, Padding{Profile: ProfileShape, MinGapMs: 7, Sizes: []int{200}})
	if len(s.sizes) != 1 || s.sizes[0] != 200 || s.minGap != 7*time.Millisecond || s.jitter != shapeJitter {
		t.Errorf("the shape profile with settings is %+v", s)
	}
	// The sizes of the profile are the sizes of a TLS record at most
	for _, size := range defaultSizes {
		if size > MaxFrame {
			t.Errorf("the size %d of the profile is more than a frame", size)
		}
	}
	if got := mustResolve(t, Padding{}).maxPayload(); got != MaxFrame-frameHeader {
		t.Errorf("without sizes a frame holds %d bytes of payload", got)
	}
}

// A frameConn frames what is written to it, reads the frames of what comes in, and ends its
// writing side when the connection can.
func TestFrameConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ca := newFrameConn(a, mustResolve(t, Padding{Profile: ProfileSize}))
	cb := newFrameConn(b, shape{})

	go func() {
		ca.Write([]byte("hello, frames"))
	}()
	got := make([]byte, len("hello, frames"))
	if _, err := io.ReadFull(cb, got); err != nil || string(got) != "hello, frames" {
		t.Errorf("read %q, %v", got, err)
	}
	// net.Pipe cannot end one direction: CloseWrite is nothing, not an error
	if err := ca.CloseWrite(); err != nil {
		t.Errorf("CloseWrite = %v", err)
	}
}
