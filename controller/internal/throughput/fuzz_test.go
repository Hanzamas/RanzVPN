package throughput

import (
	"bytes"
	"testing"
	"time"
)

// The fuzz tests of the throughput package (ADR-0040 item 1, .github/quality/fuzz-targets.txt),
// which the ranz workflow runs with go test -fuzz.

// FuzzRead reads the input as what a peer sends to a test server or to a test client: a request
// (ReadRequest), a report (ReadReport), and a stream of frames that arrives in pieces
// (Receiver.Input), the size of each piece one more than the second argument. What reads is within
// the limits of the protocol, and a receiver never counts more than it was given.
func FuzzRead(f *testing.F) {
	var request, report bytes.Buffer
	if err := (Request{Direction: Upload, Span: time.Second}).Write(&request); err != nil {
		f.Fatal(err)
	}
	if err := (Report{Bytes: 5, Elapsed: time.Second}).Write(&report); err != nil {
		f.Fatal(err)
	}
	f.Add(request.Bytes(), uint8(7))
	f.Add(report.Bytes(), uint8(1))
	f.Add(stream(10, 100), uint8(3))
	f.Add([]byte{0, 0, 0, 5, 1, 2}, uint8(2))
	f.Add([]byte{0, 1, 0, 1}, uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, piece uint8) {
		if req, err := ReadRequest(bytes.NewReader(data)); err == nil {
			if (req.Direction != Download && req.Direction != Upload) || req.Span <= 0 || req.Span > MaxSpan {
				t.Fatalf("ReadRequest read %+v", req)
			}
		}
		if rep, err := ReadReport(bytes.NewReader(data)); err == nil && rep.Elapsed < 0 {
			t.Fatalf("ReadReport read %+v", rep)
		}
		var r Receiver
		rest := data
		for len(rest) > 0 {
			n := min(int(piece)+1, len(rest))
			done, err := r.Input(rest[:n])
			rest = rest[n:]
			if err != nil {
				break
			}
			if done && len(rest) == 0 {
				break
			}
		}
		if r.Bytes() > uint64(len(data)) {
			t.Fatalf("a receiver counted %d bytes of %d", r.Bytes(), len(data))
		}
	})
}
