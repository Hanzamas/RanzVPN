package throughput

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// The Ethernet frame that carries a TCP segment of a full payload, as vpncmd counted it: a payload
// of 1,460 bytes (the MSS of an MTU of 1,500) in a frame of 1,514 bytes.
const (
	ethernetFrame = 1514.0
	tcpPayload    = 1460.0
)

// Stream is what one direction of a test moved.
type Stream struct {
	// Connections is the number of connections that carried it.
	Connections int `json:"connections"`
	// Bytes is the bytes that its receivers counted, as Ethernet frames unless the test was raw.
	Bytes uint64 `json:"bytes"`
	// WindowSeconds is the time over which the rate is taken: from the first data that arrived
	// to the last.
	WindowSeconds float64 `json:"windowSeconds"`
	// Bps is the rate in bits per second: Bytes over the window, doubled for a doubled test.
	Bps uint64 `json:"bps"`
}

// finish turns the bytes that were counted into the figures of the stream: the bytes as Ethernet
// frames unless raw is set, and the rate over window.
func (s *Stream) finish(window time.Duration, raw, double bool) {
	if !raw {
		s.Bytes = uint64(float64(s.Bytes) * ethernetFrame / tcpPayload)
	}
	s.WindowSeconds = window.Seconds()
	if window > 0 {
		s.Bps = uint64(float64(s.Bytes) * 8 / window.Seconds())
		if double {
			s.Bps *= 2
		}
	}
}

// Result is what a test measured.
type Result struct {
	// Address is the server that the test ran against.
	Address string `json:"address"`
	// Raw and Double are the options of the same name.
	Raw    bool `json:"raw"`
	Double bool `json:"double"`
	// SpanSeconds is the span that the senders sent for.
	SpanSeconds float64 `json:"spanSeconds"`
	// Download is the data that came from the server, Upload the data that went to it.
	Download Stream `json:"download"`
	Upload   Stream `json:"upload"`
	// TotalBytes and TotalBps are the sums of the two directions.
	TotalBytes uint64 `json:"totalBytes"`
	TotalBps   uint64 `json:"totalBps"`
}

// summarize returns the result of a test from the outcomes of its connections. Each direction is
// the bytes of its receivers over one window: for a download, from the first data to arrive at the
// client on any connection to the last, on the clock of the client; for an upload, the longest
// time that the server counted on one of its connections, since the clock of the server is not
// the client's.
func summarize(address string, opts Options, outs []outcome) Result {
	res := Result{Address: address, Raw: opts.Raw, Double: opts.Double, SpanSeconds: opts.Span.Seconds()}
	var first, last time.Time
	var elapsed time.Duration
	for _, o := range outs {
		switch o.dir {
		case Download:
			res.Download.Connections++
			res.Download.Bytes += o.bytes
			if o.bytes > 0 {
				if first.IsZero() || o.first.Before(first) {
					first = o.first
				}
				if o.last.After(last) {
					last = o.last
				}
			}
		case Upload:
			res.Upload.Connections++
			res.Upload.Bytes += o.bytes
			elapsed = max(elapsed, o.elapsed)
		}
	}
	var window time.Duration
	if !first.IsZero() {
		window = last.Sub(first)
	}
	res.Download.finish(window, opts.Raw, opts.Double)
	res.Upload.finish(elapsed, opts.Raw, opts.Double)
	res.TotalBytes = res.Download.Bytes + res.Upload.Bytes
	res.TotalBps = res.Download.Bps + res.Upload.Bps
	return res
}

// String returns the result as the text that `ranz test throughput` prints.
func (r Result) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Throughput test to %s\n", r.Address)
	fmt.Fprintf(&b, "  Time span                %s\n", time.Duration(r.SpanSeconds*float64(time.Second)))
	fmt.Fprintf(&b, "  Ethernet headers counted %s\n", yesNo(!r.Raw))
	fmt.Fprintf(&b, "  Rates doubled            %s\n\n", yesNo(r.Double))
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\tConnections\tBytes\tRate\t")
	for _, row := range []struct {
		name string
		s    Stream
	}{{"Download", r.Download}, {"Upload", r.Upload}} {
		fmt.Fprintf(w, "  %s\t%d\t%s bytes\t%s\t\n", row.name, row.s.Connections, grouped(row.s.Bytes), rate(row.s.Bps))
	}
	fmt.Fprintf(w, "  Total\t%d\t%s bytes\t%s\t\n", r.Download.Connections+r.Upload.Connections, grouped(r.TotalBytes), rate(r.TotalBps))
	w.Flush()
	return b.String()
}

// yesNo returns "yes" or "no".
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// grouped returns n with its digits in groups of three: 1,234,567.
func grouped(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// rate returns a rate in bits per second with its unit: 1.23 Gbps.
func rate(bps uint64) string {
	v := float64(bps)
	for _, unit := range []string{"bps", "Kbps", "Mbps", "Gbps"} {
		if v < 1000 {
			return fmt.Sprintf("%.2f %s", v, unit)
		}
		v /= 1000
	}
	return fmt.Sprintf("%.2f Tbps", v)
}
