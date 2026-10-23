package telemetry

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// collected is an IPFIX message as a collector reads it (RFC 7011): the header, the templates of
// its template sets and the raw records of each data set, by template id.
type collected struct {
	version   uint16
	length    uint16
	exported  uint32
	sequence  uint32
	domain    uint32
	templates map[uint16][]field
	records   map[uint16][][]byte
}

// collect reads one IPFIX message, and fails the test when it is not well formed.
func collect(t *testing.T, b []byte) collected {
	t.Helper()
	if len(b) < ipfixHeaderSize {
		t.Fatalf("a message of %d bytes has no header", len(b))
	}
	c := collected{version: binary.BigEndian.Uint16(b[0:]), length: binary.BigEndian.Uint16(b[2:]), exported: binary.BigEndian.Uint32(b[4:]),
		sequence: binary.BigEndian.Uint32(b[8:]), domain: binary.BigEndian.Uint32(b[12:]), templates: map[uint16][]field{}, records: map[uint16][][]byte{}}
	if c.version != 10 || int(c.length) != len(b) {
		t.Fatalf("the header says version %d and length %d, and the message has %d bytes", c.version, c.length, len(b))
	}
	for off := ipfixHeaderSize; off < len(b); {
		if off+4 > len(b) {
			t.Fatalf("a set header at %d runs past the end of the message", off)
		}
		id, n := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+2:]))
		if n < 4 || n%4 != 0 || off+n > len(b) {
			t.Fatalf("the set %d at %d has the length %d in a message of %d bytes", id, off, n, len(b))
		}
		body := b[off+4 : off+n]
		off += n
		if id == 2 {
			for len(body) > 0 {
				tid, count := binary.BigEndian.Uint16(body[0:]), int(binary.BigEndian.Uint16(body[2:]))
				body = body[4:]
				var fields []field
				for range count {
					if binary.BigEndian.Uint16(body[0:])&0x8000 != 0 {
						t.Fatalf("the template %d has an enterprise field, which the controller does not send", tid)
					}
					fields = append(fields, field{element: binary.BigEndian.Uint16(body[0:]), length: binary.BigEndian.Uint16(body[2:])})
					body = body[4:]
				}
				c.templates[tid] = fields
			}
			continue
		}
		fields, ok := c.templates[id]
		if !ok {
			t.Fatalf("the data set %d comes before its template", id)
		}
		size := recordSize(fields)
		for len(body) >= size {
			c.records[id] = append(c.records[id], body[:size])
			body = body[size:]
		}
		if len(body) >= 4 {
			t.Fatalf("the data set %d has %d bytes that are no record and too many for padding", id, len(body))
		}
	}
	return c
}

// udpCollector is a UDP socket that an IPFIX exporter can send to.
type udpCollector struct {
	conn net.PacketConn
	addr string
}

func listenUDP(t *testing.T) *udpCollector {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return &udpCollector{conn: pc, addr: pc.LocalAddr().String()}
}

// read returns the next datagram within 5 s.
func (c *udpCollector) read(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 2048)
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func testFlow(i int) Flow {
	return Flow{VRF: 7, Src: netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}), Dst: netip.AddrFrom4([4]byte{100, 64, 0, 200}), Protocol: 6, SrcPort: uint16(40000 + i), DstPort: 443,
		Packets: uint64(10 + i), Bytes: uint64(1500 * (i + 1)), Start: time.UnixMilli(1760000000000 + int64(i)*1000).UTC(), End: time.UnixMilli(1760000000500 + int64(i)*1000).UTC()}
}

func TestIPFIXMessagesCarryTemplateAndRecords(t *testing.T) {
	now := time.Unix(1760000100, 0)
	flows := []Flow{testFlow(1), testFlow(2), testFlow(3)}
	v6 := Flow{VRF: 7, Src: netip.MustParseAddr("fd12::1"), Dst: netip.MustParseAddr("fd12::2"), Protocol: 17, SrcPort: 5353, DstPort: 5353, Packets: 2, Bytes: 180,
		Start: time.UnixMilli(1760000000000).UTC(), End: time.UnixMilli(1760000000100).UTC()}
	msgs := messages(0xDEADBEEF, 100, now, append(flows, v6))
	if len(msgs) != 2 || msgs[0].records != 3 || msgs[1].records != 1 {
		t.Fatalf("got %d messages %+v, want one of 3 records and one of 1", len(msgs), msgs)
	}

	c := collect(t, msgs[0].bytes)
	if c.exported != 1760000100 || c.sequence != 100 || c.domain != 0xDEADBEEF {
		t.Errorf("the first message has the export time %d, sequence %d and domain %x", c.exported, c.sequence, c.domain)
	}
	if got := c.templates[templateIPv4]; len(got) != 10 || got[0] != (field{152, 8}) || got[9] != (field{234, 4}) {
		t.Errorf("the template 256 is %+v", got)
	}
	recs := c.records[templateIPv4]
	if len(recs) != 3 {
		t.Fatalf("the data set holds %d records, want 3", len(recs))
	}
	r := recs[1]
	want := appendRecord(nil, flows[1])
	if len(r) != 49 || !bytes.Equal(r, want) {
		t.Fatalf("the second record is % x, want % x", r, want)
	}
	if binary.BigEndian.Uint64(r[0:]) != 1760000002000 || binary.BigEndian.Uint64(r[8:]) != 1760000002500 || !bytes.Equal(r[16:20], []byte{100, 64, 0, 2}) ||
		!bytes.Equal(r[20:24], []byte{100, 64, 0, 200}) || binary.BigEndian.Uint16(r[24:]) != 40002 || binary.BigEndian.Uint16(r[26:]) != 443 || r[28] != 6 ||
		binary.BigEndian.Uint64(r[29:]) != 12 || binary.BigEndian.Uint64(r[37:]) != 4500 || binary.BigEndian.Uint32(r[45:]) != 7 {
		t.Errorf("the second record does not carry its flow: % x", r)
	}

	// The next message continues the sequence: it counts the records sent before it
	c = collect(t, msgs[1].bytes)
	if c.sequence != 103 || len(c.templates[templateIPv6]) != 10 || c.templates[templateIPv6][2] != (field{27, 16}) {
		t.Errorf("the IPv6 message has the sequence %d and the template %+v", c.sequence, c.templates[templateIPv6])
	}
	if recs := c.records[templateIPv6]; len(recs) != 1 || len(recs[0]) != 73 || !bytes.Equal(recs[0][16:32], v6.Src.AsSlice()) {
		t.Errorf("the IPv6 data set holds %d records: % x", len(recs), recs)
	}
}

func TestIPFIXMessagesFitOneDatagram(t *testing.T) {
	var flows []Flow
	for i := range 60 {
		flows = append(flows, testFlow(i))
	}
	msgs := messages(1, 0, time.Unix(1760000100, 0), flows)
	var records, seq uint32
	for i, m := range msgs {
		if len(m.bytes) > maxMessage || len(m.bytes)%4 != 0 {
			t.Errorf("message %d has %d bytes, more than %d or no multiple of 4", i, len(m.bytes), maxMessage)
		}
		c := collect(t, m.bytes)
		if c.sequence != seq || len(c.records[templateIPv4]) != int(m.records) {
			t.Errorf("message %d has the sequence %d and %d records, want %d and %d", i, c.sequence, len(c.records[templateIPv4]), seq, m.records)
		}
		seq += m.records
		records += m.records
	}
	if len(msgs) != 3 || records != 60 {
		t.Errorf("60 flows came in %d messages with %d records, want 3 messages (27, 27 and 6) with 60", len(msgs), records)
	}
	if got := messages(1, 0, time.Unix(0, 0), nil); len(got) != 0 {
		t.Errorf("no flows gave %d messages", len(got))
	}
}

func TestIPFIXExportsOverUDP(t *testing.T) {
	pc := listenUDP(t)
	x, err := NewIPFIX(export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://" + pc.addr})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	read := func() collected {
		t.Helper()
		return collect(t, pc.read(t))
	}
	if err := x.Export("node-a", []Flow{testFlow(1), testFlow(2)}); err != nil {
		t.Fatal(err)
	}
	first := read()
	if first.domain != DomainOf("node-a") || first.sequence != 0 || len(first.records[templateIPv4]) != 2 {
		t.Errorf("the first message is %+v", first)
	}
	if err := x.Export("node-a", []Flow{testFlow(3)}); err != nil {
		t.Fatal(err)
	}
	if second := read(); second.sequence != 2 || len(second.records[templateIPv4]) != 1 {
		t.Errorf("the second message has the sequence %d and %d records, want 2 and 1", second.sequence, len(second.records[templateIPv4]))
	}

	// The records of each node count in a sequence of their own, in the domain of its name
	if err := x.Export("node-b", []Flow{testFlow(4)}); err != nil {
		t.Fatal(err)
	}
	if other := read(); other.domain != DomainOf("node-b") || other.sequence != 0 || DomainOf("node-a") == DomainOf("node-b") {
		t.Errorf("the message of node-b has the domain %x and the sequence %d", other.domain, other.sequence)
	}

	if err := x.Export("node-a", nil); err != nil {
		t.Errorf("exporting no flows: %v", err)
	}
	x.Close()
	if err := x.Export("node-a", []Flow{testFlow(5)}); err != nil {
		t.Errorf("exporting after Close: %v", err)
	}
	if err := pc.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := pc.conn.ReadFrom(make([]byte, 2048)); err == nil {
		t.Errorf("an exporter that was closed sent %d bytes", n)
	}
}

func TestIPFIXExportsOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	x, err := NewIPFIX(export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "tcp://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if err := x.Export("node-a", []Flow{testFlow(1)}); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A message is its own length: the stream is messages one after the other
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, int(binary.BigEndian.Uint16(head[2:]))-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		t.Fatal(err)
	}
	if c := collect(t, append(head, rest...)); len(c.records[templateIPv4]) != 1 || c.sequence != 0 {
		t.Errorf("the message over TCP is %+v", c)
	}
}

func TestIPFIXNeedsACollectorAddress(t *testing.T) {
	for _, url := range []string{"udp://192.0.2.10", "http://192.0.2.10:4739", "192.0.2.10:4739", "%zz"} {
		if _, err := NewIPFIX(export.Target{Name: "flows", URL: url}); err == nil {
			t.Errorf("NewIPFIX took %q", url)
		}
	}
	// A collector that cannot be reached is an error of the export, which loses its flows
	x, err := NewIPFIX(export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "tcp://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Export("node-a", []Flow{testFlow(1)}); err == nil {
		t.Error("an export to a collector that does not listen succeeded")
	}
}
