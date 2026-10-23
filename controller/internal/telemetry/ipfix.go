package telemetry

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// Flow is one flow record of a node: the packets of one protocol between two addresses and ports
// in one VRF, in one direction, from Start to End (IPFIX, ADR-0030 decision 4). For ICMP the ports
// are 0 and DstPort holds the type times 256 plus the code.
type Flow struct {
	VRF      uint32
	Src      netip.Addr
	Dst      netip.Addr
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	Packets  uint64
	Bytes    uint64
	Start    time.Time
	End      time.Time
}

// FlowsOf returns the flow records of the summary t that are well formed: both addresses of the
// same family, 4 or 16 bytes, and a protocol and ports in range. A record that is not is left out.
func FlowsOf(t *controlpb.Telemetry) []Flow {
	var out []Flow
	for _, f := range t.GetFlows() {
		src, ok1 := netip.AddrFromSlice(f.GetSrc())
		dst, ok2 := netip.AddrFromSlice(f.GetDst())
		if !ok1 || !ok2 {
			continue
		}
		src, dst = src.Unmap(), dst.Unmap()
		if src.Is4() != dst.Is4() || f.GetProtocol() > 255 || f.GetSrcPort() > 65535 || f.GetDstPort() > 65535 {
			continue
		}
		out = append(out, Flow{VRF: f.GetVrfId(), Src: src, Dst: dst, Protocol: uint8(f.GetProtocol()), SrcPort: uint16(f.GetSrcPort()), DstPort: uint16(f.GetDstPort()),
			Packets: f.GetPacketCount(), Bytes: f.GetByteCount(), Start: unixMilli(f.GetStartMs()), End: unixMilli(f.GetEndMs())})
	}
	return out
}

// unixMilli returns the time that is ms milliseconds after the Unix epoch, the epoch itself for a
// value that no time can hold.
func unixMilli(ms uint64) time.Time {
	if ms > 1<<53 {
		return time.UnixMilli(0).UTC()
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// The IPFIX messages of RFC 7011 that the controller sends. Every message has the template set of
// its template and one data set of records, so a collector needs no template refresh, whatever the
// transport.
const (
	ipfixVersion    = 10
	ipfixHeaderSize = 16
	ipfixSetHeader  = 4
	templateSetID   = 2
)

// templateIPv4 and templateIPv6 are the ids of the two templates, which RFC 7011 numbers from 256.
const (
	templateIPv4 = 256
	templateIPv6 = 257
)

// maxMessage keeps a message in one UDP datagram that crosses an Ethernet path.
const maxMessage = 1400

// field is one field of a template: the number of its information element in the IANA registry
// and its length in octets.
type field struct {
	element uint16
	length  uint16
}

// The fields of the two templates, in the order of a record: flowStartMilliseconds,
// flowEndMilliseconds, the two addresses, the two ports, protocolIdentifier, packetDeltaCount,
// octetDeltaCount and ingressVRFID.
var (
	fieldsIPv4 = []field{{152, 8}, {153, 8}, {8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {2, 8}, {1, 8}, {234, 4}}
	fieldsIPv6 = []field{{152, 8}, {153, 8}, {27, 16}, {28, 16}, {7, 2}, {11, 2}, {4, 1}, {2, 8}, {1, 8}, {234, 4}}
)

// recordSize is the length of one record of the fields.
func recordSize(fields []field) int {
	n := 0
	for _, f := range fields {
		n += int(f.length)
	}
	return n
}

// templateSet returns the template set of the template id with fields.
func templateSet(id uint16, fields []field) []byte {
	b := binary.BigEndian.AppendUint16(nil, templateSetID)
	b = binary.BigEndian.AppendUint16(b, uint16(ipfixSetHeader+4+4*len(fields)))
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, uint16(len(fields)))
	for _, f := range fields {
		b = binary.BigEndian.AppendUint16(b, f.element)
		b = binary.BigEndian.AppendUint16(b, f.length)
	}
	return b
}

// appendRecord appends the record of f, whose addresses are of the family of the template.
func appendRecord(b []byte, f Flow) []byte {
	b = binary.BigEndian.AppendUint64(b, uint64(f.Start.UnixMilli()))
	b = binary.BigEndian.AppendUint64(b, uint64(f.End.UnixMilli()))
	b = append(b, f.Src.AsSlice()...)
	b = append(b, f.Dst.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, f.SrcPort)
	b = binary.BigEndian.AppendUint16(b, f.DstPort)
	b = append(b, f.Protocol)
	b = binary.BigEndian.AppendUint64(b, f.Packets)
	b = binary.BigEndian.AppendUint64(b, f.Bytes)
	return binary.BigEndian.AppendUint32(b, f.VRF)
}

// message is one IPFIX message and the number of data records in it.
type message struct {
	bytes   []byte
	records uint32
}

// messages returns the IPFIX messages that carry flows from the observation domain domain at time
// now, the first with the sequence number seq, the number of data records sent before it. A message
// holds the flows of one family, at most maxMessage octets.
func messages(domain, seq uint32, now time.Time, flows []Flow) []message {
	var out []message
	for _, v6 := range []bool{false, true} {
		id, fields := uint16(templateIPv4), fieldsIPv4
		if v6 {
			id, fields = templateIPv6, fieldsIPv6
		}
		var mine []Flow
		for _, f := range flows {
			if f.Src.Is4() != v6 {
				mine = append(mine, f)
			}
		}
		tmpl := templateSet(id, fields)
		room := (maxMessage - ipfixHeaderSize - len(tmpl) - ipfixSetHeader) / recordSize(fields)
		for len(mine) > 0 {
			n := min(len(mine), room)
			data := binary.BigEndian.AppendUint16(nil, id)
			data = binary.BigEndian.AppendUint16(data, 0)
			for _, f := range mine[:n] {
				data = appendRecord(data, f)
			}
			// The set ends on a multiple of 4 octets, and its length says so
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			binary.BigEndian.PutUint16(data[2:], uint16(len(data)))

			m := binary.BigEndian.AppendUint16(nil, ipfixVersion)
			m = binary.BigEndian.AppendUint16(m, uint16(ipfixHeaderSize+len(tmpl)+len(data)))
			m = binary.BigEndian.AppendUint32(m, uint32(now.Unix()))
			m = binary.BigEndian.AppendUint32(m, seq)
			m = binary.BigEndian.AppendUint32(m, domain)
			m = append(m, tmpl...)
			m = append(m, data...)
			out = append(out, message{bytes: m, records: uint32(n)})

			seq += uint32(n)
			mine = mine[n:]
		}
	}
	return out
}

// DomainOf returns the observation domain id of a node: the FNV-1a hash of its name, so that a
// collector tells the nodes apart and the id of a node stays the same.
func DomainOf(node string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(node))
	return h.Sum32()
}

// IPFIX sends the flow records of the nodes to one IPFIX collector (RFC 7011), over UDP or TCP.
// The controller exports on behalf of its nodes: each node is an observation domain of its own,
// whose id is DomainOf the name of the node and whose records count in a sequence of their own.
type IPFIX struct {
	network string
	address string
	now     func() time.Time

	mu     sync.Mutex
	closed bool
	conn   net.Conn
	seq    map[uint32]uint32
}

// NewIPFIX returns the exporter to the collector that t names, udp://host:port or tcp://host:port.
// It connects when it first sends.
func NewIPFIX(t export.Target) (*IPFIX, error) {
	u, err := url.Parse(t.URL)
	if err != nil || (u.Scheme != "udp" && u.Scheme != "tcp") || u.Port() == "" {
		return nil, fmt.Errorf("telemetry: IPFIX target %q: %q is not udp://host:port or tcp://host:port", t.Name, t.URL)
	}
	return &IPFIX{network: u.Scheme, address: u.Host, now: time.Now, seq: map[uint32]uint32{}}, nil
}

// Export sends the flows that node observed. It returns an error when the collector cannot be
// reached; the flows are not kept then, as in any exporter whose collector is down.
func (x *IPFIX) Export(node string, flows []Flow) error {
	if len(flows) == 0 {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	domain := DomainOf(node)
	for _, m := range messages(domain, x.seq[domain], x.now(), flows) {
		if x.conn == nil {
			c, err := net.DialTimeout(x.network, x.address, 5*time.Second)
			if err != nil {
				return fmt.Errorf("telemetry: IPFIX collector %s://%s: %w", x.network, x.address, err)
			}
			x.conn = c
		}
		_ = x.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := x.conn.Write(m.bytes); err != nil {
			x.conn.Close()
			x.conn = nil
			return fmt.Errorf("telemetry: IPFIX collector %s://%s: %w", x.network, x.address, err)
		}
		x.seq[domain] += m.records
	}
	return nil
}

// Close closes the connection to the collector, and Export sends nothing after it.
func (x *IPFIX) Close() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.closed = true
	if x.conn != nil {
		x.conn.Close()
		x.conn = nil
	}
}
