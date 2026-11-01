// Package sidecar is `ranz bgp`, the BGP sidecar of a Ranz node (ADR-0010, ADR-0022, CORE-S7-1
// #82): GoBGP as a library, peering with the operator's own routers, driven by the node over a
// local named pipe. The node installs the learned routes into Windows through IP Helper; the sidecar
// installs nothing (no FIB), so there is no BGP in the node and no RRAS.
//
// The protocol is JSON, one object per line (UTF-8, at most MaxLine bytes with its newline), and
// every object has a "type".
//
// From the node:
//
//	start     the BGP settings, always the first message: asn, router_id, listen_port (179 when 0
//	          or left out, -1 for no listener), listen_addresses (all when left out), peers
//	          (address, asn, port: 179 when 0, passive: wait for the peer to connect) and accept
//	          (the prefixes, with their more specific ones, that are taken from the peers; with
//	          none, nothing is learned)
//	announce  announce prefix to the peers, with next_hop (the address of the session when left
//	          out); an announced prefix is announced again with the new next hop
//	withdraw  withdraw an announced prefix
//	ping      ask whether the sidecar runs: it answers pong once GoBGP answers it too
//
// From the sidecar:
//
//	ready      BGP runs with the settings of start: version (of ranz bgp and GoBGP) and protocol
//	peer       the session with peer (and its asn) is now in state: idle, connect, active,
//	           opensent, openconfirm or established
//	learned    the best route of the peers to prefix is now via next_hop, learned from peer
//	withdrawn  no peer has a route to prefix any more (it came from peer)
//	refused    GoBGP refused a session from peer, an address that no peer of the settings has
//	pong       the answer to ping: the sidecar and its GoBGP run
//	error      a message of the node could not be applied: error, with its prefix if it had one;
//	           an error for start ends the session
//
// A start with an address runs the peering of the standard mode (SDN-77 #357, peering.go): the
// peers are other Ranz nodes, which reach the node at that address on a network that the operator
// trusts. The sidecar listens there only, connects from there, and is the next hop of what it
// announces; listen_addresses and accept are not given, and peers may be empty while the node is
// alone in its VRFs. Each peer has hold_time (the BGP hold time
// in seconds, 90 when 0) and vrfs: the VRFs that the two nodes share (id) with the prefixes that the
// peer may announce in each, exactly (accept). The routes are VPN routes
// (RFC 4364) whose route distinguisher holds the VRF id, so a route of one VRF never reaches
// another; announce, withdraw, learned and withdrawn carry the vrf. A peers message from the node
// holds the peers in place of the ones before: a peer that changes starts its session again. A
// peers message with more holds part of them: the sidecar takes the peers of the messages with
// more and of the next one without it together, so that a list longer than one line goes in
// several (SDN-77-R1 #531).
//
// The session ends when the node closes the pipe: the sidecar then stops BGP, which tells the
// peers with a Cease notification, and exits.
//
// A start with evpn makes the node an EVPN gateway to a data-centre fabric (evpn.go; SDN-25 #201),
// and has no address: its peers are the routers of the fabric, not Ranz nodes. evpn names the VTEP
// of the node, its router_mac and its vrfs (vrf, the L3 vni, the rd, the
// import and export route targets, and accept: the prefixes, with their more specific ones, that
// are taken from the fabric into the VRF). An announce or withdraw with the vrf of one of them is
// an IP prefix route (EVPN type 5) of that VRF, with the VTEP as its next hop, so it has no
// next_hop; one with any other vrf is refused. A learned message with a vni is an IP prefix route
// of the fabric in the EVPN VRF vrf, and goes again whenever its route or its vteps change. vteps
// are the next hops of every route that the peers offer for the prefix in the VRF, next_hop among
// them, all VTEPs that the node takes the frames of the VRF from, a leaf whose route lost among
// them (SDN-25-R3 #571). The message holds the prefix via the VTEP next_hop of the fabric, with the vni
// and the router_mac to send it in VXLAN; a withdrawn message with a vni is one that went. The
// node installs them into the forwarding of the VRF, never into the Windows routing table.
package sidecar

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion is the version of the protocol that ready reports: 2 adds the peering of the
// standard mode and the refused message, 3 the EVPN of a gateway, 4 the more of a peers message,
// ping and pong, 5 the vteps of a learned message of an EVPN VRF (SDN-25-R3 #571).
const ProtocolVersion = 5

// MaxLine is the size of one message at most, with its newline.
const MaxLine = 64 * 1024

// The message types.
const (
	TypeStart     = "start"
	TypeAnnounce  = "announce"
	TypeWithdraw  = "withdraw"
	TypeReady     = "ready"
	TypePeer      = "peer"
	TypeLearned   = "learned"
	TypeWithdrawn = "withdrawn"
	TypeError     = "error"
	TypePeers     = "peers"
	TypeRefused   = "refused"
	TypePing      = "ping"
	TypePong      = "pong"
)

// The session states of a peer message.
const (
	StateIdle        = "idle"
	StateConnect     = "connect"
	StateActive      = "active"
	StateOpenSent    = "opensent"
	StateOpenConfirm = "openconfirm"
	StateEstablished = "established"
)

// Message is one message of either side; each type uses some of the fields.
type Message struct {
	Type string `json:"type"`

	// start
	ASN             uint32   `json:"asn,omitempty"` // also the AS of the peer of a peer message
	RouterID        string   `json:"router_id,omitempty"`
	ListenPort      int32    `json:"listen_port,omitempty"`
	ListenAddresses []string `json:"listen_addresses,omitempty"`
	Peers           []Peer   `json:"peers,omitempty"` // also of peers
	Accept          []string `json:"accept,omitempty"`
	// More says of a peers message that more peers follow in the next one
	More bool `json:"more,omitempty"`
	// Address is the node's own address in the peering of the standard mode
	Address string `json:"address,omitempty"`

	// announce, withdraw, learned, withdrawn, error
	Prefix  string `json:"prefix,omitempty"`
	NextHop string `json:"next_hop,omitempty"`
	// VRF is the VRF id of a route of the peering of the standard mode or of an EVPN VRF (evpn.go),
	// 0 for none
	VRF uint32 `json:"vrf,omitempty"`
	// VTEPs are the next hops of every route that the peers offer for the prefix of a learned message
	// of an EVPN VRF, NextHop among them, each once and in order (evpn_vteps.go; SDN-25-R3 #571)
	VTEPs []string `json:"vteps,omitempty"`

	// peer, learned, withdrawn, refused: the address of the peer
	Peer  string `json:"peer,omitempty"`
	State string `json:"state,omitempty"`

	// ready
	Version  string `json:"version,omitempty"`
	Protocol int    `json:"protocol,omitempty"`

	// error
	Error string `json:"error,omitempty"`

	// The EVPN of a gateway (evpn.go; SDN-25 #201): its settings in start; the VNI of a route of
	// an EVPN VRF in learned and withdrawn, and the router MAC of the fabric in learned
	EVPN      *EVPN  `json:"evpn,omitempty"`
	VNI       uint32 `json:"vni,omitempty"`
	RouterMAC string `json:"router_mac,omitempty"`
}

// Peer is one router of the operator in a start message, or one Ranz node in the peering of the
// standard mode.
type Peer struct {
	Address string `json:"address"`
	ASN     uint32 `json:"asn"`
	Port    uint32 `json:"port,omitempty"`
	Passive bool   `json:"passive,omitempty"`
	// HoldTime and VRFs are of a Ranz node: the BGP hold time in seconds, 0 for the default, and
	// the VRFs that it shares with the node
	HoldTime uint32    `json:"hold_time,omitempty"`
	VRFs     []PeerVRF `json:"vrfs,omitempty"`
}

// PeerVRF is a VRF that a Ranz node shares with the node, and the prefixes that it may announce
// there, exactly: a more specific prefix of one is none of them (SDN-77-R1 #531).
type PeerVRF struct {
	ID     uint32   `json:"id"`
	Accept []string `json:"accept,omitempty"`
}

// ErrLineTooLong is returned by Reader.Read for a message longer than MaxLine.
var ErrLineTooLong = errors.New("message longer than the protocol allows")

// Reader reads the messages of one side.
type Reader struct {
	s *bufio.Scanner
}

// NewReader reads messages from r.
func NewReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), MaxLine)
	return &Reader{s: s}
}

// Read returns the next message; io.EOF when the other side closed the pipe between two messages.
// Empty lines are skipped.
func (r *Reader) Read() (Message, error) {
	for r.s.Scan() {
		line := r.s.Bytes()
		if len(line) == 0 || (len(line) == 1 && line[0] == '\r') {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return Message{}, fmt.Errorf("not a JSON message: %w", err)
		}
		if m.Type == "" {
			return Message{}, errors.New("message without a type")
		}
		return m, nil
	}
	if err := r.s.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return Message{}, ErrLineTooLong
		}
		return Message{}, err
	}
	return Message{}, io.EOF
}

// Writer writes the messages of one side; it is safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter writes messages to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Write sends m as one line.
func (w *Writer) Write(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > MaxLine {
		return ErrLineTooLong
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(b)
	return err
}
