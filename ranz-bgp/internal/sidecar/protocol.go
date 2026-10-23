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
//
// From the sidecar:
//
//	ready      BGP runs with the settings of start: version (of ranz bgp and GoBGP) and protocol
//	peer       the session with peer (and its asn) is now in state: idle, connect, active,
//	           opensent, openconfirm or established
//	learned    the best route of the peers to prefix is now via next_hop, learned from peer
//	withdrawn  no peer has a route to prefix any more (it came from peer)
//	error      a message of the node could not be applied: error, with its prefix if it had one;
//	           an error for start ends the session
//
// The session ends when the node closes the pipe: the sidecar then stops BGP, which tells the
// peers with a Cease notification, and exits.
package sidecar

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion is the version of the protocol that ready reports.
const ProtocolVersion = 1

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
	Peers           []Peer   `json:"peers,omitempty"`
	Accept          []string `json:"accept,omitempty"`

	// announce, withdraw, learned, withdrawn, error
	Prefix  string `json:"prefix,omitempty"`
	NextHop string `json:"next_hop,omitempty"`

	// peer, learned, withdrawn: the address of the peer
	Peer  string `json:"peer,omitempty"`
	State string `json:"state,omitempty"`

	// ready
	Version  string `json:"version,omitempty"`
	Protocol int    `json:"protocol,omitempty"`

	// error
	Error string `json:"error,omitempty"`
}

// Peer is one router of the operator in a start message.
type Peer struct {
	Address string `json:"address"`
	ASN     uint32 `json:"asn"`
	Port    uint32 `json:"port,omitempty"`
	Passive bool   `json:"passive,omitempty"`
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
