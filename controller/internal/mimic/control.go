package mimic

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The control pipe is the pipe that the node creates and starts the sidecar with (-pipe NAME). It
// carries JSON, one object per line (UTF-8, at most MaxLine bytes with its newline), and every
// object has a "type".
//
// From the node:
//
//	start  the settings of the sidecar, always the first message: role (server or client), pipe
//	       (the data pipe, see below) and the settings of the role, server or client
//	stats  asks for the counters of the sidecar
//
// From the sidecar:
//
//	ready     the sidecar runs with the settings of start: version (of ranz mimic and the libraries
//	          it embeds) and protocol. The server role adds listen (the address of the REALITY
//	          listener, with the port the system gave when the settings asked for port 0) and, in
//	          the own decoy mode, decoy (the address of the decoy site), and with the hysteria part of
//	          its settings, hysteria (the UDP address of the listener of the Hysteria mode, hysteria.go)
//	accepted  a client of the server role completed the REALITY handshake: peer is its address
//	probe     a connection that is no Ranz client (a prober, a browser, a client with a wrong key
//	          or short id) was spliced to the decoy: peer and reason
//	stats     the counters: accepted, probes and streams since the start, dropped (events that did
//	          not fit the queue of the pipe)
//	error     a message could not be applied or the sidecar stopped: error; an error for start ends
//	          the session
//
// The session ends when the node closes the pipe: the sidecar then closes its listeners and its
// streams and exits.
//
// The data pipe carries the inner streams, one pipe connection for each. The server role dials it,
// once for each client that authenticated: the node created it before start, with one pipe instance
// to accept the next connection on at all times. The client role creates it and listens: the node
// connects once for each stream it wants. A stream is a byte stream, with a line in front of it that
// tells the channel binding of the outer TLS session, the TLS exporter of RFC 8446 section 7.5 with
// the label BindingLabel, 32 bytes as 64 hex digits, or "-" when the sidecar has none (a stream of the
// Hysteria mode carries the SHA-256 of the certificate of the server instead, hysteria.go):
//
//	server role, the sidecar writes first:  bind <binding>\n
//	client role, the node writes first:     dial <address>\n    the address of a link of start
//	            the sidecar answers:        ok <binding>\n      and the stream starts,
//	                                        or error <reason>\n and closes the pipe
//
// After that line, every byte that one end writes reaches the other end, in order, until one end
// closes: the inner stream is the Noise session of the node, which neither sidecar looks into.

// ProtocolVersion is the version of the protocol that ready reports.
const ProtocolVersion = 1

// MaxLine is the size of one message at most, with its newline.
const MaxLine = 64 * 1024

// BindingLabel is the label of the TLS exporter that both ends of the outer session give their node
// as the channel binding of the stream (the label of the session module, Core/Noise.h).
const BindingLabel = "EXPORTER-ranz-session-noise"

// BindingSize is the size of the channel binding, in bytes.
const BindingSize = 32

// The message types.
const (
	TypeStart    = "start"
	TypeStats    = "stats"
	TypeReady    = "ready"
	TypeAccepted = "accepted"
	TypeProbe    = "probe"
	TypeError    = "error"
)

// The roles of a sidecar.
const (
	RoleServer = "server"
	RoleClient = "client"
)

// Message is one message of either side; each type uses some of the fields.
type Message struct {
	Type string `json:"type"`

	// start
	Role   string          `json:"role,omitempty"`
	Pipe   string          `json:"pipe,omitempty"`
	Server *ServerSettings `json:"server,omitempty"`
	Client *ClientSettings `json:"client,omitempty"`

	// ready
	Version  string `json:"version,omitempty"`
	Protocol int    `json:"protocol,omitempty"`
	Listen   string `json:"listen,omitempty"`
	Decoy    string `json:"decoy,omitempty"`
	Hysteria string `json:"hysteria,omitempty"`

	// accepted, probe
	Peer   string `json:"peer,omitempty"`
	Reason string `json:"reason,omitempty"`

	// stats
	Accepted uint64 `json:"accepted,omitempty"`
	Probes   uint64 `json:"probes,omitempty"`
	Streams  uint64 `json:"streams,omitempty"`
	Dropped  uint64 `json:"dropped,omitempty"`

	// error
	Error string `json:"error,omitempty"`
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
// Empty lines are skipped. A field that this version does not know is an error, so that a
// misspelt setting does not start a sidecar that ignores it.
func (r *Reader) Read() (Message, error) {
	for r.s.Scan() {
		line := r.s.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m Message
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return Message{}, fmt.Errorf("not a message: %w", err)
		}
		var rest json.RawMessage
		if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
			return Message{}, errors.New("not a message: data after the object")
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
