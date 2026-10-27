package controller

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The MAC tables and the IP tables of the L2 Networks (SDN-50 #243, ADR-0031 amendment of 2026-10-27).
// An operator reads the table that the L2 switch of a Network holds on a node, or clears it, to
// troubleshoot an address problem. Each node holds tables of its own, so the call names the Network and,
// when it should ask one node alone, the node; without one it asks every node that holds the Network,
// and the answer has a result for each, with its own status, since one node that is down or does not
// answer must not hide what the others say. A node is sent the Operation of the control protocol only
// when it is connected and reports the Capability operations (operations.go).

// TableKind is one of the two tables that an L2 Network has on a node.
type TableKind string

const (
	// TableMAC is the MAC table: the entries that the L2 switch of the Network learnt, in every VLAN.
	TableMAC TableKind = "mac"
	// TableIP is the IP table: the addresses that the node saw the members of the Network use.
	TableIP TableKind = "ip"
)

// The statuses of the answer of one node.
const (
	// TableOK: the node answered, and did what was asked.
	TableOK = "ok"
	// TableNotConnected: the node has no control stream, so it was not asked, or its stream ended
	// before it answered.
	TableNotConnected = "not-connected"
	// TableUnsupported: the node does not report the Capability operations, so it was not asked.
	TableUnsupported = "unsupported"
	// TableNoNetwork: the node has no L2 Network of that name.
	TableNoNetwork = "no-network"
	// TableFailed: the node could not do it, or the call ended before the node answered.
	TableFailed = "failed"
	// TableTimeout: the node did not answer within the timeout.
	TableTimeout = "timeout"
)

const (
	// MaxTableNodes is the most nodes that one call asks at a time. A Network on more nodes needs the
	// call to name the node, so that one call does not collect the tables of a whole fleet.
	MaxTableNodes = 32
	// maxTableEntries is the most entries of one table that a node lists, and that the controller takes
	// from its answer: OperationResult.entries of control.options.
	maxTableEntries = 512
	// maxMember is the longest name of the member of an entry: TableEntry.member of control.options,
	// without the terminating NUL.
	maxMember = 63
	// maxResultMessage is the longest message that the controller takes from the answer of a node:
	// OperationResult.message of control.options, without the terminating NUL.
	maxResultMessage = 255
)

// TableRequest is a live operation on the MAC table or the IP table of an L2 Network.
type TableRequest struct {
	// Network is the L2 Network whose table it is.
	Network string
	// Node is the node to ask, empty for every node that holds the Network.
	Node string
	// Table is the table: TableMAC or TableIP.
	Table TableKind
	// Clear says that the operation removes entries, and does not read them.
	Clear bool
	// MAC is, with Clear on the MAC table, the one entry to remove, a MAC address of 6 bytes; none removes
	// every entry.
	MAC net.HardwareAddr
	// Address is, with Clear on the IP table, the one entry to remove; the invalid address removes every
	// entry.
	Address netip.Addr
}

// TableEntry is one entry of a MAC table or of an IP table, as a node listed it.
type TableEntry struct {
	// VLAN is the VLAN of the entry, 0 for the entries that no VLAN tag came with.
	VLAN uint32 `json:"vlan,omitempty"`
	// MAC is the MAC address of the entry, as 02:00:5e:10:00:01.
	MAC string `json:"mac,omitempty"`
	// Address is, in the IP table, the IP address of the entry.
	Address string `json:"address,omitempty"`
	// Member is the name of the peer, session or port that the entry belongs to, left out for none.
	Member string `json:"member,omitempty"`
	// LastSeen is the time of the last frame from the entry, left out when the node gave none.
	LastSeen time.Time `json:"lastSeen,omitzero"`
}

// NodeTable is what one node answered, or why it did not.
type NodeTable struct {
	// Node is the name of the node.
	Node string `json:"node"`
	// Status is one of the statuses above.
	Status string `json:"status"`
	// Message says more: why a node that did not do it did not, or a note on its answer.
	Message string `json:"message,omitempty"`
	// Total is how many entries the table holds, of which Entries lists at most 512; for a clear, how many
	// entries it removed.
	Total uint32 `json:"total"`
	// Entries are the entries of the table that a read gave, ordered: by VLAN, then MAC address for the MAC
	// table, and by address for the IP table. A clear lists none.
	Entries []TableEntry `json:"entries"`
}

// TableResult is the answer to a TableRequest: the result of each node that holds the Network, ordered
// by the name of the node.
type TableResult struct {
	Network string      `json:"network"`
	Table   TableKind   `json:"table"`
	Cleared bool        `json:"cleared,omitempty"`
	Nodes   []NodeTable `json:"nodes"`
}

// failed reports whether a node of r did not do what was asked.
func (r TableResult) failed() bool {
	return slices.ContainsFunc(r.Nodes, func(n NodeTable) bool { return n.Status != TableOK })
}

// summary describes r for the audit log: each node, how it ended and how many entries it listed or removed.
func (r TableResult) summary() string {
	if len(r.Nodes) == 0 {
		return "no node holds the Network"
	}
	parts := make([]string, len(r.Nodes))
	for i, n := range r.Nodes {
		parts[i] = n.Node + ": " + n.Status
		switch {
		case n.Status == TableOK && r.Cleared:
			parts[i] += fmt.Sprintf(", %d removed", n.Total)
		case n.Status == TableOK:
			parts[i] += fmt.Sprintf(", %d entries", n.Total)
		case n.Message != "":
			parts[i] += " (" + n.Message + ")"
		}
	}
	return strings.Join(parts, "; ")
}

// action returns the action of the audit record of q: mac-table, mac-table-clear, ip-table or
// ip-table-clear.
func (q TableRequest) action() string {
	if q.Clear {
		return string(q.Table) + "-table-clear"
	}
	return string(q.Table) + "-table"
}

// subject returns what the audit record of q says that it was done to: the Network, the node when the
// request names one and the entry of a clear that names one.
func (q TableRequest) subject() string {
	s := "network " + q.Network
	if q.Node != "" {
		s += " on node " + q.Node
	}
	if len(q.MAC) != 0 {
		s += ", entry " + q.MAC.String()
	}
	if q.Address.IsValid() {
		s += ", entry " + q.Address.String()
	}
	return clip(s, 240)
}

// operation returns the Operation that q asks of a node, without its id, or an error that wraps
// intent.ErrInvalid when q asks something that no Operation says.
func (q TableRequest) operation() (*controlpb.Operation, error) {
	op := &controlpb.Operation{Network: q.Network}
	switch {
	case q.Table == TableMAC && !q.Clear:
		op.Kind = controlpb.OperationKind_OPERATION_KIND_MAC_TABLE
	case q.Table == TableMAC:
		op.Kind = controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE
	case q.Table == TableIP && !q.Clear:
		op.Kind = controlpb.OperationKind_OPERATION_KIND_IP_TABLE
	case q.Table == TableIP:
		op.Kind = controlpb.OperationKind_OPERATION_KIND_CLEAR_IP_TABLE
	default:
		return nil, fmt.Errorf("%w: the table is %s or %s, not %q", intent.ErrInvalid, TableMAC, TableIP, clip(string(q.Table), maxSubject))
	}
	switch {
	case len(q.MAC) != 0 && (q.Table != TableMAC || !q.Clear):
		return nil, fmt.Errorf("%w: only a clear of the MAC table names a MAC address", intent.ErrInvalid)
	case q.Address.IsValid() && (q.Table != TableIP || !q.Clear):
		return nil, fmt.Errorf("%w: only a clear of the IP table names an address", intent.ErrInvalid)
	case len(q.MAC) != 0 && len(q.MAC) != 6:
		return nil, fmt.Errorf("%w: a MAC address has 6 bytes, not %d", intent.ErrInvalid, len(q.MAC))
	}
	if len(q.MAC) != 0 {
		op.Mac = slices.Clone([]byte(q.MAC))
	}
	if q.Address.IsValid() {
		op.Address = q.Address.Unmap().AsSlice()
	}
	return op, nil
}

// tableTarget is a node that a request is for: its stream when it can be asked, and otherwise why not.
type tableTarget struct {
	name    string
	stream  *stream
	status  string
	message string
}

// tableTargets returns the nodes that q is for, ordered by name. It is an error that wraps
// intent.ErrNotFound when the Network or the named node does not exist, and one that wraps
// intent.ErrInvalid when the Network is an L3 Network, when the named node does not hold the Network,
// or when more than MaxTableNodes nodes would be asked.
func (c *Controller) tableTargets(q TableRequest) ([]tableTarget, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	nw, ok := c.intent.Networks[q.Network]
	if !ok {
		return nil, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNetwork, clip(q.Network, maxSubject))
	}
	if nw.Mode != intent.ModeL2 {
		return nil, fmt.Errorf("%w: Network %q is an L3 Network, and only an L2 Network has a MAC table and an IP table", intent.ErrInvalid, q.Network)
	}
	if _, ok := c.intent.Nodes[q.Node]; q.Node != "" && !ok {
		return nil, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindNode, clip(q.Node, maxSubject))
	}
	holds := desired.Key{Kind: controlpb.Kind_KIND_NETWORK, Name: q.Network}
	var out []tableTarget
	for _, name := range slices.Sorted(maps.Keys(c.intent.Nodes)) {
		if q.Node != "" && name != q.Node {
			continue
		}
		n := c.nodes[name]
		if n == nil || n.state[holds] == nil {
			if q.Node != "" {
				return nil, fmt.Errorf("%w: Node %q does not hold Network %q: it is no member of VRF %q, or the licence in force leaves it out", intent.ErrInvalid, name, q.Network, nw.VRF)
			}
			continue
		}
		t := tableTarget{name: name, stream: n.stream}
		// Apply validated the key.
		key, _ := intent.ParseKey(c.intent.Nodes[name].PublicKey)
		switch {
		case n.stream == nil:
			t.status, t.message = TableNotConnected, errNoStream.Error()
		case !c.caps[string(key)].GetOperations():
			t.status, t.message, t.stream = TableUnsupported, "the node does not report the Capability operations", nil
		}
		out = append(out, t)
	}
	if len(out) > MaxTableNodes {
		return nil, fmt.Errorf("%w: Network %q is on %d nodes, and one call asks at most %d: name a node", intent.ErrInvalid, q.Network, len(out), MaxTableNodes)
	}
	return out, nil
}

// TableOperation does the live operation q on the nodes that hold the Network (GET and DELETE of
// /api/v1/operations/networks/{network}/mac-table and ip-table): it sends each node that can be asked
// the Operation and waits for the answers, and gives the result of every node, also of the ones that
// were not asked or did not answer. The errors are those of tableTargets and of operation. The call is
// recorded in the audit log: as a failure when no node did what was asked, with the result of each node
// as its message.
func (c *Controller) TableOperation(ctx context.Context, q TableRequest) (TableResult, error) {
	res, err := c.tableOperation(ctx, q)
	// A node that did not do it is no error of the call, which says what each node did, but it is a
	// failure of the operation
	failure := err
	if err == nil && res.failed() {
		failure = errors.New(res.summary())
	}
	c.auditOperation(ctx, q.action(), q.subject(), failure, res.summary())
	return res, err
}

func (c *Controller) tableOperation(ctx context.Context, q TableRequest) (TableResult, error) {
	op, err := q.operation()
	if err != nil {
		return TableResult{}, err
	}
	targets, err := c.tableTargets(q)
	if err != nil {
		return TableResult{}, err
	}
	res := TableResult{Network: q.Network, Table: q.Table, Cleared: q.Clear, Nodes: make([]NodeTable, len(targets))}
	var wg sync.WaitGroup
	for i, t := range targets {
		res.Nodes[i] = NodeTable{Node: t.name, Status: t.status, Message: t.message, Entries: []TableEntry{}}
		if t.stream == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each node is sent an Operation of its own: operate gives it its id
			answer, err := c.operate(ctx, t.stream, proto.Clone(op).(*controlpb.Operation))
			res.Nodes[i] = nodeTable(t.name, q, answer, err)
		}()
	}
	wg.Wait()
	return res, nil
}

// nodeTable returns the result of the node name for q, which answer is the answer of, or err is why
// there is none.
func nodeTable(name string, q TableRequest, answer *controlpb.OperationResult, err error) NodeTable {
	t := NodeTable{Node: name, Entries: []TableEntry{}}
	switch {
	case errors.Is(err, ErrOperationTimeout):
		t.Status, t.Message = TableTimeout, err.Error()
		return t
	case errors.Is(err, errNoStream):
		t.Status, t.Message = TableNotConnected, "the control stream of the node ended before it answered"
		return t
	case err != nil:
		t.Status, t.Message = TableFailed, err.Error()
		return t
	}
	t.Message = clip(answer.GetMessage(), maxResultMessage)
	t.Total = answer.GetTotal()
	switch answer.GetStatus() {
	case controlpb.OperationStatus_OPERATION_STATUS_OK:
		t.Status = TableOK
	case controlpb.OperationStatus_OPERATION_STATUS_NO_NETWORK:
		t.Status = TableNoNetwork
		if t.Message == "" {
			t.Message = "the node has no L2 Network of that name"
		}
	default:
		t.Status = TableFailed
		if t.Message == "" {
			t.Message = "the node could not do it"
		}
	}
	if t.Status == TableOK && !q.Clear {
		var left int
		t.Entries, left = tableEntries(answer.GetEntries(), q.Table)
		if left > 0 {
			t.Message = strings.TrimSpace(fmt.Sprintf("%s %d entries were left out: not well formed, or more than the %d that a node lists", t.Message, left, maxTableEntries))
		}
	}
	return t
}

// tableEntries returns the entries that a node listed in the form of the API, ordered, and how many it
// left out: an entry of the MAC table needs a MAC address of 6 bytes, and one of the IP table an address
// of 4 or 16 bytes and, when it has one, a MAC address of 6 bytes. A node lists at most maxTableEntries;
// the controller takes no more.
func tableEntries(entries []*controlpb.TableEntry, table TableKind) (out []TableEntry, left int) {
	// An entry with the keys that order it
	type keyed struct {
		TableEntry
		mac  []byte
		addr netip.Addr
	}
	var taken []keyed
	for i, e := range entries {
		if i >= maxTableEntries {
			left += len(entries) - i
			break
		}
		mac := e.GetMac()
		if len(mac) != 0 && len(mac) != 6 {
			left++
			continue
		}
		addr, hasAddr := netip.AddrFromSlice(e.GetAddress())
		if (table == TableMAC && len(mac) == 0) || (table == TableIP && !hasAddr) {
			left++
			continue
		}
		k := keyed{TableEntry: TableEntry{VLAN: e.GetVlan(), Member: clip(e.GetMember(), maxMember)}, mac: mac}
		if len(mac) != 0 {
			k.MAC = net.HardwareAddr(mac).String()
		}
		if table == TableIP {
			k.addr = addr.Unmap()
			k.Address = k.addr.String()
		}
		if ms := e.GetLastSeenMs(); ms != 0 && ms <= math.MaxInt64 {
			k.LastSeen = time.UnixMilli(int64(ms)).UTC()
		}
		taken = append(taken, k)
	}
	slices.SortFunc(taken, func(a, b keyed) int {
		return cmp.Or(cmp.Compare(a.VLAN, b.VLAN), a.addr.Compare(b.addr), bytes.Compare(a.mac, b.mac))
	})
	out = make([]TableEntry, len(taken))
	for i, k := range taken {
		out[i] = k.TableEntry
	}
	return out, left
}
