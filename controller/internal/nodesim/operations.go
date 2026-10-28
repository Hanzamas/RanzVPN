package nodesim

import (
	"errors"
	"slices"
	"sync"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The live operations of the control protocol (SDN-50 #243): the controller sends the node an Operation,
// which reads or clears the MAC table or the IP table of an L2 Network, and the node answers with an
// OperationResult of the same id. A simulated node answers through its Operations handler; Tables is
// the handler of a node that holds tables.

// maxEntries is the most entries of one table that an OperationResult lists (OperationResult.entries
// of control.options).
const maxEntries = 512

// OperationHandler answers one Operation of the controller with the OperationResult that the node
// sends back, whose id is the one of the Operation; a handler that gives no result makes the node answer
// nothing, as a node that is too slow does. A result without an id is given the id of the Operation.
type OperationHandler func(op *controlpb.Operation) *controlpb.OperationResult

// operate answers the Operation op on conn with the handler of the node.
func (n *Node) operate(conn *control.Conn, op *controlpb.Operation) error {
	if n.Operations == nil {
		return errors.New("nodesim: the controller sent an Operation to a node that has no handler for it, and so reports no Capability operations")
	}
	res := n.Operations(op)
	if res == nil {
		return nil
	}
	if res.GetId() == 0 {
		res.Id = op.GetId()
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_OperationResult{OperationResult: res}})
}

// OperationResult sends the controller the OperationResult r on the stream that Run serves, as the
// node does when it answers an Operation, also when the controller asked for none: a test sends the answer
// that a node sends too late, or for an id that it was never given.
func (n *Node) OperationResult(r *controlpb.OperationResult) error {
	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return errors.New("nodesim: no stream to send an OperationResult on")
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_OperationResult{OperationResult: r}})
}

// Tables are the MAC tables and the IP tables that a simulated node holds for its L2 Networks, by the
// name of the Network. Handle is the OperationHandler that reads and clears them as the control protocol
// says. The zero value holds no Network.
type Tables struct {
	mu  sync.Mutex
	mac map[string][]*controlpb.TableEntry
	ip  map[string][]*controlpb.TableEntry
}

// SetMAC sets the MAC table of the Network network to entries, and so makes the node hold the Network.
func (t *Tables) SetMAC(network string, entries ...*controlpb.TableEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mac == nil {
		t.mac = map[string][]*controlpb.TableEntry{}
	}
	t.mac[network] = slices.Clone(entries)
}

// SetIP sets the IP table of the Network network to entries, and so makes the node hold the Network.
func (t *Tables) SetIP(network string, entries ...*controlpb.TableEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ip == nil {
		t.ip = map[string][]*controlpb.TableEntry{}
	}
	t.ip[network] = slices.Clone(entries)
}

// MAC returns the MAC table of the Network network as it is now.
func (t *Tables) MAC(network string) []*controlpb.TableEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.mac[network])
}

// IP returns the IP table of the Network network as it is now.
func (t *Tables) IP(network string) []*controlpb.TableEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.ip[network])
}

// Handle answers the Operation op. A read lists at most 512 entries of the table and says in total how
// many it holds. A clear with a MAC address or an address removes the entry that has it, and without
// one every entry of the table, and says in total how many it removed. A Network that the node holds no
// table of is OPERATION_STATUS_NO_NETWORK, and an Operation that is none of the four kinds is
// OPERATION_STATUS_FAILED.
func (t *Tables) Handle(op *controlpb.Operation) *controlpb.OperationResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mac == nil {
		t.mac = map[string][]*controlpb.TableEntry{}
	}
	if t.ip == nil {
		t.ip = map[string][]*controlpb.TableEntry{}
	}
	res := &controlpb.OperationResult{Id: op.GetId(), Status: controlpb.OperationStatus_OPERATION_STATUS_OK}
	_, hasMAC := t.mac[op.GetNetwork()]
	_, hasIP := t.ip[op.GetNetwork()]
	if !hasMAC && !hasIP {
		res.Status = controlpb.OperationStatus_OPERATION_STATUS_NO_NETWORK
		res.Message = "no L2 Network of that name"
		return res
	}
	switch op.GetKind() {
	case controlpb.OperationKind_OPERATION_KIND_MAC_TABLE:
		read(res, t.mac[op.GetNetwork()])
	case controlpb.OperationKind_OPERATION_KIND_IP_TABLE:
		read(res, t.ip[op.GetNetwork()])
	case controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE:
		t.mac[op.GetNetwork()] = removeMatching(res, t.mac[op.GetNetwork()], func(e *controlpb.TableEntry) bool {
			return len(op.GetMac()) == 0 || slices.Equal(e.GetMac(), op.GetMac())
		})
	case controlpb.OperationKind_OPERATION_KIND_CLEAR_IP_TABLE:
		t.ip[op.GetNetwork()] = removeMatching(res, t.ip[op.GetNetwork()], func(e *controlpb.TableEntry) bool {
			return len(op.GetAddress()) == 0 || slices.Equal(e.GetAddress(), op.GetAddress())
		})
	default:
		res.Status = controlpb.OperationStatus_OPERATION_STATUS_FAILED
		res.Message = "an Operation of a kind that the node does not know"
	}
	return res
}

// read puts the entries of a table in res: the first 512 of them, and how many there are.
func read(res *controlpb.OperationResult, entries []*controlpb.TableEntry) {
	res.Total = uint32(len(entries))
	res.Entries = slices.Clone(entries[:min(len(entries), maxEntries)])
}

// removeMatching removes the entries of a table that match holds of, puts how many it removed in res as
// its total, and returns the entries that stay.
func removeMatching(res *controlpb.OperationResult, entries []*controlpb.TableEntry, match func(*controlpb.TableEntry) bool) []*controlpb.TableEntry {
	var kept []*controlpb.TableEntry
	for _, e := range entries {
		if match(e) {
			res.Total++
			continue
		}
		kept = append(kept, e)
	}
	return kept
}
