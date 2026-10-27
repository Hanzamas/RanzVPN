package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// tableMAC returns the 6 bytes of a MAC address that ends in last.
func tableMAC(last byte) []byte { return []byte{0x02, 0x00, 0x5e, 0x10, 0x00, last} }

// tableAddr returns the bytes of the address s: 4 for IPv4, 16 for IPv6.
func tableAddr(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

// entryLines writes entries one line each: the VLAN, the MAC address, the address and the member.
func entryLines(entries []TableEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = strings.Join(strings.Fields(fmt.Sprintf("%d %s %s %s", e.VLAN, e.MAC, e.Address, e.Member)), " ")
	}
	return out
}

// An entry of the MAC table has a MAC address of 6 bytes, and the entries come ordered by VLAN, then MAC
// address, whatever order the node lists them in; the name of a member is cut at 63 bytes and a time that is
// none is left out of the entry. An entry that is not well formed is left out and counted.
func TestTableEntriesOfTheMACTable(t *testing.T) {
	long := strings.Repeat("m", 70)
	entries := []*controlpb.TableEntry{
		{Vlan: 20, Mac: tableMAC(3), Member: "c"},
		{Vlan: 0, Mac: tableMAC(2), Member: long, LastSeenMs: 1700000000123},
		{Vlan: 0, Mac: tableMAC(1)},
		{Mac: []byte{1, 2, 3, 4, 5}},
		{Address: tableAddr("10.0.0.1")},
		{Vlan: 0, Mac: tableMAC(4), LastSeenMs: math.MaxUint64},
	}
	got, left := tableEntries(entries, TableMAC)
	want := []string{"0 02:00:5e:10:00:01", "0 02:00:5e:10:00:02 " + long[:63], "0 02:00:5e:10:00:04", "20 02:00:5e:10:00:03 c"}
	if lines := entryLines(got); !slices.Equal(lines, want) || left != 2 {
		t.Errorf("the entries are\n%s\nwith %d left out, want\n%s\nwith 2 left out", strings.Join(lines, "\n"), left, strings.Join(want, "\n"))
	}
	if seen := time.UnixMilli(1700000000123).UTC(); !got[1].LastSeen.Equal(seen) || !got[2].LastSeen.IsZero() || !got[0].LastSeen.IsZero() {
		t.Errorf("the times of the entries are %v, %v and %v, want %v for the second alone", got[0].LastSeen, got[1].LastSeen, got[2].LastSeen, seen)
	}
}

// An entry of the IP table has an address of 4 or 16 bytes, and a MAC address of 6 bytes when it has one;
// an IPv4 address that arrives as 16 bytes is written as IPv4, and the entries come ordered by address,
// the IPv4 ones before the IPv6 ones, and by number, not by text.
func TestTableEntriesOfTheIPTable(t *testing.T) {
	entries := []*controlpb.TableEntry{
		{Address: tableAddr("10.0.0.10"), Mac: tableMAC(1)},
		{Address: tableAddr("10.0.0.9")},
		{Address: tableAddr("fd00::1")},
		{Address: tableAddr("::ffff:10.0.0.2")},
		{Address: []byte{1, 2, 3, 4, 5}},
		{Mac: tableMAC(2)},
		{Address: tableAddr("10.0.0.1"), Mac: []byte{1, 2}},
	}
	got, left := tableEntries(entries, TableIP)
	want := []string{"0 10.0.0.2", "0 10.0.0.9", "0 02:00:5e:10:00:01 10.0.0.10", "0 fd00::1"}
	if lines := entryLines(got); !slices.Equal(lines, want) || left != 3 {
		t.Errorf("the entries are\n%s\nwith %d left out, want\n%s\nwith 3 left out", strings.Join(lines, "\n"), left, strings.Join(want, "\n"))
	}
}

// The controller takes no more than the 512 entries that a node lists: it counts the rest as left out.
func TestTableEntriesTakeNoMoreThanANodeLists(t *testing.T) {
	var entries []*controlpb.TableEntry
	for i := 0; i < 600; i++ {
		entries = append(entries, &controlpb.TableEntry{Vlan: uint32(i), Mac: tableMAC(byte(i))})
	}
	if got, left := tableEntries(entries, TableMAC); len(got) != 512 || left != 88 {
		t.Errorf("of 600 entries the controller took %d and left out %d, want 512 and 88", len(got), left)
	}
	if got, left := tableEntries(nil, TableIP); got == nil || len(got) != 0 || left != 0 {
		t.Errorf("of no entry the controller took %v and left out %d, want an empty list", got, left)
	}
}

// The time of the last frame of an entry is one that JSON can write, so that one entry of a node never leaves the
// answer of the API empty: the last instant of the year 9999 is taken, and a later one is left out.
func TestTableEntriesLastSeenIsWritableAsJSON(t *testing.T) {
	last := time.Date(9999, time.December, 31, 23, 59, 59, 999000000, time.UTC)
	got, left := tableEntries([]*controlpb.TableEntry{
		{Mac: tableMAC(1), LastSeenMs: maxLastSeenMs},
		{Mac: tableMAC(2), LastSeenMs: maxLastSeenMs + 1},
		{Mac: tableMAC(3), LastSeenMs: math.MaxInt64},
	}, TableMAC)
	if left != 0 || len(got) != 3 || !got[0].LastSeen.Equal(last) || !got[1].LastSeen.IsZero() || !got[2].LastSeen.IsZero() {
		t.Fatalf("the entries are %+v with %d left out, want the first at %v and no time for the other two", got, left, last)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("the entries cannot be written as JSON: %v", err)
	}
}

// The result of a node says how it ended: an answer that did what was asked, and each way that it could not.
func TestNodeTableGivesTheStatusOfEachWayItEnds(t *testing.T) {
	read := TableRequest{Network: "corp-dmz", Table: TableMAC}
	remove := TableRequest{Network: "corp-dmz", Table: TableMAC, Clear: true}
	ok := &controlpb.OperationResult{Status: controlpb.OperationStatus_OPERATION_STATUS_OK, Total: 2,
		Entries: []*controlpb.TableEntry{{Mac: tableMAC(1)}, {Mac: []byte{1}}}}
	for _, c := range []struct {
		what    string
		q       TableRequest
		answer  *controlpb.OperationResult
		err     error
		status  string
		message string
		total   uint32
		entries int
	}{
		{"an answer", read, ok, nil, TableOK, "1 entries were left out", 2, 1},
		{"the answer to a clear", remove, ok, nil, TableOK, "", 2, 0},
		{"no Network", read, &controlpb.OperationResult{Status: controlpb.OperationStatus_OPERATION_STATUS_NO_NETWORK}, nil, TableNoNetwork, "the node has no L2 Network of that name", 0, 0},
		{"a failure", read, &controlpb.OperationResult{Status: controlpb.OperationStatus_OPERATION_STATUS_FAILED, Message: "the switch is down"}, nil, TableFailed, "the switch is down", 0, 0},
		{"a failure that says nothing", read, &controlpb.OperationResult{}, nil, TableFailed, "the node could not do it", 0, 0},
		{"a message that is no UTF-8", read, &controlpb.OperationResult{Status: controlpb.OperationStatus_OPERATION_STATUS_FAILED, Message: "no \xff text"}, nil, TableFailed, "no  text", 0, 0},
		{"a timeout", read, nil, ErrOperationTimeout, TableTimeout, ErrOperationTimeout.Error(), 0, 0},
		{"a stream that ended", read, nil, fmt.Errorf("wrapped: %w", errNoStream), TableNotConnected, "the control stream of the node ended before it answered", 0, 0},
		{"another error", read, nil, errors.New("the call ended"), TableFailed, "the call ended", 0, 0},
	} {
		got := nodeTable("branch-1", c.q, c.answer, c.err)
		said := got.Message == c.message || (c.message != "" && strings.Contains(got.Message, c.message))
		if got.Node != "branch-1" || got.Status != c.status || !said || got.Total != c.total || len(got.Entries) != c.entries || got.Entries == nil {
			t.Errorf("%s: the result is %+v, want the status %s, the message %q, the total %d and %d entries", c.what, got, c.status, c.message, c.total, c.entries)
		}
	}
}

// A request says what it asks only when what it names fits the table: an entry to remove is named by a
// clear alone, a MAC address by a clear of the MAC table and an address by a clear of the IP table.
func TestTableRequestOperation(t *testing.T) {
	mac := net.HardwareAddr(tableMAC(1))
	addr := netip.MustParseAddr("::ffff:10.0.0.1")
	for _, c := range []struct {
		q    TableRequest
		kind controlpb.OperationKind
		err  string
	}{
		{TableRequest{Network: "n", Table: TableMAC}, controlpb.OperationKind_OPERATION_KIND_MAC_TABLE, ""},
		{TableRequest{Network: "n", Table: TableMAC, Clear: true}, controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE, ""},
		{TableRequest{Network: "n", Table: TableMAC, Clear: true, MAC: mac}, controlpb.OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE, ""},
		{TableRequest{Network: "n", Table: TableIP}, controlpb.OperationKind_OPERATION_KIND_IP_TABLE, ""},
		{TableRequest{Network: "n", Table: TableIP, Clear: true, Address: addr}, controlpb.OperationKind_OPERATION_KIND_CLEAR_IP_TABLE, ""},
		{TableRequest{Network: "n", Table: "arp"}, 0, `the table is mac or ip, not "arp"`},
		{TableRequest{Network: "n", Table: TableMAC, MAC: mac}, 0, "only a clear of the MAC table names a MAC address"},
		{TableRequest{Network: "n", Table: TableIP, Clear: true, MAC: mac}, 0, "only a clear of the MAC table names a MAC address"},
		{TableRequest{Network: "n", Table: TableMAC, Clear: true, Address: addr}, 0, "only a clear of the IP table names an address"},
		{TableRequest{Network: "n", Table: TableIP, Address: addr}, 0, "only a clear of the IP table names an address"},
		{TableRequest{Network: "n", Table: TableMAC, Clear: true, MAC: net.HardwareAddr{1, 2, 3, 4, 5, 6, 7, 8}}, 0, "a MAC address has 6 bytes, not 8"},
	} {
		op, err := c.q.operation()
		if c.err != "" {
			if !errors.Is(err, intent.ErrInvalid) || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%+v asks %+v (%v), want an error that says %q", c.q, op, err, c.err)
			}
			continue
		}
		if err != nil || op.GetKind() != c.kind || op.GetNetwork() != "n" {
			t.Errorf("%+v asks %+v (%v), want the kind %v", c.q, op, err, c.kind)
		}
	}
	// An IPv4 address that is written as an IPv6 one is sent as the 4 bytes of the IPv4 one
	op, err := TableRequest{Network: "n", Table: TableIP, Clear: true, Address: addr}.operation()
	if err != nil || !slices.Equal(op.GetAddress(), []byte{10, 0, 0, 1}) {
		t.Errorf("the clear of ::ffff:10.0.0.1 asks %+v (%v), want the 4 bytes of 10.0.0.1", op, err)
	}
	// What the request says is what the audit log says of it
	q := TableRequest{Network: "corp-dmz", Node: "branch-1", Table: TableMAC, Clear: true, MAC: mac}
	if q.action() != "mac-table-clear" || q.subject() != "network corp-dmz on node branch-1, entry 02:00:5e:10:00:01" {
		t.Errorf("the audit record of %+v has the action %q and the subject %q", q, q.action(), q.subject())
	}
}

// The reason of a ban is text of a bounded length, with no control character.
func TestCheckBanReason(t *testing.T) {
	for _, c := range []struct {
		reason string
		ok     bool
	}{
		{"", true},
		{"stolen laptop", true},
		{"left the company; émigré", true},
		{strings.Repeat("x", MaxBanReason), true},
		{strings.Repeat("x", MaxBanReason+1), false},
		{"two\nlines", false},
		{"tab\there", false},
		{"no \xff text", false},
	} {
		err := checkBanReason(c.reason)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, intent.ErrInvalid)) {
			t.Errorf("the reason %q gave %v, want ok %v", c.reason, err, c.ok)
		}
	}
}

// The message of a Refuse is cut at a character, so that the ban of a user with a long reason that is not
// ASCII still makes a Refuse that can be encoded: cut at a byte, it would end inside a character.
func TestRefusalIsCutAtACharacter(t *testing.T) {
	reason := strings.Repeat("é", MaxBanReason/2)
	r := refusal(controlpb.RefuseReason_REFUSE_REASON_OPERATOR, "%s", banReason(store.Ban{User: "alice", Reason: reason}))
	msg := r.GetMessage()
	if len(msg) > maxRefuseMessage || !utf8.ValidString(msg) || !strings.HasPrefix(msg, `User "alice" is banned: é`) {
		t.Errorf("the message of the Refuse has %d bytes and is %q, want at most %d bytes of text that starts with the ban", len(msg), msg, maxRefuseMessage)
	}
	if _, err := proto.Marshal(r); err != nil {
		t.Errorf("the Refuse of a ban cannot be encoded: %v", err)
	}
}
