package controller

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The fuzz tests of the live operations (SDN-50 #243), which the controller workflow runs with go test
// -fuzz (ADR-0040 item 1, .github/quality/fuzz-targets.txt).

// FuzzTableEntries reads the input as what a node lists in the OperationResult of a table (tableEntries): a
// MAC address, an address, the name of a member, a VLAN and a time, which the one entry repeats up to 700 times,
// so that the 512 entries that the controller takes at most are met. A node is not trusted, so whatever the
// bytes are the controller takes no more than 512 entries, each one well formed and in order, counts every one
// that it leaves out, and the answer that holds them can be written as JSON.
func FuzzTableEntries(f *testing.F) {
	f.Add(tableMAC(1), tableAddr("10.0.0.1"), "bob-phone", uint32(20), uint64(1700000000123), uint16(3), false)
	f.Add(tableMAC(2), tableAddr("fd00::5"), "", uint32(0), uint64(0), uint16(600), true)
	f.Add(tableMAC(3), tableAddr("::ffff:10.0.0.2"), "m", uint32(4094), uint64(maxLastSeenMs), uint16(1), true)
	f.Add([]byte{1, 2, 3, 4, 5}, []byte{10, 0, 0}, "no \xff text", uint32(math.MaxUint32), uint64(math.MaxUint64), uint16(0), true)
	f.Add([]byte(nil), []byte(nil), strings.Repeat("é", 40), uint32(1), uint64(maxLastSeenMs+1), uint16(700), false)

	f.Fuzz(func(t *testing.T, mac, addr []byte, member string, vlan uint32, seen uint64, count uint16, ip bool) {
		table := TableMAC
		if ip {
			table = TableIP
		}
		n := int(count) % 700
		entries := make([]*controlpb.TableEntry, n)
		for i := range entries {
			entries[i] = &controlpb.TableEntry{Vlan: vlan + uint32(i), Mac: mac, Address: addr, Member: member, LastSeenMs: seen + uint64(i)}
		}
		out, left := tableEntries(entries, table)
		if len(out) > maxTableEntries || len(out)+left != n {
			t.Fatalf("%d entries became %d with %d left out, want at most %d taken and every entry taken or counted", n, len(out), left, maxTableEntries)
		}
		for i, e := range out {
			if len(e.Member) > maxMember || !utf8.ValidString(e.Member) {
				t.Fatalf("entry %d has the member %q, want UTF-8 of at most %d bytes", i, e.Member, maxMember)
			}
			if e.MAC != "" {
				if hw, err := net.ParseMAC(e.MAC); err != nil || len(hw) != 6 {
					t.Fatalf("entry %d has the MAC address %q, want 6 bytes", i, e.MAC)
				}
			} else if table == TableMAC {
				t.Fatalf("entry %d of the MAC table has no MAC address", i)
			}
			a, err := netip.ParseAddr(e.Address)
			switch {
			case table == TableMAC && e.Address != "":
				t.Fatalf("entry %d of the MAC table has the address %q", i, e.Address)
			case table == TableIP && (err != nil || a.Is4In6() || a.Zone() != ""):
				t.Fatalf("entry %d of the IP table has the address %q, want an IPv4 or IPv6 address that is not IPv4-mapped", i, e.Address)
			}
			if i > 0 && out[i-1].VLAN > e.VLAN {
				t.Fatalf("entry %d has the VLAN %d after the VLAN %d, want them ordered", i, e.VLAN, out[i-1].VLAN)
			}
		}
		if _, err := json.Marshal(out); err != nil {
			t.Fatalf("the entries cannot be written as JSON: %v", err)
		}
	})
}

// FuzzCheckBanReason reads the input as the reason of a ban that an operator gives the API (checkBanReason):
// it is taken when it is text of at most MaxBanReason bytes with no control character, and then the Refuse
// that tells the node of the ban holds it, cut at a character, and can be encoded. One that is refused is an
// intent.ErrInvalid, so that the API answers 400.
func FuzzCheckBanReason(f *testing.F) {
	for _, s := range []string{"", "stolen laptop", "left the company; émigré", "two\nlines", "tab\there", "no \xff text", "next\u0085line",
		"line separator", strings.Repeat("x", MaxBanReason), strings.Repeat("é", MaxBanReason/2), strings.Repeat("é", MaxBanReason/2+1)} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, reason string) {
		if err := checkBanReason(reason); err != nil {
			if !errors.Is(err, intent.ErrInvalid) {
				t.Fatalf("the reason %q is refused with %v, which is no intent.ErrInvalid, so the API would not answer 400", reason, err)
			}
			return
		}
		if len(reason) > MaxBanReason || !utf8.ValidString(reason) || strings.ContainsFunc(reason, unicode.IsControl) {
			t.Fatalf("the reason %q is taken, and it has more than %d bytes, is no UTF-8 or holds a control character", reason, MaxBanReason)
		}
		r := refusal(controlpb.RefuseReason_REFUSE_REASON_OPERATOR, "%s", banReason(store.Ban{User: "alice", Reason: reason}))
		if _, err := proto.Marshal(r); err != nil {
			t.Fatalf("the Refuse of a ban for the reason %q cannot be encoded: %v", reason, err)
		}
	})
}
