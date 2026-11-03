package forkimport

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The access list. The fork judges a frame by the first active entry of the list of its Virtual Hub whose match holds,
// in the order of the priorities, a pass entry before a discard entry of one priority (CmpAccessList of HubTable.c),
// and lets through a frame that no entry matches (ApplyAccessListToForwardPacket of Hub.c). The Policies of a VRF are
// judged by the first match too, but a deny rule comes before an allow rule of one priority, and a flow that no rule
// allows is denied (ADR-0029). So the entries become Policies in the order of the fork, each priority that the order
// needs a step of its own, and a last Policy allows what no entry matches. The reading of an entry is the one of the
// import into the configuration store of a Node (ConfigStoreImport.c, CORE-S4-3 #76): what a Policy has no match for
// never lets through the first packet of a flow that the fork dropped. The replies of a flow that a Policy allowed pass
// on the conntrack table (ADR-0029), where the fork judged every frame by itself.

const (
	// maxEntries is the most entries of an access list that the fork loads of a Virtual Hub (MAX_ACCESSLISTS).
	maxEntries = 4096 * 8
	// priorityStep is the distance between the priorities of the Policies, so that an operator can put a Policy of
	// its own between two of them.
	priorityStep = 10
	// rulesRoom is the number of Policies of a VRF above which a note warns: the desired state of a Node holds 64
	// objects at most (Update.set of control.options), its VRFs, Networks, peers and every rule that can match at
	// it among them.
	rulesRoom = 40
)

// entry is an entry of the access list of a Virtual Hub as the fork loads it (SiLoadHubAccessCfg of Server.c).
type entry struct {
	// index is its place among the folders of the list, which the fork loads in that order.
	index int
	// active is Active, discard is Discard: an entry that is discard denies, the others allow.
	active, discard bool
	// ipv6 is IsIPv6: its addresses and protocol are those of IPv6, and it matches the packets of IPv6.
	ipv6 bool
	// priority is Priority: the entries judge in the order of their priorities, the lowest first.
	priority uint32
	// src, srcMask, dst and dstMask are its addresses and their masks, IPv4 in the first 4 bytes.
	src, srcMask, dst, dstMask [16]byte
	// protocol is Protocol, 0 for any.
	protocol uint32
	// srcPorts and dstPorts are the first and the last of its ports, both 0 for any.
	srcPorts, dstPorts [2]uint32
	// srcUser and dstUser are SrcUsername and DestUsername: a user or a group, as the fork matches either.
	srcUser, dstUser string
	// checkSrcMac and checkDstMac are the matches by MAC address that the fork can read.
	checkSrcMac, checkDstMac bool
	// checkTCP is CheckTcpState: the entry matches by the state of a TCP segment.
	checkTCP bool
	// effects says that the entry has a Delay, a Jitter or a Loss, redirect that it has a RedirectUrl.
	effects, redirect bool
	// note is Note.
	note string
}

// readEntries reads the entries of the access list folder list, in the order of its folders, at most maxEntries.
func readEntries(list *Folder) []entry {
	var out []entry
	for i, f := range list.Sorted() {
		if i >= maxEntries {
			break
		}
		out = append(out, readEntry(f, i))
	}
	return out
}

// readEntry reads the folder f of an entry, the index-th of its list.
func readEntry(f *Folder, index int) entry {
	e := entry{index: index, note: displayName(f.Str("Note")), active: f.Bool("Active"), discard: f.Bool("Discard"),
		ipv6: f.Bool("IsIPv6"), priority: f.Uint("Priority"), protocol: f.Uint("Protocol"),
		srcUser: f.Str("SrcUsername"), dstUser: f.Str("DestUsername")}
	suffix := ""
	if e.ipv6 {
		suffix = "6"
	}
	e.src = addressField(f, "SrcIpAddress"+suffix, e.ipv6)
	e.srcMask = addressField(f, "SrcSubnetMask"+suffix, e.ipv6)
	e.dst = addressField(f, "DestIpAddress"+suffix, e.ipv6)
	e.dstMask = addressField(f, "DestSubnetMask"+suffix, e.ipv6)
	e.srcPorts = [2]uint32{f.Uint("SrcPortStart"), f.Uint("SrcPortEnd")}
	e.dstPorts = [2]uint32{f.Uint("DestPortStart"), f.Uint("DestPortEnd")}
	// A range that has a first port ends at it at least (AddAccessListEx of HubTable.c)
	if e.srcPorts[0] != 0 {
		e.srcPorts[1] = max(e.srcPorts[1], e.srcPorts[0])
	}
	if e.dstPorts[0] != 0 {
		e.dstPorts[1] = max(e.dstPorts[1], e.dstPorts[0])
	}
	e.checkSrcMac = f.Bool("CheckSrcMac") && macOK(f, "SrcMacAddress") && macOK(f, "SrcMacMask")
	e.checkDstMac = f.Bool("CheckDstMac") && macOK(f, "DstMacAddress") && macOK(f, "DstMacMask")
	e.checkTCP = f.Bool("CheckTcpState")
	e.effects = f.Uint("Delay") != 0 || f.Uint("Jitter") != 0 || f.Uint("Loss") != 0
	e.redirect = strings.TrimSpace(f.Str("RedirectUrl")) != ""
	return e
}

// addressField reads the address item name of f as the fork does: an IPv6 address, or an IPv4 address in the first 4
// bytes, all 0 for none.
func addressField(f *Folder, name string, v6 bool) [16]byte {
	var out [16]byte
	a, err := netip.ParseAddr(strings.TrimSpace(f.Str(name)))
	if err != nil {
		return out
	}
	if v6 {
		if a.Is6() && a.Zone() == "" {
			out = a.As16()
		}
		return out
	}
	if a.Is4() {
		b := a.As4()
		copy(out[:], b[:])
	}
	return out
}

// macOK reports whether the item name of f reads as a MAC address, as the fork reads one: a byte item, or the text of
// six bytes, whose hex digits are what counts.
func macOK(f *Folder, name string) bool {
	if len(f.Bytes(name)) != 0 {
		return true
	}
	digits := 0
	for _, c := range []byte(f.Str(name)) {
		if _, ok := hexDigit(c); ok {
			digits++
		}
	}
	return digits/2 == 6
}

// isZero reports whether every byte of b is 0.
func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// aclName returns the user or group that the item SrcUsername or DestUsername raw of an entry names, as the fork matches
// it: what comes before an @, and after the domain and its backslash, without the spaces at its ends. file is true
// for a list of users in a file, include: or exclude:, which a Policy cannot hold.
func aclName(raw string) (name string, file bool) {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "include:") || strings.HasPrefix(lower, "exclude:") {
		return "", true
	}
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	if i := strings.IndexByte(raw, '@'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '\\'); i >= 0 {
		raw = raw[i+1:]
		if j := strings.IndexByte(raw, '\\'); j >= 0 {
			raw = raw[:j]
		}
	}
	return strings.TrimSpace(raw), false
}

// prefixOf returns the prefix that an address and a mask of the fork make: the address with the first bits kept, as many
// as the mask has ones at its start. present is false for a side that has no address and no mask, which every address
// meets, and exact for a mask that is a prefix: the fork matches the addresses whose bits under the mask equal the
// ones of the address, which the prefix holds all of and more than, when the ones of the mask are not all at its start.
func prefixOf(addr, mask [16]byte, v6 bool) (p netip.Prefix, present, exact bool) {
	size := 4
	if v6 {
		size = 16
	}
	if isZero(addr[:size]) && isZero(mask[:size]) {
		return netip.Prefix{}, false, true
	}
	exact = true
	length := 0
	zero := false
	for i := 0; i < size*8; i++ {
		shift := i % 8
		bit := mask[i/8] << shift & 0x80
		switch {
		case bit == 0:
			zero = true
		case zero:
			exact = false
		default:
			length++
		}
	}
	if v6 {
		p = netip.PrefixFrom(netip.AddrFrom16(addr), length)
	} else {
		p = netip.PrefixFrom(netip.AddrFrom4([4]byte(addr[:4])), length)
	}
	return p.Masked(), true, exact
}

// addressText writes the prefix p of an end of a Policy in the one form that intent keeps: an address alone for the
// prefix of its whole length.
func addressText(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// protocolName writes the IP protocol n of an entry as the protocol of a Policy: empty for any, the name of ICMP, TCP and
// UDP, else the number.
func protocolName(n uint32) string {
	switch n {
	case 0:
		return ""
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return strconv.FormatUint(uint64(n), 10)
}

// byForkOrder orders two entries as the fork does (CmpAccessList): by priority, a pass entry before a discard entry,
// then by their place in the list, which leaves the verdicts as they are: two entries of one priority and one action
// judge a frame alike whichever comes first.
func byForkOrder(a, b entry) int {
	return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(boolInt(a.discard), boolInt(b.discard)), cmp.Compare(a.index, b.index))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// accessList makes the Policies of the access list folder list of the hub: one for each rule of each entry, named
// <vrf>-acl-<n>, or <vrf>-acl-<n>-<k> when the entry takes several (ports without a protocol take TCP and UDP, and the
// TCP state takes TCP alone), where n is the place of the entry in the order of the fork, which is its Id in vpncmd; and <vrf>-default-allow,
// which lets through what no entry matches. The priority of a Policy is a step of priorityStep for each priority and
// action of an entry that comes before it. It returns the entries that the fork loads and the Policies made.
func (h *hubImport) accessList(list *Folder) (entries, policies int) {
	if n := len(list.Sorted()); n > maxEntries {
		h.say("the fork loads %d entries of an access list at most: the last %d are left out", maxEntries, n-maxEntries)
	}
	all := readEntries(list)
	slices.SortStableFunc(all, byForkOrder)
	rank := 0
	inactive := 0
	for i, e := range all {
		if i == 0 || e.priority != all[i-1].priority || e.discard != all[i-1].discard {
			rank++
		}
		if !e.active {
			inactive++
			continue
		}
		priority := uint32(rank) * priorityStep
		policies += h.entry(e, i+1, priority)
	}
	if inactive > 0 {
		h.say("inactive entries left out: %d", inactive)
	}
	name := h.im.names.take(intent.KindPolicy, h.prefix+"-default-allow")
	h.im.add(intent.KindPolicy, name, intent.Policy{VRF: h.vrf, Action: intent.PolicyAllow, Priority: intent.MaxPriority})
	policies++
	if policies > rulesRoom {
		h.say("%d Policies: the desired state of a Node holds 64 objects at most, its VRFs, Networks, peers and the rules that can match at it among them, so a VRF with this many rules has room for few Nodes", policies)
	}
	return len(all), policies
}

// entry makes the Policies of the active entry e, the n-th of the list in the order of the fork, at the priority
// priority, and returns how many. What a Policy has no match for (MAC addresses, source ports, the TCP state, user list
// files, a mask that is no prefix) never lets through a frame that the fork dropped: a deny entry is carried without
// it, so that it denies more, and an allow entry that has it is left out. An entry with a redirect URL is carried as a
// deny entry, as the fork drops the TCP data that it redirects, and the delay, the jitter and the loss of an entry are
// left out.
func (h *hubImport) entry(e entry, n int, priority uint32) int {
	label := fmt.Sprintf("entry %d", n)
	if e.note != "" {
		label += " (" + strconv.Quote(e.note) + ")"
	}

	var lacks []string
	if e.checkSrcMac {
		lacks = append(lacks, "source MAC addresses")
	}
	if e.checkDstMac {
		lacks = append(lacks, "destination MAC addresses")
	}
	if e.srcPorts[0] != 0 || e.srcPorts[1] != 0 {
		lacks = append(lacks, "source ports")
	}
	if e.checkTCP {
		lacks = append(lacks, "the TCP state")
	}
	src, srcFile := aclName(e.srcUser)
	dst, dstFile := aclName(e.dstUser)
	if srcFile || dstFile {
		lacks = append(lacks, "user list files")
	}
	srcPrefix, srcAddr, srcExact := prefixOf(e.src, e.srcMask, e.ipv6)
	dstPrefix, dstAddr, dstExact := prefixOf(e.dst, e.dstMask, e.ipv6)
	if !srcExact || !dstExact {
		lacks = append(lacks, "masks that are no prefix")
	}

	// The destination ports; a range that the fork never matches makes an entry that matches nothing
	dead := false
	ports := ""
	if e.dstPorts[0] != 0 || e.dstPorts[1] != 0 {
		last := min(e.dstPorts[1], 65535)
		switch {
		case e.dstPorts[0] > last:
			dead = true
		case e.dstPorts[0] == last:
			ports = strconv.FormatUint(uint64(last), 10)
		default:
			ports = strconv.FormatUint(uint64(e.dstPorts[0]), 10) + "-" + strconv.FormatUint(uint64(last), 10)
		}
	}

	// The protocols: TCP for the TCP state, TCP or UDP for ports, both for ports without a protocol; an entry whose
	// protocol cannot have the TCP state or ports matches nothing
	withPorts := e.srcPorts[0] != 0 || e.srcPorts[1] != 0 || e.dstPorts[0] != 0 || e.dstPorts[1] != 0
	var protocols []string
	switch {
	case e.checkTCP:
		if e.protocol == 0 || e.protocol == 6 {
			protocols = []string{"tcp"}
		} else {
			dead = true
		}
	case withPorts:
		switch e.protocol {
		case 0:
			protocols = []string{"tcp", "udp"}
		case 6:
			protocols = []string{"tcp"}
		case 17:
			protocols = []string{"udp"}
		default:
			dead = true
		}
	case e.protocol > 255:
		dead = true
	default:
		protocols = []string{protocolName(e.protocol)}
	}
	// A Policy of the protocol icmp judges the ICMP of either family, where an entry of IPv6 that names the protocol 1
	// matches nothing; and a Policy holds no IPv4-mapped IPv6 address, which no frame of IPv6 carries either
	if e.ipv6 && e.protocol == 1 {
		dead = true
	}
	if (srcAddr && srcPrefix.Addr().Is4In6()) || (dstAddr && dstPrefix.Addr().Is4In6()) {
		dead = true
	}

	allow := !e.discard && !e.redirect
	switch {
	case dead:
		h.say("%s matches no frame in the fork: left out", label)
		return 0
	case len(lacks) > 0 && allow:
		h.say("%s left out: it lets through what it matches by %s, which a Policy cannot match, so it would let through more than the fork does", label, strings.Join(lacks, ", "))
		return 0
	case len(lacks) > 0:
		h.say("%s carried without its match by %s, which a Policy cannot match: it denies more than the fork does", label, strings.Join(lacks, ", "))
	}
	if e.redirect {
		h.say("%s has a redirect URL: carried as a deny rule, which drops the flow where the fork drops its data and redirects it", label)
	} else if e.effects && !e.discard {
		h.say("%s: its delay, jitter and loss are left out", label)
	}

	// An entry with a protocol, ports or the TCP state and without addresses takes every address of its family, as the
	// fork matches the packets of one family only
	everyAddress := "0.0.0.0/0"
	if e.ipv6 {
		everyAddress = "::/0"
	}
	family := e.protocol != 0 || withPorts || e.checkTCP
	var policies []intent.Policy
	for _, protocol := range protocols {
		pol := intent.Policy{VRF: h.vrf, Action: intent.PolicyDeny, Priority: priority, Protocol: intent.PolicyValue(protocol)}
		if allow {
			pol.Action = intent.PolicyAllow
		}
		if src != "" {
			pol.From.Tags = []string{h.tagOf(src)}
		}
		if srcAddr {
			pol.From.Addresses = []string{addressText(srcPrefix)}
		} else if family && !dstAddr {
			pol.From.Addresses = []string{everyAddress}
		}
		if dst != "" {
			pol.To.Tags = []string{h.tagOf(dst)}
		}
		if dstAddr {
			pol.To.Addresses = []string{addressText(dstPrefix)}
		}
		if ports != "" {
			pol.Ports = []intent.PolicyValue{intent.PolicyValue(ports)}
		}
		policies = append(policies, pol)
	}
	for _, p := range []netip.Prefix{srcPrefix, dstPrefix} {
		if p.Addr().Is4() && p.Bits() > 0 {
			h.prefixes = append(h.prefixes, p)
		}
	}

	base := fmt.Sprintf("%s-acl-%d", h.prefix, n)
	for k, pol := range policies {
		name := base
		if len(policies) > 1 {
			name = base + "-" + strconv.Itoa(k+1)
		}
		h.im.add(intent.KindPolicy, h.im.names.take(intent.KindPolicy, name), pol)
	}
	return len(policies)
}
