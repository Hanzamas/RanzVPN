// Policy.h
// The policy engine of the new core (ADR-0019 decisions 1 and 3, ADR-0029; CORE-S4-2, #75): the stateful, identity-based
// firewall of the Networks of a Node, in place of the access list of the Hub, with the isolation set of the fork kept
// first-class. One engine serves L2 and L3 Networks; WFP only protects the host. The type is POLICY_ENGINE: POLICY is the
// per-session policy of the slim fork (CONTEXT.md).
//
// Rules. A document of JSON rules (PolicySetRules) defines the Networks, the address groups and the rules. A rule has a
// name, a priority, an action (allow or deny) and what it matches: the identity of the two ends of a flow (user, group,
// node tag), their addresses and address groups, the Network and the VLAN of the frame, the IP protocol, the destination
// ports and the direction ("forward" from the from end to the to end, or "both"). The rules of each Network are compiled
// into a table of its own, indexed by protocol and destination port, and evaluated once per flow on ingress, in the
// order of their priorities (the lowest first). The tables of a document replace those of the one before at once: a
// frame is judged by one document or the other, never by a part of each. A frame that no rule matches takes the default
// action of its Network, which is deny for every Network (ADR-0019 amendment of 2026-10-21): traffic passes only through
// rules that allow it.
//
// Connection tracking. The rules judge the first frame of a flow (TCP, UDP, an ICMP echo, another IP protocol); the
// frames that follow, in either direction, take the fast path of the conntrack table of the Network, so the replies of an
// allowed flow pass without a mirror rule, and an ICMP error about a tracked flow passes with it. A flow is bound to its
// two members: a frame of another member never takes it. Each Network bounds its table (maxFlows), whose memory is taken
// once: a full table evicts its least recently used flow. A flow expires after the timeout of its protocol and state,
// which the document sets per Network. After a new document, the next frame of each tracked flow has the flow judged
// again by the new rules, as its first frame was, so a rule taken out ends the flows it allowed. Frames to a broadcast or
// multicast address, later fragments (which have no ports) and ICMP messages other than echoes are judged one by one.
//
// Members and the isolation set. Each sender of frames is a member (PolicyAddMember): a user session, a cascade, a
// bridge or a node, in one Network, with its identity and its guard (POLICY_GUARD_*), the isolation set of the fork:
// client isolation (PrivacyFilter), the MAC and IP checks (CheckMac, CheckIP) with their limits (MaxMac, MaxIP), ARP and
// DHCP only (ArpDhcpOnly), no DHCP server (DHCPNoServer), no router advertisements (RAFilter), and the filters of IPv4,
// IPv6 and non-IP frames (FilterIPv4, FilterIPv6, FilterNonIP). The guard judges every frame that a member sends before
// the rules; its filters, ARP and DHCP only and its RA filter also judge every frame that the member gets (PolicyInput
// for a frame to it, PolicyDeliver for a frame to a group address), as the fork's Hub applies them on both sides. A member
// owns the source addresses it was given (PolicyBindMac, PolicyBindIp) and, under a check, those it sent from first, up
// to its limit; no other member of its Network may send from them. ARP, IPv6 neighbour discovery and DHCP pass the guard
// and not the rules, as the segment needs them. The security of an L2 Network (Core/SwitchSecurity.h; SDN-41, #234) adds
// two flags: the RA guard of a client, which sends no router advertisement and still gets those of the gateway
// (POLICY_GUARD_NO_ROUTER), and the gateway itself (POLICY_GUARD_GATEWAY), which is never refused a source address and
// owns each one it sends from, up to POLICY_MAX_GATEWAY of each kind, taking it over from a member that is no gateway, so
// that no member under a check can take an address of the gateway or keep one from it. The engine reads two VLAN tags of
// a frame, an outer and an inner one, and eight IPv6 extension headers of a packet: a member under the IP check or a DHCP
// or RA guard sends no frame that carries more, which could hide a source address, a DHCP server message or a router
// advertisement from them.
//
// Counters. Each rule counts the flows it allowed and the frames and bytes it matched, and the default action of each
// Network counts its own (PolicyGetCounters; PolicyCountersJson for the admin API, PolicyCountersText for the CLI). A rule
// keeps its counters across documents while its Network has a rule of its name.
//
// Time is the caller's, in ms, as for the switch (Switch.h): PolicyInput and PolicyAge take it.

#ifndef CORE_POLICY_H
#define CORE_POLICY_H

#include <windows.h>

#include <stdbool.h>

// The limits of a document and of an engine
#define POLICY_MAX_NAME     63      // Bytes of a name at most: of a Network, a rule, an address group, a user, a group or a tag
#define POLICY_MAX_DOCUMENT 1048576 // Bytes of a document at most
#define POLICY_MAX_NETWORKS 64      // Networks at most: of a document, and of an engine
#define POLICY_MAX_RULES    1024    // Rules of a document at most
#define POLICY_MAX_GROUPS   256     // Address groups of a document at most
#define POLICY_MAX_VALUES   64      // Values of one list at most: the users, groups, tags, addresses, VLANs or ports of a rule
#define POLICY_MAX_RANGES   4096    // Port ranges of a document at most
#define POLICY_MAX_MEMBERS  65536   // Members of an engine at most
#define POLICY_MAX_FLOWS    1048576 // Flows of the conntrack table of a Network at most
#define POLICY_MAX_IDS      32      // Groups, and tags, of a member at most
#define POLICY_MAX_BOUND    64      // Addresses of a member at most, of each kind (MAC, IP)
#define POLICY_MAX_GATEWAY  65536   // Addresses of each kind that a gateway (POLICY_GUARD_GATEWAY) owns at most

// The values of a member or a Network that sets none
#define POLICY_DEFAULT_MEMBERS 1024  // Members of an engine without max_members
#define POLICY_DEFAULT_FLOWS   65536 // Flows of a Network without maxFlows
#define POLICY_DEFAULT_MACS    1     // MAC addresses that a member may own, without a limit of its own
#define POLICY_DEFAULT_IPS     8     // IP addresses that a member may own, without a limit of its own

// The timeouts of a flow (ms), of a Network that sets none
#define POLICY_TCP_ESTABLISHED 3600000 // A TCP flow that both ends sent on (timeouts.tcpEstablished)
#define POLICY_TCP_TRANSITORY  120000  // ... that opens or closes (timeouts.tcpTransitory)
#define POLICY_TCP_CLOSED      10000   // ... after a reset, in every Network
#define POLICY_UDP_TIMEOUT     60000   // A UDP flow (timeouts.udp)
#define POLICY_ICMP_TIMEOUT    30000   // An ICMP echo (timeouts.icmp)
#define POLICY_OTHER_TIMEOUT   60000   // A flow of another IP protocol (timeouts.other)

// The actions of a rule and of a Network
#define POLICY_ALLOW 0 // Let the frame through
#define POLICY_DENY  1 // Drop it

// The kinds of Network
#define POLICY_L2 0 // Ethernet frames, switched
#define POLICY_L3 1 // IP packets, routed

// The families of an IP address
#define POLICY_IPV4 4 // IPv4: the address in the first 4 of 16 bytes
#define POLICY_IPV6 6 // IPv6

#define POLICY_NO_MEMBER 0xFFFFFFFF // No member: the end of a flow outside the Network, or what PolicyAddMember returns when it adds none

// The guard of a member: the isolation set of the fork
#define POLICY_GUARD_ISOLATE        0x0001 // Client isolation: no frame to a member that has it too (PrivacyFilter)
#define POLICY_GUARD_CHECK_MAC      0x0002 // Source MAC addresses of its own only (CheckMac, MaxMac); the sender of an ARP frame too
#define POLICY_GUARD_CHECK_IP       0x0004 // Source IP addresses of its own only (CheckIP, MaxIP); the sender of an ARP frame too
#define POLICY_GUARD_ARP_DHCP_ONLY  0x0008 // Frames to a group address: ARP, DHCP and IPv6 neighbour discovery only (ArpDhcpOnly)
#define POLICY_GUARD_NO_DHCP_SERVER 0x0010 // No DHCP or DHCPv6 server messages (DHCPNoServer)
#define POLICY_GUARD_NO_RA          0x0020 // No IPv6 router advertisements (RAFilter)
#define POLICY_GUARD_NO_IPV4        0x0040 // No IPv4 or ARP frames (FilterIPv4)
#define POLICY_GUARD_NO_IPV6        0x0080 // No IPv6 frames (FilterIPv6)
#define POLICY_GUARD_NO_NON_IP      0x0100 // No frames of another EtherType (FilterNonIP)
#define POLICY_GUARD_NO_ROUTER      0x0200 // Sends no IPv6 router advertisements, and still gets them (the RA guard of an L2 Network)
#define POLICY_GUARD_GATEWAY        0x0400 // The gateway of an L2 Network: never refused a source address, and owns those it sends from
#define POLICY_GUARD_ALL            0x07FF // Every flag

// The reasons of a verdict (POLICY_RESULT): a frame passes for one of the first five, and is dropped for any other
#define POLICY_PASS_RULE        0  // The first frame of a flow, or a frame that is no flow's, that a rule allowed
#define POLICY_PASS_DEFAULT     1  // ... that the default action of its Network allowed (none does: the default action is deny)
#define POLICY_PASS_FLOW        2  // A frame of a tracked flow, in either direction: the fast path
#define POLICY_PASS_RELATED     3  // An ICMP error about a tracked flow
#define POLICY_PASS_CONTROL     4  // ARP, IPv6 neighbour discovery or DHCP, which the rules do not judge
#define POLICY_DROP_RULE        5  // A rule denied it
#define POLICY_DROP_DEFAULT     6  // The default action of its Network denied it
#define POLICY_DROP_MALFORMED   7  // Shorter than its headers, or a header that is none
#define POLICY_DROP_MEMBER      8  // From a member that is none, or to one that left or is of another Network
#define POLICY_DROP_NETWORK     9  // Of a Network that the document in force does not define
#define POLICY_DROP_ISOLATED    10 // Between two members with client isolation
#define POLICY_DROP_MAC         11 // From a MAC address that the member does not own and may not take
#define POLICY_DROP_IP          12 // From an IP address that the member does not own and may not take
#define POLICY_DROP_BROADCAST   13 // To a group address, other than ARP, DHCP and neighbour discovery, under ARP and DHCP only
#define POLICY_DROP_DHCP_SERVER 14 // A DHCP or DHCPv6 server message of a member that may send none
#define POLICY_DROP_RA          15 // An IPv6 router advertisement of a member that may send none
#define POLICY_DROP_PROTOCOL    16 // An IPv4, IPv6 or non-IP frame of a member that filters them; one that carries more than the engine reads, of a member under the IP check or a DHCP or RA guard
#define POLICY_NUM_REASONS      17

// A member (PolicyAddMember). The strings are copied.
typedef struct POLICY_MEMBER_CONFIG {
	const char *Network;       // The name of its Network
	const char *User;          // Its user, NULL for none (a bridge, a node)
	const char *const *Groups; // Its groups
	UINT NumGroups;            // ... their number, POLICY_MAX_IDS at most
	const char *const *Tags;   // The tags of its node
	UINT NumTags;              // ... their number, POLICY_MAX_IDS at most
	UINT Guard;                // Its guard: POLICY_GUARD_* flags
	UINT MaxMacs;              // MAC addresses that it may own, POLICY_MAX_BOUND at most; 0 for POLICY_DEFAULT_MACS
	UINT MaxIps;               // ... and IP addresses; 0 for POLICY_DEFAULT_IPS
} POLICY_MEMBER_CONFIG;

// The verdict of a frame (PolicyInput)
typedef struct POLICY_RESULT {
	bool Pass;                      // The frame passes
	UINT Reason;                    // Why: POLICY_PASS_* or POLICY_DROP_*
	char Rule[POLICY_MAX_NAME + 1]; // The rule that judged the frame or its flow, default:deny for the default action of its Network; empty for none
	UINT64 Document;                // The number of the document that judged it, 0 for none
} POLICY_RESULT;

// The counters of an engine (PolicyGetStats)
typedef struct POLICY_STATS {
	UINT NumMembers;                    // The members
	UINT NumNetworks;                   // The Networks that members or documents named
	UINT64 Document;                    // The number of the document in force: 0 before the first
	UINT64 Frames;                      // Frames that PolicyInput judged
	UINT64 Reasons[POLICY_NUM_REASONS]; // ... by the reason of their verdict
} POLICY_STATS;

// The state of a Network (PolicyGetNetworkStats)
typedef struct POLICY_NETWORK_STATS {
	bool Defined;       // The document in force defines it; without it, the fields up to MaxFlows are 0
	UINT Mode;          // POLICY_L2 or POLICY_L3
	UINT DefaultAction; // POLICY_DENY
	UINT NumRules;      // The rules of its table
	UINT NumMembers;    // Its members
	UINT Flows;         // The flows of its conntrack table
	UINT MaxFlows;      // ... at most
	UINT64 Tracked;     // Flows that its tables took
	UINT64 Evicted;     // ... that left them as the least recently used of a full table
	UINT64 Expired;     // ... that left them after their timeout
} POLICY_NETWORK_STATS;

// The counters of a rule or of the default action of a Network (PolicyGetCounters)
typedef struct POLICY_COUNTERS {
	char Network[POLICY_MAX_NAME + 1]; // The Network
	char Rule[POLICY_MAX_NAME + 1];    // The rule, or default:deny for the default action of the Network
	bool Default;                      // The default action of the Network, not a rule
	UINT Priority;                     // The priority of the rule
	UINT Action;                       // POLICY_ALLOW or POLICY_DENY
	UINT64 Flows;                      // The flows it allowed, which the conntrack table took
	UINT64 Packets;                    // The frames it matched: those of the flows it allowed, in both directions, and those it judged alone
	UINT64 Bytes;                      // ... their bytes
} POLICY_COUNTERS;

// The policy engine of a Node, Policy.c
typedef struct POLICY_ENGINE POLICY_ENGINE;

// Policy.c
POLICY_ENGINE *PolicyNew(UINT max_members);
void PolicyFree(POLICY_ENGINE *p);
bool PolicySetRules(POLICY_ENGINE *p, const char *json, UINT size, char *error, UINT error_size);
UINT PolicyAddMember(POLICY_ENGINE *p, const POLICY_MEMBER_CONFIG *cfg);
bool PolicyDelMember(POLICY_ENGINE *p, UINT member);
bool PolicyBindMac(POLICY_ENGINE *p, UINT member, const UCHAR *mac);
bool PolicyBindIp(POLICY_ENGINE *p, UINT member, UINT family, const UCHAR *ip);
bool PolicyInput(POLICY_ENGINE *p, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size, POLICY_RESULT *r);
bool PolicyDeliver(POLICY_ENGINE *p, UINT from, UINT to, const UCHAR *frame, UINT size);
UINT PolicyAge(POLICY_ENGINE *p, UINT64 now);
void PolicyGetStats(POLICY_ENGINE *p, POLICY_STATS *st);
bool PolicyGetNetworkStats(POLICY_ENGINE *p, const char *network, POLICY_NETWORK_STATS *st);
UINT PolicyGetCounters(POLICY_ENGINE *p, POLICY_COUNTERS *list, UINT max);

// PolicyRules.c
bool PolicyParseRules(const char *json, UINT size, char *error, UINT error_size);
char *PolicyCountersJson(POLICY_ENGINE *p);
char *PolicyCountersText(POLICY_ENGINE *p);
void PolicyFreeString(char *s);

// PolicyTable.c: the rule tables that a document compiles to, as text (CORE-S4-3, #76)
char *PolicyTableText(const char *json, UINT size, char *error, UINT error_size);

#endif // CORE_POLICY_H
