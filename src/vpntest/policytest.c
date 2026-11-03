// policytest.c
// Named policy test of vpntest ("policy" command, CORE-S4-2 #75)
//
// The policy engine of the new core (src/Core/Policy.h) in process, with members whose frames the test builds byte for
// byte:
// - Golden family "policy". Each case puts one frame of a member into the engine and writes its verdict to the report as
//   "<n> <case>: pass|drop <reason> <rule> doc <document>"; it must have the reason that the case names, and the report
//   must match the golden file. A report ends with the state of its Networks, the counters of the rules and of the
//   default action of each Network, and the frames of the engine by reason.
//   - policy_conntrack.txt: TCP, UDP, ICMP, ICMPv6 and GRE flows that a rule allows one way, in an L2 and an L3 Network:
//     their replies pass on the fast path of the conntrack table with no rule for them, and so do the ICMP errors about
//     them; a flow is its two members', a reset ends one and a SYN after it opens another; fragments; a new document
//     judges the tracked flows again, so a rule taken out ends the flows it allowed; a flow expires after the timeout of
//     its protocol, and the ages of the flows take out the rest.
//   - policy_identity.txt: rules that match the user, the groups and the node tags of each end without case, address
//     groups of IPv4 and IPv6 prefixes, the addresses of an end outside the Network, the Network and the VLAN of a frame,
//     port ranges, the direction both, the priorities and the order of the document; then the counters as the JSON of
//     the admin API and the text of the CLI, with the default action of each Network.
//   - policy_isolation.txt: the isolation set of the fork: client isolation, the MAC and IP checks with their limits and
//     the addresses bound to a member, ARP and DHCP only, no DHCP server, the RA filter and the filters of IPv4, IPv6 and
//     non-IP frames, on the frames that a member sends and on those it gets (PolicyDeliver for a frame to a group
//     address); a member that leaves; malformed frames.
//   - policy_documents.txt: the documents that the engine takes and those it refuses, each with its reason, and the
//     bounds of a document and of an engine; PolicyParseRules and PolicySetRules agree on each.
// - Then: a full conntrack table gives its least recently used flow to a new one, and a flood of flows never takes a
//   table past its bound; the configurations of members that the engine refuses; and threads that judge frames while
//   the main thread puts two documents in force in turn: every verdict is that of the document whose number it carries.
// Print "POLICY TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Policy.h"

#include <stdio.h>
#include <string.h>

#define	PTEST_BUDGET			120000		// The test ends within this time, or the watchdog ends the process (ms)
#define	PTEST_FRAME_MAX			512			// Bytes of a frame of a case at most
#define	PTEST_LRU_FLOWS			64			// The bound of the conntrack table of the eviction case
#define	PTEST_FLOOD_BOUND		4096		// ... and of the flood
#define	PTEST_FLOOD				100000		// Flows of the flood
#define	PTEST_THREADS			4			// Threads that judge frames while the documents change
#define	PTEST_SPAN				300			// ms that the main thread changes documents while the threads judge
#define	PTEST_SWAPS				400			// Documents that it puts in force at most
#define	PTEST_BIG_RULES			1024		// Rules of the document whose indexes take more than a table may have
#define	PTEST_BIG_PORTED		64			// ... the first of them with PTEST_BIG_PORTS ports each
#define	PTEST_BIG_PORTS			64

// The TCP flags of a segment
#define	PT_FIN					0x01
#define	PT_SYN					0x02
#define	PT_RST					0x04
#define	PT_PSH					0x08
#define	PT_ACK					0x10

#define	PTEST_BIT(i)			(1u << (i))	// A member in the set of members that a delivery case must reach

// The reasons of a verdict (POLICY_PASS_*, POLICY_DROP_*) in a report
static const char *const ptest_reasons[POLICY_NUM_REASONS] =
{
	"pass-rule", "pass-default", "pass-flow", "pass-related", "pass-control", "drop-rule", "drop-default", "drop-malformed",
	"drop-member", "drop-network", "drop-isolated", "drop-mac", "drop-ip", "drop-broadcast", "drop-dhcp-server", "drop-ra",
	"drop-protocol",
};

// Group addresses
static const UCHAR pt_mac_bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const UCHAR pt_mac_all_nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};		// IPv6 ff02::1
static const UCHAR pt_mac_solicited[6] = {0x33, 0x33, 0xFF, 0x00, 0x00, 0x01};		// IPv6 ff02::1:ff00:1
static const UCHAR pt_mac_group_source[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};	// A group address, which is no source
static const UCHAR pt_ip_bcast[4] = {255, 255, 255, 255};
static const UCHAR pt_ip_any[4] = {0, 0, 0, 0};
static const UCHAR pt_ip_group[4] = {224, 0, 0, 7};
static const UCHAR pt_ip6_all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const UCHAR pt_ip6_solicited[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x00, 0x00, 0x01};

// policy_conntrack.txt: lab (L2) and wan (L3)
static const UCHAR pt_mac_alice[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x01};
static const UCHAR pt_mac_server[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x0A};
static const UCHAR pt_mac_carol[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x03};
static const UCHAR pt_ip_alice[4] = {10, 1, 0, 1};
static const UCHAR pt_ip_server[4] = {10, 1, 0, 10};
static const UCHAR pt_ip6_dave[16] = {0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};				// fd00::1
static const UCHAR pt_ip6_far[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05};		// 2001:db8::5, behind the gateway
static const UCHAR pt_gre[4] = {0x00, 0x00, 0x08, 0x00};													// A GRE header of an IPv4 payload

// policy_identity.txt: corp (L2) and ops (L3)
static const UCHAR pt_mac_ann[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x01};
static const UCHAR pt_mac_bob[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x02};
static const UCHAR pt_mac_srv[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x0A};
static const UCHAR pt_mac_prn[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x05};
static const UCHAR pt_mac_router[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0xFE};
static const UCHAR pt_ip_ann[4] = {10, 2, 1, 1};
static const UCHAR pt_ip_bob[4] = {10, 2, 1, 2};
static const UCHAR pt_ip_srv[4] = {10, 2, 0, 10};
static const UCHAR pt_ip_prn[4] = {10, 2, 5, 3};
static const UCHAR pt_ip_outside[4] = {10, 2, 9, 9};
static const UCHAR pt_ip_opsadm[4] = {10, 3, 0, 1};
static const UCHAR pt_ip_opssrv[4] = {10, 3, 0, 10};
static const UCHAR pt_ip6_ann[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};	// 2001:db8:1::1
static const UCHAR pt_ip6_srv[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};	// 2001:db8:2::10

// policy_isolation.txt: guest (L2)
static const UCHAR pt_mac_g1[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x11};
static const UCHAR pt_mac_g1b[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x12};	// A second address of g1, over its limit
static const UCHAR pt_mac_g2[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x21};
static const UCHAR pt_mac_gw[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x01};
static const UCHAR pt_mac_v4[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x31};
static const UCHAR pt_mac_v6[6] = {0x02, 0x00, 0x00, 0x00, 0x04, 0x41};
static const UCHAR pt_ip_g1[4] = {10, 4, 0, 11};
static const UCHAR pt_ip_g1b[4] = {10, 4, 0, 12};
static const UCHAR pt_ip_g1c[4] = {10, 4, 0, 13};
static const UCHAR pt_ip_g2[4] = {10, 4, 0, 21};
static const UCHAR pt_ip_g3[4] = {10, 4, 0, 23};
static const UCHAR pt_ip_gw[4] = {10, 4, 0, 1};
static const UCHAR pt_ip_v4[4] = {10, 4, 0, 31};
static const UCHAR pt_ip_v6[4] = {10, 4, 0, 41};
static const UCHAR pt_ip6_ll_g1[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11};
static const UCHAR pt_ip6_ll_g2[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21};
static const UCHAR pt_ip6_ll_gw[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const UCHAR pt_ip6_v4[16] = {0xFD, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31};
static const UCHAR pt_ip6_v6[16] = {0xFD, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41};
static const UCHAR pt_ip6_gw[16] = {0xFD, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

// The eviction, the flood and the threads: L3 Networks
static const UCHAR pt_ip_a[4] = {10, 5, 0, 1};
static const UCHAR pt_ip_b[4] = {10, 5, 0, 2};

// The document of policy_conntrack.txt: rules from the group staff and the user dave, and none for the replies
static const char pt_doc_conntrack[] =
	"{\"networks\": [{\"name\": \"lab\", \"mode\": \"l2\", \"maxFlows\": 64, \"timeouts\": {\"tcpEstablished\": 300, \"tcpTransitory\": 30, \"udp\": 20, \"icmp\": 10, \"other\": 40}},"
	" {\"name\": \"wan\", \"mode\": \"l3\"}],"
	" \"rules\": ["
	"{\"name\": \"web\", \"action\": \"allow\", \"priority\": 10, \"from\": {\"groups\": [\"staff\"]}, \"to\": {\"tags\": [\"server\"]}, \"protocol\": \"tcp\", \"ports\": [80, 443]},"
	"{\"name\": \"dns\", \"action\": \"allow\", \"priority\": 20, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": \"udp\", \"ports\": [53]},"
	"{\"name\": \"ping\", \"action\": \"allow\", \"priority\": 30, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": \"icmp\"},"
	"{\"name\": \"gre\", \"action\": \"allow\", \"priority\": 40, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": 47},"
	"{\"name\": \"wan-out\", \"action\": \"allow\", \"priority\": 50, \"networks\": [\"wan\"], \"from\": {\"users\": [\"dave\"]}}]}";

// ... and the document after it: gre is gone, ssh is new, and the other rules keep their names
static const char pt_doc_conntrack2[] =
	"{\"networks\": [{\"name\": \"lab\", \"mode\": \"l2\", \"maxFlows\": 64, \"timeouts\": {\"tcpEstablished\": 300, \"tcpTransitory\": 30, \"udp\": 20, \"icmp\": 10, \"other\": 40}},"
	" {\"name\": \"wan\", \"mode\": \"l3\"}],"
	" \"rules\": ["
	"{\"name\": \"ssh\", \"action\": \"allow\", \"priority\": 5, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": \"tcp\", \"ports\": [22]},"
	"{\"name\": \"web\", \"action\": \"allow\", \"priority\": 10, \"from\": {\"groups\": [\"staff\"]}, \"to\": {\"tags\": [\"server\"]}, \"protocol\": \"tcp\", \"ports\": [80, 443]},"
	"{\"name\": \"dns\", \"action\": \"allow\", \"priority\": 20, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": \"udp\", \"ports\": [53]},"
	"{\"name\": \"ping\", \"action\": \"allow\", \"priority\": 30, \"from\": {\"groups\": [\"staff\"]}, \"protocol\": \"icmp\"},"
	"{\"name\": \"wan-out\", \"action\": \"allow\", \"priority\": 50, \"networks\": [\"wan\"], \"from\": {\"users\": [\"dave\"]}}]}";

// The document of policy_identity.txt
static const char pt_doc_identity[] =
	"{\"networks\": [{\"name\": \"corp\", \"mode\": \"l2\"}, {\"name\": \"ops\", \"mode\": \"l3\"}],"
	" \"addressGroups\": [{\"name\": \"dmz\", \"addresses\": [\"10.2.0.0/24\", \"2001:db8:2::/64\"]}],"
	" \"rules\": ["
	"{\"name\": \"ann-ssh\", \"action\": \"allow\", \"priority\": 1, \"from\": {\"users\": [\"ANN\"]}, \"to\": {\"tags\": [\"server\"]}, \"protocol\": \"tcp\", \"ports\": [22]},"
	"{\"name\": \"staff-web\", \"action\": \"allow\", \"priority\": 5, \"from\": {\"groups\": [\"staff\"]}, \"to\": {\"addressGroups\": [\"dmz\"]}, \"protocol\": \"tcp\", \"ports\": [80, \"8000-8080\"]},"
	"{\"name\": \"guests-no-dmz\", \"action\": \"deny\", \"priority\": 6, \"from\": {\"groups\": [\"guests\"]}, \"to\": {\"addressGroups\": [\"dmz\"]}},"
	"{\"name\": \"guests-web\", \"action\": \"allow\", \"priority\": 7, \"from\": {\"groups\": [\"guests\"]}, \"protocol\": \"tcp\", \"ports\": [80]},"
	"{\"name\": \"vlan-20\", \"action\": \"allow\", \"priority\": 8, \"networks\": [\"corp\"], \"vlans\": [20], \"protocol\": \"udp\"},"
	"{\"name\": \"print\", \"action\": \"allow\", \"priority\": 9, \"networks\": [\"corp\"], \"to\": {\"tags\": [\"printer\"]}, \"protocol\": \"tcp\", \"ports\": [9100]},"
	"{\"name\": \"admins\", \"action\": \"allow\", \"priority\": 10, \"networks\": [\"ops\"], \"from\": {\"groups\": [\"admins\"]}},"
	"{\"name\": \"snmp\", \"action\": \"allow\", \"priority\": 12, \"from\": {\"tags\": [\"printer\"]}, \"to\": {\"groups\": [\"staff\"]}, \"protocol\": \"udp\", \"ports\": [161], \"direction\": \"both\"},"
	"{\"name\": \"server-any\", \"action\": \"allow\", \"priority\": 30, \"networks\": [\"corp\"], \"from\": {\"tags\": [\"server\"]}},"
	"{\"name\": \"tie-deny\", \"action\": \"deny\", \"priority\": 40, \"protocol\": \"udp\", \"ports\": [9999]},"
	"{\"name\": \"tie-allow\", \"action\": \"allow\", \"priority\": 40, \"protocol\": \"udp\", \"ports\": [9999]},"
	"{\"name\": \"outside\", \"action\": \"allow\", \"priority\": 50, \"from\": {\"addresses\": [\"10.2.1.0/24\"]}, \"to\": {\"addresses\": [\"10.2.9.9\"]}, \"protocol\": 6}]}";

// The document of policy_isolation.txt: the starter rule lets everything through, so that only the guards drop
static const char pt_doc_isolation[] =
	"{\"networks\": [{\"name\": \"guest\", \"mode\": \"l2\"}], \"rules\": [{\"name\": \"starter\", \"action\": \"allow\", \"priority\": 1000000}]}";

// The document of the eviction and the flood
static const char pt_doc_eviction[] =
	"{\"networks\": [{\"name\": \"lru\", \"maxFlows\": 64}, {\"name\": \"flood\", \"maxFlows\": 4096, \"timeouts\": {\"udp\": 600}}],"
	" \"rules\": [{\"name\": \"out\", \"action\": \"allow\", \"from\": {\"users\": [\"a\"]}, \"protocol\": \"udp\"}]}";

// The two documents that the main thread puts in force in turn while the threads judge: A has the odd numbers
static const char pt_doc_swap_a[] =
	"{\"networks\": [{\"name\": \"swap\", \"maxFlows\": 16}], \"rules\": ["
	"{\"name\": \"a-allow\", \"action\": \"allow\", \"priority\": 1, \"protocol\": \"udp\", \"ports\": [7000]},"
	"{\"name\": \"a-deny\", \"action\": \"deny\", \"priority\": 2, \"protocol\": \"udp\", \"ports\": [7001]}]}";
static const char pt_doc_swap_b[] =
	"{\"networks\": [{\"name\": \"swap\", \"maxFlows\": 16}], \"rules\": ["
	"{\"name\": \"b-deny\", \"action\": \"deny\", \"priority\": 1, \"protocol\": \"udp\", \"ports\": [7000]},"
	"{\"name\": \"b-allow\", \"action\": \"allow\", \"priority\": 2, \"protocol\": \"udp\", \"ports\": [7001]}]}";

// A document of policy_documents.txt, and whether the engine takes it
typedef struct PTEST_DOC
{
	const char *Name;
	const char *Json;
	bool Accept;
} PTEST_DOC;

static const PTEST_DOC pt_docs[] =
{
	{"minimal", "{\"networks\": [{\"name\": \"lab\"}]}", true},
	{"every_key", "{\"networks\": [{\"name\": \"lab\", \"mode\": \"l2\", \"maxFlows\": 4, \"timeouts\": {\"tcpEstablished\": 604800, \"tcpTransitory\": 1, \"udp\": 1, \"icmp\": 1, \"other\": 1}}],"
		" \"addressGroups\": [{\"name\": \"g\", \"addresses\": [\"10.0.0.0/8\", \"::/0\", \"192.0.2.1\"]}, {\"name\": \"empty\"}],"
		" \"rules\": [{\"name\": \"r\", \"action\": \"deny\", \"priority\": 1000000, \"networks\": [\"lab\"], \"vlans\": [1, 4094],"
		" \"from\": {\"users\": [\"u\"], \"groups\": [\"g\"], \"tags\": [\"t\"], \"addresses\": [\"fe80::/10\"], \"addressGroups\": [\"g\", \"empty\"]}, \"to\": {},"
		" \"protocol\": \"udp\", \"ports\": [0, 65535, \"1-2\"], \"direction\": \"both\"}, {\"name\": \"default-allow-all\", \"action\": \"allow\", \"priority\": 1000000}]}", true},
	{"empty", "", false},
	{"not_json", "{\"networks\": [", false},
	{"not_an_object", "[{\"networks\": []}]", false},
	{"unknown_key", "{\"rulez\": []}", false},
	{"key_twice", "{\"networks\": [{\"name\": \"a\", \"name\": \"b\"}]}", false},
	{"more_keys_than_it_has", "{\"networks\": [{\"name\": \"a\", \"mode\": \"l2\", \"maxFlows\": 5, \"timeouts\": {}, \"mode\": \"l3\"}]}", false},
	{"networks_not_an_array", "{\"networks\": {\"name\": \"a\"}}", false},
	{"network_not_an_object", "{\"networks\": [\"lab\"]}", false},
	{"network_without_name", "{\"networks\": [{\"mode\": \"l2\"}]}", false},
	{"network_name_not_a_string", "{\"networks\": [{\"name\": 7}]}", false},
	{"network_name_with_a_space", "{\"networks\": [{\"name\": \"a b\"}]}", false},
	{"network_twice", "{\"networks\": [{\"name\": \"a\"}, {\"name\": \"a\"}]}", false},
	{"default_action", "{\"networks\": [{\"name\": \"a\", \"defaultAction\": \"allow\"}]}", false},
	{"mode_unknown", "{\"networks\": [{\"name\": \"a\", \"mode\": \"l4\"}]}", false},
	{"max_flows_zero", "{\"networks\": [{\"name\": \"a\", \"maxFlows\": 0}]}", false},
	{"max_flows_over_the_bound", "{\"networks\": [{\"name\": \"a\", \"maxFlows\": 1048577}]}", false},
	{"max_flows_not_whole", "{\"networks\": [{\"name\": \"a\", \"maxFlows\": 1.5}]}", false},
	{"timeouts_not_an_object", "{\"networks\": [{\"name\": \"a\", \"timeouts\": 30}]}", false},
	{"timeout_unknown", "{\"networks\": [{\"name\": \"a\", \"timeouts\": {\"sctp\": 30}}]}", false},
	{"timeout_over_a_week", "{\"networks\": [{\"name\": \"a\", \"timeouts\": {\"udp\": 604801}}]}", false},
	{"address_group_without_name", "{\"addressGroups\": [{\"addresses\": []}]}", false},
	{"address_group_twice", "{\"addressGroups\": [{\"name\": \"g\"}, {\"name\": \"g\"}]}", false},
	{"address_not_a_string", "{\"addressGroups\": [{\"name\": \"g\", \"addresses\": [10]}]}", false},
	{"prefix_too_long", "{\"addressGroups\": [{\"name\": \"g\", \"addresses\": [\"10.0.0.0/33\"]}]}", false},
	{"prefix_without_length", "{\"addressGroups\": [{\"name\": \"g\", \"addresses\": [\"10.0.0.0/\"]}]}", false},
	{"prefix_of_four_digits", "{\"addressGroups\": [{\"name\": \"g\", \"addresses\": [\"::/0128\"]}]}", false},
	{"address_not_an_address", "{\"addressGroups\": [{\"name\": \"g\", \"addresses\": [\"10.0.0.256\"]}]}", false},
	{"rule_without_action", "{\"rules\": [{\"name\": \"r\"}]}", false},
	{"action_unknown", "{\"rules\": [{\"name\": \"r\", \"action\": \"permit\"}]}", false},
	{"rule_twice", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\"}, {\"name\": \"r\", \"action\": \"deny\"}]}", false},
	{"priority_negative", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"priority\": -1}]}", false},
	{"priority_over_the_bound", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"priority\": 1000001}]}", false},
	{"rule_of_an_unknown_network", "{\"networks\": [{\"name\": \"lab\"}], \"rules\": [{\"name\": \"r\", \"action\": \"deny\", \"networks\": [\"nope\"]}]}", false},
	{"vlans_not_an_array", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"vlans\": 10}]}", false},
	{"vlan_4095", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"vlans\": [4095]}]}", false},
	{"vlan_zero", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"vlans\": [0]}]}", false},
	{"ports_without_protocol", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"ports\": [80]}]}", false},
	{"ports_of_icmp", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"icmp\", \"ports\": [1]}]}", false},
	{"port_range_backwards", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"udp\", \"ports\": [\"90-80\"]}]}", false},
	{"port_range_open", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"udp\", \"ports\": [\"80-\"]}]}", false},
	{"port_over_the_bound", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"tcp\", \"ports\": [65536]}]}", false},
	{"port_of_six_digits", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"tcp\", \"ports\": [\"123456\"]}]}", false},
	{"protocol_over_the_bound", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": 256}]}", false},
	{"protocol_unknown", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"protocol\": \"sctp\"}]}", false},
	{"end_not_an_object", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"from\": [\"u\"]}]}", false},
	{"end_unknown_key", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"from\": {\"user\": [\"u\"]}}]}", false},
	{"identity_with_a_space", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"from\": {\"users\": [\"a b\"]}}]}", false},
	{"address_group_unknown", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"to\": {\"addressGroups\": [\"nope\"]}}]}", false},
	{"direction_unknown", "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"direction\": \"reverse\"}]}", false},
};

// The test
typedef struct PTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	char OutDir[MAX_SIZE];						// The output and golden directories of the golden family "policy"
	char GoldenDir[MAX_SIZE];
	bool Update;								// Update mode: the golden files are written, not compared
} PTEST_CTX;

// A golden engine: an engine, the report of its golden file and the cases whose verdict is not the one they name
typedef struct PTEST_GOLDEN
{
	POLICY_ENGINE *Engine;
	bool SetupOk;								// Every member and document was made
	BUF *Report;
	UINT NumCases;
	UINT NumWrong;
	char Wrong[MAX_SIZE];						// ... their numbers
} PTEST_GOLDEN;

// A thread that judges frames while the documents change
typedef struct PTEST_JUDGE
{
	POLICY_ENGINE *Engine;
	HANDLE Start;								// Set when the threads begin
	volatile LONG *Stop;						// Set when they end
	UINT From;									// The member whose frames it judges
	UINT Index;									// Its number among the threads
	UINT64 Judged;								// Frames it judged
	UINT Torn;									// ... whose verdict is not that of the document whose number it carries
	UINT NoDocument;							// ... that no document judged
	HANDLE Thread;
} PTEST_JUDGE;

static bool PtCheck(PTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PtCheck(PTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so that a lost wake-up is a failed test instead of a hung CI
// step. Its parameter is the event that ends it.
static DWORD WINAPI PtWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, PTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "POLICY TEST FAILED (did not finish within %u ms)\n", (UINT)PTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The name of the reason of a verdict
static const char *PtReason(UINT reason)
{
	return (reason < POLICY_NUM_REASONS ? ptest_reasons[reason] : "unknown");
}

// Add a string to a buffer
static void PtAdd(BUF *b, const char *s)
{
	WriteBuf(b, s, StrLen(s));
}

//
// The frames
//

// The Ethernet header of a frame at f: to dst from src, of the EtherType type; its size
static UINT PtEth(UCHAR *f, const UCHAR *dst, const UCHAR *src, USHORT type)
{
	Copy(f, dst, 6);
	Copy(f + 6, src, 6);
	f[12] = (UCHAR)(type >> 8);
	f[13] = (UCHAR)type;

	return 14;
}

// Put a tag of the VLAN vlan into the untagged Ethernet frame f of size bytes, after its addresses; its new size
static UINT PtTag(UCHAR *f, UINT size, USHORT vlan)
{
	MoveMemory(f + 16, f + 12, size - 12);
	f[12] = 0x81;
	f[13] = 0x00;
	f[14] = (UCHAR)(vlan >> 8);
	f[15] = (UCHAR)vlan;

	return size + 4;
}

// An IP packet at f of the family family (POLICY_IPV4: addresses of 4 bytes, POLICY_IPV6: of 16) from src to dst of the
// IP protocol protocol, with the l4_size bytes at l4 after its header; its size
static UINT PtIp(UCHAR *f, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR protocol, const UCHAR *l4, UINT l4_size)
{
	if (family == POLICY_IPV4)
	{
		Zero(f, 20);
		f[0] = 0x45;
		f[2] = (UCHAR)((20 + l4_size) >> 8);
		f[3] = (UCHAR)(20 + l4_size);
		f[6] = 0x40;							// Don't fragment
		f[8] = 64;
		f[9] = protocol;
		Copy(f + 12, src, 4);
		Copy(f + 16, dst, 4);
		Copy(f + 20, l4, l4_size);

		return 20 + l4_size;
	}

	Zero(f, 40);
	f[0] = 0x60;
	f[4] = (UCHAR)(l4_size >> 8);
	f[5] = (UCHAR)l4_size;
	f[6] = protocol;
	f[7] = 64;
	Copy(f + 8, src, 16);
	Copy(f + 24, dst, 16);
	Copy(f + 40, l4, l4_size);

	return 40 + l4_size;
}

// A frame at f: in an L2 Network (dmac not NULL) the Ethernet header to dmac from smac, then the IP packet of PtIp; its
// size
static UINT PtFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR protocol, const UCHAR *l4,
	UINT l4_size)
{
	UINT head = 0;

	if (dmac != NULL)
	{
		head = PtEth(f, dmac, smac, family == POLICY_IPV4 ? 0x0800 : 0x86DD);
	}

	return head + PtIp(f + head, family, src, dst, protocol, l4, l4_size);
}

// A TCP header at l4 from the port sport to dport with the flags flags; its size
static UINT PtTcp(UCHAR *l4, USHORT sport, USHORT dport, UCHAR flags)
{
	Zero(l4, 20);
	l4[0] = (UCHAR)(sport >> 8);
	l4[1] = (UCHAR)sport;
	l4[2] = (UCHAR)(dport >> 8);
	l4[3] = (UCHAR)dport;
	l4[12] = 0x50;
	l4[13] = flags;
	l4[14] = 0xFF;
	l4[15] = 0xFF;

	return 20;
}

// A UDP datagram at l4 from the port sport to dport with 4 bytes of data; its size
static UINT PtUdp(UCHAR *l4, USHORT sport, USHORT dport)
{
	Zero(l4, 8);
	l4[0] = (UCHAR)(sport >> 8);
	l4[1] = (UCHAR)sport;
	l4[2] = (UCHAR)(dport >> 8);
	l4[3] = (UCHAR)dport;
	l4[5] = 12;
	Copy(l4 + 8, "RANZ", 4);

	return 12;
}

// A frame at f of a TCP segment (PtFrame, PtTcp); its size
static UINT PtTcpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, USHORT sport, USHORT dport,
	UCHAR flags)
{
	UCHAR l4[20];
	UINT n = PtTcp(l4, sport, dport, flags);

	return PtFrame(f, dmac, smac, family, src, dst, 6, l4, n);
}

// A frame at f of a UDP datagram (PtFrame, PtUdp); its size
static UINT PtUdpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, USHORT sport, USHORT dport)
{
	UCHAR l4[12];
	UINT n = PtUdp(l4, sport, dport);

	return PtFrame(f, dmac, smac, family, src, dst, 17, l4, n);
}

// A frame at f of an ICMP (family POLICY_IPV4) or ICMPv6 message of the type type, with the id id of an echo and 4 bytes
// of data; its size
static UINT PtIcmpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR type, USHORT id)
{
	UCHAR l4[12];

	Zero(l4, 8);
	l4[0] = type;
	l4[4] = (UCHAR)(id >> 8);
	l4[5] = (UCHAR)id;
	l4[7] = 1;
	Copy(l4 + 8, "ping", 4);

	return PtFrame(f, dmac, smac, family, src, dst, family == POLICY_IPV4 ? 1 : 58, l4, sizeof(l4));
}

// A frame at f of an ICMP or ICMPv6 error of the type type and the code code that quotes the first quoted_size bytes of
// the packet quoted; its size
static UINT PtIcmpErrorFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR type, UCHAR code,
	const UCHAR *quoted, UINT quoted_size)
{
	UCHAR l4[PTEST_FRAME_MAX];

	Zero(l4, 8);
	l4[0] = type;
	l4[1] = code;
	Copy(l4 + 8, quoted, quoted_size);

	return PtFrame(f, dmac, smac, family, src, dst, family == POLICY_IPV4 ? 1 : 58, l4, 8 + quoted_size);
}

// An ARP frame at f for Ethernet and IPv4 from smac to dmac: the operation op of the sender sha, spa for the target tpa;
// its size
static UINT PtArpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, USHORT op, const UCHAR *sha, const UCHAR *spa, const UCHAR *tpa)
{
	UCHAR *a = f + PtEth(f, dmac, smac, 0x0806);

	Zero(a, 28);
	a[1] = 1;									// Ethernet
	a[2] = 0x08;								// IPv4
	a[4] = 6;
	a[5] = 4;
	a[6] = (UCHAR)(op >> 8);
	a[7] = (UCHAR)op;
	Copy(a + 8, sha, 6);
	Copy(a + 14, spa, 4);
	Copy(a + 24, tpa, 4);

	return 14 + 28;
}

// A frame at f of the EtherType 0x88B5 (IEEE local experimental) from smac to dmac, with 6 bytes of data; its size
static UINT PtNonIpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac)
{
	UINT head = PtEth(f, dmac, smac, 0x88B5);

	Copy(f + head, "RANZPT", 6);

	return head + 6;
}

//
// The golden engines
//

// A golden engine of the default size, with an empty report
static PTEST_GOLDEN *PtNewGolden(void)
{
	PTEST_GOLDEN *g = ZeroMalloc(sizeof(PTEST_GOLDEN));

	g->Engine = PolicyNew(0);
	g->SetupOk = (g->Engine != NULL);
	g->Report = NewBuf();

	return g;
}

static void PtFreeGolden(PTEST_GOLDEN *g)
{
	PolicyFree(g->Engine);
	FreeBuf(g->Report);
	Free(g);
}

// A member of a golden engine in the Network network with its identity, guard and limits: its number. A member that the
// engine refuses fails the setup.
static UINT PtMember(PTEST_GOLDEN *g, const char *network, const char *user, const char *const *groups, UINT num_groups, const char *const *tags,
	UINT num_tags, UINT guard, UINT max_macs, UINT max_ips)
{
	POLICY_MEMBER_CONFIG c;
	UINT member = POLICY_NO_MEMBER;

	Zero(&c, sizeof(c));
	c.Network = network;
	c.User = user;
	c.Groups = groups;
	c.NumGroups = num_groups;
	c.Tags = tags;
	c.NumTags = num_tags;
	c.Guard = guard;
	c.MaxMacs = max_macs;
	c.MaxIps = max_ips;

	if (g->Engine != NULL)
	{
		member = PolicyAddMember(g->Engine, &c);
	}
	if (member == POLICY_NO_MEMBER)
	{
		g->SetupOk = false;
	}

	return member;
}

// Put a document in force in a golden engine; a document that it refuses fails the setup
static void PtSetRules(PTEST_GOLDEN *g, const char *json)
{
	char error[MAX_SIZE];

	if (g->Engine == NULL)
	{
		g->SetupOk = false;
	}
	else if (PolicySetRules(g->Engine, json, StrLen(json), error, sizeof(error)) == false)
	{
		Print("  the engine refuses the document: %s\n", error);
		g->SetupOk = false;
	}
}

// Whether a golden engine, its members and its document were made
static bool PtSetupOk(PTEST_CTX *ctx, PTEST_GOLDEN *g, char *what)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "%s: the engine, its members and its document are made", what);

	return PtCheck(ctx, g->SetupOk, tmp, "PolicyNew, PolicyAddMember, PolicyBindMac, PolicyBindIp or PolicySetRules failed");
}

// Note a case whose verdict is not the one it names
static void PtWrong(PTEST_GOLDEN *g)
{
	char num[16];

	Format(num, sizeof(num), " %u", g->NumCases);
	StrCat(g->Wrong, sizeof(g->Wrong), num);
	g->NumWrong++;
}

// A case: the member from sends the frame of size bytes, of the VLAN vlan, to the member to at now. Its verdict goes to
// the report as "<n> <name>: pass|drop <reason> <rule> doc <document>"; expect is the reason that it must have.
static void PtCase(PTEST_GOLDEN *g, const char *name, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size, UINT expect)
{
	char line[MAX_SIZE * 2];
	POLICY_RESULT r;
	bool pass = PolicyInput(g->Engine, now, from, to, vlan, frame, size, &r);

	g->NumCases++;
	Format(line, sizeof(line), "%u %s: %s %s %s doc %I64u\n", g->NumCases, name, pass ? "pass" : "drop", PtReason(r.Reason), r.Rule[0] != 0 ? r.Rule : "-",
		r.Document);
	PtAdd(g->Report, line);

	if (r.Reason != expect || pass != (expect <= POLICY_PASS_CONTROL))
	{
		PtWrong(g);
	}
}

// A delivery case: the frame of size bytes that the member from sent to a group address, offered to each of the num
// members (PolicyDeliver), whose names are names. The report gets "<n> <name>: <member> yes|no ..."; expect is the set of
// the members that must take it (PTEST_BIT of their places in the list).
static void PtDeliver(PTEST_GOLDEN *g, const char *name, UINT from, const UINT *members, const char *const *names, UINT num, const UCHAR *frame, UINT size,
	UINT expect)
{
	char line[MAX_SIZE * 2];
	UINT got = 0;

	g->NumCases++;
	Format(line, sizeof(line), "%u %s:", g->NumCases, name);
	for (UINT i = 0; i < num; i++)
	{
		bool ok = PolicyDeliver(g->Engine, from, members[i], frame, size);

		StrCat(line, sizeof(line), " ");
		StrCat(line, sizeof(line), names[i]);
		StrCat(line, sizeof(line), ok ? " yes" : " no");
		if (ok)
		{
			got |= PTEST_BIT(i);
		}
	}
	StrCat(line, sizeof(line), "\n");
	PtAdd(g->Report, line);

	if (got != expect)
	{
		PtWrong(g);
	}
}

// The end of a report: the state of the Networks nets, the counters of the document in force (for each of its Networks,
// its rules by priority, then its default action) and the frames of the engine by reason
static void PtTrailer(PTEST_GOLDEN *g, const char *const *nets, UINT num_nets)
{
	char line[MAX_SIZE * 2];
	char priority[16];
	POLICY_STATS st;
	UINT max = PolicyGetCounters(g->Engine, NULL, 0);
	POLICY_COUNTERS *list = ZeroMalloc(sizeof(POLICY_COUNTERS) * (max + 1));
	UINT num = PolicyGetCounters(g->Engine, list, max + 1);

	if (num > max + 1)
	{
		num = max + 1;
	}

	for (UINT i = 0; i < num_nets; i++)
	{
		POLICY_NETWORK_STATS ns;

		if (PolicyGetNetworkStats(g->Engine, nets[i], &ns) == false)
		{
			Format(line, sizeof(line), "network %s: unknown\n", nets[i]);
		}
		else if (ns.Defined == false)
		{
			Format(line, sizeof(line), "network %s: not in the document, members %u\n", nets[i], ns.NumMembers);
		}
		else
		{
			Format(line, sizeof(line), "network %s: %s, default %s, rules %u, members %u, flows %u of %u, tracked %I64u, evicted %I64u, expired %I64u\n",
				nets[i], ns.Mode == POLICY_L2 ? "l2" : "l3", ns.DefaultAction == POLICY_ALLOW ? "allow" : "deny", ns.NumRules, ns.NumMembers, ns.Flows,
				ns.MaxFlows, ns.Tracked, ns.Evicted, ns.Expired);
		}
		PtAdd(g->Report, line);
	}

	for (UINT i = 0; i < num; i++)
	{
		if (list[i].Default)
		{
			StrCpy(priority, sizeof(priority), "-");
		}
		else
		{
			Format(priority, sizeof(priority), "%u", list[i].Priority);
		}
		Format(line, sizeof(line), "counter %s %s: priority %s, %s, flows %I64u, packets %I64u, bytes %I64u\n", list[i].Network, list[i].Rule, priority,
			list[i].Action == POLICY_ALLOW ? "allow" : "deny", list[i].Flows, list[i].Packets, list[i].Bytes);
		PtAdd(g->Report, line);
	}

	PolicyGetStats(g->Engine, &st);
	Format(line, sizeof(line), "engine: members %u, networks %u, document %I64u, frames %I64u\n", st.NumMembers, st.NumNetworks, st.Document, st.Frames);
	PtAdd(g->Report, line);
	for (UINT k = 0; k < POLICY_NUM_REASONS; k++)
	{
		if (st.Reasons[k] != 0)
		{
			Format(line, sizeof(line), "frames %s: %I64u\n", PtReason(k), st.Reasons[k]);
			PtAdd(g->Report, line);
		}
	}

	Free(list);
}

// Check that every case of a golden engine had the verdict it names, and compare its report with the golden file
static void PtGoldenEnd(PTEST_CTX *ctx, PTEST_GOLDEN *g, char *file, char *what)
{
	HARNESS h;
	char tmp[MAX_SIZE];
	char *report = HarnessBufToStr(g->Report);

	Format(tmp, sizeof(tmp), "%s: every case has the verdict that it names", what);
	PtCheck(ctx, g->NumWrong == 0, tmp, "cases%s have another verdict (the report is below)", g->Wrong);
	if (g->NumWrong != 0)
	{
		Print("--- the report of %s:\n%s", file, report);
	}

	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, file, report, ctx->Update);
	Format(tmp, sizeof(tmp), "%s: the report matches the golden file %s", what, file);
	PtCheck(ctx, h.NumFail == 0, tmp, "it differs from the golden file (the diff is above)");

	Free(report);
}

//
// policy_conntrack.txt
//

// TCP, UDP, ICMP, ICMPv6 and GRE flows that a rule allows one way: their replies pass on the fast path with no rule for
// them; the ICMP errors about a flow; the end of a flow, fragments, a new document and the timeouts
static void PtConntrack(PTEST_CTX *ctx)
{
	static const char *const staff[] = {"staff"};
	static const char *const guests[] = {"guests"};
	static const char *const server_tags[] = {"server"};
	static const char *const gateway_tags[] = {"gateway"};
	static const char *const nets[] = {"lab", "wan"};
	PTEST_GOLDEN *g = PtNewGolden();
	UCHAR f[PTEST_FRAME_MAX];
	UCHAR l4[PTEST_FRAME_MAX];
	UCHAR quoted[PTEST_FRAME_MAX];
	char line[MAX_SIZE];
	UINT size;
	UINT n;

	Print("[conntrack: the replies of allowed flows pass without a mirror rule]\n");

	UINT alice = PtMember(g, "lab", "alice", staff, 1, NULL, 0, 0, 0, 0);
	UINT server = PtMember(g, "lab", NULL, NULL, 0, server_tags, 1, 0, 0, 0);
	UINT carol = PtMember(g, "lab", "carol", guests, 1, NULL, 0, 0, 0, 0);
	UINT dave = PtMember(g, "wan", "dave", NULL, 0, NULL, 0, 0, 0, 0);
	UINT gw = PtMember(g, "wan", NULL, NULL, 0, gateway_tags, 1, 0, 0, 0);
	PtSetRules(g, pt_doc_conntrack);

	if (PtSetupOk(ctx, g, "conntrack") == false)
	{
		PtFreeGolden(g);
		return;
	}

	// TCP in lab: the handshake, the data and the end of a flow that web allows from alice to the server
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40000, 80, PT_SYN);
	PtCase(g, "tcp_syn", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40000, PT_SYN | PT_ACK);
	PtCase(g, "tcp_syn_ack_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40000, 80, PT_ACK);
	PtCase(g, "tcp_ack", 1000, alice, server, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40000, PT_PSH | PT_ACK);
	PtCase(g, "tcp_data_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40001, PT_SYN);
	PtCase(g, "tcp_new_flow_from_server", 1000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_carol, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40000, PT_ACK);
	PtCase(g, "tcp_reply_from_another_member", 1000, carol, alice, 0, f, size, POLICY_DROP_DEFAULT);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40000, 80, PT_FIN | PT_ACK);
	PtCase(g, "tcp_fin", 1000, alice, server, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40000, PT_FIN | PT_ACK);
	PtCase(g, "tcp_fin_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40000, 80, PT_ACK);
	PtCase(g, "tcp_last_ack", 1000, alice, server, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40002, 22, PT_SYN);
	PtCase(g, "tcp_port_without_rule", 1000, alice, server, 0, f, size, POLICY_DROP_DEFAULT);

	// A reset ends a flow, a SYN after it opens a new one, and a reset opens none
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40003, 443, PT_SYN);
	PtCase(g, "tcp_syn_443", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 443, 40003, PT_RST | PT_ACK);
	PtCase(g, "tcp_reset_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40003, 443, PT_SYN);
	PtCase(g, "tcp_syn_after_reset", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40004, 80, PT_RST);
	PtCase(g, "tcp_reset_opens_no_flow", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40004, PT_ACK);
	PtCase(g, "tcp_reply_after_reset", 1000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);

	// UDP and ICMP
	size = PtUdpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40010, 53);
	PtCase(g, "udp_query", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 53, 40010);
	PtCase(g, "udp_answer", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtUdpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 53, 40011);
	PtCase(g, "udp_answer_to_another_port", 1000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);
	size = PtIcmpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 8, 0x4242);
	PtCase(g, "icmp_echo", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtIcmpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 0, 0x4242);
	PtCase(g, "icmp_echo_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtIcmpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 8, 0x4343);
	PtCase(g, "icmp_echo_from_server", 1000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);

	// ICMP errors that quote the IP header and the first 8 bytes of a UDP datagram: of the flow of udp_query, and of none
	n = PtUdp(l4, 40010, 53);
	PtIp(quoted, POLICY_IPV4, pt_ip_alice, pt_ip_server, 17, l4, n);
	size = PtIcmpErrorFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 3, 3, quoted, 28);
	PtCase(g, "icmp_error_about_a_flow", 1000, server, alice, 0, f, size, POLICY_PASS_RELATED);
	n = PtUdp(l4, 40099, 53);
	PtIp(quoted, POLICY_IPV4, pt_ip_alice, pt_ip_server, 17, l4, n);
	size = PtIcmpErrorFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 3, 3, quoted, 28);
	PtCase(g, "icmp_error_about_no_flow", 1000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);

	// Another IP protocol, GRE, and a later fragment of UDP, which has no ports and is judged alone
	size = PtFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 47, pt_gre, sizeof(pt_gre));
	PtCase(g, "gre", 1000, alice, server, 0, f, size, POLICY_PASS_RULE);
	size = PtFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 47, pt_gre, sizeof(pt_gre));
	PtCase(g, "gre_reply", 1000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtUdpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40010, 53);
	f[14 + 6] = 0x00;
	f[14 + 7] = 0xB9;
	PtCase(g, "udp_later_fragment", 1000, alice, server, 0, f, size, POLICY_DROP_DEFAULT);

	// wan, an L3 Network: IPv6 from dave to a host behind the gateway, and back
	size = PtTcpFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_dave, pt_ip6_far, 50000, 443, PT_SYN);
	PtCase(g, "ipv6_tcp_syn", 1000, dave, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_far, pt_ip6_dave, 443, 50000, PT_SYN | PT_ACK);
	PtCase(g, "ipv6_tcp_syn_ack_reply", 1000, gw, dave, 0, f, size, POLICY_PASS_FLOW);
	n = PtTcp(l4, 50000, 443, PT_SYN);
	PtIp(quoted, POLICY_IPV6, pt_ip6_dave, pt_ip6_far, 6, l4, n);
	size = PtIcmpErrorFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_far, pt_ip6_dave, 1, 0, quoted, 48);
	PtCase(g, "icmpv6_error_about_a_flow", 1000, gw, dave, 0, f, size, POLICY_PASS_RELATED);
	size = PtIcmpFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_dave, pt_ip6_far, 128, 7);
	PtCase(g, "icmpv6_echo", 1000, dave, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtIcmpFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_far, pt_ip6_dave, 129, 7);
	PtCase(g, "icmpv6_echo_reply", 1000, gw, dave, 0, f, size, POLICY_PASS_FLOW);
	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_far, pt_ip6_dave, 53, 5353);
	PtCase(g, "ipv6_new_flow_from_gateway", 1000, gw, dave, 0, f, size, POLICY_DROP_DEFAULT);

	// IPv6 with a hop-by-hop header and the fragment header of a first fragment, then a later fragment
	Zero(l4, 16);
	l4[0] = 44;									// Hop-by-hop options: the fragment header next, a PadN option
	l4[2] = 1;
	l4[3] = 4;
	l4[8] = 17;									// The fragment header: UDP next, offset 0, more fragments
	l4[11] = 0x01;
	l4[15] = 0x2A;
	n = PtUdp(l4 + 16, 50001, 53);
	size = PtFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_dave, pt_ip6_far, 0, l4, 16 + n);
	PtCase(g, "ipv6_first_fragment", 1000, dave, gw, 0, f, size, POLICY_PASS_RULE);
	Zero(l4, 16);
	l4[0] = 17;									// The fragment header of the next fragment: offset 8 bytes
	l4[3] = 0x08;
	l4[7] = 0x2A;
	size = PtFrame(f, NULL, NULL, POLICY_IPV6, pt_ip6_dave, pt_ip6_far, 44, l4, 16);
	PtCase(g, "ipv6_later_fragment", 1000, dave, gw, 0, f, size, POLICY_PASS_RULE);

	// A new document: gre is gone, ssh is new. Each tracked flow is judged again by it at its next frame.
	PtSetRules(g, pt_doc_conntrack2);
	PtAdd(g->Report, "a new document: gre is gone, ssh is new\n");
	size = PtFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 47, pt_gre, sizeof(pt_gre));
	PtCase(g, "gre_reply_after_its_rule_went", 2000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);
	size = PtFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 47, pt_gre, sizeof(pt_gre));
	PtCase(g, "gre_after_its_rule_went", 2000, alice, server, 0, f, size, POLICY_DROP_DEFAULT);
	size = PtIcmpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 0, 0x4242);
	PtCase(g, "icmp_echo_reply_of_a_kept_rule", 2000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 80, 40000, PT_ACK);
	PtCase(g, "tcp_reply_of_a_kept_rule", 2000, server, alice, 0, f, size, POLICY_PASS_FLOW);
	size = PtTcpFrame(f, pt_mac_server, pt_mac_alice, POLICY_IPV4, pt_ip_alice, pt_ip_server, 40020, 22, PT_SYN);
	PtCase(g, "tcp_of_the_new_rule", 2000, alice, server, 0, f, size, POLICY_PASS_RULE);

	// The UDP flow expires 20 s after its last frame; then the ages take out every flow of both Networks
	size = PtUdpFrame(f, pt_mac_alice, pt_mac_server, POLICY_IPV4, pt_ip_server, pt_ip_alice, 53, 40010);
	PtCase(g, "udp_answer_after_the_timeout", 21000, server, alice, 0, f, size, POLICY_DROP_DEFAULT);
	Format(line, sizeof(line), "ages at 301001 ms: %u flows expired\n", PolicyAge(g->Engine, 301001));
	PtAdd(g->Report, line);

	PtTrailer(g, nets, 2);
	PtGoldenEnd(ctx, g, "policy_conntrack.txt", "conntrack");
	PtFreeGolden(g);
}

//
// policy_identity.txt
//

// Rules that match identities, address groups, Networks, VLANs, ports, the direction both and the priorities; the
// counters as the admin API and the CLI show them
static void PtIdentity(PTEST_CTX *ctx)
{
	static const char *const staff[] = {"staff"};
	static const char *const guests[] = {"guests"};
	static const char *const admins[] = {"Admins"};
	static const char *const srv_tags[] = {"server", "linux"};
	static const char *const prn_tags[] = {"printer"};
	static const char *const server_tags[] = {"server"};
	static const char *const nets[] = {"corp", "ops"};
	PTEST_GOLDEN *g = PtNewGolden();
	UCHAR f[PTEST_FRAME_MAX];
	UINT size;

	Print("[identity: users, groups, tags, address groups, Networks, VLANs, ports and priorities]\n");

	UINT ann = PtMember(g, "corp", "ann", staff, 1, NULL, 0, 0, 0, 0);
	UINT bob = PtMember(g, "corp", "bob", guests, 1, NULL, 0, 0, 0, 0);
	UINT srv = PtMember(g, "corp", NULL, NULL, 0, srv_tags, 2, 0, 0, 0);
	UINT prn = PtMember(g, "corp", NULL, NULL, 0, prn_tags, 1, 0, 0, 0);
	UINT opsadm = PtMember(g, "ops", "Ops-Admin", admins, 1, NULL, 0, 0, 0, 0);
	UINT opssrv = PtMember(g, "ops", NULL, NULL, 0, server_tags, 1, 0, 0, 0);
	PtSetRules(g, pt_doc_identity);

	if (PtSetupOk(ctx, g, "identity") == false)
	{
		PtFreeGolden(g);
		return;
	}

	// Users without case, the tags and the address groups of the other end, port ranges and their bounds
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40000, 22, PT_SYN);
	PtCase(g, "user_without_case_to_a_tag", 1000, ann, srv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_srv, 40000, 22, PT_SYN);
	PtCase(g, "another_user_denied_by_a_group", 1000, bob, srv, 0, f, size, POLICY_DROP_RULE);
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40001, 80, PT_SYN);
	PtCase(g, "group_to_an_address_group", 1000, ann, srv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40002, 8000, PT_SYN);
	PtCase(g, "first_port_of_a_range", 1000, ann, srv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40003, 8080, PT_SYN);
	PtCase(g, "last_port_of_a_range", 1000, ann, srv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40004, 8081, PT_SYN);
	PtCase(g, "port_after_a_range", 1000, ann, srv, 0, f, size, POLICY_DROP_DEFAULT);

	// The priorities: a deny before an allow, and the allow where the deny does not match
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_srv, 40005, 80, PT_SYN);
	PtCase(g, "deny_before_allow", 1000, bob, srv, 0, f, size, POLICY_DROP_RULE);
	size = PtTcpFrame(f, pt_mac_prn, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_prn, 40006, 80, PT_SYN);
	PtCase(g, "allow_outside_the_address_group", 1000, bob, prn, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_prn, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_prn, 40007, 9100, PT_SYN);
	PtCase(g, "tag_of_the_destination", 1000, bob, prn, 0, f, size, POLICY_PASS_RULE);

	// The VLAN of a frame: tagged frames of VLANs 20 and 30, and an untagged one
	size = PtTag(f, PtUdpFrame(f, pt_mac_ann, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_ann, 40000, 5000), 20);
	PtCase(g, "vlan_of_the_rule", 1000, bob, ann, 20, f, size, POLICY_PASS_RULE);
	size = PtTag(f, PtUdpFrame(f, pt_mac_ann, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_ann, 40001, 5000), 30);
	PtCase(g, "another_vlan", 1000, bob, ann, 30, f, size, POLICY_DROP_DEFAULT);
	size = PtUdpFrame(f, pt_mac_ann, pt_mac_bob, POLICY_IPV4, pt_ip_bob, pt_ip_ann, 40002, 5000);
	PtCase(g, "no_vlan", 1000, bob, ann, 0, f, size, POLICY_DROP_DEFAULT);

	// Direction both: the rule matches from either end, to the destination port; rules of one priority in the order of
	// the document
	size = PtUdpFrame(f, pt_mac_ann, pt_mac_prn, POLICY_IPV4, pt_ip_prn, pt_ip_ann, 50000, 161);
	PtCase(g, "both_from_its_from_end", 1000, prn, ann, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_prn, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_prn, 50001, 161);
	PtCase(g, "both_from_its_to_end", 1000, ann, prn, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_srv, 40010, 9999);
	PtCase(g, "same_priority_first_in_the_document", 1000, ann, srv, 0, f, size, POLICY_DROP_RULE);

	// An IPv6 prefix of an address group, the addresses of an end outside the Network, and frames that are not IP
	size = PtTcpFrame(f, pt_mac_srv, pt_mac_ann, POLICY_IPV6, pt_ip6_ann, pt_ip6_srv, 40011, 80, PT_SYN);
	PtCase(g, "ipv6_prefix_of_an_address_group", 1000, ann, srv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, pt_mac_router, pt_mac_ann, POLICY_IPV4, pt_ip_ann, pt_ip_outside, 40012, 443, PT_SYN);
	PtCase(g, "addresses_of_an_end_outside", 1000, ann, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_RULE);
	size = PtNonIpFrame(f, pt_mac_ann, pt_mac_srv);
	PtCase(g, "not_ip_by_a_rule_of_any_protocol", 1000, srv, ann, 0, f, size, POLICY_PASS_RULE);
	size = PtNonIpFrame(f, pt_mac_srv, pt_mac_ann);
	PtCase(g, "not_ip_without_a_rule", 1000, ann, srv, 0, f, size, POLICY_DROP_DEFAULT);

	// ops, an L3 Network: a group without case, and a rule of another Network
	size = PtTcpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_opsadm, pt_ip_opssrv, 40000, 3389, PT_SYN);
	PtCase(g, "group_without_case", 1000, opsadm, opssrv, 0, f, size, POLICY_PASS_RULE);
	size = PtTcpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_opssrv, pt_ip_opsadm, 40001, 22, PT_SYN);
	PtCase(g, "rule_of_another_network", 1000, opssrv, opsadm, 0, f, size, POLICY_DROP_DEFAULT);

	PtTrailer(g, nets, 2);

	// The counters as the admin API and the CLI show them
	char *json = PolicyCountersJson(g->Engine);
	char *text = PolicyCountersText(g->Engine);

	PtAdd(g->Report, "admin api:\n");
	PtAdd(g->Report, json != NULL ? json : "(none)");
	PtAdd(g->Report, "\ncli:\n");
	PtAdd(g->Report, text != NULL ? text : "(none)\n");
	PtCheck(ctx, json != NULL && text != NULL && InStr(json, "\"defaultAction\":\"deny\"") && InStr(json, "\"name\":\"staff-web\"") &&
		InStr(text, "default action deny") && InStr(text, "default:deny"), "identity: the admin API JSON and the CLI text show the counters of each rule and the default action of each Network",
		"PolicyCountersJson or PolicyCountersText (the report is in the golden file)");
	PolicyFreeString(json);
	PolicyFreeString(text);

	PtGoldenEnd(ctx, g, "policy_identity.txt", "identity");
	PtFreeGolden(g);
}

//
// policy_isolation.txt
//

// The isolation set of the fork on the frames that a member sends and on those it gets; members that leave; malformed
// frames
static void PtIsolation(PTEST_CTX *ctx)
{
	static const char *const gateway_tags[] = {"gateway"};
	static const char *const nets[] = {"guest", "nowhere"};
	static const char *const names_a[] = {"g1", "gw", "v4", "v6"};
	static const char *const names_b[] = {"g1", "g2", "v4", "v6"};
	PTEST_GOLDEN *g = PtNewGolden();
	UCHAR f[PTEST_FRAME_MAX];
	UCHAR l4[PTEST_FRAME_MAX];
	UINT members[4];
	UINT size;

	Print("[isolation: client isolation, anti-spoofing, ARP and DHCP only, the RA filter and the protocol filters]\n");

	UINT g1 = PtMember(g, "guest", "g1", NULL, 0, NULL, 0,
		POLICY_GUARD_ISOLATE | POLICY_GUARD_CHECK_MAC | POLICY_GUARD_CHECK_IP | POLICY_GUARD_ARP_DHCP_ONLY | POLICY_GUARD_NO_DHCP_SERVER | POLICY_GUARD_NO_RA, 1, 2);
	UINT g2 = PtMember(g, "guest", "g2", NULL, 0, NULL, 0, POLICY_GUARD_ISOLATE | POLICY_GUARD_CHECK_MAC | POLICY_GUARD_CHECK_IP, 0, 0);
	UINT gw = PtMember(g, "guest", NULL, NULL, 0, gateway_tags, 1, 0, 0, 0);
	UINT v4 = PtMember(g, "guest", "v4", NULL, 0, NULL, 0, POLICY_GUARD_NO_IPV6 | POLICY_GUARD_NO_NON_IP, 0, 0);
	UINT v6 = PtMember(g, "guest", "v6", NULL, 0, NULL, 0, POLICY_GUARD_NO_IPV4, 0, 0);
	UINT stray = PtMember(g, "nowhere", "stray", NULL, 0, NULL, 0, 0, 0, 0);
	if (g->Engine != NULL && (PolicyBindMac(g->Engine, gw, pt_mac_gw) == false || PolicyBindIp(g->Engine, gw, POLICY_IPV4, pt_ip_gw) == false))
	{
		g->SetupOk = false;
	}
	PtSetRules(g, pt_doc_isolation);

	if (PtSetupOk(ctx, g, "isolation") == false)
	{
		PtFreeGolden(g);
		return;
	}

	// The MAC and IP checks: the first addresses of a member are its own up to its limits, and the addresses of another
	// member or bound to one are not
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_gw, 5000, 53);
	PtCase(g, "first_mac_and_ip_taken", 1000, g1, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1b, POLICY_IPV4, pt_ip_g1, pt_ip_gw, 5000, 53);
	PtCase(g, "second_mac_over_the_limit", 1000, g1, gw, 0, f, size, POLICY_DROP_MAC);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g1b, pt_ip_gw, 5001, 53);
	PtCase(g, "second_ip_within_the_limit", 1000, g1, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g1c, pt_ip_gw, 5001, 53);
	PtCase(g, "third_ip_over_the_limit", 1000, g1, gw, 0, f, size, POLICY_DROP_IP);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g2, pt_ip_gw, 5002, 53);
	PtCase(g, "mac_of_another_member", 1000, g2, gw, 0, f, size, POLICY_DROP_MAC);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g2, POLICY_IPV4, pt_ip_gw, pt_ip_gw, 5002, 53);
	PtCase(g, "ip_bound_to_the_gateway", 1000, g2, gw, 0, f, size, POLICY_DROP_IP);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g2, POLICY_IPV4, pt_ip_g2, pt_ip_gw, 5002, 53);
	PtCase(g, "own_addresses", 1000, g2, gw, 0, f, size, POLICY_PASS_RULE);

	// Client isolation between two members that have it, not with the gateway
	size = PtUdpFrame(f, pt_mac_g2, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_g2, 5003, 7);
	PtCase(g, "isolated_members", 1000, g1, g2, 0, f, size, POLICY_DROP_ISOLATED);
	size = PtUdpFrame(f, pt_mac_g1, pt_mac_gw, POLICY_IPV4, pt_ip_gw, pt_ip_g1, 53, 5000);
	PtCase(g, "reply_of_the_gateway", 1000, gw, g1, 0, f, size, POLICY_PASS_FLOW);

	// ARP: the sender addresses are checked as the source of a frame
	size = PtArpFrame(f, pt_mac_bcast, pt_mac_g1, 1, pt_mac_g1, pt_ip_g1, pt_ip_gw);
	PtCase(g, "arp_request", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_CONTROL);
	size = PtArpFrame(f, pt_mac_bcast, pt_mac_g1, 1, pt_mac_g1, pt_ip_gw, pt_ip_g2);
	PtCase(g, "arp_sender_ip_of_the_gateway", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_IP);
	size = PtArpFrame(f, pt_mac_bcast, pt_mac_g2, 2, pt_mac_g1, pt_ip_g2, pt_ip_gw);
	PtCase(g, "arp_sender_mac_of_another_member", 1000, g2, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_MAC);

	// DHCP, ARP and DHCP only, and no DHCP server
	size = PtUdpFrame(f, pt_mac_bcast, pt_mac_g1, POLICY_IPV4, pt_ip_any, pt_ip_bcast, 68, 67);
	PtCase(g, "dhcp_discover", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_CONTROL);
	size = PtUdpFrame(f, pt_mac_bcast, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_bcast, 67, 68);
	PtCase(g, "dhcp_server_message", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_DHCP_SERVER);
	size = PtUdpFrame(f, pt_mac_bcast, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_bcast, 137, 137);
	PtCase(g, "broadcast_under_arp_and_dhcp_only", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_BROADCAST);
	size = PtUdpFrame(f, pt_mac_bcast, pt_mac_g2, POLICY_IPV4, pt_ip_g2, pt_ip_bcast, 137, 137);
	PtCase(g, "broadcast_of_another_member", 1000, g2, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_RULE);
	members[0] = g1;
	members[1] = gw;
	members[2] = v4;
	members[3] = v6;
	PtDeliver(g, "broadcast_delivered", g2, members, names_a, 4, f, size, PTEST_BIT(1) | PTEST_BIT(2));

	// Router advertisements: dropped from a member under the RA filter, delivered to none that has it; neighbour
	// discovery
	size = PtIcmpFrame(f, pt_mac_all_nodes, pt_mac_g1, POLICY_IPV6, pt_ip6_ll_g1, pt_ip6_all_nodes, 134, 0);
	PtCase(g, "router_advertisement_filtered", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_RA);
	size = PtIcmpFrame(f, pt_mac_all_nodes, pt_mac_gw, POLICY_IPV6, pt_ip6_ll_gw, pt_ip6_all_nodes, 134, 0);
	PtCase(g, "router_advertisement_of_the_gateway", 1000, gw, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_CONTROL);
	members[0] = g1;
	members[1] = g2;
	members[2] = v4;
	members[3] = v6;
	PtDeliver(g, "router_advertisement_delivered", gw, members, names_b, 4, f, size, PTEST_BIT(1) | PTEST_BIT(3));
	size = PtIcmpFrame(f, pt_mac_solicited, pt_mac_g2, POLICY_IPV6, pt_ip6_ll_g2, pt_ip6_solicited, 135, 0);
	PtCase(g, "neighbour_solicitation", 1000, g2, POLICY_NO_MEMBER, 0, f, size, POLICY_PASS_CONTROL);

	// The filters of IPv4, IPv6 and non-IP frames, on what a member sends and on what it gets
	size = PtUdpFrame(f, pt_mac_v6, pt_mac_v4, POLICY_IPV6, pt_ip6_v4, pt_ip6_v6, 5000, 5001);
	PtCase(g, "ipv6_of_a_member_without_ipv6", 1000, v4, v6, 0, f, size, POLICY_DROP_PROTOCOL);
	size = PtNonIpFrame(f, pt_mac_gw, pt_mac_v4);
	PtCase(g, "non_ip_of_a_member_without_it", 1000, v4, gw, 0, f, size, POLICY_DROP_PROTOCOL);
	size = PtTcpFrame(f, pt_mac_gw, pt_mac_v4, POLICY_IPV4, pt_ip_v4, pt_ip_gw, 40000, 80, PT_SYN);
	PtCase(g, "ipv4_of_a_member_without_ipv6", 1000, v4, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_v6, POLICY_IPV4, pt_ip_v6, pt_ip_gw, 5000, 53);
	PtCase(g, "ipv4_of_a_member_without_ipv4", 1000, v6, gw, 0, f, size, POLICY_DROP_PROTOCOL);
	size = PtArpFrame(f, pt_mac_bcast, pt_mac_v6, 1, pt_mac_v6, pt_ip_v6, pt_ip_gw);
	PtCase(g, "arp_of_a_member_without_ipv4", 1000, v6, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_PROTOCOL);
	size = PtUdpFrame(f, pt_mac_v4, pt_mac_v6, POLICY_IPV6, pt_ip6_v6, pt_ip6_v4, 5000, 5001);
	PtCase(g, "ipv6_to_a_member_without_ipv6", 1000, v6, v4, 0, f, size, POLICY_DROP_PROTOCOL);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_v6, POLICY_IPV6, pt_ip6_v6, pt_ip6_gw, 5000, 5001);
	PtCase(g, "ipv6_of_a_member_without_ipv4", 1000, v6, gw, 0, f, size, POLICY_PASS_RULE);

	// Members of another Network, and of one that the document does not define
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_gw, 5004, 53);
	PtCase(g, "member_of_a_network_without_rules", 1000, stray, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_NETWORK);
	PtCase(g, "to_a_member_of_another_network", 1000, g1, stray, 0, f, size, POLICY_DROP_MEMBER);

	// Malformed frames
	PtCase(g, "shorter_than_an_ethernet_header", 1000, g1, gw, 0, f, 10, POLICY_DROP_MALFORMED);
	PtCase(g, "vlan_4095", 1000, g1, gw, 4095, f, size, POLICY_DROP_MALFORMED);
	PtCase(g, "ip_packet_cut_short", 1000, g1, gw, 0, f, size - 5, POLICY_DROP_MALFORMED);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_group_source, POLICY_IPV4, pt_ip_g1, pt_ip_gw, 5004, 53);
	PtCase(g, "group_source_address", 1000, g1, gw, 0, f, size, POLICY_DROP_MALFORMED);
	PtTcp(l4, 40000, 80, PT_SYN);
	size = PtFrame(f, pt_mac_gw, pt_mac_g1, POLICY_IPV4, pt_ip_g1, pt_ip_gw, 6, l4, 10);
	PtCase(g, "tcp_header_cut_short", 1000, g1, gw, 0, f, size, POLICY_DROP_MALFORMED);
	size = PtEth(f, pt_mac_gw, pt_mac_g1, 0x8100);
	f[size++] = 0x00;
	f[size++] = 0x0A;
	PtCase(g, "tag_cut_short", 1000, g1, gw, 0, f, size, POLICY_DROP_MALFORMED);
	size = PtArpFrame(f, pt_mac_bcast, pt_mac_g1, 1, pt_mac_g1, pt_ip_g1, pt_ip_gw);
	f[14 + 5] = 16;
	PtCase(g, "arp_not_of_ipv4", 1000, g1, POLICY_NO_MEMBER, 0, f, size, POLICY_DROP_MALFORMED);

	// A member that leaves: its frames, and the frames to it, are dropped; a new member takes its number and its MAC
	// address, but not its flows
	PtAdd(g->Report, "g2 leaves, g3 joins\n");
	if (PolicyDelMember(g->Engine, g2) == false)
	{
		g->SetupOk = false;
	}
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g2, POLICY_IPV4, pt_ip_g2, pt_ip_gw, 5002, 53);
	PtCase(g, "frame_of_a_member_that_left", 1000, g2, gw, 0, f, size, POLICY_DROP_MEMBER);
	size = PtUdpFrame(f, pt_mac_g2, pt_mac_gw, POLICY_IPV4, pt_ip_gw, pt_ip_g2, 53, 5002);
	PtCase(g, "frame_to_a_member_that_left", 1000, gw, g2, 0, f, size, POLICY_DROP_MEMBER);
	UINT g3 = PtMember(g, "guest", "g3", NULL, 0, NULL, 0, POLICY_GUARD_CHECK_MAC | POLICY_GUARD_CHECK_IP, 0, 0);
	PtCheck(ctx, g->SetupOk && g3 == g2, "isolation: a member that leaves frees its number, which the next member takes", "g2 was %u, g3 is %u", g2, g3);
	size = PtUdpFrame(f, pt_mac_gw, pt_mac_g2, POLICY_IPV4, pt_ip_g3, pt_ip_gw, 5005, 53);
	PtCase(g, "mac_of_a_member_that_left", 1000, g3, gw, 0, f, size, POLICY_PASS_RULE);
	size = PtUdpFrame(f, pt_mac_g2, pt_mac_gw, POLICY_IPV4, pt_ip_gw, pt_ip_g2, 53, 5002);
	PtCase(g, "flow_of_a_member_that_left", 1000, gw, g3, 0, f, size, POLICY_PASS_RULE);

	PtTrailer(g, nets, 2);
	PtGoldenEnd(ctx, g, "policy_isolation.txt", "isolation");
	PtFreeGolden(g);
}

//
// policy_documents.txt
//

// A document of size bytes for PolicyParseRules and for PolicySetRules on the engine of g, which must agree on it and
// take it when accept is set. The report gets "<n> <name>: accepted" or "<n> <name>: refused: <reason>".
static void PtDocument(PTEST_GOLDEN *g, const char *name, const char *json, UINT size, bool accept)
{
	char parse_error[MAX_SIZE];
	char set_error[MAX_SIZE];
	char line[MAX_SIZE * 2];
	bool parsed = PolicyParseRules(json, size, parse_error, sizeof(parse_error));
	bool set = PolicySetRules(g->Engine, json, size, set_error, sizeof(set_error));

	g->NumCases++;
	if (set)
	{
		Format(line, sizeof(line), "%u %s: accepted\n", g->NumCases, name);
	}
	else
	{
		Format(line, sizeof(line), "%u %s: refused: %s\n", g->NumCases, name, set_error);
	}
	PtAdd(g->Report, line);

	if (parsed != set || set != accept || (set == false && StrCmp(parse_error, set_error) != 0))
	{
		PtWrong(g);
	}
}

// The documents that the engine takes and those it refuses, the bounds of a document, and an engine that has all its
// Networks
static void PtDocuments(PTEST_CTX *ctx)
{
	PTEST_GOLDEN *g = PtNewGolden();
	POLICY_ENGINE *full = PolicyNew(0);
	POLICY_MEMBER_CONFIG c;
	POLICY_STATS st;
	char name[POLICY_MAX_NAME + 2];
	char item[MAX_SIZE];
	char error[MAX_SIZE];
	char line[MAX_SIZE * 2];
	UINT accepted = 0;
	UINT added = 0;
	BUF *b;

	Print("[documents: what the engine takes and what it refuses]\n");

	if (PtSetupOk(ctx, g, "documents") == false || PtCheck(ctx, full != NULL, "documents: a second engine is made", "PolicyNew returned NULL") == false)
	{
		PolicyFree(full);
		PtFreeGolden(g);
		return;
	}

	for (UINT i = 0; i < sizeof(pt_docs) / sizeof(pt_docs[0]); i++)
	{
		PtDocument(g, pt_docs[i].Name, pt_docs[i].Json, StrLen(pt_docs[i].Json), pt_docs[i].Accept);
		if (pt_docs[i].Accept)
		{
			accepted++;
		}
	}

	// A name of 63 bytes is a name, one of 64 is not
	for (UINT i = 0; i <= POLICY_MAX_NAME; i++)
	{
		name[i] = 'n';
	}
	name[POLICY_MAX_NAME] = 0;
	Format(item, sizeof(item), "{\"networks\": [{\"name\": \"%s\", \"maxFlows\": 8}]}", name);
	PtDocument(g, "network_name_of_63_bytes", item, StrLen(item), true);
	accepted++;
	name[POLICY_MAX_NAME] = 'n';
	name[POLICY_MAX_NAME + 1] = 0;
	Format(item, sizeof(item), "{\"networks\": [{\"name\": \"%s\"}]}", name);
	PtDocument(g, "network_name_of_64_bytes", item, StrLen(item), false);
	Format(item, sizeof(item), "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"from\": {\"groups\": [\"%s\"]}}]}", name);
	PtDocument(g, "group_name_of_64_bytes", item, StrLen(item), false);

	// More Networks than a document may have, more values than a list may have, more bytes than a document may have
	b = NewBuf();
	PtAdd(b, "{\"networks\": [");
	for (UINT i = 0; i <= POLICY_MAX_NETWORKS; i++)
	{
		Format(item, sizeof(item), "%s{\"name\": \"n%u\"}", i == 0 ? "" : ", ", i);
		PtAdd(b, item);
	}
	PtAdd(b, "]}");
	PtDocument(g, "networks_over_the_bound", (const char *)b->Buf, b->Size, false);
	FreeBuf(b);

	b = NewBuf();
	PtAdd(b, "{\"rules\": [{\"name\": \"r\", \"action\": \"allow\", \"vlans\": [");
	for (UINT i = 1; i <= POLICY_MAX_VALUES + 1; i++)
	{
		Format(item, sizeof(item), "%s%u", i == 1 ? "" : ", ", i);
		PtAdd(b, item);
	}
	PtAdd(b, "]}]}");
	PtDocument(g, "values_over_the_bound", (const char *)b->Buf, b->Size, false);
	FreeBuf(b);

	char *huge = ZeroMalloc(POLICY_MAX_DOCUMENT + 1);
	Copy(huge, "{}", 2);
	PtDocument(g, "longer_than_a_document", huge, POLICY_MAX_DOCUMENT + 1, false);
	Free(huge);

	// Indexes that would take more entries than a table may have: the rules without ports, of direction both, are in
	// every interval of destination ports that the ports of the first rules make
	b = NewBuf();
	PtAdd(b, "{\"networks\": [{\"name\": \"lab\"}], \"rules\": [");
	for (UINT i = 0; i < PTEST_BIG_RULES; i++)
	{
		Format(item, sizeof(item), "%s{\"name\": \"r%u\", \"action\": \"allow\", \"protocol\": \"tcp\", \"direction\": \"both\"", i == 0 ? "" : ", ", i);
		PtAdd(b, item);
		if (i < PTEST_BIG_PORTED)
		{
			PtAdd(b, ", \"ports\": [");
			for (UINT k = 0; k < PTEST_BIG_PORTS; k++)
			{
				Format(item, sizeof(item), "%s%u", k == 0 ? "" : ", ", 1 + i * PTEST_BIG_PORTS + k);
				PtAdd(b, item);
			}
			PtAdd(b, "]");
		}
		PtAdd(b, "}");
	}
	PtAdd(b, "]}");
	PtDocument(g, "indexes_over_the_bound", (const char *)b->Buf, b->Size, false);
	FreeBuf(b);

	// An engine whose members named POLICY_MAX_NETWORKS Networks takes no document that names one more; PolicyParseRules,
	// which knows no engine, takes it
	Zero(&c, sizeof(c));
	c.Network = name;
	for (UINT i = 0; i < POLICY_MAX_NETWORKS; i++)
	{
		Format(name, sizeof(name), "n%u", i);
		if (PolicyAddMember(full, &c) != POLICY_NO_MEMBER)
		{
			added++;
		}
	}
	Format(item, sizeof(item), "{\"networks\": [{\"name\": \"extra\", \"maxFlows\": 1}]}");
	bool parsed = PolicyParseRules(item, StrLen(item), error, sizeof(error));
	bool set = PolicySetRules(full, item, StrLen(item), error, sizeof(error));
	g->NumCases++;
	Format(line, sizeof(line), "%u engine_with_every_network: %s by PolicyParseRules, %s by PolicySetRules: %s\n", g->NumCases, parsed ? "accepted" : "refused",
		set ? "accepted" : "refused", set ? "-" : error);
	PtAdd(g->Report, line);
	if (added != POLICY_MAX_NETWORKS || parsed == false || set)
	{
		PtWrong(g);
	}

	PolicyGetStats(g->Engine, &st);
	Format(line, sizeof(line), "document in force: %I64u\n", st.Document);
	PtAdd(g->Report, line);
	PtCheck(ctx, st.Document == accepted, "documents: each document that the engine takes is the next in force, and one that it refuses leaves the one in force",
		"document %I64u in force after %u accepted", st.Document, accepted);

	PtGoldenEnd(ctx, g, "policy_documents.txt", "documents");
	PolicyFree(full);
	PtFreeGolden(g);
}

//
// The conntrack table under load
//

// A full conntrack table gives its least recently used flow to a new one; a flood of flows never takes a table past its
// bound; and the flows expire
static void PtEviction(PTEST_CTX *ctx)
{
	PTEST_GOLDEN *g = PtNewGolden();
	UCHAR f[PTEST_FRAME_MAX];
	POLICY_NETWORK_STATS ns;
	POLICY_NETWORK_STATS lru;
	POLICY_NETWORK_STATS flood;
	POLICY_RESULT r;
	UINT size;
	UINT passed = 0;
	UINT most = 0;
	bool ok;

	Print("[eviction: a full conntrack table, and a flood of flows]\n");

	UINT a = PtMember(g, "lru", "a", NULL, 0, NULL, 0, 0, 0, 0);
	UINT b = PtMember(g, "lru", "b", NULL, 0, NULL, 0, 0, 0, 0);
	UINT fa = PtMember(g, "flood", "a", NULL, 0, NULL, 0, 0, 0, 0);
	UINT fb = PtMember(g, "flood", "b", NULL, 0, NULL, 0, 0, 0, 0);
	PtSetRules(g, pt_doc_eviction);

	if (PtSetupOk(ctx, g, "eviction") == false)
	{
		PtFreeGolden(g);
		return;
	}

	// The flows of a, one per source port, fill the table of lru
	for (UINT i = 0; i < PTEST_LRU_FLOWS; i++)
	{
		size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_a, pt_ip_b, (USHORT)(10000 + i), 53);
		if (PolicyInput(g->Engine, 1000, a, b, 0, f, size, &r) && r.Reason == POLICY_PASS_RULE)
		{
			passed++;
		}
	}
	ok = PolicyGetNetworkStats(g->Engine, "lru", &ns);
	PtCheck(ctx, ok && passed == PTEST_LRU_FLOWS && ns.Flows == PTEST_LRU_FLOWS && ns.MaxFlows == PTEST_LRU_FLOWS && ns.Evicted == 0,
		"eviction: 64 flows fill a conntrack table of 64 flows", "%u passed, %u flows of %u, %I64u evicted", passed, ns.Flows, ns.MaxFlows, ns.Evicted);

	// The reply of the first flow makes it the most recently used; a new flow then takes the place of the second
	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_b, pt_ip_a, 53, 10000);
	ok = PolicyInput(g->Engine, 1000, b, a, 0, f, size, &r) && r.Reason == POLICY_PASS_FLOW;
	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_a, pt_ip_b, (USHORT)(10000 + PTEST_LRU_FLOWS), 53);
	ok = ok && PolicyInput(g->Engine, 1000, a, b, 0, f, size, &r) && r.Reason == POLICY_PASS_RULE;
	ok = ok && PolicyGetNetworkStats(g->Engine, "lru", &ns);
	PtCheck(ctx, ok && ns.Flows == PTEST_LRU_FLOWS && ns.Evicted == 1 && ns.Tracked == PTEST_LRU_FLOWS + 1,
		"eviction: a new flow in a full table evicts one flow, and the table stays at its bound", "%u flows, %I64u tracked, %I64u evicted", ns.Flows, ns.Tracked,
		ns.Evicted);

	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_b, pt_ip_a, 53, 10000);
	bool first = PolicyInput(g->Engine, 1000, b, a, 0, f, size, &r) && r.Reason == POLICY_PASS_FLOW;
	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_b, pt_ip_a, 53, 10001);
	bool second = PolicyInput(g->Engine, 1000, b, a, 0, f, size, &r) == false && r.Reason == POLICY_DROP_DEFAULT;
	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_b, pt_ip_a, 53, (USHORT)(10000 + PTEST_LRU_FLOWS));
	bool newest = PolicyInput(g->Engine, 1000, b, a, 0, f, size, &r) && r.Reason == POLICY_PASS_FLOW;
	PtCheck(ctx, first && second && newest, "eviction: the flow that left is the least recently used: the reply of the second flow is dropped, those of the first and the new one pass",
		"first %s, second %s, new %s", first ? "passes" : "is dropped", second ? "is dropped" : "passes", newest ? "passes" : "is dropped");

	// A flood of flows in a table of 4096 flows in shards: the table never holds more than its bound
	passed = 0;
	for (UINT i = 0; i < PTEST_FLOOD; i++)
	{
		size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, pt_ip_a, pt_ip_b, (USHORT)(1024 + i % 60000), (USHORT)(1 + i / 60000));
		if (PolicyInput(g->Engine, 1000, fa, fb, 0, f, size, &r))
		{
			passed++;
		}
		if ((i & 1023) == 1023 && PolicyGetNetworkStats(g->Engine, "flood", &ns) && ns.Flows > most)
		{
			most = ns.Flows;
		}
	}
	ok = PolicyGetNetworkStats(g->Engine, "flood", &ns);
	PtCheck(ctx, ok && passed == PTEST_FLOOD && most <= PTEST_FLOOD_BOUND && ns.Flows <= PTEST_FLOOD_BOUND && ns.Tracked == PTEST_FLOOD &&
		ns.Evicted == ns.Tracked - ns.Flows, "eviction: a flood of 100000 flows never takes a table of 4096 flows past its bound; the least recently used flows leave",
		"%u passed, at most %u flows, %u flows of %u, %I64u tracked, %I64u evicted", passed, most, ns.Flows, ns.MaxFlows, ns.Tracked, ns.Evicted);

	// Every flow expires after the timeout of its Network
	UINT before = 0;
	if (PolicyGetNetworkStats(g->Engine, "lru", &lru) && PolicyGetNetworkStats(g->Engine, "flood", &flood))
	{
		before = lru.Flows + flood.Flows;
	}
	UINT aged = PolicyAge(g->Engine, 1000 + 600000);
	ok = PolicyGetNetworkStats(g->Engine, "lru", &lru) && PolicyGetNetworkStats(g->Engine, "flood", &flood);
	PtCheck(ctx, ok && before != 0 && aged == before && lru.Flows == 0 && flood.Flows == 0 && lru.Expired + flood.Expired == aged,
		"eviction: PolicyAge takes out every flow after its timeout", "%u flows before, %u aged, %u and %u left", before, aged, lru.Flows, flood.Flows);

	PtFreeGolden(g);
}

//
// The members
//

// The configurations of members that the engine refuses, its bounds, and an engine without a document
static void PtMembers(PTEST_CTX *ctx)
{
	static const char *const one[] = {"g"};
	static const UCHAR mac[6] = {0x02, 0x00, 0x00, 0x00, 0x06, 0x01};
	static const UCHAR ip[16] = {10, 6, 0, 1};
	const char *many[POLICY_MAX_IDS + 1];
	POLICY_ENGINE *p = PolicyNew(2);
	POLICY_MEMBER_CONFIG c;
	POLICY_NETWORK_STATS ns;
	POLICY_RESULT r;
	UCHAR f[PTEST_FRAME_MAX];
	UINT size;

	Print("[members: the configurations that the engine refuses, and an engine without a document]\n");

	PtCheck(ctx, PolicyNew(POLICY_MAX_MEMBERS + 1) == NULL, "members: an engine of more than POLICY_MAX_MEMBERS members is refused", "PolicyNew made one");
	if (PtCheck(ctx, p != NULL, "members: an engine of 2 members is made", "PolicyNew returned NULL") == false)
	{
		return;
	}

	for (UINT i = 0; i <= POLICY_MAX_IDS; i++)
	{
		many[i] = "g";
	}

	Zero(&c, sizeof(c));
	c.Network = "a b";
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member of a Network whose name is none is refused", "it was added");
	c.Network = "lab";
	c.User = "a b";
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member whose user name has a space is refused", "it was added");
	c.User = "u";
	c.Groups = many;
	c.NumGroups = POLICY_MAX_IDS + 1;
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member of more than POLICY_MAX_IDS groups is refused", "it was added");
	c.Groups = one;
	c.NumGroups = 1;
	c.NumTags = 1;
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member with a number of tags and no list of them is refused", "it was added");
	c.NumTags = 0;
	c.Guard = POLICY_GUARD_ALL + 1;
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member with an unknown guard flag is refused", "it was added");
	c.Guard = POLICY_GUARD_ALL;
	c.MaxIps = POLICY_MAX_BOUND + 1;
	PtCheck(ctx, PolicyAddMember(p, &c) == POLICY_NO_MEMBER, "members: a member that may own more than POLICY_MAX_BOUND IP addresses is refused", "it was added");
	c.MaxIps = 0;

	UINT m1 = PolicyAddMember(p, &c);
	UINT m2 = PolicyAddMember(p, &c);
	UINT m3 = PolicyAddMember(p, &c);
	PtCheck(ctx, m1 == 0 && m2 == 1 && m3 == POLICY_NO_MEMBER, "members: an engine of 2 members takes 2 and refuses a third", "members %u, %u and %u", m1, m2, m3);
	PtCheck(ctx, PolicyBindMac(p, m1, mac) && PolicyBindMac(p, m1, mac) && PolicyBindMac(p, m2, mac) == false,
		"members: a MAC address bound to a member is its own and no other member's", "PolicyBindMac");
	PtCheck(ctx, PolicyBindIp(p, m1, 5, ip) == false && PolicyBindIp(p, m1, POLICY_IPV4, ip) && PolicyBindIp(p, m2, POLICY_IPV4, ip) == false,
		"members: an IP address is bound for a family of IP only, and to one member", "PolicyBindIp");
	PtCheck(ctx, PolicyBindMac(p, POLICY_NO_MEMBER, mac) == false && PolicyDelMember(p, 7) == false,
		"members: no address is bound to, and no member is taken out of, a number that no member has", "PolicyBindMac or PolicyDelMember took it");

	// An engine without a document: its counters, its Networks and its frames
	char *text = PolicyCountersText(p);
	char *json = PolicyCountersJson(p);
	PtCheck(ctx, text != NULL && StrCmp(text, "no document of rules\n") == 0, "members: the CLI text of an engine without a document says so", "\"%s\"",
		text != NULL ? text : "(none)");
	PtCheck(ctx, json != NULL && StrCmp(json, "{\"document\":0,\"networks\":[]}") == 0, "members: the admin API JSON of an engine without a document has no Network",
		"%s", json != NULL ? json : "(none)");
	PolicyFreeString(text);
	PolicyFreeString(json);

	size = PtUdpFrame(f, NULL, NULL, POLICY_IPV4, ip, ip, 1, 2);
	bool dropped = (PolicyInput(p, 1000, m2, POLICY_NO_MEMBER, 0, f, size, &r) == false && r.Reason == POLICY_DROP_NETWORK);
	PtCheck(ctx, dropped, "members: a frame of a Network that no document defines is dropped", "reason %s", PtReason(r.Reason));
	bool known = PolicyGetNetworkStats(p, "lab", &ns) && ns.Defined == false && ns.NumMembers == 2;
	PtCheck(ctx, known && PolicyGetNetworkStats(p, "nowhere", &ns) == false, "members: the state of a Network without a document, and of none",
		"PolicyGetNetworkStats");

	// A member that leaves frees its number and its addresses
	PtCheck(ctx, PolicyDelMember(p, m1) && PolicyDelMember(p, m1) == false && PolicyAddMember(p, &c) == m1,
		"members: a member that leaves frees its number for the next one", "PolicyDelMember or PolicyAddMember");
	PtCheck(ctx, PolicyBindMac(p, m2, mac), "members: the MAC address of a member that left is free", "PolicyBindMac refused it");

	bool none = (PolicyInput(NULL, 0, 0, 0, 0, f, size, &r) == false && r.Reason == POLICY_DROP_MEMBER && PolicyAge(NULL, 0) == 0 &&
		PolicyDeliver(NULL, 0, 0, f, size) == false && PolicyGetCounters(NULL, NULL, 0) == 0);
	PtCheck(ctx, none, "members: the calls on no engine do nothing", "one of them did something");

	PolicyFree(p);
}

//
// Documents that change while threads judge frames
//

// A thread that judges frames of its member to the UDP ports 7000 and 7001 of a group address, each frame by itself,
// until it is told to stop. Document A (odd numbers) allows 7000 by a-allow and denies 7001 by a-deny; document B (even
// numbers) denies 7000 by b-deny and allows 7001 by b-allow.
static DWORD WINAPI PtJudgeThread(LPVOID param)
{
	PTEST_JUDGE *j = (PTEST_JUDGE *)param;
	UCHAR f[2][PTEST_FRAME_MAX];
	UINT size[2];

	size[0] = PtUdpFrame(f[0], NULL, NULL, POLICY_IPV4, pt_ip_a, pt_ip_group, 5000, 7000);
	size[1] = PtUdpFrame(f[1], NULL, NULL, POLICY_IPV4, pt_ip_a, pt_ip_group, 5000, 7001);

	WaitForSingleObject(j->Start, INFINITE);

	for (UINT n = j->Index; InterlockedCompareExchange(j->Stop, 0, 0) == 0; n++)
	{
		POLICY_RESULT r;
		UINT k = (n & 1);
		bool pass = PolicyInput(j->Engine, 1000, j->From, POLICY_NO_MEMBER, 0, f[k], size[k], &r);
		bool odd = ((r.Document & 1) != 0);
		const char *rule = (odd ? (k == 0 ? "a-allow" : "a-deny") : (k == 0 ? "b-deny" : "b-allow"));
		bool expect = (odd ? (k == 0) : (k == 1));

		j->Judged++;
		if (r.Document == 0)
		{
			j->NoDocument++;
		}
		else if (pass != expect || strcmp(r.Rule, rule) != 0)
		{
			j->Torn++;
		}
	}

	return 0;
}

// Threads judge frames while the main thread puts two documents in force in turn: each frame is judged by one document,
// the one whose number its verdict carries, never by a part of each
static void PtConcurrent(PTEST_CTX *ctx)
{
	PTEST_GOLDEN *g = PtNewGolden();
	PTEST_JUDGE *judges = ZeroMalloc(sizeof(PTEST_JUDGE) * PTEST_THREADS);
	HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
	volatile LONG stop = 0;
	char error[MAX_SIZE];
	POLICY_STATS st;
	UINT swaps = 0;
	UINT refused = 0;
	UINT started = 0;
	UINT torn = 0;
	UINT none = 0;
	UINT64 judged = 0;

	Print("[atomic documents: threads judge frames while the documents change]\n");

	UINT a = PtMember(g, "swap", "a", NULL, 0, NULL, 0, 0, 0, 0);
	PtSetRules(g, pt_doc_swap_a);

	if (PtSetupOk(ctx, g, "atomic documents") == false || PtCheck(ctx, start != NULL, "atomic documents: the start event is made", "CreateEventW") == false)
	{
		if (start != NULL)
		{
			CloseHandle(start);
		}
		Free(judges);
		PtFreeGolden(g);
		return;
	}

	for (UINT i = 0; i < PTEST_THREADS; i++)
	{
		PTEST_JUDGE *j = &judges[i];

		j->Engine = g->Engine;
		j->Start = start;
		j->Stop = &stop;
		j->From = a;
		j->Index = i;
		j->Thread = CreateThread(NULL, 0, PtJudgeThread, j, 0, NULL);
		if (j->Thread != NULL)
		{
			started++;
		}
	}

	SetEvent(start);
	UINT64 begin = GetTickCount64();
	while (swaps < PTEST_SWAPS && GetTickCount64() - begin < PTEST_SPAN)
	{
		const char *doc = (swaps % 2 == 0 ? pt_doc_swap_b : pt_doc_swap_a);

		if (PolicySetRules(g->Engine, doc, StrLen(doc), error, sizeof(error)) == false)
		{
			refused++;
		}
		swaps++;
	}
	InterlockedExchange(&stop, 1);

	for (UINT i = 0; i < PTEST_THREADS; i++)
	{
		if (judges[i].Thread != NULL)
		{
			WaitForSingleObject(judges[i].Thread, INFINITE);
			CloseHandle(judges[i].Thread);
		}
		judged += judges[i].Judged;
		torn += judges[i].Torn;
		none += judges[i].NoDocument;
	}

	PolicyGetStats(g->Engine, &st);
	PtCheck(ctx, started == PTEST_THREADS, "atomic documents: the threads start", "%u of %u", started, (UINT)PTEST_THREADS);
	PtCheck(ctx, refused == 0 && st.Document == 1 + (UINT64)swaps, "atomic documents: every document is put in force, each with the next number",
		"%u refused, document %I64u after %u changes", refused, st.Document, swaps);
	PtCheck(ctx, judged != 0 && torn == 0 && none == 0,
		"atomic documents: every frame is judged by one whole document, whose number, verdict and rule it carries",
		"%I64u frames judged, %u torn, %u judged by no document", judged, torn, none);
	Print("  %u documents put in force while the threads judged %I64u frames\n", swaps, judged);

	CloseHandle(start);
	Free(judges);
	PtFreeGolden(g);
}

RANZ_TEST_TAGS("policy", policy_test, "core", "Policy: the stateful identity-based policy engine of the new core against golden files (golden family policy): replies of TCP, UDP and ICMP flows on the conntrack fast path, identity rules with address groups, VLANs, priorities and the counters of the admin API and the CLI, the isolation set of the fork and the documents it refuses; LRU eviction under a flood of flows, and documents that change while threads judge frames.");
void policy_test(UINT num, char **arg)
{
	PTEST_CTX *ctx = ZeroMalloc(sizeof(PTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, PtWatchdog, done, 0, NULL) : NULL);

	Print("Policy test: the policy engine of the new core, against golden verdicts and counters\n");

	HarnessGetFamilyDirs("policy", ctx->OutDir, sizeof(ctx->OutDir), ctx->GoldenDir, sizeof(ctx->GoldenDir), &ctx->Update);
	MakeDirEx(ctx->OutDir);
	Print("POLICY GOLDEN MODE %s\n", ctx->Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx->GoldenDir);

	PtConntrack(ctx);
	PtIdentity(ctx);
	PtIsolation(ctx);
	PtDocuments(ctx);
	PtEviction(ctx);
	PtMembers(ctx);
	PtConcurrent(ctx);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx->NumFailed == 0)
	{
		Print("POLICY TEST OK\n");
	}
	else
	{
		Print("POLICY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
