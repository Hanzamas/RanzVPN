// grouppolicytest.c
// Named source group policy test of vpntest ("grouppolicy" command, SDN-87 #386)
//
// The node that takes a packet of a peer judges it by the rules of its VRF for the source group that the packet carried
// (Cedar/NodeSourceGroup.c, NodePolicy.c). The test runs the overlay of in-process nodes, as seam 2 of #45 runs the data
// plane and linktest.c the kinds of the links: fake adapters stand in for the hosts of node-a and node-b, and of node-c,
// which only the case of the hub uses, the in-process loopback transport carries their Noise sessions, node-a and node-b
// have a tunnel endpoint on 127.0.0.1, and the test applies their desired states itself (NodeOverlayApply), as the
// controller makes them (desired/sourcegroup.go). VRF red (101) has three groups: admin (1, the tag set 0x1), the
// WireGuard Device phone at 10.0.0.50, whose gateway node-a is;
// guest (2, 0x2), node-a; and server (3, 0x4), node-b. Node-b enforces the policy of red, one rule written by tag,
// admin-in, from the tag admin to the tag server, and default deny; node-a enforces none, so every packet of its host
// leaves it. Each case sends one UDP packet to node-b's host, or to node-c's through node-b in the case of the hub, from a
// source port of its own so that no flow of the conntrack of node-b carries a verdict from one case to the next. It waits
// until node-b counted the packet in the tag mode in which it judged it (NodeSourceGroupGetStatus), exactly once, then for
// what the host of the destination takes.
// - Over each kind of link, noise, vxlan and geneve (in the tag mode trusted-underlay): a packet of node-a's host from
//   10.0.0.1 carries guest, which admin-in does not allow, and is dropped; one from 10.0.0.50, the address of phone,
//   carries admin and arrives. In the next Generation node-a stamps admin on the packets of its own address, a group that
//   it may assert as the gateway of phone, and the packet from 10.0.0.1 arrives: the rule judges it by the group that it
//   carries. In the one after, node-a stamps server, the group of node-b, which it may not assert: node-b drops the packet
//   as an unknown group, counts it as refused and logs it.
// - Over vxlan and geneve a harness tunnel endpoint on 127.0.0.1, the address of node-a, sends node-b datagrams that it
//   made itself. In trusted-underlay a forged admin on a packet from 10.0.0.1 is honoured, the limit of that mode, and
//   guest on one from 10.0.0.50 is judged as guest; without the option, the map of address to group judges the packet,
//   so the one from 10.0.0.1 is dropped and the one from 10.0.0.50 arrives; a claim of server is refused, and over
//   geneve so is admin with the tag set of another group; and a packet from 10.0.0.99, an address that no route of red
//   leads to node-a, is in no group and dropped. In the tag mode off the option is ignored and the map judges each
//   packet, and node-a sends none, which node-b counts as missing.
// Each claim names the group generation of node-a in red (Cedar/NodeSourceGroup.c), the Generation of node-a's state from
// which on it may assert what it asserts there, 1 while the states agree. A claim of a group that node-a may not assert is
// refused whatever group generation it names: over noise and geneve node-a stamps server with the group generation
// 0xffffffff, which no state of node-b gives it, and node-b drops the packet, counts it as refused and logs it, in the
// first line of its node log about refused claims, which names that group generation. Over geneve a claim of server from
// the harness tunnel endpoint that names another group generation of node-a than node-b's state is refused too, while a
// claim of admin that names one is taken, as a group ID means the same set of tags in every Generation: it arrives.
// A node on a stale state must not misjudge the honest packets of a peer on another one, over each kind of link, the group
// policy extension of VXLAN too, which has no room for the group generation: it ignores a claim of a group that the peer
// could assert before the Generation that last changed its groups, and one of a group ID that its state does not know at
// all, as a group of a Generation that it does not run yet; and a peer that moves into a group ID that its state gives
// another endpoint stamps no group until the node runs a state that lets the peer assert it. Over noise, vxlan and geneve:
// - The controller deletes Device phone: its Generation goes in at node-b, while node-a forwards on the one before, which
//   still holds phone, as a node that the controller cannot reach does. Node-a may assert another set of groups from that
//   Generation on, so node-b's state gives it the group generation 2, and node-a's own still names 1. Guest and server keep
//   their group IDs and tag sets (desired/sourcegroup.go), so node-b still takes the claim of guest on a packet from
//   10.0.0.1 and drops the packet as guest; the packet of 10.0.0.50 has no route of red to node-a any more and is dropped
//   before any group. Once node-a stamps admin, the retired group of phone, on the packets of its own address, node-b
//   ignores the claim, made on the state before, and the map judges the packet as guest: dropped, and counted as ignored,
//   not as a refused claim. Over noise and geneve the same claim that names the group generation 2, which node-a may not
//   make on that state, is an unknown group.
// - The other way round: node-a runs the Generation that deletes phone, of the group generation 2, and node-b the one
//   before. Node-a stamps guest, which keeps its number, and node-b takes it as guest, not as admin, the group of phone
//   whose gateway node-a was in node-b's state: dropped. Where numbers by rank would have given guest the group ID of admin
//   in the Generation without phone, node-b would have let the packet in as admin. Node-a, whose tags are ops in a
//   Generation of the group generation 3, stamps ops, a group that node-b's state does not know: node-b ignores the claim,
//   made on another state, and the map judges the packet as guest, counted as ignored.
// - The Groups of the owner of phone change, so that its tags are admin and ops, a set of tags whose group ID 5 comes after
//   the largest one of red. While node-a runs that Generation, of the group generation 4, and node-b the one before, node-a
//   stamps 5 on the packets of phone, a group that node-b's state does not know: node-b ignores the claim, and the map
//   judges the packet as phone, admin: it arrives. While node-b runs it and node-a the one before, node-a stamps admin,
//   which it could assert before: node-b ignores the claim, and the map judges the packet as phone, whose tags are admin
//   and ops now: it arrives.
// - The tags of node-a move into server, the set of tags of node-b, whose group ID 3 node-b's state gives node-b alone, so
//   that node-b cannot tell a claim of it from a forged one. While node-a runs that Generation, of the group generation 5,
//   and node-b the one before, the controller holds node-a's own group in red (CONTROL_SOURCE_GROUP.Held): node-a stamps
//   no source group, and node-b judges its packets by the map, so the one from 10.0.0.1 is dropped as guest and the one
//   from 10.0.0.50 arrives as admin, both counted as missing. The same Generation without the hold would make node-b drop
//   the packet as an unknown group, counted as refused.
// - The Generations roll out: node-a reports the Capability tags and stamps admin on the records that it sends node-b,
//   while the state of node-b gives node-a the frame version 0 and none of its groups, as until the Generation of node-b
//   goes in, or while the controller cannot reach node-b. Node-b ignores those claims and judges the packets by the map:
//   the one from 10.0.0.1 is dropped as guest, the one from 10.0.0.50 arrives as admin, and it counts both as ignored.
// - Frame version 0: with node-a a node without the Capability tags, which has no group and sends node-b records of frame
//   version 0, its packets over noise still go and are judged by the map: the one from 10.0.0.50 arrives, the one from
//   10.0.0.1 is dropped, and node-b counts both as missing.
// - The hub (SDN-19-R2, #508): red becomes hub-and-spoke with the hub node-b and the spokes node-a and node-c (server,
//   10.0.0.3, which enforces no policy), over noise. Node-b judges the source group of each packet that it sends on from
//   node-a to node-c as a destination would, and its policy, admin-in, judges the packet by the group that it took: the
//   packet from 10.0.0.1 carries guest and is dropped at the hub, the one from 10.0.0.50 carries admin and arrives at
//   node-c, and so does the one from 10.0.0.1 once node-a stamps admin on it; a claim of server, which node-a may not
//   assert, is dropped at the hub as an unknown group and counted as refused. Node-c takes each packet as a record of frame
//   version 0, without the source group that it carried, and counts it as missing.
// - The EVPN gateway (SDN-25, #201): node-b hands red to a data-centre fabric (Cedar/NodeEvpn.c), with the IP prefix route
//   172.16.1.0/24 of the fabric on the L3 VNI of red via a harness VTEP on 127.0.0.1, and the state of node-a routes the LAN
//   subnets of node-b, 172.16.0.0/12, to it, as the controller routes the LAN subnets of a gateway. The test starts the EVPN
//   of node-b from the evpn object of a Bgp setting and hands it the route as the BGP sidecar of node-b would, without the
//   sidecar. Node-b is the destination of the packets of node-a's host to the fabric, over noise, and judges the source group
//   that they carried as for a packet to its host: the packet from 10.0.0.1 carries guest and is dropped, the one from
//   10.0.0.50 carries admin and the harness VTEP takes it on the L3 VNI of red, without a source group; once node-a stamps
//   admin on the packets of its own address, the packet from 10.0.0.1 reaches the fabric too, and a claim of server is
//   dropped as an unknown group and counted as refused.
// Print "GROUPPOLICY TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeSourceGroup.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <cjson/cJSON.h>

#include <stdio.h>

#define	GPTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	GPTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	GPTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	GPTEST_POLL				10			// Poll interval of observable state (ms)
#define	GPTEST_SIZE				100			// The size of a test packet
#define	GPTEST_VNI				5101		// The VNI of red over vxlan and geneve
#define	GPTEST_VRF				101			// The id of red
#define	GPTEST_PORT				9000		// The UDP port of node-b's host that every packet goes to
#define	GPTEST_FIRST_PORT		20000		// The UDP source port of the first case; each case takes the next
#define	GPTEST_PHONE			"10.0.0.50"	// The address of the Device phone
#define	GPTEST_L3VNI			10101		// The L3 VNI of red at the EVPN gateway node-b
#define	GPTEST_FABRIC_ADDR		"172.16.1.20"	// An address of the fabric, which the IP prefix route of the fabric holds

// The Bgp setting of node-b, the EVPN gateway, with the UDP port of its VTEP and of the harness VTEP of the fabric: its evpn
// object alone, which hands red to the fabric on its L3 VNI
#define	GPTEST_EVPN				"{\"evpn\":{\"vtep\":\"127.0.0.1\",\"port\":%u,\"fabric_port\":%u,\"vrfs\":[{\"vrf\":101,\"vni\":10101}]}}"

// The learned message of the IP prefix route of the fabric in red, as the BGP sidecar of node-b hands it over: 172.16.1.0/24
// on the L3 VNI of red, via the harness VTEP of the fabric on 127.0.0.1, with the router MAC of the fabric
#define	GPTEST_FABRIC_ROUTE		"{\"type\":\"learned\",\"vrf\":101,\"vni\":10101,\"prefix\":\"172.16.1.0/24\",\"next_hop\":\"127.0.0.1\",\"router_mac\":\"02:00:5e:10:00:01\",\"peer\":\"fabric\"}"

// The nodes: node-a and node-b, and node-c, a spoke of the hub node-b in the case of the hub
#define	GPTEST_A				0
#define	GPTEST_B				1
#define	GPTEST_C				2
#define	GPTEST_NUM_NODES		3

// The groups of red, as the controller numbers them when red comes in one intent (desired/sourcegroup.go): one for each set
// of tags of an endpoint, admin, guest and server in name order, and a bit of the tag set for each tag of red in name
// order; ops comes with a later intent and takes the numbers after them, and the set of admin and ops, the tags of phone
// once the Groups of its owner change, with one after that. A number stays with its set of tags or its tag for good, also
// once no endpoint has them.
#define	GPTEST_ADMIN			1
#define	GPTEST_GUEST			2
#define	GPTEST_SERVER			3
#define	GPTEST_OPS				4
#define	GPTEST_ADMIN_OPS		5
#define	GPTEST_ADMIN_TAGS		0x1ULL
#define	GPTEST_GUEST_TAGS		0x2ULL
#define	GPTEST_SERVER_TAGS		0x4ULL
#define	GPTEST_OPS_TAGS			0x8ULL
#define	GPTEST_ADMIN_OPS_TAGS	0x9ULL

// The group generations of node-a in red: the one of the states that agree, the one of the Generation that deletes Device
// phone, the one of the Generation in which the tags of node-a are ops, the one of the Generation in which the tags of
// phone are admin and ops, and the one of the Generation in which the tags of node-a are server; and one that no state of
// node-a names
#define	GPTEST_SINCE			1
#define	GPTEST_SINCE_NO_PHONE	2
#define	GPTEST_SINCE_OPS		3
#define	GPTEST_SINCE_ADMIN_OPS	4
#define	GPTEST_SINCE_SERVER		5
#define	GPTEST_SINCE_FORGED		0xFFFFFFFF

// What node-b counts a packet as in the tag mode of the case (NODE_SOURCE_GROUP_STATUS), or GPTEST_UNCOUNTED: its overlay
// drops it before it judges its source group, as no route of red leads its source to node-a
#define	GPTEST_CARRIED			0
#define	GPTEST_MISSING			1
#define	GPTEST_IGNORED			2
#define	GPTEST_REFUSED			3
#define	GPTEST_UNCOUNTED		4

static char *gptest_names[GPTEST_NUM_NODES] = {"node-a", "node-b", "node-c"};

// The addresses of each node in red, IPv4 and IPv6, and its tag
static char *gptest_addrs[GPTEST_NUM_NODES][2] =
{
	{"10.0.0.1", "fd00::1"},
	{"10.0.0.2", "fd00::2"},
	{"10.0.0.3", "fd00::3"},
};
static char *gptest_tags[GPTEST_NUM_NODES] = {"guest", "server", "server"};

static char *gptest_kind_names[3] = {"noise", "vxlan", "geneve"};
static char *gptest_mode_names[CONTROL_TAG_MODES] = {"off", "trusted-underlay", "session"};
static char *gptest_results[4] = {"carried", "missing", "ignored", "refused"};

// The MAC address of both ends of the Ethernet header of a frame of a link
static const UCHAR gptest_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// The router MAC of the fabric, which the IP prefix route of the fabric names: the destination of a frame to the fabric
static const UCHAR gptest_fabric_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x00, 0x01};

// One case: a UDP packet of red to node-b's host, to node-c's through the hub node-b, or to the fabric of node-b, the EVPN
// gateway, which node-a's host sends, or the harness tunnel endpoint with the source group that its datagram carries; and
// what node-b counts it as and whether the host of its destination, or the harness VTEP of the fabric, takes it
typedef struct GPTEST_CASE
{
	char *What;							// What the case shows
	bool Inject;						// The harness tunnel endpoint sends it, else node-a's host
	char *Src;							// Its source address
	bool HasGroup;						// An injected datagram carries a source group ...
	UINT Group;							// ... of this group ID ...
	UINT64 Tags;						// ... with this tag set, which only Geneve carries, as the group generation
	UINT Result;						// What node-b counts it as (GPTEST_*)
	bool Arrives;						// The host of its destination takes it, as it was sent
	bool Stale;							// An injected datagram of Geneve names another group generation of node-a than node-b's state
} GPTEST_CASE;

// The packets of node-a's host while node-a stamps guest, its own group, on the packets of its address and admin, the group
// of phone, on those of the address of phone
static GPTEST_CASE gptest_own[] =
{
	{"a packet of node-a's host from 10.0.0.1 carries guest, its group, which the rule admin-in does not allow: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
	{"one from 10.0.0.50, the address of phone, carries admin, the group of phone, which admin-in allows: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps admin, which it may assert as the gateway of phone, on the packets of its own address
static GPTEST_CASE gptest_admin[] =
{
	{"the same packet from 10.0.0.1 carries admin now: the rule written by tag judges it by the group that it carries, and it arrives", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps server, the group of node-b, which it may not assert
static GPTEST_CASE gptest_rogue[] =
{
	{"a packet from 10.0.0.1 that claims server, which node-a may not assert: dropped as an unknown group, counted as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// ... and names the group generation 0xffffffff, which node-b's state does not give node-a
static GPTEST_CASE gptest_rogue_generation[] =
{
	{"a packet from 10.0.0.1 that claims server and names the group generation 0xffffffff, which node-b's state does not give node-a: refused all the same, dropped as an unknown group", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The datagrams of the harness tunnel endpoint on 127.0.0.1, the address of node-a, in the tag mode trusted-underlay
static GPTEST_CASE gptest_trusted[] =
{
	{"trusted-underlay: a forged admin on a packet from 10.0.0.1 is honoured, the limit of that mode: it arrives", true, "10.0.0.1", true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS, GPTEST_CARRIED, true},
	{"trusted-underlay: guest on a packet from 10.0.0.50 is judged as guest, not as the group of the address of phone: dropped", true, GPTEST_PHONE, true, GPTEST_GUEST, GPTEST_GUEST_TAGS, GPTEST_CARRIED, false},
	{"trusted-underlay: without the option, the map of address to group judges the packet from 10.0.0.1 as guest: dropped", true, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
	{"trusted-underlay: without the option, the map judges the packet from 10.0.0.50 as admin: it arrives", true, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
	{"trusted-underlay: a claim of server, which node-a may not assert, is dropped as an unknown group and counted as refused", true, "10.0.0.1", true, GPTEST_SERVER, GPTEST_SERVER_TAGS, GPTEST_REFUSED, false},
	{"trusted-underlay: without the option, a packet from 10.0.0.99, an address that no route of red leads to node-a, is in no group: dropped", true, "10.0.0.99", false, 0, 0, GPTEST_UNCOUNTED, false},
};

// ... and over geneve, which carries the tag set: a claim of admin with the tag set of guest and admin
static GPTEST_CASE gptest_tag_set[] =
{
	{"trusted-underlay: a claim of admin with the tag set 0x3, not the one of admin, is refused", true, "10.0.0.1", true, GPTEST_ADMIN, 0x3ULL, GPTEST_REFUSED, false},
};

// ... and in the tag mode off
static GPTEST_CASE gptest_off[] =
{
	{"off: a forged admin on a packet from 10.0.0.1 is ignored, and the map judges it as guest: dropped", true, "10.0.0.1", true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS, GPTEST_IGNORED, false},
	{"off: guest on a packet from 10.0.0.50 is ignored, and the map judges it as admin: it arrives", true, GPTEST_PHONE, true, GPTEST_GUEST, GPTEST_GUEST_TAGS, GPTEST_IGNORED, true},
	{"off: node-a sends no option, and the map judges the packet of its host from 10.0.0.1 as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
	{"off: ... and the one from 10.0.0.50 as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
};

// The packets of node-a's host over noise once node-b runs the Generation that deletes Device phone and node-a the one
// before, which holds phone: guest keeps its group ID and tag set, and admin, the group of phone, is retired
static GPTEST_CASE gptest_kept[] =
{
	{"a packet from 10.0.0.1 carries guest, whose group ID and tag set stay as they were: node-b takes it as guest, which admin-in does not allow: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
	{"one from 10.0.0.50, the address of phone, which no route of red leads to node-a any more, is in no group: dropped", false, GPTEST_PHONE, false, 0, 0, GPTEST_UNCOUNTED, false},
};

// ... while node-a stamps admin, the retired group of phone, on the packets of its own address, with the group generation of
// the state before
static GPTEST_CASE gptest_retired[] =
{
	{"a packet from 10.0.0.1 that claims admin, the retired group of phone, made on the state before: node-b ignores the claim, and the map judges the packet as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_IGNORED, false},
};

// ... and with the group generation that node-b's state gives node-a, which node-a's state does not name: a forged claim
static GPTEST_CASE gptest_forged[] =
{
	{"a packet from 10.0.0.1 that claims admin, which node-a may no longer assert, and names the group generation of node-b's state: dropped as an unknown group, counted as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The packets of node-a's host over noise once node-a runs the Generation that deletes Device phone and node-b the one
// before, which holds phone
static GPTEST_CASE gptest_ahead[] =
{
	{"a packet from 10.0.0.1 carries guest, which keeps its number: node-b, on the state before, takes it as guest and not as admin, the group of phone, whose gateway node-a was: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
};

// ... while node-a runs a Generation in which its tags are ops, a group that node-b's state does not know
static GPTEST_CASE gptest_ahead_ops[] =
{
	{"a packet from 10.0.0.1 claims ops, a group that node-b's state does not know: node-b ignores the claim, made on a later state of node-a, and the map judges the packet as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_IGNORED, false},
	{"one from 10.0.0.50 carries admin, the group of phone in both states: node-b takes it, and it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_CARRIED, true},
};

// The packets of node-a's host from the address of phone once the Groups of the owner of phone change, so that its tags are
// admin and ops: node-a runs that Generation and node-b the one before
static GPTEST_CASE gptest_regroup_ahead[] =
{
	{"a packet from 10.0.0.50 claims 5, the new group of phone, which node-b's state does not know: node-b ignores the claim, made on a later state of node-a, and the map judges the packet as phone, admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_IGNORED, true},
};

// ... node-b runs that Generation and node-a the one before
static GPTEST_CASE gptest_regroup_behind[] =
{
	{"a packet from 10.0.0.50 claims admin, the group of phone that node-a could assert before: node-b ignores the claim, made on the state before, and the map judges the packet as phone, admin and ops now: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_IGNORED, true},
};

// The packets of node-a's host once its tags are server, the set of tags of node-b, whose group ID 3 node-b's state gives
// node-b alone: node-a runs that Generation, in which the controller holds its own group in red, and node-b the one before
static GPTEST_CASE gptest_held[] =
{
	{"a packet from 10.0.0.1 while node-a holds its groups in red: it carries no source group, and the map of node-b judges it as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
	{"one from 10.0.0.50, the address of phone, carries none either, and the map judges it as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
};

// ... and the same Generation of node-a without the hold, which the controller never sends while node-b runs that state
static GPTEST_CASE gptest_unheld[] =
{
	{"a packet from 10.0.0.1 that claims server without the hold: node-b's state gives server to node-b alone, so node-b cannot tell the claim from a forged one and drops it as an unknown group, counted as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The datagrams of the harness tunnel endpoint over geneve, in the tag mode trusted-underlay, that name another group
// generation of node-a than node-b's state
static GPTEST_CASE gptest_stale_geneve[] =
{
	{"trusted-underlay: a claim of server that names another group generation of node-a is refused all the same: dropped as an unknown group, counted as refused", true, "10.0.0.1", true, GPTEST_SERVER, GPTEST_SERVER_TAGS, GPTEST_REFUSED, false, true},
	{"trusted-underlay: a claim of admin that names another group generation of node-a is taken, as admin means the same in every Generation: it arrives", true, "10.0.0.1", true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS, GPTEST_CARRIED, true, true},
};

// The packets of node-a's host to node-c's through node-b, the hub of red, while node-a stamps guest, its own group, on the
// packets of its address and admin on those of the address of phone
static GPTEST_CASE gptest_hub[] =
{
	{"a packet from 10.0.0.1 to node-c carries guest: the hub takes the claim, and its policy drops the packet, as admin-in does not allow guest", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
	{"one from 10.0.0.50 to node-c carries admin, which admin-in allows: it passes the hub and arrives at node-c", false, GPTEST_PHONE, false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps admin on the packets of its own address
static GPTEST_CASE gptest_hub_admin[] =
{
	{"a packet from 10.0.0.1 to node-c carries admin now: the policy of the hub judges it by the group that it carries, and it arrives at node-c", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps server, which it may not assert
static GPTEST_CASE gptest_hub_rogue[] =
{
	{"a packet from 10.0.0.1 to node-c that claims server, which node-a may not assert: the hub drops it as an unknown group and counts it as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The packets of node-a's host to the fabric of node-b, the EVPN gateway, while node-a stamps guest, its own group, on the
// packets of its address and admin on those of the address of phone
static GPTEST_CASE gptest_fabric[] =
{
	{"a packet from 10.0.0.1 to the fabric carries guest: node-b, the EVPN gateway, takes the claim, and its policy drops the packet, as admin-in does not allow guest", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, false},
	{"one from 10.0.0.50 to the fabric carries admin, which admin-in allows: node-b hands it to the fabric", false, GPTEST_PHONE, false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps admin on the packets of its own address
static GPTEST_CASE gptest_fabric_admin[] =
{
	{"a packet from 10.0.0.1 to the fabric carries admin now: the policy of node-b judges it by the group that it carries, and it reaches the fabric", false, "10.0.0.1", false, 0, 0, GPTEST_CARRIED, true},
};

// ... while node-a stamps server, which it may not assert
static GPTEST_CASE gptest_fabric_rogue[] =
{
	{"a packet from 10.0.0.1 to the fabric that claims server, which node-a may not assert: node-b drops it as an unknown group and counts it as refused", false, "10.0.0.1", false, 0, 0, GPTEST_REFUSED, false},
};

// The packets of node-a's host over noise while node-a stamps admin on them and node-b does not know the groups of node-a
// yet
static GPTEST_CASE gptest_rollout[] =
{
	{"a claim of admin from node-a, whose groups node-b does not know yet, is ignored, and the map judges the packet from 10.0.0.1 as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_IGNORED, false},
	{"... and the one from 10.0.0.50 as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_IGNORED, true},
};

// The packets of node-a's host over noise while node-a is a node without the Capability tags
static GPTEST_CASE gptest_version0[] =
{
	{"a record of frame version 0 of a packet from 10.0.0.50 is judged by the map, as admin: it arrives", false, GPTEST_PHONE, false, 0, 0, GPTEST_MISSING, true},
	{"one of a packet from 10.0.0.1 is judged by the map, as guest: dropped", false, "10.0.0.1", false, 0, 0, GPTEST_MISSING, false},
};

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct GPTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	USHORT VxlanPort;					// The UDP port of its socket of VXLAN ...
	USHORT GenevePort;					// ... and of Geneve
	UINT64 Generation;					// The Generation of the last state that the test applied
	bool NoPhone;						// Its next states hold no Device phone: the controller deleted it
	bool AdminOps;						// Its next states give phone the tags admin and ops: the Groups of its owner changed
	bool Held;							// Its next states hold its own group in red, so that it stamps none there (node-a)
	UINT64 Since;						// The group generation of node-a in red that its next states name: of its own group at node-a, of the Peer node-a at node-b
	SRWLOCK Lock;						// Arrivals, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UCHAR Last[GPTEST_SIZE * 2];		// The last one, as much as fits
	UINT LastSize;
} GPTEST_NODE;

// The test
typedef struct GPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	GPTEST_NODE Nodes[GPTEST_NUM_NODES];
	SOCKET Vtep;						// The harness tunnel endpoint, on 127.0.0.1: the address of the tunnel endpoint of node-a
	UINT NextPort;						// The UDP source port of the next case
	SOCKET Fabric;						// The harness VTEP of the fabric of node-b, on 127.0.0.1 ...
	USHORT FabricPort;					// ... and its UDP port
	bool Gateway;						// The next states of node-a route the LAN subnets of node-b, the EVPN gateway, to it
} GPTEST_CTX;

static bool GpTestCheck(GPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool GpTestCheck(GPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI
// step
static DWORD WINAPI GpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, GPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "GROUPPOLICY TEST FAILED (did not finish within %u ms)\n", GPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT GpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	if (IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
		return 4;
	}

	Copy(addr, ip.address, 16);
	return 16;
}

// The test packet from the address src and the UDP port sport to the address dst on GPTEST_PORT, GPTEST_SIZE bytes of
// IPv4, into buf
static void GpTestPacketTo(UCHAR *buf, char *src, char *dst, UINT sport)
{
	UCHAR addr[16];

	Zero(buf, GPTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, GPTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	GpTestAddress(addr, src);
	Copy(buf + 12, addr, 4);
	GpTestAddress(addr, dst);
	Copy(buf + 16, addr, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, sport);
	WRITE_USHORT(buf + 22, GPTEST_PORT);
	WRITE_USHORT(buf + 24, GPTEST_SIZE - 20);
	for (UINT i = 28;i < GPTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + sport);
	}
}

// The test packet from the address src and the UDP port sport to the host of the node dst (GpTestPacketTo)
static void GpTestPacket(UCHAR *buf, char *src, UINT dst, UINT sport)
{
	GpTestPacketTo(buf, src, gptest_addrs[dst][0], sport);
}

// The num free UDP ports of the wildcard address into ports, which the system picks, each another: the sockets that
// found them stay open until all are found. False when one cannot be found.
static bool GpTestFreePorts(USHORT *ports, UINT num)
{
	SOCKET sockets[4] = {INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET};
	bool ok = (num <= 4);

	for (UINT i = 0;i < num && ok;i++)
	{
		struct sockaddr_in6 sa;
		int sa_size = sizeof(sa);

		ports[i] = 0;
		sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		Zero(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		if (sockets[i] != INVALID_SOCKET && bind(sockets[i], (struct sockaddr *)&sa, sizeof(sa)) == 0 && getsockname(sockets[i], (struct sockaddr *)&sa, &sa_size) == 0)
		{
			ports[i] = ntohs(sa.sin6_port);
		}
		ok = (ports[i] != 0);
	}

	for (UINT i = 0;i < num && i < 4;i++)
	{
		if (sockets[i] != INVALID_SOCKET)
		{
			closesocket(sockets[i]);
		}
	}

	return ok;
}

// The harness tunnel endpoint: a UDP socket on 127.0.0.1, on a port that the system picks
static SOCKET GpTestOpenVtep()
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in sa;

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Send node-b, from the harness tunnel endpoint, a datagram of the encapsulation of the link of kind on the VNI of red: its
// header, with the source group group, its tag set tags and the group generation generation when has_group is set (the
// group policy extension of VXLAN, the group ID alone, or the option of the source group of Geneve, Core/VxlanGroup.c),
// then the frame of packet behind the Ethernet header of a link. Whether it went.
static bool GpTestInject(GPTEST_CTX *ctx, UINT kind, const UCHAR *packet, bool has_group, UINT group, UINT64 tags, UINT generation)
{
	UCHAR datagram[GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + NODE_LINK_ETHER + GPTEST_SIZE];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	bool geneve = (kind == CONTROL_LINK_GENEVE);
	UINT header = VXLAN_HEADER_SIZE;
	struct sockaddr_in sa;

	Zero(datagram, sizeof(datagram));
	if (geneve)
	{
		VxlanWriteGeneve(datagram, GPTEST_VNI);
		header = GENEVE_HEADER_SIZE;
		if (has_group)
		{
			// The length of the one option in 4-byte words, and the option
			datagram[0] |= (UCHAR)(GENEVE_GROUP_OPTION / 4);
			VxlanWriteGroupOption(datagram + GENEVE_HEADER_SIZE, (USHORT)group, tags, generation);
			header += GENEVE_GROUP_OPTION;
		}
	}
	else
	{
		datagram[0] = VXLAN_FLAG_VNI;
		datagram[4] = (UCHAR)(GPTEST_VNI >> 16);
		datagram[5] = (UCHAR)(GPTEST_VNI >> 8);
		datagram[6] = (UCHAR)GPTEST_VNI;
		if (has_group)
		{
			VxlanWriteGroup(datagram, (USHORT)group);
		}
	}

	// The frame: the Ethernet header of a link and the packet
	Copy(datagram + header, gptest_mac, 6);
	Copy(datagram + header + 6, gptest_mac, 6);
	WRITE_USHORT(datagram + header + 12, MAC_PROTO_IPV4);
	Copy(datagram + header + NODE_LINK_ETHER, packet, GPTEST_SIZE);

	UINT size = header + NODE_LINK_ETHER + GPTEST_SIZE;
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(geneve ? b->GenevePort : b->VxlanPort);

	return sendto(ctx->Vtep, (char *)datagram, (int)size, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)size;
}

// The UDP port of the socket s, 0 for none
static USHORT GpTestPortOf(SOCKET s)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);

	Zero(&sa, sizeof(sa));
	if (s == INVALID_SOCKET || getsockname(s, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		return 0;
	}

	return ntohs(sa.sin_port);
}

// The next datagram that the harness VTEP of the fabric takes within timeout ms, into buf of size bytes: its size, 0 for
// none
static UINT GpTestTakeFabric(GPTEST_CTX *ctx, UCHAR *buf, UINT size, UINT timeout)
{
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(ctx->Fabric, &fds);
	tv.tv_sec = (long)(timeout / 1000);
	tv.tv_usec = (long)((timeout % 1000) * 1000);
	if (select(0, &fds, NULL, NULL, &tv) != 1)
	{
		return 0;
	}

	int got = recvfrom(ctx->Fabric, (char *)buf, (int)size, 0, NULL, NULL);

	return (got > 0 ? (UINT)got : 0);
}

// Drop what the harness VTEP of the fabric holds
static void GpTestDrainFabric(GPTEST_CTX *ctx)
{
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	while (GpTestTakeFabric(ctx, buf, sizeof(buf), 0) != 0)
	{
	}
}

// Whether the datagram d of size bytes that the harness VTEP of the fabric took is the VXLAN datagram of packet: the I flag
// alone, as the gateway hands a packet to the fabric without its source group, and the L3 VNI of red; then the Ethernet
// header to the router MAC of the fabric, untagged, with the EtherType of IPv4; and the packet as it was sent
static bool GpTestIsFabricFrame(const UCHAR *d, UINT size, const UCHAR *packet)
{
	if (size != VXLAN_HEADER_SIZE + NODE_EVPN_ETHER + GPTEST_SIZE || d[0] != VXLAN_FLAG_VNI)
	{
		return false;
	}
	if ((((UINT)d[4] << 16) | ((UINT)d[5] << 8) | d[6]) != GPTEST_L3VNI)
	{
		return false;
	}

	return (Cmp(d + VXLAN_HEADER_SIZE, gptest_fabric_mac, 6) == 0 && READ_USHORT(d + VXLAN_HEADER_SIZE + 12) == MAC_PROTO_IPV4 &&
		Cmp(d + VXLAN_HEADER_SIZE + NODE_EVPN_ETHER, packet, GPTEST_SIZE) == 0);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void GpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"grouppolicytest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void GpTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A link delivers on the
// receive thread of its socket and a session on the thread of the overlay, so the lock orders the two.
static void GpTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	GPTEST_NODE *t = (GPTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The addresses of node i in red into a
static UINT GpTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT k = 0;k < 2;k++)
	{
		Zero(&a[k], sizeof(CONTROL_ADDRESS));
		StrCpy(a[k].Network, sizeof(a[k].Network), "red");
		a[k].VrfId = GPTEST_VRF;
		a[k].AddressSize = GpTestAddress(a[k].Address, gptest_addrs[i][k]);
		a[k].Length = (a[k].AddressSize == 4 ? 24 : 64);
	}

	return 2;
}

// The tunnel endpoint of node i into v: 127.0.0.1 and its ports, or only its ports for itself
static void GpTestVtep(GPTEST_CTX *ctx, UINT i, CONTROL_VTEP *v, bool address)
{
	Zero(v, sizeof(CONTROL_VTEP));
	if (address)
	{
		v->AddressSize = GpTestAddress(v->Address, "127.0.0.1");
	}
	v->VxlanPort = ctx->Nodes[i].VxlanPort;
	v->GenevePort = ctx->Nodes[i].GenevePort;
}

// The Device phone into d: its address in red and its tag admin, or its tags admin and ops with admin_ops, its source group
// when grouped, and in the state of node-a, its gateway, the WireGuard key that makes node-a terminate it. The state names
// no WireGuard port, so node-a runs no WireGuard interface for it, and the address of phone leads to node-a's host, which
// sends from it as phone would.
static void GpTestPhone(CONTROL_DEVICE *d, bool gateway, bool grouped, bool admin_ops)
{
	Zero(d, sizeof(CONTROL_DEVICE));
	StrCpy(d->Name, sizeof(d->Name), "phone");
	d->VrfId = GPTEST_VRF;
	d->NumAddresses = 1;
	StrCpy(d->Addresses[0].Network, sizeof(d->Addresses[0].Network), "red");
	d->Addresses[0].VrfId = GPTEST_VRF;
	d->Addresses[0].AddressSize = GpTestAddress(d->Addresses[0].Address, GPTEST_PHONE);
	d->Addresses[0].Length = 32;
	d->NumTags = 1;
	StrCpy(d->Tags[0], sizeof(d->Tags[0]), "admin");
	if (admin_ops)
	{
		d->NumTags = 2;
		StrCpy(d->Tags[1], sizeof(d->Tags[1]), "ops");
	}
	StrCpy(d->Gateway, sizeof(d->Gateway), gptest_names[GPTEST_A]);

	if (gateway)
	{
		d->HasKey = true;
		for (UINT i = 0;i < NOISE_KEY_SIZE;i++)
		{
			d->Key[i] = (UCHAR)(0x11 + i);
		}
	}

	if (grouped)
	{
		d->Group = (admin_ops ? GPTEST_ADMIN_OPS : GPTEST_ADMIN);
		d->TagSet = (admin_ops ? GPTEST_ADMIN_OPS_TAGS : GPTEST_ADMIN_TAGS);
	}
}

// Add the route of red to prefix/length to the routes of the Peer p
static void GpTestRoute(CONTROL_PEER *p, char *prefix, UINT length)
{
	CONTROL_ROUTE *r = &p->Routes[p->NumRoutes++];

	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = GPTEST_VRF;
	r->AddressSize = GpTestAddress(r->Address, prefix);
	r->Length = length;
}

// Apply the next Generation of node i: its addresses, its tag and its tunnel endpoint; VRF red with the link of kind and
// the tag mode mode, whose policy node-b enforces with the rule admin-in and node-a not at all; the other node as its
// peer; and the Device phone, unless the node's states hold it no more (NoPhone), with the tags admin and ops once the
// Groups of its owner changed (AdminOps). With tagged, both nodes report the Capability tags, as the controller then makes
// their states: node-a's own group in red is own_group with the tag set own_tags, held while its Held is set, node-b's
// server, each node's Peer object names the group of the other and the frame version 1, and phone has its group. The group
// generation of node-a is the Since of the node, at node-a in its own group, at node-b in its Peer node-a; node-b's is
// GPTEST_SINCE. Without, node-a is a node without the Capability: its state names no group and no frame version, and
// node-b's names no group of node-a and no frame version, but its own group and that of phone, as node-b still reports
// the Capability.
static bool GpTestApply(GPTEST_CTX *ctx, UINT i, UINT kind, UINT mode, bool tagged, UINT own_group, UINT64 own_tags)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_RULE *rule = ZeroMalloc(sizeof(CONTROL_RULE));
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	CONTROL_DEVICE *phone = ZeroMalloc(sizeof(CONTROL_DEVICE));
	GPTEST_NODE *t = &ctx->Nodes[i];
	bool b = (i == GPTEST_B);
	UINT j = 1 - i;

	st->Generation = ++t->Generation;
	StrCpy(st->Name, sizeof(st->Name), gptest_names[i]);
	st->NumAddresses = GpTestAddresses(i, st->Addresses);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), gptest_tags[i]);
	GpTestVtep(ctx, i, &st->Vtep, false);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = GPTEST_VRF;
	st->Vrfs[0].Policy = b;
	st->Vrfs[0].Link = kind;
	st->Vrfs[0].Vni = (kind != CONTROL_LINK_NOISE ? GPTEST_VNI : 0);
	st->Vrfs[0].TagMode = mode;

	// The rule of red that node-b enforces: from the tag admin to the tag server, any protocol
	if (b)
	{
		StrCpy(rule->Name, sizeof(rule->Name), "admin-in");
		rule->VrfId = GPTEST_VRF;
		rule->Priority = 100;
		rule->From.NumTags = 1;
		StrCpy(rule->From.Tags[0], sizeof(rule->From.Tags[0]), "admin");
		rule->To.NumTags = 1;
		StrCpy(rule->To.Tags[0], sizeof(rule->To.Tags[0]), "server");
		st->NumRules = 1;
		st->Rules = rule;
	}

	// Its own source group in red
	if (tagged || b)
	{
		st->NumGroups = 1;
		st->Groups[0].VrfId = GPTEST_VRF;
		st->Groups[0].Group = (b ? GPTEST_SERVER : own_group);
		st->Groups[0].TagSet = (b ? GPTEST_SERVER_TAGS : own_tags);
		st->Groups[0].Generation = (b ? GPTEST_SINCE : t->Since);
		st->Groups[0].Held = (b ? false : t->Held);
	}

	// The other node, its peer, with the group that the controller gives it from its tag
	StrCpy(p->Name, sizeof(p->Name), gptest_names[j]);
	Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = GPTEST_VRF;
	p->NumAddresses = GpTestAddresses(j, p->Addresses);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), gptest_tags[j]);
	GpTestVtep(ctx, j, &p->Vtep, true);
	if (tagged)
	{
		p->NumGroups = 1;
		p->Groups[0].VrfId = GPTEST_VRF;
		p->Groups[0].Group = (b ? GPTEST_GUEST : GPTEST_SERVER);
		p->Groups[0].TagSet = (b ? GPTEST_GUEST_TAGS : GPTEST_SERVER_TAGS);
		p->Groups[0].Generation = (b ? t->Since : GPTEST_SINCE);
		p->FrameVersion = NODE_FRAME_VERSION;
	}
	// The LAN subnets of node-b, the EVPN gateway, which the state of node-a routes to it as the controller routes the LAN
	// subnets of a gateway: the fabric holds 172.16.1.0/24 of them (SDN-25, #201)
	if (ctx->Gateway && b == false)
	{
		GpTestRoute(p, "172.16.0.0", 12);
	}
	st->NumPeers = 1;
	st->Peers = p;

	// The Device phone, whose gateway node-a is, unless the controller deleted it
	if (t->NoPhone == false)
	{
		GpTestPhone(phone, b == false, tagged || b, t->AdminOps);
		st->NumDevices = 1;
		st->Devices = phone;
	}

	bool ok = NodeOverlayApply(t->Node, st);

	Free(phone);
	Free(p);
	Free(rule);
	Free(st);

	return ok;
}

// Whether each node runs the Generation that the test applied last with its session to the other up, within GPTEST_BOUND
static bool GpTestWaitLinks(GPTEST_CTX *ctx)
{
	UINT64 end = Tick64() + GPTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[GPTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[GPTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == ctx->Nodes[GPTEST_A].Generation && b.Generation == ctx->Nodes[GPTEST_B].Generation)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}
}

// One Generation of node-a, as GpTestApply makes it, and the wait for it
static bool GpTestApplyA(GPTEST_CTX *ctx, UINT kind, UINT mode, bool tagged, UINT own_group, UINT64 own_tags)
{
	return GpTestApply(ctx, GPTEST_A, kind, mode, tagged, own_group, own_tags) && GpTestWaitLinks(ctx);
}

// One Generation of each node with the link of kind and the tag mode mode, node-b first, node-a with its own group guest:
// each runs it and the session stays up
static bool GpTestSwitch(GPTEST_CTX *ctx, UINT kind, UINT mode, bool tagged)
{
	char what[MAX_SIZE];

	bool applied = GpTestApply(ctx, GPTEST_B, kind, mode, tagged, 0, 0) && GpTestApply(ctx, GPTEST_A, kind, mode, tagged, GPTEST_GUEST, GPTEST_GUEST_TAGS);
	bool linked = applied && GpTestWaitLinks(ctx);

	Format(what, sizeof(what), "The link of red is %s in the tag mode %s, %s: one Generation of each node, node-b first, and the session stays up",
		gptest_kind_names[kind], gptest_mode_names[mode], tagged ? "both nodes with the Capability tags" : "node-a without the Capability tags");
	return GpTestCheck(ctx, applied && linked, what, "applied %u, the Generations %I64u and %I64u and the session on both %u", (UINT)applied,
		ctx->Nodes[GPTEST_A].Generation, ctx->Nodes[GPTEST_B].Generation, (UINT)linked);
}

// Whether the host of node t took at least target packets within timeout
static bool GpTestArrived(GPTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}

	return true;
}

// The counter of the status st that counts the packets of the tag mode mode as result (GPTEST_*)
static UINT64 GpTestCount(const NODE_SOURCE_GROUP_STATUS *st, UINT mode, UINT result)
{
	const CONTROL_GROUP_COUNTERS *c = &st->Modes[mode];

	switch (result)
	{
	case GPTEST_CARRIED:
		return c->Carried;
	case GPTEST_MISSING:
		return c->Missing;
	case GPTEST_IGNORED:
		return c->Ignored;
	case GPTEST_REFUSED:
		return c->Refused;
	}

	return 0;
}

// All the packets that the status st counts
static UINT64 GpTestTotal(const NODE_SOURCE_GROUP_STATUS *st)
{
	UINT64 sum = 0;

	for (UINT mode = 0;mode < CONTROL_TAG_MODES;mode++)
	{
		for (UINT result = 0;result < GPTEST_UNCOUNTED;result++)
		{
			sum += GpTestCount(st, mode, result);
		}
	}

	return sum;
}

// Whether node-b logged at least num lines about the claims that it refused within GPTEST_BOUND, with its status in *st
static bool GpTestLogged(GPTEST_CTX *ctx, UINT64 num, NODE_SOURCE_GROUP_STATUS *st)
{
	UINT64 end = Tick64() + GPTEST_BOUND;

	while (true)
	{
		NodeSourceGroupGetStatus(ctx->Nodes[GPTEST_B].Node, st);
		if (st->Logged >= num)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}
}

//
// The cases
//

// One case over the link of kind, whose packets of node-a node-b judges in the tag mode mode, to the host of the node dst:
// node-b's own, or node-c's through node-b, the hub of red. The packet goes from a source port of its own; node-b must count
// it once, as the case says, or drop it uncounted, and the host of dst take it as it was sent or nothing. An injected
// datagram of Geneve names the group generation of node-a that node-b's state gives, or another one. Node-c takes the
// packet that the hub sends on without the source group that it carried, and counts it as missing.
static void GpTestCaseTo(GPTEST_CTX *ctx, UINT kind, UINT mode, GPTEST_CASE *c, UINT dst)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	GPTEST_NODE *d = &ctx->Nodes[dst];
	NODE_SOURCE_GROUP_STATUS before, after, d_before, d_after;
	NODE_OVERLAY_STATUS ob, oa;
	UCHAR packet[GPTEST_SIZE];
	char what[MAX_SIZE * 2];
	bool sent, counted = false, same = false;

	GpTestPacket(packet, c->Src, dst, ctx->NextPort++);
	NodeSourceGroupGetStatus(b->Node, &before);
	NodeSourceGroupGetStatus(d->Node, &d_before);
	NodeOverlayGetStatus(b->Node, &ob);
	LONG arrivals = InterlockedCompareExchange(&d->Arrivals, 0, 0);

	if (c->Inject)
	{
		sent = GpTestInject(ctx, kind, packet, c->HasGroup, c->Group, c->Tags, (UINT)(b->Since + (c->Stale ? 1 : 0)));
	}
	else
	{
		NodeReaderOnline(a->Node, &a->Reader);
		sent = NodeOverlayInput(a->Node, GPTEST_VRF, packet, GPTEST_SIZE);
		NodeReaderOffline(&a->Reader);
	}

	// Node-b judged the packet once it counted it: by its tag mode and its source group, or, for a packet whose source no
	// route leads to node-a, as a drop of its overlay before any group
	UINT64 end = Tick64() + GPTEST_BOUND;
	while (sent && counted == false)
	{
		NodeSourceGroupGetStatus(b->Node, &after);
		NodeOverlayGetStatus(b->Node, &oa);
		counted = (c->Result == GPTEST_UNCOUNTED ? oa.Dropped > ob.Dropped : GpTestCount(&after, mode, c->Result) > GpTestCount(&before, mode, c->Result));
		if (counted == false)
		{
			if (Tick64() >= end)
			{
				break;
			}
			SleepThread(GPTEST_POLL);
		}
	}

	bool arrived = sent && GpTestArrived(d, arrivals + 1, c->Arrives ? GPTEST_BOUND : GPTEST_QUIET);
	NodeSourceGroupGetStatus(b->Node, &after);
	NodeSourceGroupGetStatus(d->Node, &d_after);

	AcquireSRWLockShared(&d->Lock);
	{
		same = (arrived && d->LastSize == GPTEST_SIZE && Cmp(d->Last, packet, GPTEST_SIZE) == 0);
	}
	ReleaseSRWLockShared(&d->Lock);

	// The packet of the case is the one packet that node-b counted, none for one that it dropped before any group
	UINT64 counts = GpTestTotal(&after) - GpTestTotal(&before);
	UINT64 want = (c->Result == GPTEST_UNCOUNTED ? 0 : 1);
	// ... and node-c took the packet of the hub as one without a source group
	bool stripped = (dst != GPTEST_C || arrived == false ||
		GpTestCount(&d_after, CONTROL_TAG_MODE_SESSION, GPTEST_MISSING) == GpTestCount(&d_before, CONTROL_TAG_MODE_SESSION, GPTEST_MISSING) + 1);

	Format(what, sizeof(what), "  %s: %s", gptest_kind_names[kind], c->What);
	GpTestCheck(ctx, sent && counted && counts == want && arrived == c->Arrives && (c->Arrives == false || same) && stripped, what,
		"sent %u, counted as %s in the tag mode %s %u, %I64u counted in all, arrived %u, as it was sent %u, without its source group %u", (UINT)sent,
		c->Result < GPTEST_UNCOUNTED ? gptest_results[c->Result] : "a drop of the overlay", gptest_mode_names[mode], (UINT)counted, counts,
		(UINT)arrived, (UINT)same, (UINT)stripped);
}

// The num cases of cases, in order, to the host of the node dst
static void GpTestCasesTo(GPTEST_CTX *ctx, UINT kind, UINT mode, GPTEST_CASE *cases, UINT num, UINT dst)
{
	for (UINT i = 0;i < num;i++)
	{
		GpTestCaseTo(ctx, kind, mode, &cases[i], dst);
	}
}

// The num cases of cases, in order, to node-b's host
static void GpTestCases(GPTEST_CTX *ctx, UINT kind, UINT mode, GPTEST_CASE *cases, UINT num)
{
	GpTestCasesTo(ctx, kind, mode, cases, num, GPTEST_B);
}

// The packets of node-a's host over the link of kind, by the group that node-a stamps on them: guest, its own, and admin for
// the address of phone; then admin, which it may assert as the gateway of phone, and server, the group of node-b, which it
// may not, on the packets of its own address: over noise and geneve first with the group generation 0xffffffff, which
// node-b's state does not give node-a, then with the one that it gives. Node-b logs the first claim that it refuses, with
// the group generation that the claim names.
static void GpTestStamped(GPTEST_CTX *ctx, UINT kind)
{
	UINT mode = (kind == CONTROL_LINK_NOISE ? CONTROL_TAG_MODE_SESSION : CONTROL_TAG_MODE_TRUSTED);
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	NODE_SOURCE_GROUP_STATUS st;
	char what[MAX_SIZE];

	GpTestCases(ctx, kind, mode, gptest_own, sizeof(gptest_own) / sizeof(gptest_own[0]));

	Format(what, sizeof(what), "  %s: node-a stamps admin on the packets of its own address, one Generation of node-a", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_admin, sizeof(gptest_admin) / sizeof(gptest_admin[0]));
	}

	NodeSourceGroupGetStatus(ctx->Nodes[GPTEST_B].Node, &st);
	UINT64 logged = st.Logged;

	// The group generation that a claim names does not save a claim of a group that node-a may not assert; the group policy
	// extension of VXLAN names none
	if (kind != CONTROL_LINK_VXLAN)
	{
		a->Since = GPTEST_SINCE_FORGED;
		Format(what, sizeof(what), "  %s: node-a stamps server, the group of node-b, on them with the group generation 0xffffffff, one Generation of node-a", gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_rogue_generation, sizeof(gptest_rogue_generation) / sizeof(gptest_rogue_generation[0]));
		}
		a->Since = GPTEST_SINCE;
	}

	Format(what, sizeof(what), "  %s: node-a stamps server, the group of node-b, on them, one Generation of node-a", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_rogue, sizeof(gptest_rogue) / sizeof(gptest_rogue[0]));
	}

	// The first claim that node-b refused is logged, over noise the one that names the group generation 0xffffffff; it counts
	// the ones within NODE_SOURCE_GROUP_LOG ms after it in its next line
	if (logged == 0)
	{
		bool ok = GpTestLogged(ctx, 1, &st);

		Format(what, sizeof(what), "  %s: node-b logged the first claim that it refused, as an unknown group, with the group generation 0xffffffff that it named", gptest_kind_names[kind]);
		GpTestCheck(ctx, ok && InStr(st.Last, "node-a claimed the group 3") && InStr(st.Last, "in its group generation 4294967295") && InStr(st.Last, "dropped as an unknown group"),
			what, "%I64u lines, the last \"%s\"", st.Logged, st.Last);
	}

	Format(what, sizeof(what), "  %s: node-a stamps guest again, one Generation of node-a", gptest_kind_names[kind]);
	GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS), what, "not within %u ms", GPTEST_BOUND);
}

// The datagrams of the harness tunnel endpoint over the link of kind, vxlan or geneve, in the tag mode trusted-underlay,
// then off
static void GpTestInjected(GPTEST_CTX *ctx, UINT kind)
{
	GpTestCases(ctx, kind, CONTROL_TAG_MODE_TRUSTED, gptest_trusted, sizeof(gptest_trusted) / sizeof(gptest_trusted[0]));
	if (kind == CONTROL_LINK_GENEVE)
	{
		GpTestCases(ctx, kind, CONTROL_TAG_MODE_TRUSTED, gptest_tag_set, sizeof(gptest_tag_set) / sizeof(gptest_tag_set[0]));
		// The option of Geneve names the group generation of node-a, which the extension of VXLAN has no room for
		GpTestCases(ctx, kind, CONTROL_TAG_MODE_TRUSTED, gptest_stale_geneve, sizeof(gptest_stale_geneve) / sizeof(gptest_stale_geneve[0]));
	}

	if (GpTestSwitch(ctx, kind, CONTROL_TAG_MODE_OFF, true))
	{
		GpTestCases(ctx, kind, CONTROL_TAG_MODE_OFF, gptest_off, sizeof(gptest_off) / sizeof(gptest_off[0]));
	}
}

// The tag mode in which node-b judges the packets of node-a over the link of kind in the tag mode trusted-underlay: session
// for the records of the Noise session, trusted-underlay for the datagrams of vxlan and geneve
static UINT GpTestModeOf(UINT kind)
{
	return (kind == CONTROL_LINK_NOISE ? CONTROL_TAG_MODE_SESSION : CONTROL_TAG_MODE_TRUSTED);
}

// The controller deletes Device phone, over the link of kind: its Generation goes in at node-b, whose state then holds no
// phone and gives node-a guest alone, of the group generation 2, while node-a runs the one before, which holds phone and
// names the group generation 1, as a node that the controller cannot reach forwards on the state that it applied last.
// Guest and server keep their numbers and admin, the group of phone, is retired: a claim of guest is still taken, a claim
// of admin made on the state before is ignored, and over noise and geneve one that names the group generation 2 is an
// unknown group. The group policy extension of VXLAN names no group generation.
static void GpTestRetired(GPTEST_CTX *ctx, UINT kind)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	UINT mode = GpTestModeOf(kind);
	char what[MAX_SIZE];

	Print("[the controller deletes Device phone, whose group admin is retired: node-b runs that Generation, node-a the one before, over %s]\n", gptest_kind_names[kind]);
	b->NoPhone = true;
	b->Since = GPTEST_SINCE_NO_PHONE;
	bool applied = GpTestApply(ctx, GPTEST_B, kind, CONTROL_TAG_MODE_TRUSTED, true, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitLinks(ctx);
	Format(what, sizeof(what), "The link of red is %s; the state of node-b holds no phone and gives node-a guest alone, of the group generation 2, and the state of node-a holds phone still, of the group generation 1",
		gptest_kind_names[kind]);
	if (GpTestCheck(ctx, applied, what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_kept, sizeof(gptest_kept) / sizeof(gptest_kept[0]));

		Format(what, sizeof(what), "  %s: node-a stamps admin, the retired group of phone, on the packets of its own address, of the group generation 1, one Generation of node-a",
			gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_retired, sizeof(gptest_retired) / sizeof(gptest_retired[0]));
		}

		// A claim that names the group generation of node-b's state, for a group that node-a may not assert in it
		if (kind != CONTROL_LINK_VXLAN)
		{
			a->Since = GPTEST_SINCE_NO_PHONE;
			Format(what, sizeof(what), "  %s: node-a stamps admin with the group generation 2 that node-b's state gives it, one Generation of node-a", gptest_kind_names[kind]);
			if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS), what, "not within %u ms", GPTEST_BOUND))
			{
				GpTestCases(ctx, kind, mode, gptest_forged, sizeof(gptest_forged) / sizeof(gptest_forged[0]));
			}
		}
	}
	b->NoPhone = false;
	a->Since = GPTEST_SINCE;
	b->Since = GPTEST_SINCE;
}

// The other way round, over the link of kind: node-a runs the Generation that deletes Device phone, of the group generation
// 2, while node-b runs the one before, which holds phone and gives node-a the group generation 1. Guest keeps its number,
// so node-b takes the claim of guest as guest. Then node-a runs a Generation in which its tags are ops, of the group
// generation 3, with phone: node-b ignores the claim of ops, a group that its state does not know, and takes the claim of
// admin of phone.
static void GpTestAhead(GPTEST_CTX *ctx, UINT kind)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	UINT mode = GpTestModeOf(kind);
	char what[MAX_SIZE];

	Print("[the controller deletes Device phone: node-a runs that Generation, node-b the one before, over %s]\n", gptest_kind_names[kind]);
	a->NoPhone = true;
	a->Since = GPTEST_SINCE_NO_PHONE;
	bool applied = GpTestApply(ctx, GPTEST_B, kind, CONTROL_TAG_MODE_TRUSTED, true, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitLinks(ctx);
	Format(what, sizeof(what), "The link of red is %s; the state of node-a holds no phone, of the group generation 2, and the state of node-b holds phone still and gives node-a the group generation 1",
		gptest_kind_names[kind]);
	if (GpTestCheck(ctx, applied, what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, kind, mode, gptest_ahead, sizeof(gptest_ahead) / sizeof(gptest_ahead[0]));

		a->NoPhone = false;
		a->Since = GPTEST_SINCE_OPS;
		Format(what, sizeof(what), "  %s: node-a runs a Generation in which its tags are ops, of the group generation 3, with phone, one Generation of node-a", gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_OPS, GPTEST_OPS_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_ahead_ops, sizeof(gptest_ahead_ops) / sizeof(gptest_ahead_ops[0]));
		}
	}
	a->NoPhone = false;
	a->Since = GPTEST_SINCE;
}

// The Groups of the owner of phone change, over the link of kind, so that the tags of phone are admin and ops, whose group
// ID 5 comes after the largest one of red, and node-a may assert another set of groups, of the group generation 4. First
// node-a runs that Generation and node-b the one before: node-a stamps 5 on the packets of phone, which node-b's state does
// not know, and node-b ignores the claim. Then node-b runs it and node-a the one before: node-a stamps admin, which it
// could assert before, and node-b ignores the claim. Either way the map of node-b judges the packet as phone, which
// admin-in allows: honest packets go while the Generations roll out, over vxlan too, whose claims name no group generation.
static void GpTestRegroup(GPTEST_CTX *ctx, UINT kind)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	UINT mode = GpTestModeOf(kind);
	char what[MAX_SIZE];

	Print("[the Groups of the owner of phone change, so that its tags are admin and ops: one node runs that Generation, the other the one before, over %s]\n", gptest_kind_names[kind]);
	bool applied = GpTestApply(ctx, GPTEST_B, kind, CONTROL_TAG_MODE_TRUSTED, true, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitLinks(ctx);
	Format(what, sizeof(what), "The link of red is %s; one Generation of each node, which agree, node-b first", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, applied, what, "not within %u ms", GPTEST_BOUND))
	{
		a->AdminOps = true;
		a->Since = GPTEST_SINCE_ADMIN_OPS;
		Format(what, sizeof(what), "  %s: node-a runs the Generation in which phone is admin and ops, group 5, of the group generation 4, and node-b the one before", gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_regroup_ahead, sizeof(gptest_regroup_ahead) / sizeof(gptest_regroup_ahead[0]));
		}

		a->AdminOps = false;
		a->Since = GPTEST_SINCE;
		b->AdminOps = true;
		b->Since = GPTEST_SINCE_ADMIN_OPS;
		applied = GpTestApply(ctx, GPTEST_B, kind, CONTROL_TAG_MODE_TRUSTED, true, 0, 0) &&
			GpTestApply(ctx, GPTEST_A, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitLinks(ctx);
		Format(what, sizeof(what), "  %s: node-b runs the Generation in which phone is admin and ops and gives node-a the group generation 4, and node-a the one before", gptest_kind_names[kind]);
		if (GpTestCheck(ctx, applied, what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_regroup_behind, sizeof(gptest_regroup_behind) / sizeof(gptest_regroup_behind[0]));
		}
	}
	a->AdminOps = false;
	b->AdminOps = false;
	a->Since = GPTEST_SINCE;
	b->Since = GPTEST_SINCE;
}

// The tags of node-a move into server, over the link of kind: the set of tags of node-b, whose group ID 3 node-b's state
// gives node-b alone, so that node-b cannot tell a claim of it from a forged one. Node-a runs that Generation, of the group
// generation 5, and node-b the one before, as a node that the controller cannot reach does. The controller holds node-a's
// own group in red until node-b acknowledges a Generation that lets node-a assert server (desired/sourcegrouphold.go), and
// meanwhile node-a stamps no source group and node-b judges each of its packets by the map of address to group. The same
// Generation without the hold would make node-b drop the honest packet of node-a as of an unknown group.
static void GpTestHeld(GPTEST_CTX *ctx, UINT kind)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	UINT mode = GpTestModeOf(kind);
	char what[MAX_SIZE];

	Print("[the tags of node-a move into server, the group of node-b: node-a runs that Generation with its own group held, node-b the one before, over %s]\n", gptest_kind_names[kind]);
	bool applied = GpTestApply(ctx, GPTEST_B, kind, CONTROL_TAG_MODE_TRUSTED, true, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitLinks(ctx);
	Format(what, sizeof(what), "The link of red is %s; one Generation of each node, which agree, node-b first", gptest_kind_names[kind]);
	if (GpTestCheck(ctx, applied, what, "not within %u ms", GPTEST_BOUND))
	{
		a->Held = true;
		a->Since = GPTEST_SINCE_SERVER;
		Format(what, sizeof(what), "  %s: node-a runs the Generation in which its tags are server, of the group generation 5, with its own group in red held, and node-b the one before",
			gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_held, sizeof(gptest_held) / sizeof(gptest_held[0]));
		}

		a->Held = false;
		Format(what, sizeof(what), "  %s: node-a runs the same Generation without the hold, one Generation of node-a", gptest_kind_names[kind]);
		if (GpTestCheck(ctx, GpTestApplyA(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCases(ctx, kind, mode, gptest_unheld, sizeof(gptest_unheld) / sizeof(gptest_unheld[0]));
		}
	}
	a->Held = false;
	a->Since = GPTEST_SINCE;
}

// Add the route of the pool of red, 10.0.0.0/24, to the routes of the Peer p: a spoke reaches every other address of red
// through the hub
static void GpTestPool(CONTROL_PEER *p)
{
	GpTestRoute(p, "10.0.0.0", 24);
}

// Apply the next Generation of node i, over noise, in VRF red of topology hub-and-spoke with the hub node-b, as the
// controller compiles it (desired/topology.go): node-b, the hub, has node-a and node-c as its peers and enforces the policy
// of red with the rule admin-in; node-a and node-c each have node-b as their only peer, with the pool of red as its route,
// and enforce none. Every node reports the Capability tags: node-a's own group is own_group with the tag set own_tags,
// node-b's and node-c's server; each Peer object names the group of its peer, of the group generation GPTEST_SINCE, and the
// frame version 1. Node-a and node-b hold the Device phone, whose gateway node-a is, with its group.
static bool GpTestApplyHub(GPTEST_CTX *ctx, UINT i, UINT own_group, UINT64 own_tags)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_RULE *rule = ZeroMalloc(sizeof(CONTROL_RULE));
	CONTROL_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEER) * (GPTEST_NUM_NODES - 1));
	CONTROL_DEVICE *phone = ZeroMalloc(sizeof(CONTROL_DEVICE));
	GPTEST_NODE *t = &ctx->Nodes[i];
	bool hub = (i == GPTEST_B);

	st->Generation = ++t->Generation;
	StrCpy(st->Name, sizeof(st->Name), gptest_names[i]);
	st->NumAddresses = GpTestAddresses(i, st->Addresses);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), gptest_tags[i]);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = GPTEST_VRF;
	st->Vrfs[0].Policy = hub;
	st->Vrfs[0].Link = CONTROL_LINK_NOISE;
	st->Vrfs[0].TagMode = CONTROL_TAG_MODE_TRUSTED;
	StrCpy(st->Vrfs[0].Hub, sizeof(st->Vrfs[0].Hub), gptest_names[GPTEST_B]);

	// The rule of red that the hub enforces: from the tag admin to the tag server, any protocol
	if (hub)
	{
		StrCpy(rule->Name, sizeof(rule->Name), "admin-in");
		rule->VrfId = GPTEST_VRF;
		rule->Priority = 100;
		rule->From.NumTags = 1;
		StrCpy(rule->From.Tags[0], sizeof(rule->From.Tags[0]), "admin");
		rule->To.NumTags = 1;
		StrCpy(rule->To.Tags[0], sizeof(rule->To.Tags[0]), "server");
		st->NumRules = 1;
		st->Rules = rule;
	}

	// Its own source group in red
	st->NumGroups = 1;
	st->Groups[0].VrfId = GPTEST_VRF;
	st->Groups[0].Group = (i == GPTEST_A ? own_group : GPTEST_SERVER);
	st->Groups[0].TagSet = (i == GPTEST_A ? own_tags : GPTEST_SERVER_TAGS);
	st->Groups[0].Generation = GPTEST_SINCE;

	// Its peers: the spokes at the hub, the hub alone at a spoke
	for (UINT j = 0;j < GPTEST_NUM_NODES;j++)
	{
		if (j == i || (hub == false && j != GPTEST_B))
		{
			continue;
		}

		CONTROL_PEER *p = &peers[st->NumPeers++];
		StrCpy(p->Name, sizeof(p->Name), gptest_names[j]);
		Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		p->NumVrfs = 1;
		p->VrfIds[0] = GPTEST_VRF;
		p->NumAddresses = GpTestAddresses(j, p->Addresses);
		p->NumTags = 1;
		StrCpy(p->Tags[0], sizeof(p->Tags[0]), gptest_tags[j]);
		p->NumGroups = 1;
		p->Groups[0].VrfId = GPTEST_VRF;
		p->Groups[0].Group = (j == GPTEST_A ? GPTEST_GUEST : GPTEST_SERVER);
		p->Groups[0].TagSet = (j == GPTEST_A ? GPTEST_GUEST_TAGS : GPTEST_SERVER_TAGS);
		p->Groups[0].Generation = GPTEST_SINCE;
		p->FrameVersion = NODE_FRAME_VERSION;
		if (hub == false)
		{
			GpTestPool(p);
		}
	}
	st->Peers = peers;

	// The Device phone, whose gateway node-a is
	if (i != GPTEST_C)
	{
		GpTestPhone(phone, i == GPTEST_A, true, false);
		st->NumDevices = 1;
		st->Devices = phone;
	}

	bool ok = NodeOverlayApply(t->Node, st);

	Free(phone);
	Free(peers);
	Free(rule);
	Free(st);

	return ok;
}

// Whether each node runs the Generation that the test applied last, with the sessions of the hub node-b to node-a and node-c
// up, within GPTEST_BOUND
static bool GpTestWaitHub(GPTEST_CTX *ctx)
{
	UINT links[GPTEST_NUM_NODES] = {1, 2, 1};
	UINT64 end = Tick64() + GPTEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < GPTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS s;

			NodeOverlayGetStatus(ctx->Nodes[i].Node, &s);
			all = all && s.NumLinks == links[i] && s.Generation == ctx->Nodes[i].Generation;
		}
		if (all)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GPTEST_POLL);
	}
}

// The hub, over noise: red of topology hub-and-spoke with the hub node-b and the spokes node-a and node-c. The packets of
// node-a's host to node-c's pass node-b, which judges the source group that they carried as their destination would, lets
// its policy judge them by the group that it took, and sends them on without it: guest and admin, the groups that node-a
// stamps on the packets of its own address and of phone; admin on the packets of its own address; and server, which
// node-a may not assert.
static void GpTestHub(GPTEST_CTX *ctx)
{
	char what[MAX_SIZE];

	Print("[the hub: red is hub-and-spoke with the hub node-b and the spokes node-a and node-c, over noise]\n");
	bool applied = GpTestApplyHub(ctx, GPTEST_B, 0, 0) && GpTestApplyHub(ctx, GPTEST_C, 0, 0) &&
		GpTestApplyHub(ctx, GPTEST_A, GPTEST_GUEST, GPTEST_GUEST_TAGS) && GpTestWaitHub(ctx);
	if (GpTestCheck(ctx, applied, "One Generation of each node: node-b, the hub, has a session to node-a and one to node-c, and a spoke one to node-b alone",
		"not within %u ms", GPTEST_BOUND) == false)
	{
		return;
	}

	GpTestCasesTo(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_hub, sizeof(gptest_hub) / sizeof(gptest_hub[0]), GPTEST_C);

	Format(what, sizeof(what), "  noise: node-a stamps admin on the packets of its own address, one Generation of node-a");
	if (GpTestCheck(ctx, GpTestApplyHub(ctx, GPTEST_A, GPTEST_ADMIN, GPTEST_ADMIN_TAGS) && GpTestWaitHub(ctx), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCasesTo(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_hub_admin, sizeof(gptest_hub_admin) / sizeof(gptest_hub_admin[0]), GPTEST_C);
	}

	Format(what, sizeof(what), "  noise: node-a stamps server, which it may not assert, on them, one Generation of node-a");
	if (GpTestCheck(ctx, GpTestApplyHub(ctx, GPTEST_A, GPTEST_SERVER, GPTEST_SERVER_TAGS) && GpTestWaitHub(ctx), what, "not within %u ms", GPTEST_BOUND))
	{
		GpTestCasesTo(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_hub_rogue, sizeof(gptest_hub_rogue) / sizeof(gptest_hub_rogue[0]), GPTEST_C);
	}
}

// Start the EVPN of node-b without its BGP sidecar, as NodeBgpStart does with the node lock held: the evpn object of its Bgp
// setting, with a free UDP port for the VTEP of node-b and the harness VTEP of the fabric on 127.0.0.1 as the VTEP of the
// fabric. Then the IP prefix route of the fabric in red, as the reader thread of the sidecar hands over a learned message and
// puts the routes of one read into the table snapshot (Cedar/NodeEvpn.c). Whether the EVPN of node-b runs with the route.
static bool GpTestEvpnStart(GPTEST_CTX *ctx)
{
	NODE *n = ctx->Nodes[GPTEST_B].Node;
	NODE_EVPN_STATUS st;
	char text[MAX_SIZE];
	USHORT port = 0;

	ctx->Fabric = GpTestOpenVtep();
	ctx->FabricPort = GpTestPortOf(ctx->Fabric);
	if (ctx->FabricPort == 0 || GpTestFreePorts(&port, 1) == false)
	{
		return false;
	}

	Format(text, sizeof(text), GPTEST_EVPN, (UINT)port, (UINT)ctx->FabricPort);
	cJSON *cfg = cJSON_Parse(text);
	Lock(n->Lock);
	{
		NodeEvpnStart(n, cfg);
	}
	Unlock(n->Lock);
	cJSON_Delete(cfg);

	NodeEvpnRoute(n, GPTEST_FABRIC_ROUTE);
	NodeEvpnCommit(n);

	NodeEvpnGetStatus(n, &st);

	return (st.Running && st.NumRoutes == 1);
}

// Stop the EVPN of node-b, as NodeBgpStop does with the node lock held, while the test thread is no online reader
static void GpTestEvpnStop(GPTEST_CTX *ctx)
{
	NODE *n = ctx->Nodes[GPTEST_B].Node;

	Lock(n->Lock);
	{
		NodeEvpnStop(n);
	}
	Unlock(n->Lock);
}

// One case of the EVPN gateway, over noise: a UDP packet of node-a's host from the address of the case to the fabric, which
// node-b must count once in the tag mode session, as the case says, and the harness VTEP of the fabric take as a VXLAN
// datagram with the packet as it was sent, or take nothing
static void GpTestCaseFabric(GPTEST_CTX *ctx, GPTEST_CASE *c)
{
	GPTEST_NODE *a = &ctx->Nodes[GPTEST_A];
	GPTEST_NODE *b = &ctx->Nodes[GPTEST_B];
	NODE_SOURCE_GROUP_STATUS before, after;
	UCHAR packet[GPTEST_SIZE];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE * 2];
	bool counted = false;
	UINT size = 0;

	GpTestDrainFabric(ctx);
	GpTestPacketTo(packet, c->Src, GPTEST_FABRIC_ADDR, ctx->NextPort++);
	NodeSourceGroupGetStatus(b->Node, &before);

	NodeReaderOnline(a->Node, &a->Reader);
	bool sent = NodeOverlayInput(a->Node, GPTEST_VRF, packet, GPTEST_SIZE);
	NodeReaderOffline(&a->Reader);

	// Node-b judged the packet once it counted it, by the source group that it carried
	UINT64 end = Tick64() + GPTEST_BOUND;
	while (sent && counted == false)
	{
		NodeSourceGroupGetStatus(b->Node, &after);
		counted = (GpTestCount(&after, CONTROL_TAG_MODE_SESSION, c->Result) > GpTestCount(&before, CONTROL_TAG_MODE_SESSION, c->Result));
		if (counted == false)
		{
			if (Tick64() >= end)
			{
				break;
			}
			SleepThread(GPTEST_POLL);
		}
	}

	if (sent)
	{
		size = GpTestTakeFabric(ctx, d, sizeof(d), c->Arrives ? GPTEST_BOUND : GPTEST_QUIET);
	}
	NodeSourceGroupGetStatus(b->Node, &after);

	bool arrived = (size != 0);
	bool same = (arrived && GpTestIsFabricFrame(d, size, packet));
	// The packet of the case is the one packet that node-b counted
	UINT64 counts = GpTestTotal(&after) - GpTestTotal(&before);

	Format(what, sizeof(what), "  noise: %s", c->What);
	GpTestCheck(ctx, sent && counted && counts == 1 && arrived == c->Arrives && (c->Arrives == false || same), what,
		"sent %u, counted as %s in the tag mode session %u, %I64u counted in all, reached the fabric %u, as it was sent %u", (UINT)sent,
		gptest_results[c->Result], (UINT)counted, counts, (UINT)arrived, (UINT)same);
}

// The num cases of cases, in order, to the fabric
static void GpTestCasesFabric(GPTEST_CTX *ctx, GPTEST_CASE *cases, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		GpTestCaseFabric(ctx, &cases[i]);
	}
}

// The EVPN gateway, over noise: node-b hands red to a fabric (Cedar/NodeEvpn.c), and the state of node-a routes the LAN
// subnets of node-b to it. Node-b is the destination of the packets of node-a's host to the fabric, so it judges the source
// group that they carried as for a packet to its host: guest and admin, the groups that node-a stamps on the packets of its
// own address and of phone; admin on the packets of its own address; and server, which node-a may not assert.
static void GpTestGateway(GPTEST_CTX *ctx)
{
	char what[MAX_SIZE];

	Print("[the EVPN gateway: node-b hands red to a fabric, and node-a routes the LAN subnets of node-b to it, over noise]\n");
	bool started = GpTestEvpnStart(ctx);
	ctx->Gateway = true;
	if (GpTestCheck(ctx, started, "Node-b runs the EVPN of red, with the IP prefix route 172.16.1.0/24 of the fabric via the harness VTEP on 127.0.0.1",
		"the VTEP of the fabric on the UDP port %u, and the EVPN does not run or holds another number of routes", (UINT)ctx->FabricPort) &&
		GpTestSwitch(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true))
	{
		GpTestCasesFabric(ctx, gptest_fabric, sizeof(gptest_fabric) / sizeof(gptest_fabric[0]));

		Format(what, sizeof(what), "  noise: node-a stamps admin on the packets of its own address, one Generation of node-a");
		if (GpTestCheck(ctx, GpTestApplyA(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCasesFabric(ctx, gptest_fabric_admin, sizeof(gptest_fabric_admin) / sizeof(gptest_fabric_admin[0]));
		}

		Format(what, sizeof(what), "  noise: node-a stamps server, which it may not assert, on them, one Generation of node-a");
		if (GpTestCheck(ctx, GpTestApplyA(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_SERVER, GPTEST_SERVER_TAGS), what, "not within %u ms", GPTEST_BOUND))
		{
			GpTestCasesFabric(ctx, gptest_fabric_rogue, sizeof(gptest_fabric_rogue) / sizeof(gptest_fabric_rogue[0]));
		}
	}
	ctx->Gateway = false;

	GpTestEvpnStop(ctx);
}

// The nodes, their overlays and the harness tunnel endpoint, and the first Generation of node-a and node-b: noise, both
// with the Capability tags. Node-c, which only the case of the hub uses, runs no state until then.
static bool GpTestOpen(GPTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);
	USHORT ports[4];

	Print("[the nodes, their overlays and the harness tunnel endpoint]\n");

	// The UDP ports of VXLAN and of Geneve of node-a and node-b
	ok = GpTestCheck(ctx, ok && GpTestFreePorts(ports, 4), "Four free UDP ports for the tunnel endpoints of the nodes", "error %u", (UINT)WSAGetLastError()) && ok;

	ctx->Vtep = GpTestOpenVtep();
	ok = GpTestCheck(ctx, ok && ctx->Vtep != INVALID_SOCKET, "A harness tunnel endpoint on 127.0.0.1, the address of the tunnel endpoint of node-a", "error %u", (UINT)WSAGetLastError()) && ok;

	for (UINT i = 0;i < GPTEST_NUM_NODES && ok;i++)
	{
		GPTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		t->VxlanPort = (i < 2 ? ports[2 * i] : 0);
		t->GenevePort = (i < 2 ? ports[2 * i + 1] : 0);
		t->Since = GPTEST_SINCE;
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x61 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		GpTestNewDir(t->Dir, sizeof(t->Dir), gptest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = GpTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its tunnel endpoint on the UDP ports %u (VXLAN) and %u (Geneve)", gptest_names[i], (UINT)t->VxlanPort, (UINT)t->GenevePort);
		ok = GpTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok && GpTestSwitch(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true);
}

// The nodes first, whose overlays stop with every thread joined, then the harness tunnel endpoint
static void GpTestClose(GPTEST_CTX *ctx)
{
	for (UINT i = 0;i < GPTEST_NUM_NODES;i++)
	{
		GPTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			GpTestDeleteFiles(log_dir);
			GpTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
	if (ctx->Fabric != INVALID_SOCKET)
	{
		closesocket(ctx->Fabric);
	}
}

// The cases over noise, vxlan and geneve, each in a Generation of its own of both nodes, then over each the retired group of
// phone both ways, the new group of phone both ways and the held group of node-a, the rollout of the Generations, the
// records of frame version 0, the EVPN gateway and the hub
static void GpTestRun(GPTEST_CTX *ctx)
{
	UINT kinds[3] = {CONTROL_LINK_NOISE, CONTROL_LINK_VXLAN, CONTROL_LINK_GENEVE};

	for (UINT k = 0;k < 3;k++)
	{
		UINT kind = kinds[k];

		Print("[the link of red is %s]\n", gptest_kind_names[kind]);
		if (k != 0 && GpTestSwitch(ctx, kind, CONTROL_TAG_MODE_TRUSTED, true) == false)
		{
			return;
		}

		GpTestStamped(ctx, kind);
		if (kind != CONTROL_LINK_NOISE)
		{
			GpTestInjected(ctx, kind);
		}
	}

	// Over each kind of link: the Generation that deletes Device phone at node-b, and the one before at node-a; then the
	// other way round; then the Generation in which the Groups of the owner of phone change, at one node before the other;
	// then the one in which the tags of node-a move into the group of node-b, with node-a's own group held
	for (UINT k = 0;k < 3;k++)
	{
		GpTestRetired(ctx, kinds[k]);
		GpTestAhead(ctx, kinds[k]);
		GpTestRegroup(ctx, kinds[k]);
		GpTestHeld(ctx, kinds[k]);
	}

	// One Generation of each node: node-b's without the groups of node-a, node-a's that stamps admin
	Print("[the Generations roll out: node-a stamps its records before node-b knows its groups, over noise]\n");
	bool applied = GpTestApply(ctx, GPTEST_B, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, false, 0, 0) &&
		GpTestApply(ctx, GPTEST_A, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, true, GPTEST_ADMIN, GPTEST_ADMIN_TAGS) && GpTestWaitLinks(ctx);
	if (GpTestCheck(ctx, applied, "The link of red is noise; node-a sends records of frame version 1 that claim admin, and the state of node-b gives node-a the frame version 0 and none of its groups",
		"not within %u ms", GPTEST_BOUND))
	{
		GpTestCases(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_rollout, sizeof(gptest_rollout) / sizeof(gptest_rollout[0]));
	}

	Print("[frame version 0: node-a is a node without the Capability tags, over noise]\n");
	if (GpTestSwitch(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_TRUSTED, false))
	{
		GpTestCases(ctx, CONTROL_LINK_NOISE, CONTROL_TAG_MODE_SESSION, gptest_version0, sizeof(gptest_version0) / sizeof(gptest_version0[0]));
	}

	// The EVPN gateway judges the source group of the packets that it hands to the fabric, with both nodes' states again
	GpTestGateway(ctx);

	// The hub of a VRF of topology hub-and-spoke judges the source group of the packets that it sends on
	GpTestHub(ctx);
}

// grouppolicy: the policy of a VRF by the source group that a packet carries
RANZ_TEST_TAGS("grouppolicy", grouppolicy_test, "core", "Source group policy (SDN-87): between two nodes, a rule written by tag allows or denies a packet by the source group that it carries, over noise, vxlan and geneve; a claim of a group that the sending node may not assert is dropped, counted and logged, whatever group generation it names; a packet without one is judged by the map of address to group; trusted-underlay honours a forged group and off ignores it; over each kind of link a node on a stale state takes the claims of the groups that the peer may assert, and ignores a claim of a group that the peer could assert before or of a group ID that its state does not know; a node whose own group is held stamps none; a node ignores the claims of a peer whose groups it does not know yet; a node of frame version 0 still gets through; an EVPN gateway judges the source group of a packet of a peer that it hands to the fabric; the hub of a VRF of topology hub-and-spoke judges the source group of a packet that it sends on from one spoke to another.");
void grouppolicy_test(UINT num, char **arg)
{
	GPTEST_CTX *ctx = ZeroMalloc(sizeof(GPTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, GpTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Source group policy test: the node that takes a packet of a peer judges it by the source group that the packet carried\n");

	ctx->Vtep = INVALID_SOCKET;
	ctx->Fabric = INVALID_SOCKET;
	ctx->NextPort = GPTEST_FIRST_PORT;

	if (GpTestOpen(ctx, loopback))
	{
		GpTestRun(ctx);
	}

	GpTestClose(ctx);
	TransportLoopbackFree(loopback);

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
		Print("GROUPPOLICY TEST OK\n");
	}
	else
	{
		Print("GROUPPOLICY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
