// switchtest.c
// Named switch tests of vpntest ("switch" and "switchbench" commands, CORE-S4-1 #74)
//
// The L2 switch of the new core (src/Core/Switch.h) in process, with harness members on its ports that record every
// frame they get, byte for byte:
// - switch: three golden Networks (golden family "switch"). Each case puts one frame into one port and lists what every
//   port got; it must reach exactly the ports that the case names, and the report must match the golden file. Each
//   report ends with the MAC table, the counters of each VLAN, whose fates add up to the frames the VLAN took, and the
//   counters of the switch.
//   - switch_frames.txt: members of different VLANs across access ports, trunk ports and a native VLAN; VLAN-aware
//     learning (one address in two VLANs, on two ports); broadcast, frames to an unknown address and multicast by group
//     subscription, with a member that subscribes to nothing; priority tags; the frames that the VLAN rules drop; a
//     station that moves.
//   - switch_ethertypes.txt: IPX, NetBEUI, AppleTalk, Profinet and IEC 61850 GOOSE frames pass byte for byte, bar the tag
//     that their ports add or take off, and stay in their VLAN.
//   - switch_limits.txt: a Network of TPID 0x88A8 with per-VLAN broadcast and multicast limits on the clock of the test,
//     its per-VLAN counters, and an 0x8100 tag, which is no tag there.
//   Then the configurations that the switch refuses, a full MAC table, aging and clearing, a port that changes its VLAN
//   and a port that is deleted; and threads that forward while the main thread adds, changes and deletes ports, subscribes
//   them and clears the MAC table: each frame reaches its port once and in order, and no member gets a frame once its
//   port was deleted.
// - switchbench: the micro-benchmark of the switch. One thread, then one thread per core (SWBENCH_MAX_THREADS at most),
//   each forwarding between two ports of its own in one VLAN; then the same threads with one lock around the whole switch,
//   as the Hub has. BENCH lines carry the rates, the median of SWBENCH_RUNS runs. The test fails when the threads do not
//   forward at least SWBENCH_SCALING percent of the frames of one thread: forwarding scales across cores with no hub-wide
//   lock.
// Print "SWITCH TEST OK" and "SWITCHBENCH TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Switch.h"

#include <stdio.h>

#define	SWTEST_BUDGET			120000		// The switch test ends within this time, or the watchdog ends the process (ms)
#define	SWTEST_MAX_MEMBERS		8			// Members of a golden Network at most
#define	SWTEST_NO_MEMBER		7			// A port that no member holds in a golden Network
#define	SWTEST_MAX_COPIES		8			// Frames that a member records in one case at most
#define	SWTEST_FRAME_MAX		128			// Bytes of a frame of a case at most
#define	SWTEST_BODY_SIZE		6			// The body of a test frame: EtherType 0x88B5, 'S', 'W', 0 and the number of its case
#define	SWTEST_MAX_MACS			64			// Entries of a MAC table that a report lists at most
#define	SWTEST_FULL_MACS		16			// Entries of the MAC table of the full-table case
#define	SWTEST_FULL_SOURCES		20			// ... and the sources that it sees
#define	SWTEST_AGING			5000		// The aging time of the aging case (ms)
#define	SWTEST_THREADS			4			// Forwarding threads of the concurrent case
#define	SWTEST_VLAN_BASE		100			// The VLAN of forwarding thread i is 100 + i
#define	SWTEST_VLAN_EXTRA		50			// A VLAN of the ports that the main thread adds, besides those
#define	SWTEST_SPAN				600			// ms that the main thread changes ports while the threads forward
#define	SWTEST_ROUNDS			20000		// Rounds of changes at most
#define	SWTEST_SEQ_FRAME		18			// A frame of the concurrent case and of the benchmark: the addresses, 0x88B5 and 4 bytes

#define	SWBENCH_BUDGET			60000		// The benchmark ends within this time, or the watchdog ends the process (ms)
#define	SWBENCH_RUNS			5			// Runs of a case: the BENCH line carries their median (an odd number)
#define	SWBENCH_SPAN			200			// ms of one run
#define	SWBENCH_BATCH			64			// Frames of a thread between two looks at the end of the run
#define	SWBENCH_MAX_THREADS		4			// Threads of the scaling cases at most
#define	SWBENCH_SCALING			150			// Percent of the rate of one thread that three threads or more must reach
#define	SWBENCH_SCALING_TWO		120			// ... and two threads
#define	SWBENCH_VLAN			1			// The VLAN of every port of the benchmark

#define	SWTEST_BIT(i)			(1u << (i))	// A member in the set of members that a case must reach

// Group addresses
static const UCHAR swtest_bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const UCHAR swtest_mdns[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};		// IPv4 multicast 224.0.0.251 (mDNS)
static const UCHAR swtest_llmnr[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFC};		// 224.0.0.252 (LLMNR)
static const UCHAR swtest_hosts[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};		// 224.0.0.1 (all hosts)
static const UCHAR swtest_netbios[6] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x01};	// The NetBIOS functional address of NetBEUI
static const UCHAR swtest_appletalk[6] = {0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF};	// The AppleTalk broadcast address of phase 2
static const UCHAR swtest_dcp[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};		// Profinet DCP Identify
static const UCHAR swtest_goose[6] = {0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01};		// IEC 61850 GOOSE

// The addresses of the members
static const UCHAR swtest_mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const UCHAR swtest_mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};
static const UCHAR swtest_mac_c[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0C};
static const UCHAR swtest_mac_d[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0D};
static const UCHAR swtest_mac_t[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x1E};		// Behind the trunk port T, in each VLAN of T
static const UCHAR swtest_mac_u[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x1F};
static const UCHAR swtest_mac_x[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x99};		// On U in VLAN 10 and on C in VLAN 20
static const UCHAR swtest_mac_z[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0xFF};		// No member has it
static const UCHAR swtest_mac_p1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};
static const UCHAR swtest_mac_p2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0xA2};
static const UCHAR swtest_mac_p3[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0xA3};

// The frames of the non-IP protocols, after the two addresses and the tag: the EtherType or length, then the rest

// IPX (EtherType 0x8137): a RIP request for every network from node A to every node
static const UCHAR swtest_ipx_rip_a[] = {
	0x81, 0x37,
	0xFF, 0xFF, 0x00, 0x28, 0x00, 0x01,												// no checksum, length 40, transport control 0, RIP
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x53,			// to network 0, every node, socket RIP
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x04, 0x53,			// from network 0, node A, socket RIP
	0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,						// request: every network
};

// ... the same from node C
static const UCHAR swtest_ipx_rip_c[] = {
	0x81, 0x37,
	0xFF, 0xFF, 0x00, 0x28, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x53,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x04, 0x53,
	0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

// IPX: an NCP request from node B to node A
static const UCHAR swtest_ipx_ncp[] = {
	0x81, 0x37,
	0xFF, 0xFF, 0x00, 0x22, 0x00, 0x11,												// no checksum, length 34, transport control 0, NCP
	0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x04, 0x51,			// to network 1, node A, socket NCP
	0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x40, 0x03,			// from network 1, node B, socket 0x4003
	0x11, 0x11, 0x00, 0x01,															// request 0x1111, sequence 0, connection 1
};

// NetBEUI: an IEEE 802.3 frame of length 47 with LLC for NetBIOS (SAP 0xF0, UI) and a NAME_QUERY
static const UCHAR swtest_netbeui[] = {
	0x00, 0x2F,
	0xF0, 0xF0, 0x03,
	0x2C, 0x00, 0xFF, 0xEF, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,			// length 44, delimiter 0xEFFF, NAME_QUERY, response correlator 1
	'R', 'A', 'N', 'Z', '-', 'S', 'E', 'R', 'V', 'E', 'R', ' ', ' ', ' ', ' ', ' ',	// the name it queries
	'R', 'A', 'N', 'Z', '-', 'C', 'L', 'I', 'E', 'N', 'T', ' ', ' ', ' ', ' ', ' ',	// the name of the sender
};

// AppleTalk: an IEEE 802.3 frame of length 42 with LLC SNAP (OUI 08-00-07, type 0x809B) and a DDP datagram of NBP, a
// lookup of every AFPServer in the zone of the sender
static const UCHAR swtest_appletalk_nbp[] = {
	0x00, 0x2A,
	0xAA, 0xAA, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9B,
	0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x22, 0x02, 0xFD, 0x02,	// DDP: length 34, to every node of network 0, socket NBP, from 0xFF00.0x22, socket 0xFD
	0x21, 0x01, 0xFF, 0x00, 0x22, 0xFD, 0x00,										// NBP LkUp of one tuple, id 1, from 0xFF00.0x22, socket 0xFD
	0x01, '=', 0x09, 'A', 'F', 'P', 'S', 'e', 'r', 'v', 'e', 'r', 0x01, '*',		// =:AFPServer@*
};

// Profinet RT (EtherType 0x8892): a cyclic frame of RT class 1 (frame id 0x8000) with 8 bytes of IO data, its cycle
// counter, data status and transfer status
static const UCHAR swtest_profinet_rt[] = {
	0x88, 0x92,
	0x80, 0x00,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x12, 0x34, 0x35, 0x00,
};

// Profinet DCP: an Identify request to every station (frame id 0xFEFE)
static const UCHAR swtest_profinet_dcp[] = {
	0x88, 0x92,
	0xFE, 0xFE, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,									// Identify, request, Xid 1
	0x00, 0x01, 0x00, 0x04, 0xFF, 0xFF, 0x00, 0x00,									// response delay 1, the block of the All Selector
};

// IEC 61850 GOOSE (EtherType 0x88B8): APPID 1, length 81, and a goosePdu of 71 bytes
static const UCHAR swtest_goose_pdu[] = {
	0x88, 0xB8,
	0x00, 0x01, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,									// APPID 1, length 81, reserved
	0x61, 0x47,
	0x80, 0x11, 'R', 'A', 'N', 'Z', '/', 'L', 'L', 'N', '0', '$', 'G', 'O', '$', 'g', 'c', 'b', '1',	// gocbRef
	0x81, 0x02, 0x07, 0xD0,															// timeAllowedtoLive 2000 ms
	0x82, 0x0D, 'R', 'A', 'N', 'Z', '/', 'L', 'L', 'N', '0', '$', 'D', 'S', '1',	// datSet
	0x84, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,						// t
	0x85, 0x01, 0x01, 0x86, 0x01, 0x00, 0x87, 0x01, 0x00,							// stNum 1, sqNum 0, simulation false
	0x88, 0x01, 0x01, 0x89, 0x01, 0x00, 0x8A, 0x01, 0x01,							// confRev 1, ndsCom false, numDatSetEntries 1
	0xAB, 0x03, 0x83, 0x01, 0x01,													// allData: a boolean true
};

// The body of case 21 of the limits: an 0x8100 tag of VLAN 7 that the Network of TPID 0x88A8 carries as it is, then the
// body of a test frame
static const UCHAR swtest_inner_tag[] = {0x81, 0x00, 0x00, 0x07, 0x88, 0xB5, 'S', 'W', 0x00, 21};

// One case of a golden Network: one frame into one port
typedef struct SWTEST_CASE
{
	const char *Name;						// Its name in the report
	UINT From;								// The member that sends it; a number of no member is the port itself
	UINT64 Now;								// The time of the switch (ms)
	const UCHAR *Dst;						// The destination address
	const UCHAR *Src;						// The source address
	bool Tagged;							// With a tag after the addresses
	USHORT Tpid;							// ... of this TPID, 0 for the one of the Network
	USHORT Tci;								// ... and this tag control information
	const UCHAR *Body;						// What follows; NULL for the body of a test frame with the number of the case
	UINT BodySize;							// ... its size
	UINT Cut;								// The frame cut to this size, 0 for the whole frame
	UINT Expect;							// The members that get it (SWTEST_BIT)
} SWTEST_CASE;

// The members of switch_frames.txt
#define	SWF_A	0							// Access port of VLAN 10
#define	SWF_B	1							// Access port of VLAN 10
#define	SWF_C	2							// Access port of VLAN 20
#define	SWF_T	3							// Trunk port of VLANs 10, 20 and 30
#define	SWF_U	4							// Trunk port of VLAN 20, native VLAN 10
#define	SWF_D	5							// Access port of VLAN 30, which subscribes to nothing

static const SWTEST_CASE swtest_frames[] =
{
	{"broadcast_vlan10", SWF_A, 1000, swtest_bc, swtest_mac_a, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_B) | SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"unicast_to_learnt_vlan10", SWF_B, 1000, swtest_mac_a, swtest_mac_b, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_A)},
	{"broadcast_vlan20", SWF_C, 1000, swtest_bc, swtest_mac_c, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"trunk_vlan20_to_access", SWF_T, 1000, swtest_mac_c, swtest_mac_t, true, 0, 20, NULL, 0, 0, SWTEST_BIT(SWF_C)},
	{"trunk_vlan10_to_access", SWF_T, 1000, swtest_mac_a, swtest_mac_t, true, 0, 10, NULL, 0, 0, SWTEST_BIT(SWF_A)},
	{"native_untagged_from_trunk", SWF_U, 1000, swtest_mac_b, swtest_mac_x, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_B)},
	{"same_mac_in_vlan20", SWF_C, 1000, swtest_bc, swtest_mac_x, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"to_shared_mac_in_vlan10", SWF_T, 1000, swtest_mac_x, swtest_mac_t, true, 0, 10, NULL, 0, 0, SWTEST_BIT(SWF_U)},
	{"to_shared_mac_in_vlan20", SWF_T, 1000, swtest_mac_x, swtest_mac_t, true, 0, 20, NULL, 0, 0, SWTEST_BIT(SWF_C)},
	{"unknown_unicast_vlan10", SWF_A, 1000, swtest_mac_z, swtest_mac_a, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_B) | SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"unknown_unicast_vlan30", SWF_T, 1000, swtest_mac_z, swtest_mac_t, true, 0, 30, NULL, 0, 0, 0},
	{"broadcast_from_unsubscribed_member", SWF_D, 1000, swtest_bc, swtest_mac_d, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_T)},
	{"unicast_to_unsubscribed_member", SWF_T, 1000, swtest_mac_d, swtest_mac_t, true, 0, 30, NULL, 0, 0, SWTEST_BIT(SWF_D)},
	{"multicast_subscribed_group", SWF_A, 1000, swtest_mdns, swtest_mac_a, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_B)},
	{"multicast_every_group_subscriber", SWF_C, 1000, swtest_llmnr, swtest_mac_c, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_T)},
	{"priority_tagged_broadcast", SWF_A, 1000, swtest_bc, swtest_mac_a, true, 0, 0xA000, NULL, 0, 0, SWTEST_BIT(SWF_B) | SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"access_tag_of_own_vlan", SWF_A, 1000, swtest_mac_b, swtest_mac_a, true, 0, 10, NULL, 0, 0, SWTEST_BIT(SWF_B)},
	{"access_tag_of_other_vlan", SWF_A, 1000, swtest_mac_b, swtest_mac_a, true, 0, 20, NULL, 0, 0, 0},
	{"trunk_untagged_without_native", SWF_T, 1000, swtest_mac_a, swtest_mac_t, false, 0, 0, NULL, 0, 0, 0},
	{"trunk_vlan_not_allowed", SWF_T, 1000, swtest_bc, swtest_mac_t, true, 0, 40, NULL, 0, 0, 0},
	{"trunk_tag_of_native_vlan", SWF_U, 1000, swtest_mac_b, swtest_mac_u, true, 0, 10, NULL, 0, 0, SWTEST_BIT(SWF_B)},
	{"vlan_id_4095", SWF_T, 1000, swtest_bc, swtest_mac_t, true, 0, 0x0FFF, NULL, 0, 0, 0},
	{"group_source_address", SWF_A, 1000, swtest_mac_b, swtest_mdns, false, 0, 0, NULL, 0, 0, 0},
	{"frame_too_short", SWF_A, 1000, swtest_mac_b, swtest_mac_a, false, 0, 0, NULL, 0, 13, 0},
	{"tag_cut_short", SWF_T, 1000, swtest_mac_c, swtest_mac_t, true, 0, 20, NULL, 0, 17, 0},
	{"back_to_own_port", SWF_U, 1000, swtest_mac_x, swtest_mac_u, false, 0, 0, NULL, 0, 0, 0},
	{"station_moves", SWF_B, 1000, swtest_bc, swtest_mac_a, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWF_A) | SWTEST_BIT(SWF_T) | SWTEST_BIT(SWF_U)},
	{"unicast_after_move", SWF_T, 1000, swtest_mac_a, swtest_mac_t, true, 0, 10, NULL, 0, 0, SWTEST_BIT(SWF_B)},
	{"port_without_member", SWTEST_NO_MEMBER, 1000, swtest_bc, swtest_mac_a, false, 0, 0, NULL, 0, 0, 0},
};

// The members of switch_ethertypes.txt
#define	SWE_A	0							// Access port of VLAN 10
#define	SWE_B	1							// Access port of VLAN 10
#define	SWE_T	2							// Trunk port of VLAN 10
#define	SWE_C	3							// Access port of VLAN 20
#define	SWE_D	4							// Access port of VLAN 20

static const SWTEST_CASE swtest_ethertypes[] =
{
	{"ipx_rip_request_broadcast", SWE_A, 1000, swtest_bc, swtest_mac_a, false, 0, 0, swtest_ipx_rip_a, sizeof(swtest_ipx_rip_a), 0, SWTEST_BIT(SWE_B) | SWTEST_BIT(SWE_T)},
	{"ipx_ncp_unicast", SWE_B, 1000, swtest_mac_a, swtest_mac_b, false, 0, 0, swtest_ipx_ncp, sizeof(swtest_ipx_ncp), 0, SWTEST_BIT(SWE_A)},
	{"netbeui_name_query", SWE_A, 1000, swtest_netbios, swtest_mac_a, false, 0, 0, swtest_netbeui, sizeof(swtest_netbeui), 0, SWTEST_BIT(SWE_B) | SWTEST_BIT(SWE_T)},
	{"appletalk_nbp_lookup", SWE_T, 1000, swtest_appletalk, swtest_mac_t, true, 0, 10, swtest_appletalk_nbp, sizeof(swtest_appletalk_nbp), 0, SWTEST_BIT(SWE_A) | SWTEST_BIT(SWE_B)},
	{"profinet_rt_priority_tagged", SWE_A, 1000, swtest_mac_b, swtest_mac_a, true, 0, 0xC000, swtest_profinet_rt, sizeof(swtest_profinet_rt), 0, SWTEST_BIT(SWE_B)},
	{"profinet_dcp_identify", SWE_A, 1000, swtest_dcp, swtest_mac_a, false, 0, 0, swtest_profinet_dcp, sizeof(swtest_profinet_dcp), 0, SWTEST_BIT(SWE_B)},
	{"goose_priority_tagged", SWE_A, 1000, swtest_goose, swtest_mac_a, true, 0, 0x8000, swtest_goose_pdu, sizeof(swtest_goose_pdu), 0, SWTEST_BIT(SWE_B) | SWTEST_BIT(SWE_T)},
	{"goose_vlan_tagged_from_trunk", SWE_T, 1000, swtest_goose, swtest_mac_t, true, 0, 0x800A, swtest_goose_pdu, sizeof(swtest_goose_pdu), 0, SWTEST_BIT(SWE_A) | SWTEST_BIT(SWE_B)},
	{"ipx_rip_request_vlan20", SWE_C, 1000, swtest_bc, swtest_mac_c, false, 0, 0, swtest_ipx_rip_c, sizeof(swtest_ipx_rip_c), 0, SWTEST_BIT(SWE_D)},
};

// The members of switch_limits.txt
#define	SWL_P1	0							// Access port of VLAN 100
#define	SWL_P2	1							// Trunk port of VLANs 100 and 200
#define	SWL_P3	2							// Access port of VLAN 200

static const SWTEST_CASE swtest_limits[] =
{
	{"broadcast_within_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_within_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_within_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_within_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_over_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, 0},
	{"broadcast_over_limit", SWL_P1, 1000, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, 0},
	{"broadcast_after_250_ms", SWL_P1, 1250, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_over_limit", SWL_P1, 1250, swtest_bc, swtest_mac_p1, false, 0, 0, NULL, 0, 0, 0},
	{"unknown_unicast_under_broadcast_limit", SWL_P1, 1500, swtest_mac_z, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"unknown_unicast_over_limit", SWL_P1, 1500, swtest_mac_z, swtest_mac_p1, false, 0, 0, NULL, 0, 0, 0},
	{"multicast_within_vlan200_limit", SWL_P3, 2000, swtest_hosts, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"multicast_within_vlan200_limit", SWL_P3, 2000, swtest_hosts, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"multicast_within_vlan200_limit", SWL_P3, 2000, swtest_hosts, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"multicast_over_vlan200_limit", SWL_P3, 2000, swtest_hosts, swtest_mac_p3, false, 0, 0, NULL, 0, 0, 0},
	{"broadcast_within_vlan200_limit", SWL_P3, 2000, swtest_bc, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_within_vlan200_limit", SWL_P3, 2000, swtest_bc, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"broadcast_over_vlan200_limit", SWL_P3, 2000, swtest_bc, swtest_mac_p3, false, 0, 0, NULL, 0, 0, 0},
	{"broadcast_after_refill", SWL_P3, 5000, swtest_bc, swtest_mac_p3, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"tpid_88a8_tag_from_trunk", SWL_P2, 5000, swtest_mac_p3, swtest_mac_p2, true, 0, 200, NULL, 0, 0, SWTEST_BIT(SWL_P3)},
	{"tpid_8100_tag_is_no_tag", SWL_P2, 5000, swtest_mac_p3, swtest_mac_p2, true, 0x8100, 200, NULL, 0, 0, 0},
	{"inner_8100_tag_stays", SWL_P1, 5000, swtest_bc, swtest_mac_p1, false, 0, 0, swtest_inner_tag, sizeof(swtest_inner_tag), 0, SWTEST_BIT(SWL_P2)},
	{"multicast_vlan100", SWL_P1, 5000, swtest_hosts, swtest_mac_p1, false, 0, 0, NULL, 0, 0, SWTEST_BIT(SWL_P2)},
	{"multicast_only_to_own_port", SWL_P2, 5000, swtest_hosts, swtest_mac_p2, true, 0, 100, NULL, 0, 0, 0},
};

// The test
typedef struct SWTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	char OutDir[MAX_SIZE];						// The output and golden directories of the golden family "switch"
	char GoldenDir[MAX_SIZE];
	bool Update;								// Update mode: the golden files are written, not compared
} SWTEST_CTX;

// A member of a port of a golden Network, and what it got in the current case
typedef struct SWTEST_MEMBER
{
	const char *Name;							// Its name in the report
	UINT Port;									// Its port
	UINT NumFrames;								// The frames it got in the current case
	UINT Sizes[SWTEST_MAX_COPIES];				// ... their sizes
	UCHAR Frames[SWTEST_MAX_COPIES][SWTEST_FRAME_MAX];	// ... and their bytes
	UINT WrongPort;								// Frames that the switch handed over with the number of another port
} SWTEST_MEMBER;

// A golden Network: a switch and its members
typedef struct SWTEST_NET
{
	SWITCH *Switch;
	USHORT Tpid;								// The TPID of its tags
	bool SetupOk;								// Every port and subscription was made
	UINT NumMembers;
	SWTEST_MEMBER Members[SWTEST_MAX_MEMBERS];
	BUF *Report;								// The report of the golden file
	UINT NumWrong;								// Cases that reached other members than they name
	char Wrong[MAX_SIZE];						// ... their numbers
} SWTEST_NET;

// One side of the pair of a forwarding thread of the concurrent case
typedef struct SWTEST_SIDE
{
	UINT Port;									// Its port
	UCHAR Mac[6];								// Its address
	UCHAR PeerMac[6];							// The address of the other side, the source of every frame it gets
	UINT Next;									// The sequence number of the next frame it must get
	UINT Got;									// Frames it got
	UINT Wrong;									// ... out of order, of another source, size or port
} SWTEST_SIDE;

// A forwarding thread of the concurrent case and its pair of ports, in a VLAN of its own
typedef struct SWTEST_WORKER
{
	SWITCH *Switch;
	HANDLE Start;								// Set when the threads begin
	volatile LONG *Stop;						// Set when they end
	SWTEST_SIDE A;								// The side that sends the even frames, every 16th to the broadcast address
	SWTEST_SIDE B;								// ... and the odd frames
	UINT Sent;									// Frames sent
	HANDLE Thread;
} SWTEST_WORKER;

// A port that the main thread adds, subscribes and deletes while the threads forward
typedef struct SWTEST_EXTRA
{
	volatile LONG Deleted;						// Set once SwitchDelPort of its port returned
	volatile LONG Got;							// Frames it got
	volatile LONG Late;							// ... after it was deleted
} SWTEST_EXTRA;

// A thread of the benchmark and its pair of ports
typedef struct SWBENCH_THREAD
{
	SWITCH *Switch;
	SRWLOCK *HubLock;							// One lock around the whole switch, as the Hub has; NULL for none
	HANDLE Go;									// Set when the run begins
	volatile LONG *Stop;						// Set when it ends
	UINT PortA;
	UINT PortB;
	UCHAR FrameA[SWTEST_SEQ_FRAME];				// From A to B
	UCHAR FrameB[SWTEST_SEQ_FRAME];				// From B to A
	UCHAR Pad1[64];								// The counter on cache lines of its own
	volatile LONG64 Got;						// Frames that its ports got
	UCHAR Pad2[64];
	HANDLE Thread;
} SWBENCH_THREAD;

static bool SwTestCheck(SWTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SwTestCheck(SWTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
// step. Its parameter is the event that ends it; the budget and the name of the test come from the global below.
static UINT swtest_budget = SWTEST_BUDGET;
static char *swtest_name = "SWITCH";

static DWORD WINAPI SwTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, swtest_budget) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "%s TEST FAILED (did not finish within %u ms)\n", swtest_name, swtest_budget);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// A frame into f: to dst from src, with a tag of tpid and tci when tagged, then body; its size
static UINT SwTestBuild(UCHAR *f, const UCHAR *dst, const UCHAR *src, bool tagged, USHORT tpid, USHORT tci, const UCHAR *body, UINT body_size)
{
	UINT pos = 12;

	Copy(f, dst, 6);
	Copy(f + 6, src, 6);
	if (tagged)
	{
		f[pos++] = (UCHAR)(tpid >> 8);
		f[pos++] = (UCHAR)tpid;
		f[pos++] = (UCHAR)(tci >> 8);
		f[pos++] = (UCHAR)tci;
	}
	Copy(f + pos, body, body_size);

	return pos + body_size;
}

// The body of the test frame of case n: EtherType 0x88B5 (IEEE local experimental), 'S', 'W', 0 and n
static void SwTestBody(UCHAR *body, UINT n)
{
	body[0] = 0x88;
	body[1] = 0xB5;
	body[2] = 'S';
	body[3] = 'W';
	body[4] = 0;
	body[5] = (UCHAR)n;
}

//
// The golden Networks
//

// The procedure of a member of a golden Network: it records the frame
static void SwTestRecord(void *param, UINT port, const UCHAR *frame, UINT size)
{
	SWTEST_MEMBER *m = (SWTEST_MEMBER *)param;

	if (port != m->Port)
	{
		m->WrongPort++;
	}
	if (m->NumFrames < SWTEST_MAX_COPIES)
	{
		m->Sizes[m->NumFrames] = size;
		Copy(m->Frames[m->NumFrames], frame, MIN(size, SWTEST_FRAME_MAX));
	}
	m->NumFrames++;
}

// A golden Network: a switch of the TPID tpid with the limits broadcast and multicast
static SWTEST_NET *SwTestNewNet(USHORT tpid, UINT broadcast, UINT multicast)
{
	SWTEST_NET *net = ZeroMalloc(sizeof(SWTEST_NET));
	SWITCH_CONFIG c;

	Zero(&c, sizeof(c));
	c.Tpid = tpid;
	c.MaxPorts = SWTEST_MAX_MEMBERS;
	c.MaxMacs = 1024;
	c.BroadcastLimit = broadcast;
	c.MulticastLimit = multicast;

	net->Switch = SwitchNew(&c);
	net->Tpid = (tpid != 0 ? tpid : SWITCH_TPID_8021Q);
	net->SetupOk = (net->Switch != NULL);
	net->Report = NewBuf();

	return net;
}

static void SwTestFreeNet(SWTEST_NET *net)
{
	SwitchFree(net->Switch);
	FreeBuf(net->Report);
	Free(net);
}

// A member of a golden Network on the next port: access (no allowed list) or trunk
static void SwTestMember(SWTEST_NET *net, const char *name, UINT mode, UINT vlan, const USHORT *allowed, UINT num_allowed)
{
	SWITCH_PORT_CONFIG c;
	SWTEST_MEMBER *m = &net->Members[net->NumMembers];

	Zero(&c, sizeof(c));
	c.Mode = mode;
	c.Vlan = vlan;
	c.Allowed = allowed;
	c.NumAllowed = num_allowed;
	c.Send = SwTestRecord;
	c.Param = m;

	m->Name = name;
	m->Port = SwitchAddPort(net->Switch, &c);
	if (m->Port != net->NumMembers)
	{
		net->SetupOk = false;
	}
	net->NumMembers++;
}

// A subscription of a member of a golden Network
static void SwTestJoin(SWTEST_NET *net, UINT member, UINT vlan, const UCHAR *group)
{
	if (SwitchSubscribe(net->Switch, net->Members[member].Port, vlan, group) == false)
	{
		net->SetupOk = false;
	}
}

// The name of the member of a port, "-" for none
static const char *SwTestPortName(SWTEST_NET *net, UINT port)
{
	for (UINT i = 0; i < net->NumMembers; i++)
	{
		if (net->Members[i].Port == port)
		{
			return net->Members[i].Name;
		}
	}

	return "-";
}

// Case n of a golden Network: what each member got goes to the report as "<n> <name>: <member> got <hex>", or the case
// as "<n> <name>: nothing" when no member got anything
static void SwTestRun(SWTEST_NET *net, UINT n, const SWTEST_CASE *c)
{
	UCHAR frame[SWTEST_FRAME_MAX];
	UCHAR body[SWTEST_BODY_SIZE];
	char line[MAX_SIZE * 2];
	char hex[SWTEST_FRAME_MAX * 2 + 1];
	char num[16];
	UINT got = 0;
	UINT size;
	UINT from = (c->From < net->NumMembers ? net->Members[c->From].Port : c->From);
	USHORT tpid = (c->Tpid != 0 ? c->Tpid : net->Tpid);

	if (c->Body != NULL)
	{
		size = SwTestBuild(frame, c->Dst, c->Src, c->Tagged, tpid, c->Tci, c->Body, c->BodySize);
	}
	else
	{
		SwTestBody(body, n);
		size = SwTestBuild(frame, c->Dst, c->Src, c->Tagged, tpid, c->Tci, body, sizeof(body));
	}
	if (c->Cut != 0)
	{
		size = c->Cut;
	}

	for (UINT i = 0; i < net->NumMembers; i++)
	{
		net->Members[i].NumFrames = 0;
	}

	SwitchInput(net->Switch, c->Now, from, frame, size);

	for (UINT i = 0; i < net->NumMembers; i++)
	{
		SWTEST_MEMBER *m = &net->Members[i];

		for (UINT k = 0; k < m->NumFrames && k < SWTEST_MAX_COPIES; k++)
		{
			BinToStr(hex, sizeof(hex), m->Frames[k], MIN(m->Sizes[k], SWTEST_FRAME_MAX));
			Format(line, sizeof(line), "%u %s: %s got %s\n", n, c->Name, m->Name, hex);
			WriteBuf(net->Report, line, StrLen(line));
		}
		if (m->NumFrames != 0)
		{
			got |= SWTEST_BIT(i);
		}
	}

	if (got == 0)
	{
		Format(line, sizeof(line), "%u %s: nothing\n", n, c->Name);
		WriteBuf(net->Report, line, StrLen(line));
	}

	if (got != c->Expect)
	{
		Format(num, sizeof(num), " %u", n);
		StrCat(net->Wrong, sizeof(net->Wrong), num);
		net->NumWrong++;
	}
}

// The end of a report: the MAC table, the counters of the VLANs vlans and those of the switch. Checks that the fates of
// the frames of each VLAN add up to the frames that it took.
static void SwTestTrailer(SWTEST_CTX *ctx, SWTEST_NET *net, const UINT *vlans, UINT num_vlans, char *what)
{
	SWITCH_MAC_ENTRY *macs = ZeroMalloc(sizeof(SWITCH_MAC_ENTRY) * SWTEST_MAX_MACS);
	UINT num = SwitchGetMacs(net->Switch, macs, SWTEST_MAX_MACS);
	char line[MAX_SIZE * 2];
	char tmp[MAX_SIZE];
	char mac[MAX_SIZE];
	SWITCH_STATS st;
	bool sums = true;

	for (UINT i = 0; i < num; i++)
	{
		MacToStr(mac, sizeof(mac), macs[i].Mac);
		Format(line, sizeof(line), "mac %u %s: %s\n", macs[i].Vlan, mac, SwTestPortName(net, macs[i].Port));
		WriteBuf(net->Report, line, StrLen(line));
	}

	for (UINT i = 0; i < num_vlans; i++)
	{
		SWITCH_VLAN_STATS v;
		bool ok = SwitchGetVlanStats(net->Switch, vlans[i], &v);

		Format(line, sizeof(line), "vlan %u: in %I64u frames %I64u bytes; unicast %I64u, flooded %I64u, broadcast %I64u, multicast %I64u, limit drops %I64u, filtered %I64u; out %I64u frames %I64u bytes; limits broadcast %u/s, multicast %u/s\n",
			vlans[i], v.InFrames, v.InBytes, v.Unicast, v.Flooded, v.Broadcast, v.Multicast, v.LimitDrops, v.Filtered, v.OutFrames, v.OutBytes,
			v.BroadcastLimit, v.MulticastLimit);
		WriteBuf(net->Report, line, StrLen(line));

		if (ok == false || v.InFrames != v.Unicast + v.Flooded + v.Broadcast + v.Multicast + v.LimitDrops + v.Filtered)
		{
			sums = false;
		}
	}

	SwitchGetStats(net->Switch, &st);
	Format(line, sizeof(line), "switch: ports %u, macs %u, vlans %u, learnt %I64u, moved %I64u, refused %I64u; drops malformed %I64u, port %I64u, vlan %I64u, source %I64u\n",
		st.NumPorts, st.NumMacs, st.NumVlans, st.Learnt, st.Moved, st.Refused, st.Drops[SWITCH_DROP_MALFORMED], st.Drops[SWITCH_DROP_PORT],
		st.Drops[SWITCH_DROP_VLAN], st.Drops[SWITCH_DROP_SOURCE]);
	WriteBuf(net->Report, line, StrLen(line));

	Format(tmp, sizeof(tmp), "%s: the fates of the frames of each VLAN add up to the frames that it took", what);
	SwTestCheck(ctx, sums, tmp, "a VLAN has no state, or its counters do not add up (the counters are in the report)");

	Free(macs);
}

// Run the cases of a golden Network and compare its report with the golden file
static void SwTestGolden(SWTEST_CTX *ctx, SWTEST_NET *net, const SWTEST_CASE *cases, UINT num_cases, const UINT *vlans, UINT num_vlans, char *file, char *what)
{
	HARNESS h;
	char tmp[MAX_SIZE];
	UINT wrong_port = 0;

	Format(tmp, sizeof(tmp), "%s: the switch, its ports and their subscriptions are made", what);
	if (SwTestCheck(ctx, net->SetupOk, tmp, "SwitchNew, SwitchAddPort or SwitchSubscribe failed") == false)
	{
		return;
	}

	for (UINT i = 0; i < num_cases; i++)
	{
		SwTestRun(net, i + 1, &cases[i]);
	}

	SwTestTrailer(ctx, net, vlans, num_vlans, what);

	Format(tmp, sizeof(tmp), "%s: every case reaches exactly the members that it names", what);
	SwTestCheck(ctx, net->NumWrong == 0, tmp, "cases%s reach other members (the report is below)", net->Wrong);

	for (UINT i = 0; i < net->NumMembers; i++)
	{
		wrong_port += net->Members[i].WrongPort;
	}
	Format(tmp, sizeof(tmp), "%s: the switch hands each frame to a member with the number of its port", what);
	SwTestCheck(ctx, wrong_port == 0, tmp, "%u frames with the number of another port", wrong_port);

	char *report = HarnessBufToStr(net->Report);
	if (net->NumWrong != 0)
	{
		Print("--- the report of %s:\n%s", file, report);
	}

	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, file, report, ctx->Update);
	Format(tmp, sizeof(tmp), "%s: the report matches the golden file %s", what, file);
	SwTestCheck(ctx, h.NumFail == 0, tmp, "it differs from the golden file (the diff is above)");

	Free(report);
}

// switch_frames.txt: members of VLANs 10, 20 and 30 on access ports, trunk ports and a native VLAN
static void SwTestFrames(SWTEST_CTX *ctx)
{
	static const USHORT trunk_t[] = {10, 20, 30};
	static const USHORT trunk_u[] = {20};
	static const UINT vlans[] = {10, 20, 30};
	SWTEST_NET *net = SwTestNewNet(0, 0, 0);

	Print("[frames: access, trunk and native ports, VLAN-aware learning, broadcast and multicast by subscription]\n");

	if (net->Switch != NULL)
	{
		SwTestMember(net, "A", SWITCH_ACCESS, 10, NULL, 0);
		SwTestMember(net, "B", SWITCH_ACCESS, 10, NULL, 0);
		SwTestMember(net, "C", SWITCH_ACCESS, 20, NULL, 0);
		SwTestMember(net, "T", SWITCH_TRUNK, 0, trunk_t, sizeof(trunk_t) / sizeof(trunk_t[0]));
		SwTestMember(net, "U", SWITCH_TRUNK, 10, trunk_u, sizeof(trunk_u) / sizeof(trunk_u[0]));
		SwTestMember(net, "D", SWITCH_ACCESS, 30, NULL, 0);

		// D subscribes to nothing; T takes every group of VLAN 20
		SwTestJoin(net, SWF_A, 10, swtest_bc);
		SwTestJoin(net, SWF_B, 10, swtest_bc);
		SwTestJoin(net, SWF_T, 10, swtest_bc);
		SwTestJoin(net, SWF_U, 10, swtest_bc);
		SwTestJoin(net, SWF_C, 20, swtest_bc);
		SwTestJoin(net, SWF_U, 20, swtest_bc);
		SwTestJoin(net, SWF_T, 20, NULL);
		SwTestJoin(net, SWF_T, 30, swtest_bc);
		SwTestJoin(net, SWF_B, 10, swtest_mdns);
	}

	SwTestGolden(ctx, net, swtest_frames, sizeof(swtest_frames) / sizeof(swtest_frames[0]), vlans, sizeof(vlans) / sizeof(vlans[0]),
		"switch_frames.txt", "frames");
	SwTestFreeNet(net);
}

// switch_ethertypes.txt: IPX, NetBEUI, AppleTalk, Profinet and GOOSE in VLAN 10, and IPX in VLAN 20
static void SwTestEtherTypes(SWTEST_CTX *ctx)
{
	static const USHORT trunk_t[] = {10};
	static const UINT vlans[] = {10, 20};
	SWTEST_NET *net = SwTestNewNet(0, 0, 0);

	Print("[ethertypes: IPX, NetBEUI, AppleTalk, Profinet and IEC 61850 GOOSE pass byte for byte, bar the VLAN rules]\n");

	if (net->Switch != NULL)
	{
		SwTestMember(net, "A", SWITCH_ACCESS, 10, NULL, 0);
		SwTestMember(net, "B", SWITCH_ACCESS, 10, NULL, 0);
		SwTestMember(net, "T", SWITCH_TRUNK, 0, trunk_t, sizeof(trunk_t) / sizeof(trunk_t[0]));
		SwTestMember(net, "C", SWITCH_ACCESS, 20, NULL, 0);
		SwTestMember(net, "D", SWITCH_ACCESS, 20, NULL, 0);

		SwTestJoin(net, SWE_A, 10, swtest_bc);
		SwTestJoin(net, SWE_B, 10, swtest_bc);
		SwTestJoin(net, SWE_T, 10, swtest_bc);
		SwTestJoin(net, SWE_B, 10, swtest_netbios);
		SwTestJoin(net, SWE_T, 10, swtest_netbios);
		SwTestJoin(net, SWE_A, 10, swtest_appletalk);
		SwTestJoin(net, SWE_B, 10, swtest_appletalk);
		SwTestJoin(net, SWE_B, 10, swtest_dcp);
		SwTestJoin(net, SWE_A, 10, swtest_goose);
		SwTestJoin(net, SWE_B, 10, swtest_goose);
		SwTestJoin(net, SWE_T, 10, swtest_goose);
		SwTestJoin(net, SWE_C, 20, swtest_bc);
		SwTestJoin(net, SWE_D, 20, swtest_bc);
	}

	SwTestGolden(ctx, net, swtest_ethertypes, sizeof(swtest_ethertypes) / sizeof(swtest_ethertypes[0]), vlans, sizeof(vlans) / sizeof(vlans[0]),
		"switch_ethertypes.txt", "ethertypes");
	SwTestFreeNet(net);
}

// switch_limits.txt: a Network of TPID 0x88A8, broadcast limit 4/s and multicast limit 2/s, and VLAN 200 with limits of
// its own
static void SwTestLimits(SWTEST_CTX *ctx)
{
	static const USHORT trunk_p2[] = {100, 200};
	static const UINT vlans[] = {100, 200};
	SWTEST_NET *net = SwTestNewNet(0x88A8, 4, 2);

	Print("[limits: per-VLAN broadcast and multicast limits and counters, a Network of TPID 0x88A8]\n");

	if (net->Switch != NULL)
	{
		SwTestMember(net, "P1", SWITCH_ACCESS, 100, NULL, 0);
		SwTestMember(net, "P2", SWITCH_TRUNK, 0, trunk_p2, sizeof(trunk_p2) / sizeof(trunk_p2[0]));
		SwTestMember(net, "P3", SWITCH_ACCESS, 200, NULL, 0);

		SwTestJoin(net, SWL_P1, 100, swtest_bc);
		SwTestJoin(net, SWL_P2, 100, swtest_bc);
		SwTestJoin(net, SWL_P2, 100, swtest_hosts);
		SwTestJoin(net, SWL_P2, 200, swtest_bc);
		SwTestJoin(net, SWL_P3, 200, swtest_bc);
		SwTestJoin(net, SWL_P2, 200, swtest_hosts);
		SwTestJoin(net, SWL_P3, 200, swtest_hosts);

		if (SwitchSetVlanLimits(net->Switch, 200, 2, 3) == false)
		{
			net->SetupOk = false;
		}
	}

	SwTestGolden(ctx, net, swtest_limits, sizeof(swtest_limits) / sizeof(swtest_limits[0]), vlans, sizeof(vlans) / sizeof(vlans[0]),
		"switch_limits.txt", "limits");
	SwTestFreeNet(net);
}

//
// The configurations, the MAC table and the ports
//

// The procedure of a port that only counts what it gets
static void SwTestCount(void *param, UINT port, const UCHAR *frame, UINT size)
{
	(*(UINT *)param)++;
}

// A port configuration of the checks below
static void SwTestPortConfig(SWITCH_PORT_CONFIG *c, UINT mode, UINT vlan, const USHORT *allowed, UINT num_allowed, UINT *counter)
{
	Zero(c, sizeof(SWITCH_PORT_CONFIG));
	c->Mode = mode;
	c->Vlan = vlan;
	c->Allowed = allowed;
	c->NumAllowed = num_allowed;
	c->Send = SwTestCount;
	c->Param = counter;
}

// What the switch refuses: configurations of switches, ports, subscriptions and limits that are none
static void SwTestRefusals(SWTEST_CTX *ctx)
{
	static const USHORT bad_allowed[] = {10, 4095};
	static const USHORT allowed[] = {10};
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG p;
	UINT counter = 0;
	SWITCH *sw;
	bool ok = true;

	Print("[refusals]\n");

	Zero(&c, sizeof(c));
	c.Tpid = SWITCH_MIN_TPID - 1;
	sw = SwitchNew(&c);
	ok = (sw == NULL) && ok;
	SwitchFree(sw);
	Zero(&c, sizeof(c));
	c.MaxPorts = SWITCH_MAX_PORTS + 1;
	sw = SwitchNew(&c);
	ok = (sw == NULL) && ok;
	SwitchFree(sw);
	Zero(&c, sizeof(c));
	c.MaxMacs = SWITCH_MAX_MACS + 1;
	sw = SwitchNew(&c);
	ok = (sw == NULL) && ok;
	SwitchFree(sw);
	SwTestCheck(ctx, ok, "a switch of a TPID below 0x0600, or of more ports or MAC table entries than the limits, is refused", "SwitchNew made one");

	Zero(&c, sizeof(c));
	c.MaxPorts = 2;
	c.MaxMacs = 64;
	sw = SwitchNew(&c);
	if (SwTestCheck(ctx, sw != NULL, "a switch of two ports", "SwitchNew failed") == false)
	{
		return;
	}

	ok = true;
	SwTestPortConfig(&p, SWITCH_ACCESS, 0, NULL, 0, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, SWITCH_ACCESS, 4095, NULL, 0, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, SWITCH_TRUNK, 0, bad_allowed, 2, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, SWITCH_TRUNK, 4095, allowed, 1, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, SWITCH_TRUNK, 0, NULL, 1, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, 7, 10, NULL, 0, &counter);
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestPortConfig(&p, SWITCH_ACCESS, 10, NULL, 0, &counter);
	p.Send = NULL;
	ok = (SwitchAddPort(sw, &p) == SWITCH_PORT_NONE) && ok;
	SwTestCheck(ctx, ok, "a port of VLAN 0 or 4095, of a disallowed VLAN in its list, of another mode, or without a procedure is refused", "SwitchAddPort made one");

	SwTestPortConfig(&p, SWITCH_ACCESS, 10, NULL, 0, &counter);
	UINT first = SwitchAddPort(sw, &p);
	SwTestPortConfig(&p, SWITCH_TRUNK, 20, allowed, 1, &counter);
	UINT second = SwitchAddPort(sw, &p);
	UINT third = SwitchAddPort(sw, &p);
	SwTestCheck(ctx, first == 0 && second == 1 && third == SWITCH_PORT_NONE, "the ports take the lowest free numbers, and a switch takes no more ports than it has",
		"ports %u, %u and %u", first, second, third);

	ok = SwitchDelPort(sw, first) && SwitchDelPort(sw, first) == false;
	SwTestPortConfig(&p, SWITCH_ACCESS, 10, NULL, 0, &counter);
	ok = ok && SwitchAddPort(sw, &p) == first;
	SwTestCheck(ctx, ok, "a deleted port is free for the next member, and deleted only once", "SwitchDelPort or SwitchAddPort");

	ok = true;
	ok = (SwitchSubscribe(sw, first, 10, swtest_mac_a) == false) && ok;
	ok = (SwitchSubscribe(sw, first, 20, swtest_bc) == false) && ok;
	ok = (SwitchSubscribe(sw, first, 0, swtest_bc) == false) && ok;
	ok = (SwitchSubscribe(sw, first, 4095, swtest_bc) == false) && ok;
	ok = (SwitchSubscribe(sw, 5, 10, swtest_bc) == false) && ok;
	ok = (SwitchUnsubscribe(sw, first, 10, swtest_bc) == false) && ok;
	ok = SwitchSubscribe(sw, first, 10, swtest_bc) && SwitchSubscribe(sw, first, 10, swtest_bc) && ok;
	ok = SwitchUnsubscribe(sw, first, 10, swtest_bc) && (SwitchUnsubscribe(sw, first, 10, swtest_bc) == false) && ok;
	ok = SwitchSubscribe(sw, second, 10, NULL) && SwitchSubscribe(sw, second, 20, swtest_mdns) && ok;
	SwTestCheck(ctx, ok, "a subscription to a unicast address, to a VLAN that the port does not carry, or of a port beyond the switch is refused; one is taken once",
		"SwitchSubscribe or SwitchUnsubscribe");

	ok = (SwitchSetVlanLimits(sw, 0, 1, 1) == false) && (SwitchSetVlanLimits(sw, 4095, 1, 1) == false) && SwitchSetVlanLimits(sw, 4094, 1, 1);
	SwTestCheck(ctx, ok, "the limits of VLAN 0 and 4095 are refused, those of VLAN 4094 are set", "SwitchSetVlanLimits");

	SWITCH_VLAN_STATS v;
	ok = (SwitchGetVlanStats(sw, 30, &v) == false) && SwitchGetVlanStats(sw, 4094, &v) && v.BroadcastLimit == 1 && v.MulticastLimit == 1;
	SwTestCheck(ctx, ok, "a VLAN without state has no counters; a VLAN with limits has them", "SwitchGetVlanStats");

	SwitchFree(sw);
}

// A test frame of a source of the full-table case: 02:00:00:00:01:<i> to 02:00:00:00:00:0B
static UINT SwTestSourceFrame(UCHAR *f, UINT i)
{
	UCHAR src[6] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x00};
	UCHAR body[SWTEST_BODY_SIZE];

	src[5] = (UCHAR)i;
	SwTestBody(body, i);

	return SwTestBuild(f, swtest_mac_b, src, false, 0, 0, body, sizeof(body));
}

// The MAC table: full, aged, cleared; a port that changes its VLAN or goes leaves its groups and addresses behind
static void SwTestMacTable(SWTEST_CTX *ctx)
{
	static const USHORT allowed[] = {10, 20};
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG p;
	SWITCH_STATS st;
	UCHAR frame[SWTEST_FRAME_MAX];
	UINT got_a = 0, got_b = 0, got_t = 0;
	UINT size;
	bool ok;

	Print("[the MAC table and the changes of ports]\n");

	Zero(&c, sizeof(c));
	c.MaxPorts = 4;
	c.MaxMacs = SWTEST_FULL_MACS;
	c.AgingTime = SWTEST_AGING;
	SWITCH *sw = SwitchNew(&c);
	if (SwTestCheck(ctx, sw != NULL, "a switch of 16 MAC table entries", "SwitchNew failed") == false)
	{
		return;
	}

	SwTestPortConfig(&p, SWITCH_ACCESS, 10, NULL, 0, &got_a);
	UINT a = SwitchAddPort(sw, &p);
	SwTestPortConfig(&p, SWITCH_ACCESS, 10, NULL, 0, &got_b);
	UINT b = SwitchAddPort(sw, &p);
	SwTestPortConfig(&p, SWITCH_TRUNK, 0, allowed, 2, &got_t);
	UINT t = SwitchAddPort(sw, &p);
	ok = SwitchSubscribe(sw, a, 10, swtest_bc) && SwitchSubscribe(sw, b, 10, swtest_bc) && SwitchSubscribe(sw, t, 10, swtest_bc);

	// The sources 0 to 19 on port A, to the address of B, which the table has not learnt: the table takes 16 sources and
	// refuses the rest, and every frame floods to B and T all the same
	for (UINT i = 0; i < SWTEST_FULL_SOURCES; i++)
	{
		size = SwTestSourceFrame(frame, i);
		SwitchInput(sw, 1000, a, frame, size);
	}
	SwitchGetStats(sw, &st);
	SwTestCheck(ctx, ok && st.NumMacs == SWTEST_FULL_MACS && st.Learnt == SWTEST_FULL_MACS && st.Refused == SWTEST_FULL_SOURCES - SWTEST_FULL_MACS && got_b == SWTEST_FULL_SOURCES && got_t == SWTEST_FULL_SOURCES,
		"a full MAC table refuses the sources after its last entry and forwards their frames", "%u entries, %I64u learnt, %I64u refused, B got %u, T got %u",
		st.NumMacs, st.Learnt, st.Refused, got_b, got_t);

	// A frame to source 19, which the table refused, goes to the broadcast group; one to source 0 to port A alone
	UCHAR dst[6] = {0x02, 0x00, 0x00, 0x00, 0x01, SWTEST_FULL_SOURCES - 1};
	UCHAR body[SWTEST_BODY_SIZE];
	SwTestBody(body, 1);
	size = SwTestBuild(frame, dst, swtest_mac_b, false, 0, 0, body, sizeof(body));
	UINT to_refused = SwitchInput(sw, 1000, b, frame, size);
	dst[5] = 0;
	size = SwTestBuild(frame, dst, swtest_mac_b, false, 0, 0, body, sizeof(body));
	UINT to_learnt = SwitchInput(sw, 1000, b, frame, size);
	SwTestCheck(ctx, to_refused == 2 && to_learnt == 1, "a frame to a refused source floods to the broadcast group, one to a learnt source goes to its port",
		"%u and %u ports", to_refused, to_learnt);

	// Aging: nothing before the aging time has passed, everything at it
	UINT aged_before = SwitchAge(sw, 1000 + SWTEST_AGING - 1);
	UINT aged = SwitchAge(sw, 1000 + SWTEST_AGING);
	SwitchGetStats(sw, &st);
	SwTestCheck(ctx, aged_before == 0 && aged == SWTEST_FULL_MACS && st.NumMacs == 0, "SwitchAge takes out the entries that no frame refreshed for the aging time, and only those",
		"%u, then %u taken out, %u left", aged_before, aged, st.NumMacs);

	// Clearing: the frame from T is dropped, untagged on a trunk port without a native VLAN, so the table holds one entry
	size = SwTestSourceFrame(frame, 1);
	SwitchInput(sw, 7000, a, frame, size);
	size = SwTestSourceFrame(frame, 2);
	SwitchInput(sw, 7000, t, frame, size);
	UINT cleared = SwitchClearMacs(sw);
	SwitchGetStats(sw, &st);
	SwTestCheck(ctx, cleared == 1 && st.NumMacs == 0, "SwitchClearMacs empties the MAC table and counts the entries that it took out", "%u taken out, %u left", cleared,
		st.NumMacs);

	// Port B moves to VLAN 20: it leaves the broadcast group of VLAN 10, and the table forgets its address
	SwTestBody(body, 2);
	size = SwTestBuild(frame, swtest_bc, swtest_mac_b, false, 0, 0, body, sizeof(body));
	SwitchInput(sw, 8000, b, frame, size);
	SWITCH_MAC_ENTRY macs[4];
	UINT num_before = SwitchGetMacs(sw, macs, 4);
	SwTestPortConfig(&p, SWITCH_ACCESS, 20, NULL, 0, &got_b);
	ok = SwitchSetPort(sw, b, &p);
	UINT num_after = SwitchGetMacs(sw, macs, 4);
	got_b = 0;
	SwTestBody(body, 3);
	size = SwTestBuild(frame, swtest_bc, swtest_mac_a, false, 0, 0, body, sizeof(body));
	UINT reached = SwitchInput(sw, 8000, a, frame, size);
	SwTestCheck(ctx, ok && num_before == 1 && num_after == 0 && reached == 1 && got_b == 0 && SwitchUnsubscribe(sw, b, 10, swtest_bc) == false,
		"a port that moves to another VLAN leaves the groups of its old VLAN, and the MAC table forgets its addresses",
		"set %u, %u entries before and %u after, the broadcast reached %u ports, B got %u", (UINT)ok, num_before, num_after, reached, got_b);

	// Port T goes: frames from its number are dropped, and a frame to its address no longer goes to it
	SwTestBody(body, 4);
	size = SwTestBuild(frame, swtest_mac_a, swtest_mac_t, true, SWITCH_TPID_8021Q, 10, body, sizeof(body));
	SwitchInput(sw, 9000, t, frame, size);
	got_t = 0;
	ok = SwitchDelPort(sw, t);
	SwitchGetStats(sw, &st);
	UINT64 port_drops = st.Drops[SWITCH_DROP_PORT];
	SwitchInput(sw, 9000, t, frame, size);
	SwitchGetStats(sw, &st);
	size = SwTestBuild(frame, swtest_mac_t, swtest_mac_a, false, 0, 0, body, sizeof(body));
	reached = SwitchInput(sw, 9000, a, frame, size);
	SwTestCheck(ctx, ok && st.Drops[SWITCH_DROP_PORT] == port_drops + 1 && st.NumMacs == 1 && reached == 0 && got_t == 0,
		"a deleted port drops the frames of its number, and the MAC table forgets its addresses",
		"deleted %u, port drops %I64u then %I64u, %u entries, the frame to T reached %u ports", (UINT)ok, port_drops, st.Drops[SWITCH_DROP_PORT], st.NumMacs, reached);

	SwitchFree(sw);
}

//
// The concurrent case
//

// The procedure of a side of a forwarding thread: every frame must come from the other side, with the next sequence
// number of the frames to this side
static void SwTestSideRecord(void *param, UINT port, const UCHAR *frame, UINT size)
{
	SWTEST_SIDE *s = (SWTEST_SIDE *)param;
	UINT seq = 0;

	if (size == SWTEST_SEQ_FRAME)
	{
		seq = ((UINT)frame[14] << 24) | ((UINT)frame[15] << 16) | ((UINT)frame[16] << 8) | frame[17];
	}
	if (size != SWTEST_SEQ_FRAME || port != s->Port || Cmp(frame + 6, s->PeerMac, 6) != 0 || seq != s->Next)
	{
		s->Wrong++;
	}

	s->Next = seq + 2;
	s->Got++;
}

// The procedure of a port that the main thread adds and deletes
static void SwTestExtraRecord(void *param, UINT port, const UCHAR *frame, UINT size)
{
	SWTEST_EXTRA *x = (SWTEST_EXTRA *)param;

	if (InterlockedCompareExchange(&x->Deleted, 0, 0) != 0)
	{
		InterlockedIncrement(&x->Late);
	}
	InterlockedIncrement(&x->Got);
}

// A forwarding thread: frames from A to B (even numbers, every 16th to the broadcast address) and from B to A (odd
// numbers), until the main thread is done
static DWORD WINAPI SwTestWorkerThread(LPVOID param)
{
	SWTEST_WORKER *w = (SWTEST_WORKER *)param;
	UCHAR frame[SWTEST_SEQ_FRAME];
	UINT k = 0;

	WaitForSingleObject(w->Start, INFINITE);

	while (*w->Stop == 0)
	{
		bool even = ((k & 1) == 0);
		SWTEST_SIDE *from = (even ? &w->A : &w->B);
		SWTEST_SIDE *to = (even ? &w->B : &w->A);

		Copy(frame, (k % 16) == 0 ? swtest_bc : to->Mac, 6);
		Copy(frame + 6, from->Mac, 6);
		frame[12] = 0x88;
		frame[13] = 0xB5;
		frame[14] = (UCHAR)(k >> 24);
		frame[15] = (UCHAR)(k >> 16);
		frame[16] = (UCHAR)(k >> 8);
		frame[17] = (UCHAR)k;

		SwitchInput(w->Switch, GetTickCount64(), from->Port, frame, sizeof(frame));
		k++;
	}

	w->Sent = k;
	return 0;
}

// Threads that forward while the main thread adds, subscribes, changes and deletes ports, clears and ages the MAC table
// and reads the counters
static void SwTestConcurrent(SWTEST_CTX *ctx)
{
	USHORT allowed[SWTEST_THREADS + 1];
	USHORT fewer[2] = {SWTEST_VLAN_BASE, SWTEST_VLAN_EXTRA};
	SWTEST_WORKER *workers = ZeroMalloc(sizeof(SWTEST_WORKER) * SWTEST_THREADS);
	SWTEST_EXTRA *extras = ZeroMalloc(sizeof(SWTEST_EXTRA) * SWTEST_ROUNDS);
	SWITCH_MAC_ENTRY *macs = ZeroMalloc(sizeof(SWITCH_MAC_ENTRY) * SWTEST_MAX_MACS);
	HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
	volatile LONG stop = 0;
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG p;
	SWITCH_STATS st;
	UINT rounds = 0;
	UINT failed = 0;
	LONG late = 0;
	LONG extra_got = 0;
	bool ok = true;

	Print("[threads forward while ports and the MAC table change]\n");

	Zero(&c, sizeof(c));
	c.MaxPorts = 16;
	c.MaxMacs = 1024;
	SWITCH *sw = SwitchNew(&c);

	for (UINT i = 0; i < SWTEST_THREADS; i++)
	{
		SWTEST_WORKER *w = &workers[i];
		UCHAR mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
		UCHAR mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

		mac_a[4] = mac_b[4] = (UCHAR)(0x10 + i);
		allowed[i] = (USHORT)(SWTEST_VLAN_BASE + i);

		w->Switch = sw;
		w->Start = start;
		w->Stop = &stop;
		Copy(w->A.Mac, mac_a, 6);
		Copy(w->A.PeerMac, mac_b, 6);
		w->A.Next = 1;
		Copy(w->B.Mac, mac_b, 6);
		Copy(w->B.PeerMac, mac_a, 6);
		w->B.Next = 0;

		Zero(&p, sizeof(p));
		p.Mode = SWITCH_ACCESS;
		p.Vlan = SWTEST_VLAN_BASE + i;
		p.Send = SwTestSideRecord;
		p.Param = &w->A;
		w->A.Port = SwitchAddPort(sw, &p);
		p.Param = &w->B;
		w->B.Port = SwitchAddPort(sw, &p);
		ok = SwitchSubscribe(sw, w->A.Port, SWTEST_VLAN_BASE + i, swtest_bc) && SwitchSubscribe(sw, w->B.Port, SWTEST_VLAN_BASE + i, swtest_bc) && ok;
	}
	allowed[SWTEST_THREADS] = SWTEST_VLAN_EXTRA;

	if (SwTestCheck(ctx, sw != NULL && ok && start != NULL, "a switch of four pairs of ports, each pair in a VLAN of its own", "SwitchNew, SwitchAddPort or SwitchSubscribe failed"))
	{
		for (UINT i = 0; i < SWTEST_THREADS; i++)
		{
			workers[i].Thread = CreateThread(NULL, 0, SwTestWorkerThread, &workers[i], 0, NULL);
		}
		SetEvent(start);

		UINT64 end = Tick64() + SWTEST_SPAN;
		while (rounds < SWTEST_ROUNDS && Tick64() < end)
		{
			SWTEST_EXTRA *x = &extras[rounds++];

			// A trunk port of every VLAN of the threads, subscribed to their broadcast groups and to every group of
			// another VLAN; it gets broadcasts and floods while the threads run
			Zero(&p, sizeof(p));
			p.Mode = SWITCH_TRUNK;
			p.Allowed = allowed;
			p.NumAllowed = SWTEST_THREADS + 1;
			p.Send = SwTestExtraRecord;
			p.Param = x;
			UINT port = SwitchAddPort(sw, &p);
			if (port == SWITCH_PORT_NONE)
			{
				failed++;
				continue;
			}
			for (UINT i = 0; i < SWTEST_THREADS; i++)
			{
				SwitchSubscribe(sw, port, SWTEST_VLAN_BASE + i, swtest_bc);
			}
			SwitchSubscribe(sw, port, SWTEST_VLAN_EXTRA, NULL);

			// The MAC table goes, so that the next frames of the threads flood; the counters are read
			if ((rounds % 2) == 0)
			{
				SwitchClearMacs(sw);
			}
			else
			{
				SwitchAge(sw, GetTickCount64() + 10 * (UINT64)SWITCH_DEFAULT_AGING);
			}
			SwitchGetMacs(sw, macs, SWTEST_MAX_MACS);
			SwitchGetStats(sw, &st);

			// Every third port keeps two of its VLANs before it goes
			if ((rounds % 3) == 0)
			{
				p.Allowed = fewer;
				p.NumAllowed = 2;
				if (SwitchSetPort(sw, port, &p) == false)
				{
					failed++;
				}
			}

			if (SwitchDelPort(sw, port) == false)
			{
				failed++;
			}
			InterlockedExchange(&x->Deleted, 1);
		}

		InterlockedExchange(&stop, 1);
		for (UINT i = 0; i < SWTEST_THREADS; i++)
		{
			if (workers[i].Thread != NULL)
			{
				WaitForSingleObject(workers[i].Thread, INFINITE);
				CloseHandle(workers[i].Thread);
			}
		}

		for (UINT r = 0; r < rounds; r++)
		{
			late += extras[r].Late;
			extra_got += extras[r].Got;
		}
		Print("  %u rounds of changes; the ports of the rounds got %d frames\n", rounds, (int)extra_got);

		ok = (failed == 0);
		for (UINT i = 0; i < SWTEST_THREADS; i++)
		{
			SWTEST_WORKER *w = &workers[i];
			UINT to_b = (w->Sent + 1) / 2;
			UINT to_a = w->Sent / 2;

			Print("  thread %u: %u frames sent, A got %u, B got %u, %u and %u out of order or of another source\n", i, w->Sent, w->A.Got, w->B.Got, w->A.Wrong, w->B.Wrong);
			ok = ok && w->Sent != 0 && w->A.Got == to_a && w->B.Got == to_b && w->A.Wrong == 0 && w->B.Wrong == 0;
		}
		SwTestCheck(ctx, ok, "each frame of each thread reaches the other side of its pair once and in order while ports, subscriptions and the MAC table change",
			"%u changes failed; a pair lost, doubled or reordered frames (see above)", failed);
		SwTestCheck(ctx, late == 0, "no member gets a frame once SwitchDelPort of its port returned", "%d frames came late", (int)late);

		ok = true;
		for (UINT i = 0; i < SWTEST_THREADS; i++)
		{
			SWITCH_VLAN_STATS v;

			ok = SwitchGetVlanStats(sw, SWTEST_VLAN_BASE + i, &v) && v.InFrames == workers[i].Sent &&
				v.InFrames == v.Unicast + v.Flooded + v.Broadcast + v.Multicast + v.LimitDrops + v.Filtered && v.LimitDrops == 0 && ok;
		}
		SwTestCheck(ctx, ok, "the counters of each VLAN of the threads hold every frame sent, and their fates add up", "SwitchGetVlanStats");
	}

	SwitchFree(sw);
	if (start != NULL)
	{
		CloseHandle(start);
	}
	Free(macs);
	Free(extras);
	Free(workers);
}

RANZ_TEST_TAGS("switch", switch_test, "core", "Switch: frames between members of different VLANs across access, trunk and native ports, VLAN-aware learning, broadcast and multicast by group subscription, non-IP EtherTypes, per-VLAN limits and counters and the TPID of a Network against golden files (golden family switch); ports that change while threads forward.");
void switch_test(UINT num, char **arg)
{
	SWTEST_CTX *ctx = ZeroMalloc(sizeof(SWTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = NULL;

	swtest_budget = SWTEST_BUDGET;
	swtest_name = "SWITCH";
	watchdog = (done != NULL ? CreateThread(NULL, 0, SwTestWatchdog, done, 0, NULL) : NULL);

	Print("Switch test: the VLAN-aware L2 switch of the new core, against golden frames and counters\n");

	HarnessGetFamilyDirs("switch", ctx->OutDir, sizeof(ctx->OutDir), ctx->GoldenDir, sizeof(ctx->GoldenDir), &ctx->Update);
	MakeDirEx(ctx->OutDir);
	Print("SWITCH GOLDEN MODE %s\n", ctx->Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx->GoldenDir);

	SwTestFrames(ctx);
	SwTestEtherTypes(ctx);
	SwTestLimits(ctx);
	SwTestRefusals(ctx);
	SwTestMacTable(ctx);
	SwTestConcurrent(ctx);

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
		Print("SWITCH TEST OK\n");
	}
	else
	{
		Print("SWITCH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}

//
// The micro-benchmark
//

// The procedure of the ports of a thread of the benchmark: it counts
static void SwBenchCount(void *param, UINT port, const UCHAR *frame, UINT size)
{
	((SWBENCH_THREAD *)param)->Got++;
}

// A thread of the benchmark: frames from A to B and back until the run ends, each behind the lock of the Hub when the
// run has one
static DWORD WINAPI SwBenchThread(LPVOID param)
{
	SWBENCH_THREAD *t = (SWBENCH_THREAD *)param;

	WaitForSingleObject(t->Go, INFINITE);

	while (*t->Stop == 0)
	{
		UINT64 now = GetTickCount64();

		for (UINT i = 0; i < SWBENCH_BATCH; i++)
		{
			if (t->HubLock != NULL)
			{
				AcquireSRWLockExclusive(t->HubLock);
				SwitchInput(t->Switch, now, t->PortA, t->FrameA, sizeof(t->FrameA));
				ReleaseSRWLockExclusive(t->HubLock);
				AcquireSRWLockExclusive(t->HubLock);
				SwitchInput(t->Switch, now, t->PortB, t->FrameB, sizeof(t->FrameB));
				ReleaseSRWLockExclusive(t->HubLock);
			}
			else
			{
				SwitchInput(t->Switch, now, t->PortA, t->FrameA, sizeof(t->FrameA));
				SwitchInput(t->Switch, now, t->PortB, t->FrameB, sizeof(t->FrameB));
			}
		}
	}

	return 0;
}

// One run of num threads for SWBENCH_SPAN ms, behind hub when it is not NULL; the frames per second that they forward
static UINT64 SwBenchRun(SWBENCH_THREAD **threads, UINT num, SRWLOCK *hub)
{
	HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE handles[SWBENCH_MAX_THREADS];
	volatile LONG stop = 0;
	LARGE_INTEGER freq, t0, t1;
	UINT64 got = 0;
	UINT started = 0;

	if (go == NULL)
	{
		return 0;
	}

	for (UINT i = 0; i < num; i++)
	{
		SWBENCH_THREAD *t = threads[i];

		t->Go = go;
		t->Stop = &stop;
		t->HubLock = hub;
		t->Got = 0;
		handles[started] = CreateThread(NULL, 0, SwBenchThread, t, 0, NULL);
		if (handles[started] != NULL)
		{
			started++;
		}
	}

	// The threads wait for the start; the time runs from it
	Sleep(10);
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&t0);
	SetEvent(go);
	Sleep(SWBENCH_SPAN);
	InterlockedExchange(&stop, 1);
	QueryPerformanceCounter(&t1);

	if (started != 0)
	{
		WaitForMultipleObjects(started, handles, TRUE, INFINITE);
	}
	for (UINT i = 0; i < started; i++)
	{
		CloseHandle(handles[i]);
	}
	CloseHandle(go);

	for (UINT i = 0; i < num; i++)
	{
		got += (UINT64)threads[i]->Got;
	}

	UINT64 elapsed = (UINT64)(t1.QuadPart - t0.QuadPart);
	if (elapsed == 0 || started != num)
	{
		return 0;
	}

	return got * (UINT64)freq.QuadPart / elapsed;
}

// SWBENCH_RUNS runs of num threads; "BENCH <name> <median> frames/s" and "BENCH <name>_runs <run 1>,...,<run n>
// frames/s" in run order. The median.
static UINT64 SwBenchCase(char *name, SWBENCH_THREAD **threads, UINT num, SRWLOCK *hub)
{
	UINT64 runs[SWBENCH_RUNS];
	UINT64 sorted[SWBENCH_RUNS];
	char list[MAX_SIZE];
	char value[64];

	for (UINT r = 0; r < SWBENCH_RUNS; r++)
	{
		runs[r] = SwBenchRun(threads, num, hub);
		sorted[r] = runs[r];
	}

	for (UINT i = 1; i < SWBENCH_RUNS; i++)
	{
		for (UINT j = i; j > 0 && sorted[j - 1] > sorted[j]; j--)
		{
			UINT64 v = sorted[j];

			sorted[j] = sorted[j - 1];
			sorted[j - 1] = v;
		}
	}

	list[0] = 0;
	for (UINT r = 0; r < SWBENCH_RUNS; r++)
	{
		Format(value, sizeof(value), "%s%I64u", r == 0 ? "" : ",", runs[r]);
		StrCat(list, sizeof(list), value);
	}

	Print("BENCH %s %I64u frames/s\n", name, sorted[SWBENCH_RUNS / 2]);
	Print("BENCH %s_runs %s frames/s\n", name, list);

	return sorted[SWBENCH_RUNS / 2];
}

RANZ_TEST("switchbench", switchbench_test, "Switch benchmark: the forwarding of the L2 switch on one thread, on one thread per core and behind one lock as the Hub; it fails when the threads do not scale (BENCH lines).");
void switchbench_test(UINT num, char **arg)
{
	SWTEST_CTX *ctx = ZeroMalloc(sizeof(SWTEST_CTX));
	SWBENCH_THREAD *threads[SWBENCH_MAX_THREADS];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = NULL;
	SRWLOCK hub;
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG p;
	UINT cores = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	UINT k = MIN(cores, SWBENCH_MAX_THREADS);
	char name[MAX_SIZE];
	bool ok = true;

	swtest_budget = SWBENCH_BUDGET;
	swtest_name = "SWITCHBENCH";
	watchdog = (done != NULL ? CreateThread(NULL, 0, SwTestWatchdog, done, 0, NULL) : NULL);

	Print("Switch benchmark: forwarding of the L2 switch on one core and on %u (%u cores), and behind one lock as the Hub\n", k, cores);

	InitializeSRWLock(&hub);
	Zero(&c, sizeof(c));
	c.MaxPorts = 2 * SWBENCH_MAX_THREADS;
	SWITCH *sw = SwitchNew(&c);
	ok = (sw != NULL);

	// One pair of ports per thread, all in one VLAN, with their addresses learnt
	for (UINT i = 0; i < SWBENCH_MAX_THREADS; i++)
	{
		SWBENCH_THREAD *t = ZeroMalloc(sizeof(SWBENCH_THREAD));
		UCHAR mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
		UCHAR mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

		mac_a[4] = mac_b[4] = (UCHAR)(0x20 + i);
		threads[i] = t;
		t->Switch = sw;
		Copy(t->FrameA, mac_b, 6);
		Copy(t->FrameA + 6, mac_a, 6);
		Copy(t->FrameB, mac_a, 6);
		Copy(t->FrameB + 6, mac_b, 6);
		t->FrameA[12] = t->FrameB[12] = 0x88;
		t->FrameA[13] = t->FrameB[13] = 0xB5;

		Zero(&p, sizeof(p));
		p.Mode = SWITCH_ACCESS;
		p.Vlan = SWBENCH_VLAN;
		p.Send = SwBenchCount;
		p.Param = t;
		t->PortA = SwitchAddPort(sw, &p);
		t->PortB = SwitchAddPort(sw, &p);
		ok = ok && t->PortA != SWITCH_PORT_NONE && t->PortB != SWITCH_PORT_NONE && SwitchSubscribe(sw, t->PortA, SWBENCH_VLAN, swtest_bc) &&
			SwitchSubscribe(sw, t->PortB, SWBENCH_VLAN, swtest_bc);
		SwitchInput(sw, GetTickCount64(), t->PortA, t->FrameA, sizeof(t->FrameA));
		SwitchInput(sw, GetTickCount64(), t->PortB, t->FrameB, sizeof(t->FrameB));
	}

	if (SwTestCheck(ctx, ok, "a switch of one pair of ports per thread in one VLAN, their addresses learnt", "SwitchNew, SwitchAddPort or SwitchSubscribe failed"))
	{
		UINT64 one = SwBenchCase("switch_fps_1", threads, 1, NULL);
		Format(name, sizeof(name), "switch_fps_%u", k);
		UINT64 many = (k > 1 ? SwBenchCase(name, threads, k, NULL) : one);
		Format(name, sizeof(name), "switch_hublock_fps_%u", k);
		UINT64 hublock = SwBenchCase(name, threads, k, &hub);
		UINT64 scaling = (one != 0 ? many * 100 / one : 0);
		UINT64 hub_scaling = (one != 0 ? hublock * 100 / one : 0);

		Print("BENCH switch_scaling_%u %I64u percent\n", k, scaling);
		Print("BENCH switch_hublock_scaling_%u %I64u percent\n", k, hub_scaling);
		Print("  %u threads forward %I64u%% of the frames of one thread; behind one lock, as the Hub, %I64u%%\n", k, scaling, hub_scaling);

		if (k < 2)
		{
			Print("  one core: there is no other core to scale to\n");
		}
		else
		{
			UINT need = (k >= 3 ? SWBENCH_SCALING : SWBENCH_SCALING_TWO);

			Format(name, sizeof(name), "forwarding scales across cores with no hub-wide lock: %u threads forward at least %u%% of the frames of one", k, need);
			SwTestCheck(ctx, one != 0 && scaling >= need, name, "%I64u frames/s on one thread, %I64u on %u: %I64u%%", one, many, k, scaling);
		}
	}

	SwitchFree(sw);
	for (UINT i = 0; i < SWBENCH_MAX_THREADS; i++)
	{
		Free(threads[i]);
	}

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
		Print("SWITCHBENCH TEST OK\n");
	}
	else
	{
		Print("SWITCHBENCH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
