// Switch.h
// The L2 switch of the new core (ADR-0019 decision 2; CORE-S4-1, #74): the forwarding plane of an L2 Network, in place of
// the forwarding of the Hub and its hub-wide lock (spec #31 D1 and D2). A switch has one port for each member of its
// Network (a user session, a cascade, a bridge, a loopback adapter). Every frame that a member sends enters at its port
// through one ingress, SwitchInput, and runs to completion on the thread that called it: the VLAN of the frame, the
// learning of its source address and its delivery. Nothing serialises the switch as a whole: the MAC table is read
// without a lock, and each port and each VLAN has locks of its own (Switch.c).
//
// VLANs (IEEE 802.1Q):
// - A port is an access port, a member of one VLAN whose frames go to and come from the member untagged, or a trunk port,
//   a member of the VLANs of its allowed list, whose frames carry a tag, and of its native VLAN, whose frames do not.
// - The tag protocol id (TPID) is the switch's, one per Network: 0x8100 unless the Network sets another, as 0x88A8. A
//   frame whose EtherType is another value is untagged for the switch, whatever it carries: an 0x8100 tag in a Network
//   of TPID 0x88A8 stays in the frame as it is.
// - An untagged frame is in the VLAN of its port: the access VLAN, or the native VLAN of a trunk port, which drops it
//   when it has none. An access port takes a tag of its own VLAN, a trunk port a tag of a VLAN that it carries, and both
//   drop any other tag. A tag with VLAN id 0, a priority tag, puts the frame in the VLAN of an untagged one and keeps its
//   priority: the frame leaves an untagged port with the priority tag it came with, and a tagged port with a tag of its
//   VLAN and that priority. A frame that leaves an untagged port with a VLAN tag loses the tag.
// - The MAC table learns each source address per VLAN: the same address may be on one port in one VLAN and on another
//   port in another VLAN.
//
// Delivery. A frame to an address that its VLAN learnt goes to that port alone. Broadcast and multicast frames go to the
// ports that subscribe to their group in the VLAN (SwitchSubscribe), never to every member: the broadcast group, which
// also takes the frames to an address that the VLAN has not learnt, each multicast group, and every group at once (for a
// bridge to a LAN). A port never gets a frame back that it sent. The frames of a group pass the limit of their VLAN first,
// in frames per second: the broadcast limit for broadcast frames and those to an unknown address, the multicast limit for
// multicast frames. Beyond the tag, the switch reads only the two addresses, so a frame of any EtherType or length field
// (IPX, NetBEUI, AppleTalk, Profinet, IEC 61850 GOOSE) passes byte for byte, bar the tag that its ports add or take off.
//
// Filter. A switch may have a filter (SWITCH_CONFIG.Admit, Deliver), which judges each frame before the switch learns its
// source, and each member that a frame to a group reaches: the security of an L2 Network, which the policy engine runs
// (SwitchSecurity.h; SDN-41, #234). A frame that it refuses goes nowhere, and its source is not learnt.
//
// IP table (SwitchIp.c; SDN-50-N, #492). Beside the MAC table the switch learns the IP addresses that the members send from,
// per VLAN, each with the MAC address and the port of its last frame, as the IP table of the Hub holds them: the source of an
// IPv4 packet and the sender of an ARP packet, the source of an IPv6 packet, but no address that no host sends from (0.0.0.0/8,
// 127.0.0.0/8, multicast, broadcast, the unspecified and the loopback address of IPv6). It reads them only; the frame passes
// byte for byte all the same. The operators read and clear both tables (the live operations of the Controller).
//
// Time is the caller's: SwitchInput and SwitchAge take it in ms (GetTickCount64, or the clock of a test), and the limits
// and the ages of the MAC table run on it.

#ifndef CORE_SWITCH_H
#define CORE_SWITCH_H

#include <windows.h>

#include <stdbool.h>

#define SWITCH_TPID_8021Q 0x8100 // The TPID of a switch that sets none: IEEE 802.1Q
#define SWITCH_MIN_TPID   0x0600 // The least TPID: the least EtherType (a smaller value is the length of an IEEE 802.3 frame)

#define SWITCH_MIN_VLAN  1 // The VLAN ids of a VLAN: 1 to 4094 (0 marks a priority tag, 4095 is reserved)
#define SWITCH_MAX_VLAN  4094
#define SWITCH_NUM_VLANS 4096 // The 12-bit VLAN ids

#define SWITCH_ADDR_SIZE 12   // The two MAC addresses at the start of a frame
#define SWITCH_TAG_SIZE  4    // A tag: the TPID and the tag control information (priority, DEI, VLAN id)
#define SWITCH_MIN_FRAME 14   // The shortest frame: the two MAC addresses and the EtherType or length, without the FCS
#define SWITCH_MAX_FRAME 9216 // The longest frame that a port takes, without the FCS: a jumbo frame

// The kinds of port
#define SWITCH_ACCESS 0 // An access port: one VLAN, untagged towards the member
#define SWITCH_TRUNK  1 // A trunk port: the VLANs of its allowed list tagged, its native VLAN untagged

#define SWITCH_PORT_NONE 0xFFFFFFFF // No port: what SwitchAddPort returns when it adds none

// The limits of one switch, and the values of a configuration that sets none
#define SWITCH_MAX_PORTS     65536   // Ports at most
#define SWITCH_DEFAULT_PORTS 1024    // Ports without SWITCH_CONFIG.MaxPorts
#define SWITCH_MAX_MACS      1048576 // Entries of the MAC table at most
#define SWITCH_DEFAULT_MACS  65536   // ... without SWITCH_CONFIG.MaxMacs: the MAX_MAC_TABLES of the Hub
#define SWITCH_DEFAULT_AGING 600000  // ms without SWITCH_CONFIG.AgingTime: the MAC_TABLE_EXPIRE_TIME of the Hub
#define SWITCH_MAX_GROUPS    1024    // Groups with subscribers in one VLAN at most, besides every group
#define SWITCH_MAX_IPS       1048576 // Entries of the IP table at most
#define SWITCH_DEFAULT_IPS   65536   // ... without SWITCH_CONFIG.MaxIps: the MAX_IP_TABLES of the Hub

// Why the switch dropped a frame before its VLAN took it (SWITCH_STATS)
#define SWITCH_DROP_MALFORMED 0 // Shorter than SWITCH_MIN_FRAME, a tag cut short, or longer than SWITCH_MAX_FRAME
#define SWITCH_DROP_PORT      1 // From a port that no member holds
#define SWITCH_DROP_VLAN      2 // Of no VLAN that the port carries, or of VLAN id 4095
#define SWITCH_DROP_SOURCE    3 // A group address as the source
#define SWITCH_DROP_FILTER    4 // Refused by the filter of the switch (SWITCH_CONFIG.Admit)
#define SWITCH_NUM_REASONS    5

#define SWITCH_NO_MEMBER 0xFFFFFFFF // No member: where a frame to a group goes, for the filter of a switch

// The filter of a switch (SWITCH_CONFIG). Admit judges each frame that the member from sends in the VLAN vlan, after its
// VLAN and before the switch learns its source: a frame to an address that the VLAN learnt goes to the member to of its
// port, any other frame to SWITCH_NO_MEMBER. Deliver judges such a frame again for each member to that it reaches. Both
// run on the thread of SwitchInput, under the shared lock of the port of from (and, for Deliver, of the port of to), and
// must not wait; true lets the frame through. The members are those of the ports (SWITCH_PORT_CONFIG.Member).
typedef bool(SWITCH_ADMIT_PROC)(void *param, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size);
typedef bool(SWITCH_DELIVER_PROC)(void *param, UINT from, UINT to, const UCHAR *frame, UINT size);

// How a switch runs (SwitchNew); a value of 0 takes the default
typedef struct SWITCH_CONFIG {
	USHORT Tpid;                  // The TPID of the Network's tags: SWITCH_MIN_TPID or above; 0 for SWITCH_TPID_8021Q
	UINT MaxPorts;                // Ports at most, up to SWITCH_MAX_PORTS; 0 for SWITCH_DEFAULT_PORTS
	UINT MaxMacs;                 // Entries of the MAC table at most, up to SWITCH_MAX_MACS; 0 for SWITCH_DEFAULT_MACS
	UINT AgingTime;               // ms after which SwitchAge takes out an entry that no frame refreshed; 0 for SWITCH_DEFAULT_AGING
	UINT BroadcastLimit;          // The broadcast limit of a VLAN that SwitchSetVlanLimits did not set, frames per second; 0 for none
	UINT MulticastLimit;          // ... and its multicast limit
	SWITCH_ADMIT_PROC *Admit;     // The filter of the switch: judges each frame, NULL for none ...
	SWITCH_DELIVER_PROC *Deliver; // ... and each member that a frame to a group reaches, NULL for none
	void *FilterParam;            // ... their first parameter
	UINT MaxIps;                  // Entries of the IP table at most, up to SWITCH_MAX_IPS; 0 for SWITCH_DEFAULT_IPS
} SWITCH_CONFIG;

// Takes a frame that the switch delivers to the member of a port, byte for byte as it leaves the port. It runs on the
// thread of SwitchInput, under the shared lock of the port, and must not wait: the frame stays valid during the call
// only, and the procedure may call no function of the switch that delivered it.
typedef void(SWITCH_SEND_PROC)(void *param, UINT port, const UCHAR *frame, UINT size);

// The membership of a port (SwitchAddPort, SwitchSetPort)
typedef struct SWITCH_PORT_CONFIG {
	UINT Mode;              // SWITCH_ACCESS or SWITCH_TRUNK
	UINT Vlan;              // An access port: its VLAN; a trunk port: its native VLAN, 0 for none
	const USHORT *Allowed;  // A trunk port: the VLANs of its allowed list, besides its native VLAN
	UINT NumAllowed;        // ... their number
	SWITCH_SEND_PROC *Send; // Takes the frames that the port delivers
	void *Param;            // ... its first parameter
	UINT Member;            // Its member for the filter of the switch, which a switch without one ignores
} SWITCH_PORT_CONFIG;

// The counters of one VLAN (SwitchGetVlanStats). Each frame that its VLAN took is counted once in InFrames and once in
// one of the six fates after it.
typedef struct SWITCH_VLAN_STATS {
	UINT64 InFrames;     // Frames that the VLAN took at a port
	UINT64 InBytes;      // ... their bytes, as they came
	UINT64 Unicast;      // ... to an address that the VLAN learnt, sent to its port
	UINT64 Flooded;      // ... to an address that it has not learnt, sent to the subscribers of its broadcast group
	UINT64 Broadcast;    // ... to the broadcast address, sent to those subscribers
	UINT64 Multicast;    // ... to another group address, sent to the subscribers of that group
	UINT64 LimitDrops;   // ... over the broadcast or multicast limit of the VLAN, sent nowhere
	UINT64 Filtered;     // ... sent nowhere for another reason: back to their own port, to a port that left the VLAN, or to a group without another subscriber
	UINT64 OutFrames;    // The frames that ports of the VLAN delivered
	UINT64 OutBytes;     // ... their bytes, as they left
	UINT BroadcastLimit; // The broadcast limit of the VLAN, frames per second, 0 for none
	UINT MulticastLimit; // ... and its multicast limit
} SWITCH_VLAN_STATS;

// The counters of a switch (SwitchGetStats)
typedef struct SWITCH_STATS {
	UINT NumPorts;                    // The ports that members hold
	UINT NumMacs;                     // The entries of the MAC table
	UINT NumVlans;                    // The VLANs with a state: one that a frame, a subscription or a limit made
	UINT64 Learnt;                    // Entries that the MAC table learnt
	UINT64 Moved;                     // ... that moved to another port
	UINT64 Refused;                   // Sources that it did not learn, as it was full
	UINT64 Drops[SWITCH_NUM_REASONS]; // Frames dropped before their VLAN took them, by reason (SWITCH_DROP_*)
	UINT NumIps;                      // The entries of the IP table
	UINT64 IpsLearnt;                 // Entries that the IP table learnt
	UINT64 IpsMoved;                  // ... that came from another MAC address or port
	UINT64 IpsRefused;                // Addresses that it did not learn, as it was full
} SWITCH_STATS;

// One entry of the MAC table (SwitchGetMacs)
typedef struct SWITCH_MAC_ENTRY {
	UINT Vlan;       // The VLAN
	UCHAR Mac[6];    // The MAC address
	UINT Port;       // The port it was learnt on
	UINT64 LastSeen; // The time of the last frame from it, as SwitchInput had it; refreshed once a second at most
} SWITCH_MAC_ENTRY;

// One entry of the IP table (SwitchGetIps)
typedef struct SWITCH_IP_ENTRY {
	UINT Vlan;         // The VLAN
	UCHAR Address[16]; // The IP address: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
	UCHAR Mac[6];      // The MAC address of the last frame from it
	UINT Port;         // ... and the port that frame came in at
	UINT64 LastSeen;   // The time of that frame, as SwitchInput had it; refreshed once a second at most
} SWITCH_IP_ENTRY;

// The L2 switch of a Network, Switch.c
typedef struct SWITCH SWITCH;

// Switch.c
SWITCH *SwitchNew(const SWITCH_CONFIG *cfg);
void SwitchFree(SWITCH *sw);
UINT SwitchAddPort(SWITCH *sw, const SWITCH_PORT_CONFIG *cfg);
bool SwitchSetPort(SWITCH *sw, UINT port, const SWITCH_PORT_CONFIG *cfg);
bool SwitchDelPort(SWITCH *sw, UINT port);
bool SwitchSubscribe(SWITCH *sw, UINT port, UINT vlan, const UCHAR *group);
bool SwitchUnsubscribe(SWITCH *sw, UINT port, UINT vlan, const UCHAR *group);
bool SwitchSetVlanLimits(SWITCH *sw, UINT vlan, UINT broadcast, UINT multicast);
UINT SwitchInput(SWITCH *sw, UINT64 now, UINT port, const UCHAR *frame, UINT size);
UINT SwitchAge(SWITCH *sw, UINT64 now);
UINT SwitchClearMacs(SWITCH *sw);
UINT SwitchClearMac(SWITCH *sw, const UCHAR *mac);
bool SwitchLearnAt(SWITCH *sw, UINT64 now, UINT port, UINT vlan, const UCHAR *mac);
UINT SwitchGetMacs(SWITCH *sw, SWITCH_MAC_ENTRY *list, UINT max);
void SwitchGetStats(SWITCH *sw, SWITCH_STATS *st);
bool SwitchGetVlanStats(SWITCH *sw, UINT vlan, SWITCH_VLAN_STATS *st);

// SwitchIp.c
UINT SwitchGetIps(SWITCH *sw, SWITCH_IP_ENTRY *list, UINT max);
UINT SwitchClearIps(SWITCH *sw, const UCHAR *address, UINT size);

#endif // CORE_SWITCH_H
