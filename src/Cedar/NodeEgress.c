// NodeEgress.c
// The internet exit of a VRF (SDN-12, #188; ADR-0025 decisions 13 to 15). The Controller gives the Node that is the exit of
// a VRF the id of the VRF in its NodeConfig (CONTROL_STATE.EgressVrfIds), and every other Node of the VRF the default route
// 0.0.0.0/0 of the VRF as a route of the Peer of the exit, so the traffic of the VRF to an address outside it reaches the
// exit over the overlay. In the forwarding tables of the exit the default route of each such VRF leads to the host
// (NodeEgressRoutes): a packet of a peer that no other route of the VRF holds is the Egress's (NodeEgressDeliver), and what
// answers it goes into the overlay as a packet of the node, whose source the default route holds too.
//
// The Egress tier is the first that the host supports, which the node reports as a Capability (NodeCaps.c). Here runs tier
// 3, the proxy on the Windows TCP/IP stack, which every host has, Home, Pro and arm64 among them; it is no TCP/IP stack of
// its own (ADR-0014). The proxy listens on the address of the node in each VRF whose exit it is, which its adapter of the VRF
// holds (NodeVrfAdapter.c), with a TCP listener and a UDP socket on ports that the system picks. A TCP segment or a UDP
// datagram of a peer to an address outside the VRF goes into the adapter with the listener as its destination and, as its
// source port, the port that its flow keeps for the peer's end (the port of the peer, unless another flow of that address
// holds it), so the Windows stack terminates the flow; the proxy dials the destination that the peer named with an ordinary
// socket and carries the bytes between the two (NodeEgressThread). What the host answers from a listener goes into the
// overlay with that destination as its source and the port of the peer again (NodeEgressFromHost), so the peer sees the
// address that it reached, and the policy of the VRF sees the flow as it began. A filter of the filter engine above the ones
// of Windows Firewall lets the peers reach the listeners, whatever the network profile of the adapter of the VRF
// (NodeEgressPermit); it lets in nothing else. An ICMP echo request goes out through
// IcmpSendEcho2 on the thread pool, and its reply into the overlay as a packet of the node. The proxy carries no fragment
// and no other ICMP message, and refuses a destination that is no address of the outside: the unspecified range, the
// loopback, link-local, multicast and the reserved range, and the prefixes that the host routes into a VRF of the node, so
// the egress of one VRF never leads into another (NodeEgressRefuses).
//
// The interfaces that carry the egress, each interface of the host but the loopback that holds an IPv4 default route, have
// Forwarding, WeakHostSend and WeakHostReceive on while the node is the exit of a VRF, as its adapters of the VRFs have them
// with the forwarding setting (NodeVrfAdapter.c): the strong host model of Windows would otherwise drop a reply that comes
// back on another interface than the one its request left by. The node keeps what each of them had before and gives it
// back once it is the exit of no VRF, or stops (NodeEgressUplinks).

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeCaps.h"
#include "NodeEgress.h"
#include "NodeInternal.h"

#include <iphlpapi.h>
#include <icmpapi.h>

// The GUIDs of the layers and of the conditions of the filters of the proxy are defined here, where the filters are made
#include <initguid.h>
#include <fwpmu.h>

// SIO_UDP_CONNRESET of mstcpip.h: off, a UDP socket does not fail its next receive on the ICMP port unreachable of a send
#define NODE_EGRESS_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

#define NODE_EGRESS_BATCH         64    // Connections or datagrams that one socket gives the thread in one pass at most
#define NODE_EGRESS_DATAGRAM_SIZE 65536 // Bytes of the buffer of the thread for one UDP datagram
#define NODE_EGRESS_PORT_TRIES    64    // Ports that a new flow tries for its peer's end as the host sees it

// Bytes of the reply buffer of an echo request: the reply, its data and the room of an ICMP error, which IcmpSendEcho2 asks for
#define NODE_EGRESS_REPLY ((UINT)sizeof(ICMP_ECHO_REPLY) + NODE_EGRESS_MAX_ECHO + 64)

// The states of a flow
#define NODE_EGRESS_NEW  0 // TCP: its SYN went to the host, which has not taken the connection yet
#define NODE_EGRESS_OPEN 1 // The proxy carries it: TCP from the connection that the host took, UDP from its first datagram
#define NODE_EGRESS_DONE 2 // TCP: its sockets closed; it stays for the last segments of the host

// What a socket that the thread waits for is
#define NODE_EGRESS_LISTENER  0 // The TCP listener of a VRF
#define NODE_EGRESS_DATAGRAMS 1 // The UDP socket of a VRF
#define NODE_EGRESS_INSIDE    2 // The connection of a TCP flow that the host took
#define NODE_EGRESS_OUTSIDE   3 // The socket of a flow to the end outside the VRF

// A prefix that the host routes into a VRF of the node: the proxy dials no address of it
typedef struct NODE_EGRESS_PREFIX {
	UCHAR Address[4]; // The prefix, in network byte order
	UINT Length;      // ... and its length, 1 to 32
} NODE_EGRESS_PREFIX;

// The internet exits of the node in one Generation (NODE_VRF_TABLES.Egress), which the data path reads without a lock
struct NODE_EGRESS_TABLE {
	UINT NumVrfs;                         // The VRFs whose exit the node is
	UINT VrfIds[CONTROL_MAX_VRFS];        // ... their ids
	UCHAR Addresses[CONTROL_MAX_VRFS][4]; // ... and the first IPv4 address of the node in each, 0.0.0.0 for none
	UINT NumInside;                       // The prefixes that the host routes into a VRF of the node
	NODE_EGRESS_PREFIX *Inside;           // ...
};

// The proxy of one VRF whose exit the node is
typedef struct NODE_EGRESS_VRF {
	UINT VrfId;       // The VRF
	UCHAR Address[4]; // The address of the node in it, which the listeners bind to
	SOCKET Tcp;       // The TCP listener, INVALID_SOCKET until it is bound
	SOCKET Udp;       // The UDP socket, INVALID_SOCKET until it is bound
	UINT TcpPort;     // Their ports, 0 until they are bound: the destination of what the proxy puts into the adapter
	UINT UdpPort;
	UINT64 NextBind;   // When the thread tries to bind them next
	bool Failed;       // The last attempt failed, and the node log said so
	UINT64 Permits[2]; // The filters that let the peers reach the TCP listener and the UDP socket, 0 for none
} NODE_EGRESS_VRF;

// A TCP or UDP flow of a peer through the proxy
typedef struct NODE_EGRESS_FLOW {
	struct NODE_EGRESS_FLOW *Prev; // The flows of the Egress, a list ...
	struct NODE_EGRESS_FLOW *Next;
	struct NODE_EGRESS_FLOW *NextByPeer;  // ... the chain of its bucket by its two ends as the peer sent them ...
	struct NODE_EGRESS_FLOW *NextByProxy; // ... and the one of its bucket by the peer's end as the host sees it
	UINT VrfId;                           // The VRF
	UINT Protocol;                        // NODE_EGRESS_TCP or NODE_EGRESS_UDP
	UCHAR Peer[4];                        // The peer's end: its address in the VRF ...
	UINT PeerPort;                        // ... its port ...
	UINT ProxyPort;                       // ... and its port as the host sees it
	UCHAR Remote[4];                      // The end outside the VRF that the peer named: its address ...
	UINT RemotePort;                      // ... and its port
	UINT State;                           // NODE_EGRESS_NEW, NODE_EGRESS_OPEN or NODE_EGRESS_DONE
	UINT64 Since;                         // When it came into its state
	UINT64 Seen;                          // When a packet of it passed last

	// What the thread of the proxy alone reads and changes
	SOCKET Inside;     // TCP: the connection that the host took from the peer's end
	SOCKET Outside;    // The socket to the end outside the VRF, INVALID_SOCKET before the dial
	bool Connected;    // The dial of Outside is done
	bool InsideEnd;    // TCP: the peer's end sent all that it sends ...
	bool OutsideEnd;   // ... and the end outside the VRF did
	bool InsideShut;   // TCP: the proxy shut the sending side of Inside once ToInside went out ...
	bool OutsideShut;  // ... and of Outside once ToOutside went out
	UINT NumToOutside; // TCP: the bytes of the peer's end that wait for Outside ...
	UINT NumToInside;  // ... and of the end outside the VRF that wait for Inside
	UCHAR *ToOutside;  // ... NODE_EGRESS_BUFFER bytes each
	UCHAR *ToInside;
} NODE_EGRESS_FLOW;

// An interface that carries the egress, which the node changed, with what it had before
typedef struct NODE_EGRESS_UPLINK {
	UINT64 Luid;          // The interface
	bool Forwarding;      // Its Forwarding before ...
	bool WeakHostSend;    // ... its WeakHostSend ...
	bool WeakHostReceive; // ... and its WeakHostReceive
} NODE_EGRESS_UPLINK;

// A socket that the thread waits for, and what it is
typedef struct NODE_EGRESS_WAIT {
	UINT Kind;              // NODE_EGRESS_LISTENER, NODE_EGRESS_DATAGRAMS, NODE_EGRESS_INSIDE or NODE_EGRESS_OUTSIDE
	UINT Vrf;               // A listener or a UDP socket of a VRF: the index of the VRF in Vrfs
	NODE_EGRESS_FLOW *Flow; // A socket of a flow: the flow
} NODE_EGRESS_WAIT;

// An echo request of a peer that the proxy sends out
typedef struct NODE_EGRESS_PING {
	NODE_EGRESS *Egress;              // The Egress
	UINT VrfId;                       // The VRF of the peer
	UCHAR Peer[4];                    // The source of the request: the peer's address in the VRF
	UCHAR Remote[4];                  // Its destination outside the VRF
	UINT Id;                          // Its identifier ...
	UINT Seq;                         // ... and its sequence number
	UINT Size;                        // The bytes of its data
	UCHAR Data[NODE_EGRESS_MAX_ECHO]; // ...
} NODE_EGRESS_PING;

// The internet exit of a node while its overlay runs
struct NODE_EGRESS {
	NODE *Node;                                          // The node
	UINT Tier;                                           // The Egress tier of the node (CONTROL_EGRESS_*), as its Capabilities report it
	SRWLOCK Lock;                                        // What the data path and the thread share: Vrfs, the wanted VRFs and the flows
	UINT NumVrfs;                                        // The VRFs whose proxy the thread runs
	NODE_EGRESS_VRF Vrfs[CONTROL_MAX_VRFS];              // ...
	UINT NumWanted;                                      // The VRFs of the Generation applied last, which the thread takes into Vrfs
	UINT WantedIds[CONTROL_MAX_VRFS];                    // ... their ids
	UCHAR WantedAddresses[CONTROL_MAX_VRFS][4];          // ... and the address of the node in each
	NODE_EGRESS_FLOW *First;                             // The flows, the newest first
	NODE_EGRESS_FLOW **ByPeer;                           // ... by their two ends as the peer sent them, NODE_EGRESS_BUCKETS chains
	NODE_EGRESS_FLOW **ByProxy;                          // ... by the peer's end as the host sees it
	UINT NumFlows;                                       // ... their number
	HANDLE Thread;                                       // The thread of the proxy, NULL until the node is the exit of a VRF
	HANDLE Wake;                                         // Wakes the thread: a new Generation, or the stop
	volatile LONG Halt;                                  // Ends the thread
	volatile LONG Changed;                               // A Generation changed the VRFs: the thread takes them
	volatile LONG Pings;                                 // Echo requests that wait for their reply
	UCHAR *Buf;                                          // The thread's: one UDP datagram
	UINT NumWaits;                                       // The thread's: the sockets that it waits for ...
	UINT MaxWaits;                                       // ... the room for them ...
	WSAPOLLFD *Fds;                                      // ... as WSAPoll takes them ...
	NODE_EGRESS_WAIT *Waits;                             // ... and what each is
	UINT NumUplinks;                                     // The thread's: the interfaces that carry the egress, which it changed
	NODE_EGRESS_UPLINK Uplinks[NODE_EGRESS_MAX_UPLINKS]; // ...
	UINT64 NextScan;                                     // The thread's: when it looks at the interfaces next
	volatile LONG UplinksOn;                             // NumUplinks, for the status
	HANDLE Engine;                                       // The thread's: the dynamic session of the filters of the listeners, NULL for none
	GUID SubLayer;                                       // ... and its sublayer
	bool EngineFailed;                                   // The thread's: the session could not be had, and the node log said so
	UINT Seed;                                           // Picks a port for a new flow, under the lock
	volatile LONG64 Tcp;                                 // The counters of NODE_EGRESS_STATUS
	volatile LONG64 Udp;
	volatile LONG64 Echoes;
	volatile LONG64 EchoReplies;
	volatile LONG64 Refused;
	volatile LONG64 Dropped;
};

//
// Packets
//

// The sum of size bytes at data as big-endian 16-bit words, on top of sum; an odd last byte is the high half of a word
static UINT NodeEgressSum(UINT sum, const UCHAR *data, UINT size) {
	UINT i = 0;

	for (; i + 1 < size; i += 2)
		sum += READ_USHORT(data + i);
	if (i < size)
		sum += (UINT)data[i] << 8;

	return sum;
}

// A sum in 16 bits, its carries added back in (RFC 1071)
static USHORT NodeEgressFold(UINT sum) {
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);

	return (USHORT)sum;
}

// Change the checksum at field, whose bytes summed to old_sum and now sum to new_sum (RFC 1624, eqn. 3)
static void NodeEgressAdjust(UCHAR *field, UINT old_sum, UINT new_sum) {
	UINT sum = (USHORT)~READ_USHORT(field);

	sum += (USHORT)~NodeEgressFold(old_sum);
	sum += NodeEgressFold(new_sum);
	WRITE_USHORT(field, ~NodeEgressFold(sum));
}

// Read the IPv4 packet of size bytes at packet as the Egress does into p: a whole TCP segment, UDP datagram or ICMP message,
// with its header lengths within the packet. False for anything else: another version or protocol, a fragment, or headers
// that the packet does not hold.
bool NodeEgressParse(const UCHAR *packet, UINT size, NODE_EGRESS_PACKET *p) {
	if (packet == NULL || p == NULL || size < 20)
		return false;

	Zero(p, sizeof(NODE_EGRESS_PACKET));
	if ((packet[0] >> 4) != 4)
		return false;

	p->HeaderSize = (UINT)(packet[0] & 0x0F) * 4;
	p->Total = READ_USHORT(packet + 2);
	if (p->HeaderSize < 20 || p->Total < p->HeaderSize || p->Total > size)
		return false;

	// A fragment carries no upper layer of its own to rewrite: more fragments follow, or it starts past the first byte
	if ((READ_USHORT(packet + 6) & 0x3FFF) != 0)
		return false;

	p->Protocol = packet[9];
	Copy(p->Src, packet + 12, 4);
	Copy(p->Dst, packet + 16, 4);

	const UCHAR *l4 = packet + p->HeaderSize;
	UINT room = p->Total - p->HeaderSize;

	if (p->Protocol == NODE_EGRESS_TCP) {
		UINT offset = (room >= 20 ? (UINT)(l4[12] >> 4) * 4 : 0);

		if (offset < 20 || offset > room)
			return false;

		p->SrcPort = READ_USHORT(l4);
		p->DstPort = READ_USHORT(l4 + 2);
		p->TcpFlags = l4[13];
		p->Payload = p->HeaderSize + offset;
		return true;
	}

	if (p->Protocol == NODE_EGRESS_UDP) {
		UINT length = (room >= 8 ? READ_USHORT(l4 + 4) : 0);

		if (length < 8 || length > room)
			return false;

		p->SrcPort = READ_USHORT(l4);
		p->DstPort = READ_USHORT(l4 + 2);
		p->Payload = p->HeaderSize + 8;
		return true;
	}

	if (p->Protocol == NODE_EGRESS_ICMP) {
		if (room < 8)
			return false;

		p->IcmpType = l4[0];
		p->IcmpCode = l4[1];
		p->EchoId = READ_USHORT(l4 + 4);
		p->EchoSeq = READ_USHORT(l4 + 6);
		p->Payload = p->HeaderSize + 8;
		return true;
	}

	return false;
}

// Give the TCP segment or UDP datagram that p read at packet (writable, as p read it) the ends src:src_port and
// dst:dst_port, with the checksum of the IPv4 header anew and the one of TCP or UDP changed for the addresses of its
// pseudo-header and its two ports (RFC 1624). A UDP datagram without a checksum keeps none. Anything else stays as it is.
void NodeEgressRewrite(UCHAR *packet, const NODE_EGRESS_PACKET *p, const UCHAR *src, UINT src_port, const UCHAR *dst, UINT dst_port) {
	if (packet == NULL || p == NULL || src == NULL || dst == NULL || p->HeaderSize < 20 || (p->Protocol != NODE_EGRESS_TCP && p->Protocol != NODE_EGRESS_UDP))
		return;

	UCHAR *l4 = packet + p->HeaderSize;
	UCHAR *check = l4 + (p->Protocol == NODE_EGRESS_TCP ? 16 : 6);
	UINT before = NodeEgressSum(NodeEgressSum(0, packet + 12, 8), l4, 4);

	Copy(packet + 12, src, 4);
	Copy(packet + 16, dst, 4);
	WRITE_USHORT(l4, src_port);
	WRITE_USHORT(l4 + 2, dst_port);

	UINT after = NodeEgressSum(NodeEgressSum(0, packet + 12, 8), l4, 4);

	WRITE_USHORT(packet + 10, 0);
	WRITE_USHORT(packet + 10, ~NodeEgressFold(NodeEgressSum(0, packet, p->HeaderSize)));

	if (p->Protocol == NODE_EGRESS_UDP && READ_USHORT(check) == 0)
		return;

	NodeEgressAdjust(check, before, after);

	// A UDP checksum that comes to 0 goes as 0xFFFF, as 0 is none (RFC 768)
	if (p->Protocol == NODE_EGRESS_UDP && READ_USHORT(check) == 0)
		WRITE_USHORT(check, 0xFFFF);
}

// Write into buf, of size bytes, the IPv4 packet of an ICMP echo reply from src to dst with the identifier id, the sequence
// number seq and the data_size bytes of data, with its checksums: its size, 0 when buf has no room for it
UINT NodeEgressEchoReply(UCHAR *buf, UINT size, const UCHAR *src, const UCHAR *dst, UINT id, UINT seq, const UCHAR *data, UINT data_size) {
	UINT total = 20 + 8 + data_size;

	if (buf == NULL || src == NULL || dst == NULL || (data == NULL && data_size != 0) || data_size > NODE_EGRESS_MAX_ECHO || total > size)
		return 0;

	Zero(buf, 28);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, total);
	buf[8] = 64;
	buf[9] = NODE_EGRESS_ICMP;
	Copy(buf + 12, src, 4);
	Copy(buf + 16, dst, 4);
	WRITE_USHORT(buf + 10, ~NodeEgressFold(NodeEgressSum(0, buf, 20)));

	UCHAR *icmp = buf + 20;
	icmp[0] = NODE_EGRESS_ECHO_REPLY;
	WRITE_USHORT(icmp + 4, id);
	WRITE_USHORT(icmp + 6, seq);
	if (data_size != 0)
		Copy(icmp + 8, data, data_size);
	WRITE_USHORT(icmp + 2, ~NodeEgressFold(NodeEgressSum(0, icmp, 8 + data_size)));

	return total;
}

// Whether the Egress refuses the destination dst (4 bytes) in any VRF, as no address of the outside: the unspecified range
// 0.0.0.0/8, the loopback 127.0.0.0/8, link-local 169.254.0.0/16, multicast 224.0.0.0/4 and the reserved 240.0.0.0/4 with
// the broadcast address. A NULL address is refused too.
bool NodeEgressRefuses(const UCHAR *dst) {
	if (dst == NULL)
		return true;

	return (dst[0] == 0 || dst[0] == 127 || (dst[0] == 169 && dst[1] == 254) || dst[0] >= 224);
}

// Whether a prefix of the table t holds dst: the host routes it into a VRF of the node
static bool NodeEgressInside(const NODE_EGRESS_TABLE *t, const UCHAR *dst) {
	UINT a = READ_UINT(dst);

	for (UINT i = 0; i < t->NumInside; i++) {
		UINT mask = 0xFFFFFFFFU << (32 - t->Inside[i].Length);

		if ((a & mask) == (READ_UINT(t->Inside[i].Address) & mask))
			return true;
	}

	return false;
}

//
// The tables of a Generation
//

// The default routes of the internet exits of the state st into routes, or their number when routes is NULL: the route
// 0.0.0.0/0 of each VRF whose exit the node is, which leads to the host. Their number.
UINT NodeEgressRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes) {
	UINT num = 0;

	for (UINT i = 0; st != NULL && i < st->NumEgress && i < CONTROL_MAX_VRFS; i++) {
		if (routes != NULL) {
			NODE_VRF_ROUTE *r = &routes[num];

			Zero(r, sizeof(NODE_VRF_ROUTE));
			r->VrfId = st->EgressVrfIds[i];
			r->AddressSize = 4;
			r->Length = 0;
			r->NextHop = NODE_VRF_LOCAL;
		}
		num++;
	}

	return num;
}

// The first IPv4 address of the node of the state st in the VRF vrf_id into address: false for none
static bool NodeEgressAddress(const CONTROL_STATE *st, UINT vrf_id, UCHAR *address) {
	for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES; i++) {
		if (st->Addresses[i].VrfId == vrf_id && st->Addresses[i].AddressSize == 4) {
			Copy(address, st->Addresses[i].Address, 4);
			return true;
		}
	}

	return false;
}

// Add the IPv4 prefix of length bits at address to the prefixes of t, which have room for it: a prefix of none, /0, or of
// another family does not go in
static void NodeEgressAddInside(NODE_EGRESS_TABLE *t, const UCHAR *address, UINT size, UINT length) {
	if (size != 4 || length == 0 || length > 32)
		return;

	NODE_EGRESS_PREFIX *p = &t->Inside[t->NumInside++];
	Copy(p->Address, address, 4);
	p->Length = length;
}

// The internet exits of the state st go in with the tables v of its Generation: the VRFs whose exit the node is, with the
// address of the node in each, and the prefixes that the host routes into a VRF of the node: those of the addresses of the
// node and of its peers, the routes of the peers but a default route, and the LAN subnets behind the node, which the host
// routes to its LAN. A state that makes the node the exit of no VRF adds nothing.
void NodeEgressAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	UINT max = 0;

	if (n == NULL || v == NULL || st == NULL || st->NumEgress == 0)
		return;

	NODE_EGRESS_TABLE *t = ZeroMalloc(sizeof(NODE_EGRESS_TABLE));

	for (UINT i = 0; i < st->NumEgress && i < CONTROL_MAX_VRFS; i++) {
		t->VrfIds[t->NumVrfs] = st->EgressVrfIds[i];
		NodeEgressAddress(st, st->EgressVrfIds[i], t->Addresses[t->NumVrfs]);
		t->NumVrfs++;
	}

	max = MIN(st->NumAddresses, CONTROL_MAX_ADDRESSES) + MIN(st->NumLanSubnets, CONTROL_MAX_ROUTES);
	for (UINT i = 0; i < st->NumPeers; i++)
		max += MIN(st->Peers[i].NumAddresses, CONTROL_MAX_ADDRESSES) + MIN(st->Peers[i].NumRoutes, CONTROL_MAX_ROUTES);

	t->Inside = ZeroMalloc(sizeof(NODE_EGRESS_PREFIX) * MAX(max, 1));

	for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES; i++)
		NodeEgressAddInside(t, st->Addresses[i].Address, st->Addresses[i].AddressSize, st->Addresses[i].Length);
	for (UINT i = 0; i < st->NumLanSubnets && i < CONTROL_MAX_ROUTES; i++)
		NodeEgressAddInside(t, st->LanSubnets[i].Address, st->LanSubnets[i].AddressSize, st->LanSubnets[i].Length);
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *p = &st->Peers[i];

		for (UINT j = 0; j < p->NumAddresses && j < CONTROL_MAX_ADDRESSES; j++)
			NodeEgressAddInside(t, p->Addresses[j].Address, p->Addresses[j].AddressSize, p->Addresses[j].Length);
		for (UINT j = 0; j < p->NumRoutes && j < CONTROL_MAX_ROUTES; j++)
			NodeEgressAddInside(t, p->Routes[j].Address, p->Routes[j].AddressSize, p->Routes[j].Length);
	}

	v->Egress = t;
}

// Free the internet exits of a Generation, with its tables (NodeFreeVrfTables)
void NodeFreeEgressTable(NODE_EGRESS_TABLE *t) {
	if (t == NULL)
		return;

	Free(t->Inside);
	Zero(t, sizeof(NODE_EGRESS_TABLE));
	Free(t);
}

// The index of the VRF vrf_id among the exits of the table t into index: false when the node is not its exit
static bool NodeEgressIndex(const NODE_EGRESS_TABLE *t, UINT vrf_id, UINT *index) {
	for (UINT i = 0; t != NULL && i < t->NumVrfs; i++) {
		if (t->VrfIds[i] == vrf_id) {
			*index = i;
			return true;
		}
	}

	return false;
}

//
// The flows
//

// FNV-1a of size bytes on top of h
static UINT NodeEgressHash(UINT h, const void *data, UINT size) {
	const UCHAR *b = (const UCHAR *)data;

	for (UINT i = 0; i < size; i++)
		h = (h ^ b[i]) * 16777619U;

	return h;
}

// The bucket of a flow by the VRF, the protocol, the peer's end and, unless remote is NULL, the end outside the VRF
static UINT NodeEgressBucket(UINT vrf_id, UINT protocol, const UCHAR *peer, UINT peer_port, const UCHAR *remote, UINT remote_port) {
	UINT h = NodeEgressHash(2166136261U, &vrf_id, sizeof(vrf_id));

	h = NodeEgressHash(h, &protocol, sizeof(protocol));
	h = NodeEgressHash(h, peer, 4);
	h = NodeEgressHash(h, &peer_port, sizeof(peer_port));
	if (remote != NULL) {
		h = NodeEgressHash(h, remote, 4);
		h = NodeEgressHash(h, &remote_port, sizeof(remote_port));
	}

	return h & (NODE_EGRESS_BUCKETS - 1);
}

// The flow of the VRF and the protocol between the peer's end and the end outside the VRF as the peer sent them, NULL for
// none. The caller holds the lock.
static NODE_EGRESS_FLOW *NodeEgressFindPeer(NODE_EGRESS *e, UINT vrf_id, UINT protocol, const UCHAR *peer, UINT peer_port, const UCHAR *remote, UINT remote_port) {
	NODE_EGRESS_FLOW *f = e->ByPeer[NodeEgressBucket(vrf_id, protocol, peer, peer_port, remote, remote_port)];

	for (; f != NULL; f = f->NextByPeer)
		if (f->VrfId == vrf_id && f->Protocol == protocol && f->PeerPort == peer_port && f->RemotePort == remote_port && Cmp(f->Peer, peer, 4) == 0 &&
		    Cmp(f->Remote, remote, 4) == 0)
			return f;

	return NULL;
}

// The flow of the VRF and the protocol whose peer's end the host sees as peer:port, NULL for none. The caller holds the lock.
static NODE_EGRESS_FLOW *NodeEgressFindProxy(NODE_EGRESS *e, UINT vrf_id, UINT protocol, const UCHAR *peer, UINT port) {
	NODE_EGRESS_FLOW *f = e->ByProxy[NodeEgressBucket(vrf_id, protocol, peer, port, NULL, 0)];

	for (; f != NULL; f = f->NextByProxy)
		if (f->VrfId == vrf_id && f->Protocol == protocol && f->ProxyPort == port && Cmp(f->Peer, peer, 4) == 0)
			return f;

	return NULL;
}

// A new flow of the packet p of a peer in the VRF vrf_id, at now: its peer's end keeps its port as the host sees it, unless
// another flow of that address holds it, and then takes a free one. NULL when the flows are full or no port is free. The
// caller holds the lock.
static NODE_EGRESS_FLOW *NodeEgressNewFlow(NODE_EGRESS *e, UINT vrf_id, const NODE_EGRESS_PACKET *p, UINT64 now) {
	UINT port = p->SrcPort;

	if (e->NumFlows >= NODE_EGRESS_MAX_FLOWS)
		return NULL;

	if (port == 0 || NodeEgressFindProxy(e, vrf_id, p->Protocol, p->Src, port) != NULL) {
		e->Seed = e->Seed * 1103515245U + 12345U;
		UINT start = e->Seed >> 8;

		port = 0;
		for (UINT i = 0; i < NODE_EGRESS_PORT_TRIES && port == 0; i++) {
			UINT candidate = 1024 + (start + i * 7919U) % (65536 - 1024);

			if (NodeEgressFindProxy(e, vrf_id, p->Protocol, p->Src, candidate) == NULL)
				port = candidate;
		}
		if (port == 0)
			return NULL;
	}

	NODE_EGRESS_FLOW *f = ZeroMalloc(sizeof(NODE_EGRESS_FLOW));
	f->VrfId = vrf_id;
	f->Protocol = p->Protocol;
	Copy(f->Peer, p->Src, 4);
	f->PeerPort = p->SrcPort;
	f->ProxyPort = port;
	Copy(f->Remote, p->Dst, 4);
	f->RemotePort = p->DstPort;
	f->State = (p->Protocol == NODE_EGRESS_TCP ? NODE_EGRESS_NEW : NODE_EGRESS_OPEN);
	f->Since = now;
	f->Seen = now;
	f->Inside = INVALID_SOCKET;
	f->Outside = INVALID_SOCKET;

	UINT by_peer = NodeEgressBucket(vrf_id, f->Protocol, f->Peer, f->PeerPort, f->Remote, f->RemotePort);
	UINT by_proxy = NodeEgressBucket(vrf_id, f->Protocol, f->Peer, f->ProxyPort, NULL, 0);

	f->NextByPeer = e->ByPeer[by_peer];
	e->ByPeer[by_peer] = f;
	f->NextByProxy = e->ByProxy[by_proxy];
	e->ByProxy[by_proxy] = f;
	f->Next = e->First;
	if (e->First != NULL)
		e->First->Prev = f;
	e->First = f;
	e->NumFlows++;

	return f;
}

// Take the flow f out of the list and the hashes. The caller holds the lock.
static void NodeEgressUnlink(NODE_EGRESS *e, NODE_EGRESS_FLOW *f) {
	NODE_EGRESS_FLOW **link = &e->ByPeer[NodeEgressBucket(f->VrfId, f->Protocol, f->Peer, f->PeerPort, f->Remote, f->RemotePort)];

	while (*link != NULL && *link != f)
		link = &(*link)->NextByPeer;
	if (*link == f)
		*link = f->NextByPeer;

	link = &e->ByProxy[NodeEgressBucket(f->VrfId, f->Protocol, f->Peer, f->ProxyPort, NULL, 0)];
	while (*link != NULL && *link != f)
		link = &(*link)->NextByProxy;
	if (*link == f)
		*link = f->NextByProxy;

	if (f->Prev != NULL)
		f->Prev->Next = f->Next;
	else
		e->First = f->Next;
	if (f->Next != NULL)
		f->Next->Prev = f->Prev;

	f->Prev = NULL;
	f->Next = NULL;
	e->NumFlows--;
}

// Close a socket at once, with a reset of a TCP connection that is open
static void NodeEgressAbort(SOCKET s) {
	struct linger l;

	if (s == INVALID_SOCKET)
		return;

	l.l_onoff = 1;
	l.l_linger = 0;
	setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
	closesocket(s);
}

// Free a flow that left the list, with its sockets, which close at once
static void NodeEgressFreeFlow(NODE_EGRESS_FLOW *f) {
	NodeEgressAbort(f->Inside);
	NodeEgressAbort(f->Outside);
	Free(f->ToOutside);
	Free(f->ToInside);
	Free(f);
}

//
// The data path
//

// The proxy of the VRF vrf_id that the thread runs, NULL for none. The caller holds the lock, or is the thread.
static NODE_EGRESS_VRF *NodeEgressVrfOf(NODE_EGRESS *e, UINT vrf_id) {
	for (UINT i = 0; i < e->NumVrfs; i++)
		if (e->Vrfs[i].VrfId == vrf_id)
			return &e->Vrfs[i];

	return NULL;
}

// Put a packet into the overlay as a packet of the host in the VRF vrf_id, from a thread that reads the tables of the node
// only for this call
static bool NodeEgressInject(NODE_EGRESS *e, UINT vrf_id, const UCHAR *packet, UINT size) {
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(e->Node, &r);
	bool ok = NodeOverlayInput(e->Node, vrf_id, packet, size);
	NodeReaderUnregister(e->Node, &r);

	return ok;
}

// An echo request of a peer on the thread pool: IcmpSendEcho2 sends it out from the host, and its reply goes into the overlay
// from the destination that the peer named to the peer
static VOID CALLBACK NodeEgressPingProc(PTP_CALLBACK_INSTANCE instance, PVOID context) {
	NODE_EGRESS_PING *ping = (NODE_EGRESS_PING *)context;
	NODE_EGRESS *e = ping->Egress;
	UCHAR *reply = ZeroMalloc(NODE_EGRESS_REPLY);
	UCHAR packet[20 + 8 + NODE_EGRESS_MAX_ECHO];
	IPAddr dst = 0;
	HANDLE icmp = IcmpCreateFile();

	Copy(&dst, ping->Remote, 4);
	InterlockedIncrement64(&e->Echoes);

	DWORD num = 0;
	if (icmp != INVALID_HANDLE_VALUE)
		num = IcmpSendEcho2(icmp, NULL, NULL, NULL, dst, ping->Data, (WORD)ping->Size, NULL, reply, NODE_EGRESS_REPLY, NODE_EGRESS_PING_WAIT);

	if (num != 0) {
		ICMP_ECHO_REPLY *r = (ICMP_ECHO_REPLY *)reply;

		if (r->Status == IP_SUCCESS && r->Address == dst && r->DataSize <= NODE_EGRESS_MAX_ECHO && (r->DataSize == 0 || r->Data != NULL)) {
			UINT size = NodeEgressEchoReply(packet, sizeof(packet), ping->Remote, ping->Peer, ping->Id, ping->Seq, (const UCHAR *)r->Data, r->DataSize);

			if (size != 0 && NodeEgressInject(e, ping->VrfId, packet, size))
				InterlockedIncrement64(&e->EchoReplies);
		}
	}

	if (icmp != INVALID_HANDLE_VALUE)
		IcmpCloseHandle(icmp);
	Free(reply);
	Free(ping);
	InterlockedDecrement(&e->Pings);
}

// An echo request of a peer to the address outside the VRF that p read at packet: on the thread pool, at most
// NODE_EGRESS_MAX_PINGS at once. Any other ICMP message is dropped.
static void NodeEgressPing(NODE_EGRESS *e, UINT vrf_id, const NODE_EGRESS_PACKET *p, const UCHAR *packet) {
	UINT size = p->Total - p->Payload;

	if (p->IcmpType != NODE_EGRESS_ECHO_REQUEST || p->IcmpCode != 0 || size > NODE_EGRESS_MAX_ECHO) {
		InterlockedIncrement64(&e->Dropped);
		return;
	}

	if (InterlockedIncrement(&e->Pings) > NODE_EGRESS_MAX_PINGS || ReadAcquire(&e->Halt) != 0) {
		InterlockedDecrement(&e->Pings);
		InterlockedIncrement64(&e->Dropped);
		return;
	}

	NODE_EGRESS_PING *ping = ZeroMalloc(sizeof(NODE_EGRESS_PING));
	ping->Egress = e;
	ping->VrfId = vrf_id;
	Copy(ping->Peer, p->Src, 4);
	Copy(ping->Remote, p->Dst, 4);
	ping->Id = p->EchoId;
	ping->Seq = p->EchoSeq;
	ping->Size = size;
	if (size != 0)
		Copy(ping->Data, packet + p->Payload, size);

	if (TrySubmitThreadpoolCallback(NodeEgressPingProc, ping, NULL) == FALSE) {
		Free(ping);
		InterlockedDecrement(&e->Pings);
		InterlockedIncrement64(&e->Dropped);
	}
}

// A TCP segment or UDP datagram of a peer to the address outside the VRF that p read at packet: into the adapter of the VRF
// to the listener of the proxy, from the port of its flow, which a UDP datagram or the SYN of a TCP connection opens
static void NodeEgressToHost(NODE_EGRESS *e, UINT vrf_id, const NODE_EGRESS_PACKET *p, const UCHAR *packet, NODE_ADAPTER_PROC *adapter, void *param) {
	UCHAR stack[NODE_EGRESS_STACK];
	UCHAR local[4];
	UINT listen = 0;
	UINT port = 0;
	bool syn = (p->Protocol == NODE_EGRESS_TCP && (p->TcpFlags & (NODE_EGRESS_SYN | NODE_EGRESS_ACK | NODE_EGRESS_RST)) == NODE_EGRESS_SYN);
	UINT64 now = GetTickCount64();

	Zero(local, sizeof(local));

	AcquireSRWLockExclusive(&e->Lock);
	{
		NODE_EGRESS_VRF *v = NodeEgressVrfOf(e, vrf_id);
		NODE_EGRESS_FLOW *f = NULL;

		if (v != NULL) {
			listen = (p->Protocol == NODE_EGRESS_TCP ? v->TcpPort : v->UdpPort);
			Copy(local, v->Address, 4);
		}
		if (listen != 0)
			f = NodeEgressFindPeer(e, vrf_id, p->Protocol, p->Src, p->SrcPort, p->Dst, p->DstPort);

		// A UDP datagram, or the SYN of a TCP connection, opens a flow; the SYN of a new connection on the ends of a flow that
		// closed opens it again
		if (f == NULL && listen != 0 && (p->Protocol == NODE_EGRESS_UDP || syn))
			f = NodeEgressNewFlow(e, vrf_id, p, now);
		else if (f != NULL && syn && f->State == NODE_EGRESS_DONE) {
			f->State = NODE_EGRESS_NEW;
			f->Since = now;
		}

		if (f != NULL) {
			f->Seen = now;
			port = f->ProxyPort;
		}
	}
	ReleaseSRWLockExclusive(&e->Lock);

	if (port == 0 || adapter == NULL) {
		InterlockedIncrement64(&e->Dropped);
		return;
	}

	UCHAR *buf = (p->Total <= sizeof(stack) ? stack : Malloc(p->Total));
	Copy(buf, packet, p->Total);
	NodeEgressRewrite(buf, p, p->Src, port, local, listen);
	adapter(e->Node, param, vrf_id, buf, p->Total);
	if (buf != stack)
		Free(buf);
}

// A packet of a peer in the VRF vrf_id, which the tables v route to the host: the Egress takes it when the node is the exit
// of the VRF and no route of the VRF but its default route holds the destination. The proxy then puts what the host should
// see into the adapter through adapter and param (NODE_ADAPTER_PROC), or sends an echo request out, and drops what it cannot
// carry; nothing of it reaches the host as it is. False for a packet that the Egress leaves to the host, which takes it as
// before. The caller is an online reader of the tables v.
bool NodeEgressDeliver(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, NODE_ADAPTER_PROC *adapter, void *param) {
	NODE_EGRESS *e = (n != NULL ? n->Egress : NULL);
	NODE_EGRESS_TABLE *t = (v != NULL ? v->Egress : NULL);
	NODE_EGRESS_PACKET p;
	UINT index = 0;

	if (e == NULL || t == NULL || packet == NULL || size < 20 || (packet[0] >> 4) != 4 || NodeEgressIndex(t, vrf_id, &index) == false)
		return false;

	// An address of the node, of a LAN behind it or of a 1:1 NAT rule is the host's: another route of the VRF holds it
	if (NodeVrfDefault(NodeGetVrfTable(v, vrf_id), packet + 16, 4) == false)
		return false;

	// The tiers on the NAT of Windows take the packet as it is, through the adapter of the VRF
	if (e->Tier != CONTROL_EGRESS_PROXY)
		return false;

	if (NodeEgressParse(packet, size, &p) == false) {
		InterlockedIncrement64(&e->Dropped);
		return true;
	}

	if (NodeEgressRefuses(p.Dst) || NodeEgressInside(t, p.Dst) || (p.Protocol != NODE_EGRESS_ICMP && p.DstPort == 0)) {
		InterlockedIncrement64(&e->Refused);
		return true;
	}

	if (p.Protocol == NODE_EGRESS_ICMP)
		NodeEgressPing(e, vrf_id, &p, packet);
	else
		NodeEgressToHost(e, vrf_id, &p, packet, adapter, param);

	return true;
}

// A packet of the host into the overlay in the VRF vrf_id, at packet (writable) after its record header: what the host answers
// from a listener of the proxy goes with the end outside the VRF that the peer reached as its source, and the port of the
// peer as its destination port. Any other packet stays as it is. The caller is an online reader of the tables v.
void NodeEgressFromHost(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *packet, UINT size) {
	NODE_EGRESS *e = (n != NULL ? n->Egress : NULL);
	NODE_EGRESS_TABLE *t = (v != NULL ? v->Egress : NULL);
	NODE_EGRESS_PACKET p;
	UCHAR remote[4];
	UINT remote_port = 0;
	UINT peer_port = 0;
	UINT index = 0;

	if (e == NULL || t == NULL || NodeEgressIndex(t, vrf_id, &index) == false || NodeEgressParse(packet, size, &p) == false ||
	    (p.Protocol != NODE_EGRESS_TCP && p.Protocol != NODE_EGRESS_UDP) || Cmp(p.Src, t->Addresses[index], 4) != 0)
		return;

	Zero(remote, sizeof(remote));

	AcquireSRWLockExclusive(&e->Lock);
	{
		NODE_EGRESS_VRF *vrf = NodeEgressVrfOf(e, vrf_id);
		UINT listen = (vrf == NULL ? 0 : (p.Protocol == NODE_EGRESS_TCP ? vrf->TcpPort : vrf->UdpPort));
		NODE_EGRESS_FLOW *f = (listen != 0 && p.SrcPort == listen ? NodeEgressFindProxy(e, vrf_id, p.Protocol, p.Dst, p.DstPort) : NULL);

		if (f != NULL) {
			f->Seen = GetTickCount64();
			Copy(remote, f->Remote, 4);
			remote_port = f->RemotePort;
			peer_port = f->PeerPort;
		}
	}
	ReleaseSRWLockExclusive(&e->Lock);

	if (remote_port != 0)
		NodeEgressRewrite(packet, &p, remote, remote_port, p.Dst, peer_port);
}

//
// The thread of the proxy
//

// A socket of the address of 4 bytes of the type SOCK_STREAM (a listener) or SOCK_DGRAM on a port that the system picks,
// which does not wait, its port into port: INVALID_SOCKET when it cannot be had, as before the address is up
static SOCKET NodeEgressListen(const UCHAR *address, int type, UINT *port) {
	SOCKADDR_IN a;
	int size = sizeof(a);
	u_long nonblock = 1;
	BOOL exclusive = TRUE;

	SOCKET s = socket(AF_INET, type, (type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP));
	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	Copy(&a.sin_addr, address, 4);
	setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive));

	if (type == SOCK_DGRAM) {
		BOOL off = FALSE;
		DWORD ret = 0;

		WSAIoctl(s, NODE_EGRESS_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &ret, NULL, NULL);
	}

	if (bind(s, (SOCKADDR *)&a, sizeof(a)) != 0 || (type == SOCK_STREAM && listen(s, SOMAXCONN) != 0) || ioctlsocket(s, FIONBIO, &nonblock) != 0 ||
	    getsockname(s, (SOCKADDR *)&a, &size) != 0) {
		int err = WSAGetLastError();

		closesocket(s);
		WSASetLastError(err);
		return INVALID_SOCKET;
	}

	*port = ntohs(a.sin_port);
	return s;
}

// Dial the end outside the VRF of the flow f with a socket that does not wait: false when the dial cannot start
static bool NodeEgressDial(NODE_EGRESS_FLOW *f) {
	SOCKADDR_IN to;
	u_long nonblock = 1;
	bool tcp = (f->Protocol == NODE_EGRESS_TCP);

	SOCKET s = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM), (tcp ? IPPROTO_TCP : IPPROTO_UDP));
	if (s == INVALID_SOCKET)
		return false;

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	Copy(&to.sin_addr, f->Remote, 4);
	to.sin_port = htons((u_short)f->RemotePort);

	if (tcp == false) {
		BOOL off = FALSE;
		DWORD ret = 0;

		WSAIoctl(s, NODE_EGRESS_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &ret, NULL, NULL);
	}

	if (ioctlsocket(s, FIONBIO, &nonblock) != 0 || (connect(s, (SOCKADDR *)&to, sizeof(to)) != 0 && WSAGetLastError() != WSAEWOULDBLOCK)) {
		closesocket(s);
		return false;
	}

	f->Outside = s;
	f->Connected = (tcp == false);

	return true;
}

// The TCP flow f ends at now: its sockets close, at once with a reset when abort, and it stays NODE_EGRESS_TCP_LINGER for
// the last segments of the host
static void NodeEgressEnd(NODE_EGRESS *e, NODE_EGRESS_FLOW *f, bool abort, UINT64 now) {
	if (abort) {
		NodeEgressAbort(f->Inside);
		NodeEgressAbort(f->Outside);
	} else {
		if (f->Inside != INVALID_SOCKET)
			closesocket(f->Inside);
		if (f->Outside != INVALID_SOCKET)
			closesocket(f->Outside);
	}

	f->Inside = INVALID_SOCKET;
	f->Outside = INVALID_SOCKET;
	f->NumToInside = 0;
	f->NumToOutside = 0;

	AcquireSRWLockExclusive(&e->Lock);
	f->State = NODE_EGRESS_DONE;
	f->Since = now;
	ReleaseSRWLockExclusive(&e->Lock);
}

// Send what waits in buf, num bytes of it, on s, as far as s takes it now: false on an error of s
static bool NodeEgressFlush(SOCKET s, UCHAR *buf, UINT *num) {
	if (*num == 0)
		return true;

	int r = send(s, (const char *)buf, (int)*num, 0);
	if (r < 0)
		return (WSAGetLastError() == WSAEWOULDBLOCK);

	memmove(buf, buf + r, *num - (UINT)r);
	*num -= (UINT)r;

	return true;
}

// Receive on s into buf, of which num bytes wait, as far as it has room: false on an error of s; *end once s sent all that
// it sends
static bool NodeEgressFill(SOCKET s, UCHAR *buf, UINT *num, bool *end) {
	if (*end || *num >= NODE_EGRESS_BUFFER)
		return true;

	int r = recv(s, (char *)buf + *num, (int)(NODE_EGRESS_BUFFER - *num), 0);
	if (r > 0)
		*num += (UINT)r;
	else if (r == 0)
		*end = true;
	else
		return (WSAGetLastError() == WSAEWOULDBLOCK);

	return true;
}

// Carry the bytes of the TCP flow f between its two sockets as far as they go now, inside and outside the events of its
// sockets in the last wait (0 for one that it did not wait for). The flow ends with a reset on an error of either socket or
// a dial that failed, and quietly once both ends sent all that they send and the other end took it.
static void NodeEgressSplice(NODE_EGRESS *e, NODE_EGRESS_FLOW *f, SHORT inside, SHORT outside, UINT64 now) {
	if (f->Connected == false) {
		if ((outside & (POLLERR | POLLHUP)) != 0 || now > f->Since + NODE_EGRESS_TCP_OPEN) {
			NodeEgressEnd(e, f, true, now);
			return;
		}
		if ((outside & POLLWRNORM) != 0) {
			f->Connected = true;
			InterlockedIncrement64(&e->Tcp);
		}
	}

	if ((inside & POLLERR) != 0 || (f->Connected && (outside & POLLERR) != 0)) {
		NodeEgressEnd(e, f, true, now);
		return;
	}

	bool ok = true;
	if ((inside & (POLLRDNORM | POLLHUP)) != 0)
		ok = NodeEgressFill(f->Inside, f->ToOutside, &f->NumToOutside, &f->InsideEnd);
	if (ok && f->Connected && (outside & (POLLRDNORM | POLLHUP)) != 0)
		ok = NodeEgressFill(f->Outside, f->ToInside, &f->NumToInside, &f->OutsideEnd);
	if (ok && f->Connected)
		ok = NodeEgressFlush(f->Outside, f->ToOutside, &f->NumToOutside);
	if (ok)
		ok = NodeEgressFlush(f->Inside, f->ToInside, &f->NumToInside);

	if (ok == false) {
		NodeEgressEnd(e, f, true, now);
		return;
	}

	// An end that sent all, once the other end took it: the other end hears it
	if (f->Connected && f->InsideEnd && f->NumToOutside == 0 && f->OutsideShut == false) {
		shutdown(f->Outside, SD_SEND);
		f->OutsideShut = true;
	}
	if (f->OutsideEnd && f->NumToInside == 0 && f->InsideShut == false) {
		shutdown(f->Inside, SD_SEND);
		f->InsideShut = true;
	}
	if (f->InsideShut && f->OutsideShut)
		NodeEgressEnd(e, f, false, now);
}

// The connections that the host took on the TCP listener of the VRF v: each is the peer's end of a flow that waits for it,
// whose dial starts; a connection of no flow closes with a reset
static void NodeEgressAccept(NODE_EGRESS *e, NODE_EGRESS_VRF *v, UINT64 now) {
	for (UINT i = 0; i < NODE_EGRESS_BATCH; i++) {
		SOCKADDR_IN from;
		int size = sizeof(from);
		NODE_EGRESS_FLOW *f = NULL;

		SOCKET s = accept(v->Tcp, (SOCKADDR *)&from, &size);
		if (s == INVALID_SOCKET)
			return;

		AcquireSRWLockExclusive(&e->Lock);
		{
			f = NodeEgressFindProxy(e, v->VrfId, NODE_EGRESS_TCP, (const UCHAR *)&from.sin_addr, ntohs(from.sin_port));
			if (f != NULL && f->State == NODE_EGRESS_NEW) {
				f->State = NODE_EGRESS_OPEN;
				f->Since = now;
				f->Seen = now;
			} else {
				f = NULL;
			}
		}
		ReleaseSRWLockExclusive(&e->Lock);

		if (f == NULL) {
			NodeEgressAbort(s);
			InterlockedIncrement64(&e->Dropped);
			continue;
		}

		f->Inside = s;
		f->InsideEnd = false;
		f->OutsideEnd = false;
		f->InsideShut = false;
		f->OutsideShut = false;
		if (f->ToOutside == NULL)
			f->ToOutside = Malloc(NODE_EGRESS_BUFFER);
		if (f->ToInside == NULL)
			f->ToInside = Malloc(NODE_EGRESS_BUFFER);

		if (NodeEgressDial(f) == false)
			NodeEgressEnd(e, f, true, now);
	}
}

// The datagrams of the peers that the UDP socket of the VRF v took: each goes to the end outside the VRF of its flow, through
// the socket of the flow, which the first one dials
static void NodeEgressDatagrams(NODE_EGRESS *e, NODE_EGRESS_VRF *v, UINT64 now) {
	for (UINT i = 0; i < NODE_EGRESS_BATCH; i++) {
		SOCKADDR_IN from;
		int size = sizeof(from);
		NODE_EGRESS_FLOW *f = NULL;

		int r = recvfrom(v->Udp, (char *)e->Buf, NODE_EGRESS_DATAGRAM_SIZE, 0, (SOCKADDR *)&from, &size);
		if (r < 0)
			return;

		AcquireSRWLockExclusive(&e->Lock);
		{
			f = NodeEgressFindProxy(e, v->VrfId, NODE_EGRESS_UDP, (const UCHAR *)&from.sin_addr, ntohs(from.sin_port));
			if (f != NULL)
				f->Seen = now;
		}
		ReleaseSRWLockExclusive(&e->Lock);

		if (f == NULL) {
			InterlockedIncrement64(&e->Dropped);
			continue;
		}

		if (f->Outside == INVALID_SOCKET) {
			if (NodeEgressDial(f) == false) {
				InterlockedIncrement64(&e->Dropped);
				continue;
			}
			InterlockedIncrement64(&e->Udp);
		}

		send(f->Outside, (const char *)e->Buf, r, 0);
	}
}

// The datagrams of the end outside the VRF of the UDP flow f: each goes to the peer's end as the host sees it, from the UDP
// socket of the VRF of the flow
static void NodeEgressReplies(NODE_EGRESS *e, NODE_EGRESS_FLOW *f, UINT64 now) {
	NODE_EGRESS_VRF *v = NodeEgressVrfOf(e, f->VrfId);
	SOCKADDR_IN to;
	bool any = false;

	if (v == NULL || v->Udp == INVALID_SOCKET)
		return;

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	Copy(&to.sin_addr, f->Peer, 4);
	to.sin_port = htons((u_short)f->ProxyPort);

	for (UINT i = 0; i < NODE_EGRESS_BATCH; i++) {
		int r = recv(f->Outside, (char *)e->Buf, NODE_EGRESS_DATAGRAM_SIZE, 0);
		if (r < 0)
			break;

		sendto(v->Udp, (const char *)e->Buf, r, 0, (SOCKADDR *)&to, sizeof(to));
		any = true;
	}

	if (any) {
		AcquireSRWLockExclusive(&e->Lock);
		f->Seen = now;
		ReleaseSRWLockExclusive(&e->Lock);
	}
}

// The filters of the proxy in a dynamic session of the filter engine, which the thread opens with the first listeners: in a
// sublayer of the node's own above the ones of Windows Firewall, a permit of a listener that clears the right of a lower
// sublayer to block, so a peer reaches the proxy whatever the network profile of the adapter of its VRF. The filters and the
// sublayer go with the session, which goes with the thread. NULL when it cannot be had (the node log says so once): a
// firewall that blocks the listeners then blocks the proxy.
static HANDLE NodeEgressEngine(NODE_EGRESS *e) {
	FWPM_SESSION0 session;
	FWPM_SUBLAYER0 sub;
	HANDLE engine = NULL;

	if (e->Engine != NULL || e->EngineFailed)
		return e->Engine;

	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"Ranz VPN: the proxy of the internet exit";

	DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err == ERROR_SUCCESS) {
		// A sublayer of its own: two nodes of one process each have their session
		Zero(&sub, sizeof(sub));
		Rand(&sub.subLayerKey, sizeof(GUID));
		sub.displayData.name = L"Ranz VPN: the proxy of the internet exit";
		sub.weight = 0xFFFF;
		err = FwpmSubLayerAdd0(engine, &sub, NULL);
		if (err == ERROR_SUCCESS) {
			e->SubLayer = sub.subLayerKey;
		} else {
			FwpmEngineClose0(engine);
			engine = NULL;
		}
	}

	if (engine == NULL) {
		e->EngineFailed = true;
		NodeLog(e->Node, "Egress: the filter engine could not be opened (error 0x%x): a firewall that blocks the listeners of the proxy blocks the proxy", (UINT)err);
		return NULL;
	}

	e->Engine = engine;
	return engine;
}

// Let the peers reach the listener of the protocol on address:port: the id of its filter, 0 when it could not be added
static UINT64 NodeEgressPermit(NODE_EGRESS *e, const UCHAR *address, UINT port, UINT protocol) {
	FWPM_FILTER_CONDITION0 cond[3];
	FWPM_FILTER0 filter;
	UINT64 id = 0;
	HANDLE engine = NodeEgressEngine(e);

	if (engine == NULL)
		return 0;

	Zero(cond, sizeof(cond));
	cond[0].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	cond[0].matchType = FWP_MATCH_EQUAL;
	// An IPv4 address of a condition is in host byte order
	cond[0].conditionValue.type = FWP_UINT32;
	cond[0].conditionValue.uint32 = READ_UINT(address);
	cond[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	cond[1].matchType = FWP_MATCH_EQUAL;
	cond[1].conditionValue.type = FWP_UINT16;
	cond[1].conditionValue.uint16 = (UINT16)port;
	cond[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	cond[2].matchType = FWP_MATCH_EQUAL;
	cond[2].conditionValue.type = FWP_UINT8;
	cond[2].conditionValue.uint8 = (UINT8)protocol;

	Zero(&filter, sizeof(filter));
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	filter.subLayerKey = e->SubLayer;
	filter.displayData.name = L"Ranz VPN: the peers of a VRF reach the proxy of its internet exit";
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 15;
	filter.numFilterConditions = 3;
	filter.filterCondition = cond;

	DWORD err = FwpmFilterAdd0(engine, &filter, NULL, &id);
	if (err != ERROR_SUCCESS) {
		NodeLog(e->Node, "Egress: the filter of the listener of protocol %u on port %u could not be added (error 0x%x)", protocol, port, (UINT)err);
		return 0;
	}

	return id;
}

// Take the VRFs of the Generation applied last at now: a VRF that stays with its address keeps its listeners and its flows;
// a VRF that goes, or whose address changed, closes them; a new VRF waits for its listeners
static void NodeEgressReconcile(NODE_EGRESS *e, UINT64 now) {
	NODE_EGRESS_VRF next[CONTROL_MAX_VRFS];
	UINT kept[CONTROL_MAX_VRFS];
	SOCKET closing[2 * CONTROL_MAX_VRFS];
	UINT64 permits[2 * CONTROL_MAX_VRFS];
	NODE_EGRESS_FLOW *gone = NULL;
	UINT num = 0;
	UINT num_kept = 0;
	UINT num_closing = 0;
	UINT num_permits = 0;

	AcquireSRWLockExclusive(&e->Lock);
	{
		for (UINT i = 0; i < e->NumWanted && num < CONTROL_MAX_VRFS; i++) {
			NODE_EGRESS_VRF *old = NodeEgressVrfOf(e, e->WantedIds[i]);
			NODE_EGRESS_VRF *v = &next[num++];

			// A VRF that stays with its address keeps its listeners and its flows: it leaves its place with them
			if (old != NULL && Cmp(old->Address, e->WantedAddresses[i], 4) == 0) {
				Copy(v, old, sizeof(NODE_EGRESS_VRF));
				kept[num_kept++] = old->VrfId;
				old->VrfId = 0;
				continue;
			}

			Zero(v, sizeof(NODE_EGRESS_VRF));
			v->VrfId = e->WantedIds[i];
			Copy(v->Address, e->WantedAddresses[i], 4);
			v->Tcp = INVALID_SOCKET;
			v->Udp = INVALID_SOCKET;
			v->NextBind = now;
		}

		// The listeners of the VRFs that went, or whose address changed
		for (UINT i = 0; i < e->NumVrfs; i++) {
			NODE_EGRESS_VRF *old = &e->Vrfs[i];

			if (old->VrfId == 0)
				continue;

			if (old->Tcp != INVALID_SOCKET)
				closing[num_closing++] = old->Tcp;
			if (old->Udp != INVALID_SOCKET)
				closing[num_closing++] = old->Udp;
			for (UINT j = 0; j < 2; j++)
				if (old->Permits[j] != 0)
					permits[num_permits++] = old->Permits[j];
		}

		// ... and their flows
		for (NODE_EGRESS_FLOW *f = e->First, *after = NULL; f != NULL; f = after) {
			bool stays = false;

			after = f->Next;
			for (UINT j = 0; j < num_kept && stays == false; j++)
				stays = (kept[j] == f->VrfId);
			if (stays)
				continue;

			NodeEgressUnlink(e, f);
			f->Next = gone;
			gone = f;
		}

		Copy(e->Vrfs, next, sizeof(NODE_EGRESS_VRF) * num);
		e->NumVrfs = num;
	}
	ReleaseSRWLockExclusive(&e->Lock);

	for (UINT i = 0; i < num_closing; i++)
		closesocket(closing[i]);
	for (UINT i = 0; i < num_permits && e->Engine != NULL; i++)
		FwpmFilterDeleteById0(e->Engine, permits[i]);

	while (gone != NULL) {
		NODE_EGRESS_FLOW *f = gone;

		gone = f->Next;
		NodeEgressFreeFlow(f);
	}
}

// Bind the listeners of each VRF that has none, once NODE_EGRESS_BIND passed since its last attempt at now: the TCP listener
// and the UDP socket on the address of the node in the VRF. Before the adapter of the VRF holds the address they cannot be
// had, and the next attempt follows.
static void NodeEgressBind(NODE_EGRESS *e, UINT64 now) {
	char a[64];

	for (UINT i = 0; i < e->NumVrfs; i++) {
		NODE_EGRESS_VRF *v = &e->Vrfs[i];
		UINT tcp_port = 0;
		UINT udp_port = 0;

		if (v->Tcp != INVALID_SOCKET || now < v->NextBind)
			continue;

		v->NextBind = now + NODE_EGRESS_BIND;
		Format(a, sizeof(a), "%u.%u.%u.%u", (UINT)v->Address[0], (UINT)v->Address[1], (UINT)v->Address[2], (UINT)v->Address[3]);

		SOCKET tcp = NodeEgressListen(v->Address, SOCK_STREAM, &tcp_port);
		SOCKET udp = (tcp != INVALID_SOCKET ? NodeEgressListen(v->Address, SOCK_DGRAM, &udp_port) : INVALID_SOCKET);
		if (udp == INVALID_SOCKET) {
			if (tcp != INVALID_SOCKET)
				closesocket(tcp);
			if (v->Failed == false)
				NodeLog(e->Node, "Egress: the proxy of VRF %u cannot listen on %s yet (error %u): the node tries again", v->VrfId, a, (UINT)WSAGetLastError());
			v->Failed = true;
			continue;
		}

		// The firewall lets the peers reach them before the data path sends them anything
		v->Permits[0] = NodeEgressPermit(e, v->Address, tcp_port, NODE_EGRESS_TCP);
		v->Permits[1] = NodeEgressPermit(e, v->Address, udp_port, NODE_EGRESS_UDP);

		AcquireSRWLockExclusive(&e->Lock);
		v->Tcp = tcp;
		v->Udp = udp;
		v->TcpPort = tcp_port;
		v->UdpPort = udp_port;
		v->Failed = false;
		ReleaseSRWLockExclusive(&e->Lock);

		NodeLog(e->Node, "Egress: the proxy of VRF %u listens on %s, TCP port %u and UDP port %u", v->VrfId, a, tcp_port, udp_port);
	}
}

// The flows whose time is up at now go, with their sockets: a TCP flow that the host did not take, or that closed and whose
// last segments passed; a UDP flow without a datagram for NODE_EGRESS_UDP_IDLE
static void NodeEgressExpire(NODE_EGRESS *e, UINT64 now) {
	NODE_EGRESS_FLOW *gone = NULL;

	AcquireSRWLockExclusive(&e->Lock);
	for (NODE_EGRESS_FLOW *f = e->First, *after = NULL; f != NULL; f = after) {
		bool expired = false;

		after = f->Next;
		if (f->Protocol == NODE_EGRESS_UDP)
			expired = (now > f->Seen + NODE_EGRESS_UDP_IDLE);
		else if (f->State == NODE_EGRESS_NEW)
			expired = (now > f->Since + NODE_EGRESS_TCP_OPEN);
		else if (f->State == NODE_EGRESS_DONE)
			expired = (now > f->Since + NODE_EGRESS_TCP_LINGER && now > f->Seen + NODE_EGRESS_TCP_LINGER);

		if (expired) {
			NodeEgressUnlink(e, f);
			f->Next = gone;
			gone = f;
		}
	}
	ReleaseSRWLockExclusive(&e->Lock);

	while (gone != NULL) {
		NODE_EGRESS_FLOW *f = gone;

		gone = f->Next;
		NodeEgressFreeFlow(f);
	}
}

// Set Forwarding, WeakHostSend and WeakHostReceive of the IPv4 interface of luid; before, when not NULL, takes what the
// interface had. The error of IP Helper, NO_ERROR when the interface has them already.
static DWORD NodeEgressSetFlags(UINT64 luid, bool forwarding, bool send, bool receive, NODE_EGRESS_UPLINK *before) {
	MIB_IPINTERFACE_ROW row;

	InitializeIpInterfaceEntry(&row);
	row.Family = AF_INET;
	row.InterfaceLuid.Value = luid;

	DWORD err = GetIpInterfaceEntry(&row);
	if (err != NO_ERROR)
		return err;

	if (before != NULL) {
		before->Luid = luid;
		before->Forwarding = (row.ForwardingEnabled != FALSE);
		before->WeakHostSend = (row.WeakHostSend != FALSE);
		before->WeakHostReceive = (row.WeakHostReceive != FALSE);
	}

	if ((row.ForwardingEnabled != FALSE) == forwarding && (row.WeakHostSend != FALSE) == send && (row.WeakHostReceive != FALSE) == receive)
		return NO_ERROR;

	row.ForwardingEnabled = (forwarding ? TRUE : FALSE);
	row.WeakHostSend = (send ? TRUE : FALSE);
	row.WeakHostReceive = (receive ? TRUE : FALSE);
	// SetIpInterfaceEntry refuses the site prefix length that GetIpInterfaceEntry gives (NodeWintunSetForwarding)
	row.SitePrefixLength = 0;

	return SetIpInterfaceEntry(&row);
}

// The interfaces that carry the egress: while the node is the exit of a VRF (exit), each interface but the loopback that
// holds an IPv4 default route gets Forwarding, WeakHostSend and WeakHostReceive on, and the node keeps what it had; with no
// VRF left, each interface that the node changed gets back what it had
static void NodeEgressUplinks(NODE_EGRESS *e, bool exit) {
	MIB_IPFORWARD_TABLE2 *table = NULL;

	if (exit == false) {
		for (UINT i = 0; i < e->NumUplinks; i++) {
			NODE_EGRESS_UPLINK *u = &e->Uplinks[i];
			NET_LUID l;
			NET_IFINDEX index = 0;

			l.Value = u->Luid;
			ConvertInterfaceLuidToIndex(&l, &index);
			DWORD err = NodeEgressSetFlags(u->Luid, u->Forwarding, u->WeakHostSend, u->WeakHostReceive, NULL);
			if (err == NO_ERROR)
				NodeLog(e->Node, "Egress: interface %u carries no egress any more: forwarding %u, weak host send %u and weak host receive %u again", (UINT)index,
				        (UINT)u->Forwarding, (UINT)u->WeakHostSend, (UINT)u->WeakHostReceive);
			else if (err != ERROR_NOT_FOUND)
				NodeLog(e->Node, "Egress: interface %u carries no egress any more, and its forwarding could not be set back (error %u)", (UINT)index, (UINT)err);
		}

		e->NumUplinks = 0;
		InterlockedExchange(&e->UplinksOn, 0);
		return;
	}

	if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR)
		return;

	for (ULONG i = 0; i < table->NumEntries && e->NumUplinks < NODE_EGRESS_MAX_UPLINKS; i++) {
		MIB_IPFORWARD_ROW2 *r = &table->Table[i];
		bool known = false;

		if (r->DestinationPrefix.PrefixLength != 0 || r->InterfaceLuid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;
		for (UINT j = 0; j < e->NumUplinks && known == false; j++)
			known = (e->Uplinks[j].Luid == r->InterfaceLuid.Value);
		if (known)
			continue;

		NODE_EGRESS_UPLINK *u = &e->Uplinks[e->NumUplinks];
		DWORD err = NodeEgressSetFlags(r->InterfaceLuid.Value, true, true, true, u);
		if (err != NO_ERROR)
			continue;

		e->NumUplinks++;
		NodeLog(e->Node, "Egress: interface %u carries the egress: forwarding, weak host send and weak host receive on (before %u, %u and %u)", (UINT)r->InterfaceIndex,
		        (UINT)u->Forwarding, (UINT)u->WeakHostSend, (UINT)u->WeakHostReceive);
	}

	FreeMibTable(table);
	InterlockedExchange(&e->UplinksOn, (LONG)e->NumUplinks);
}

// Add the socket s with the events to the sockets that the thread waits for, with what it is
static void NodeEgressWaitFor(NODE_EGRESS *e, SOCKET s, SHORT events, UINT kind, UINT vrf, NODE_EGRESS_FLOW *f) {
	if (s == INVALID_SOCKET || events == 0)
		return;

	if (e->NumWaits == e->MaxWaits) {
		e->MaxWaits = MAX(e->MaxWaits * 2, 64);
		e->Fds = (e->Fds == NULL ? Malloc(sizeof(WSAPOLLFD) * e->MaxWaits) : ReAlloc(e->Fds, sizeof(WSAPOLLFD) * e->MaxWaits));
		e->Waits = (e->Waits == NULL ? Malloc(sizeof(NODE_EGRESS_WAIT) * e->MaxWaits) : ReAlloc(e->Waits, sizeof(NODE_EGRESS_WAIT) * e->MaxWaits));
	}

	WSAPOLLFD *fd = &e->Fds[e->NumWaits];
	NODE_EGRESS_WAIT *w = &e->Waits[e->NumWaits];

	fd->fd = s;
	fd->events = events;
	fd->revents = 0;
	w->Kind = kind;
	w->Vrf = vrf;
	w->Flow = f;
	e->NumWaits++;
}

// The sockets that the thread waits for now: the listeners and UDP sockets of the VRFs, and the sockets of the flows that are
// open, each for what it can do. A flow that waits too long for its dial, which it waited for, gets its turn too.
static void NodeEgressWaits(NODE_EGRESS *e) {
	e->NumWaits = 0;

	for (UINT i = 0; i < e->NumVrfs; i++) {
		NodeEgressWaitFor(e, e->Vrfs[i].Tcp, POLLRDNORM, NODE_EGRESS_LISTENER, i, NULL);
		NodeEgressWaitFor(e, e->Vrfs[i].Udp, POLLRDNORM, NODE_EGRESS_DATAGRAMS, i, NULL);
	}

	// The list is the data path's too; the sockets of a flow are the thread's alone
	AcquireSRWLockShared(&e->Lock);
	for (NODE_EGRESS_FLOW *f = e->First; f != NULL; f = f->Next) {
		if (f->Outside == INVALID_SOCKET)
			continue;

		if (f->Protocol == NODE_EGRESS_UDP) {
			NodeEgressWaitFor(e, f->Outside, POLLRDNORM, NODE_EGRESS_OUTSIDE, 0, f);
			continue;
		}

		SHORT inside = 0;
		SHORT outside = 0;
		if (f->InsideEnd == false && f->NumToOutside < NODE_EGRESS_BUFFER)
			inside |= POLLRDNORM;
		if (f->NumToInside != 0)
			inside |= POLLWRNORM;
		if (f->Connected == false)
			outside |= POLLWRNORM;
		else {
			if (f->OutsideEnd == false && f->NumToInside < NODE_EGRESS_BUFFER)
				outside |= POLLRDNORM;
			if (f->NumToOutside != 0)
				outside |= POLLWRNORM;
		}

		NodeEgressWaitFor(e, f->Inside, inside, NODE_EGRESS_INSIDE, 0, f);
		NodeEgressWaitFor(e, f->Outside, outside, NODE_EGRESS_OUTSIDE, 0, f);
	}
	ReleaseSRWLockShared(&e->Lock);
}

// What the last wait gave: the events of each socket go to what it is. A TCP flow takes the events of its two sockets in one
// turn, at its first socket in the set; its other socket comes right after the first.
static void NodeEgressServe(NODE_EGRESS *e, UINT64 now) {
	for (UINT i = 0; i < e->NumWaits; i++) {
		NODE_EGRESS_WAIT *w = &e->Waits[i];
		SHORT events = e->Fds[i].revents;

		switch (w->Kind) {
		case NODE_EGRESS_LISTENER:
			if (events != 0)
				NodeEgressAccept(e, &e->Vrfs[w->Vrf], now);
			break;
		case NODE_EGRESS_DATAGRAMS:
			if (events != 0)
				NodeEgressDatagrams(e, &e->Vrfs[w->Vrf], now);
			break;
		default: {
			NODE_EGRESS_FLOW *f = w->Flow;

			if (f->Protocol == NODE_EGRESS_UDP) {
				if (events != 0)
					NodeEgressReplies(e, f, now);
				break;
			}

			// The events of the TCP flow: of Inside here and of Outside in the next entry, or of Outside alone
			SHORT inside = (w->Kind == NODE_EGRESS_INSIDE ? events : 0);
			SHORT outside = (w->Kind == NODE_EGRESS_OUTSIDE ? events : 0);
			if (w->Kind == NODE_EGRESS_INSIDE && i + 1 < e->NumWaits && e->Waits[i + 1].Flow == f) {
				outside = e->Fds[i + 1].revents;
				i++;
			}

			if (f->Inside != INVALID_SOCKET)
				NodeEgressSplice(e, f, inside, outside, now);
			break;
		}
		}
	}
}

// The thread of the proxy: the VRFs of each Generation and their listeners, the connections and datagrams of the peers, the
// flows whose time is up and the interfaces that carry the egress, until the Egress stops
static DWORD WINAPI NodeEgressThread(LPVOID param) {
	NODE_EGRESS *e = (NODE_EGRESS *)param;

	while (ReadAcquire(&e->Halt) == 0) {
		UINT64 now = GetTickCount64();

		if (InterlockedExchange(&e->Changed, 0) != 0) {
			NodeEgressReconcile(e, now);
			e->NextScan = 0;
		}

		NodeEgressBind(e, now);
		NodeEgressExpire(e, now);

		if (now >= e->NextScan) {
			NodeEgressUplinks(e, e->NumVrfs != 0);
			e->NextScan = now + NODE_EGRESS_SCAN;
		}

		NodeEgressWaits(e);

		// Nothing to wait for and nothing to look after: the thread sleeps until a Generation or the stop wakes it
		if (e->NumWaits == 0) {
			bool idle = (e->NumVrfs == 0 && e->NumUplinks == 0 && e->First == NULL);

			WaitForSingleObject(e->Wake, idle ? INFINITE : NODE_EGRESS_POLL);
			continue;
		}

		int ret = WSAPoll(e->Fds, e->NumWaits, NODE_EGRESS_POLL);
		NodeEgressServe(e, GetTickCount64());
		if (ret < 0)
			Sleep(NODE_EGRESS_POLL);
	}

	// The end: every flow and every listener closes, and every interface gets back what it had; the filters go with their
	// session
	AcquireSRWLockExclusive(&e->Lock);
	e->NumWanted = 0;
	ReleaseSRWLockExclusive(&e->Lock);
	NodeEgressReconcile(e, GetTickCount64());
	NodeEgressUplinks(e, false);
	if (e->Engine != NULL) {
		FwpmEngineClose0(e->Engine);
		e->Engine = NULL;
	}

	return 0;
}

//
// The Egress
//

// Start the internet exit of a node with its overlay (NodeOverlayStart): its tier is the one of its Capabilities, and the
// thread of the proxy starts once the node is the exit of a VRF
void NodeEgressStart(NODE *n) {
	CONTROL_CAPS caps;

	if (n == NULL || n->Egress != NULL)
		return;

	NODE_EGRESS *e = ZeroMalloc(sizeof(NODE_EGRESS));
	e->Node = n;
	InitializeSRWLock(&e->Lock);
	e->ByPeer = ZeroMalloc(sizeof(NODE_EGRESS_FLOW *) * NODE_EGRESS_BUCKETS);
	e->ByProxy = ZeroMalloc(sizeof(NODE_EGRESS_FLOW *) * NODE_EGRESS_BUCKETS);
	e->Buf = Malloc(NODE_EGRESS_DATAGRAM_SIZE);
	e->Wake = CreateEventW(NULL, FALSE, FALSE, NULL);
	e->Seed = (UINT)GetTickCount64() ^ (UINT)GetCurrentProcessId();

	Zero(&caps, sizeof(caps));
	NodeCapsProc(NULL, &caps);
	e->Tier = caps.EgressTier;

	n->Egress = e;
}

// Stop the internet exit of a node with its overlay (NodeOverlayStop), once no packet of a peer or of the host reaches it any
// more: the thread closes every flow and every listener and gives the interfaces back what they had, and the echo requests
// in flight end within their wait
void NodeEgressStop(NODE *n) {
	NODE_EGRESS *e = (n != NULL ? n->Egress : NULL);

	if (e == NULL)
		return;

	InterlockedExchange(&e->Halt, 1);
	if (e->Wake != NULL)
		SetEvent(e->Wake);
	if (e->Thread != NULL) {
		WaitForSingleObject(e->Thread, INFINITE);
		CloseHandle(e->Thread);
	}

	while (ReadAcquire(&e->Pings) != 0)
		Sleep(10);

	n->Egress = NULL;

	// A thread that never started leaves no flow and no interface behind: the flows come only with its listeners
	if (e->Wake != NULL)
		CloseHandle(e->Wake);
	Free(e->Fds);
	Free(e->Waits);
	Free(e->Buf);
	Free(e->ByPeer);
	Free(e->ByProxy);
	Free(e);
}

// The VRFs of a Generation that the overlay applied, once the adapters of its VRFs took it: the node is the exit of each
// VRF of st->EgressVrfIds in which it has an IPv4 address, where the proxy listens. The thread of the proxy takes them; it
// starts with the first VRF.
void NodeEgressApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_EGRESS *e = (n != NULL ? n->Egress : NULL);
	UINT num = 0;

	if (e == NULL || st == NULL)
		return;

	AcquireSRWLockExclusive(&e->Lock);
	{
		e->NumWanted = 0;
		for (UINT i = 0; i < st->NumEgress && i < CONTROL_MAX_VRFS; i++) {
			if (NodeEgressAddress(st, st->EgressVrfIds[i], e->WantedAddresses[e->NumWanted])) {
				e->WantedIds[e->NumWanted] = st->EgressVrfIds[i];
				e->NumWanted++;
			}
		}
		num = e->NumWanted;
	}
	ReleaseSRWLockExclusive(&e->Lock);

	if (st->NumEgress != 0 || e->Thread != NULL)
		NodeLog(n, "Egress: generation %I64u: the internet exit of %u VRFs, %u of them with an address of the node, tier %u", st->Generation, st->NumEgress, num, e->Tier);

	if (e->Thread == NULL && num != 0) {
		DWORD id = 0;

		e->Thread = CreateThread(NULL, 0, NodeEgressThread, e, 0, &id);
		if (e->Thread == NULL)
			NodeLog(n, "Egress: the thread of the proxy could not start (error %u)", (UINT)GetLastError());
	}

	InterlockedExchange(&e->Changed, 1);
	SetEvent(e->Wake);
}

// The state of the internet exit of a node
void NodeEgressGetStatus(NODE *n, NODE_EGRESS_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_EGRESS_STATUS));
	NODE_EGRESS *e = (n != NULL ? n->Egress : NULL);
	if (e == NULL)
		return;

	st->Tier = e->Tier;

	AcquireSRWLockShared(&e->Lock);
	{
		st->NumVrfs = e->NumVrfs;
		for (UINT i = 0; i < e->NumVrfs; i++)
			if (e->Vrfs[i].TcpPort != 0 && e->Vrfs[i].UdpPort != 0)
				st->NumReady++;
		st->NumFlows = e->NumFlows;
	}
	ReleaseSRWLockShared(&e->Lock);

	st->NumUplinks = (UINT)ReadAcquire(&e->UplinksOn);
	st->Tcp = (UINT64)ReadAcquire64(&e->Tcp);
	st->Udp = (UINT64)ReadAcquire64(&e->Udp);
	st->Echoes = (UINT64)ReadAcquire64(&e->Echoes);
	st->EchoReplies = (UINT64)ReadAcquire64(&e->EchoReplies);
	st->Refused = (UINT64)ReadAcquire64(&e->Refused);
	st->Dropped = (UINT64)ReadAcquire64(&e->Dropped);
}
