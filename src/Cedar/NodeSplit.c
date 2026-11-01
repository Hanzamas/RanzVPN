// NodeSplit.c
// TCP splitting of the L3 Networks in the overlay of a node (CORE-P2-3, #94; the ADR-0022 amendment of 2026-11-01 on the
// TCP-over-TCP meltdown). It is off by default and set per L3 Network: the Network objects of a Generation that carry
// tcp_split (CONTROL_STATE.Splits) name the Networks that split TCP. The tunnel then carries no inner TCP segment of a split
// connection, only its byte stream, so an inner TCP flow over the TLS-443 fallback no longer retransmits into a stalled outer
// TCP. An ACK that an application of the host gets means that its node has the data; the far end sees the connection come
// from the node at the other end of the tunnel.
//
// The node whose host opens a connection, the opener: the SYN of a TCP connection that its host opens from its address in a
// Network that splits TCP, to a peer that the forwarding table of the VRF routes the destination to and that has its Noise
// session, opens a split flow in place of going there as a packet (NodeSplitTake, from the forwarding of the overlay once the
// policy and the session profiles allowed the packet). The node holds the SYN and sends the peer an OPEN record with the VRF,
// the two ends and the bytes that it takes at first. Once the peer answers that it reached the destination, the node puts the
// SYN back into the adapter of the VRF with the destination as its source, from the port that the flow keeps for it (the port
// of the host's end, unless another flow to that destination holds it), and its listener on the node's address in the Network
// as its destination, so the Windows TCP stack of the host terminates the connection on that listener; it is no TCP stack of
// its own, the same rewrite as the proxy of the internet exit (NodeEgress.c; ADR-0014, ADR-0025). Every later packet of the
// host on the flow goes the same way, and what the listener answers goes back into the adapter from the destination to the
// host's end (NodeSplitFromHost), so the application sees the destination that it dialled. The thread of the module carries
// the bytes between the connection that the listener took and the peer, as records of the Noise session of the peer: data,
// a half-close and a reset. A refused destination resets the host's connect; a destination that does not answer leaves it to
// time out, as without splitting.
//
// The peer that opens the connection to the real destination: an OPEN record of a peer is taken only when the forwarding
// table of its VRF routes the source to that peer and the destination to the host, the source is an address of the peer in a
// Network that splits TCP, a destination that the default route alone holds (an internet exit) is no address that the host
// routes into a VRF of the node and none that the internet exit refuses, and the session profiles and the policy of the VRF
// allow a SYN between the two ends as the peer would have sent it. A 1:1 NAT rule translates the destination as for a packet
// of the peer. The thread dials it with an ordinary socket, answers the peer with what the dial gave, and carries the bytes.
//
// Each direction of a flow has a window: a sender sends a peer at most the bytes that it granted (NODE_SPLIT_WINDOW at first,
// more with each WINDOW record once it wrote them to its socket), so a stalled reader holds at most a window of a flow and
// never the session. A record over the window resets the flow. The flows of a peer end with its Noise session: each of its
// connections is reset. The split flows are IPv4 TCP; IPv6 and every other protocol, and the frames of an L2 Network, take
// the packet path as before.

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeEgress.h"
#include "NodeGateway.h"
#include "NodeInternal.h"
#include "NodeProfile.h"
#include "NodeSplit.h"

// The GUIDs of the layers and of the conditions of the filters of the listeners are defined here, where the filters are made
#include <initguid.h>
#include <fwpmu.h>

#include <stdlib.h>

#define NODE_SPLIT_BATCH    64  // Connections that one listener gives the thread in one pass at most
#define NODE_SPLIT_TURNS    16  // Records of one flow that the thread sends in one pass at most
#define NODE_SPLIT_MAX_SYN  128 // Bytes of the SYN of the host that a flow holds at most: its headers and their options
#define NODE_SPLIT_NAT_ROOM 128 // Bytes of the SYN that the policy judges, as a 1:1 NAT rule may grow it

// The states of a flow
#define NODE_SPLIT_WAIT    0 // The opener: its OPEN goes, or went, and it waits for the answer; it holds the SYN of the host
#define NODE_SPLIT_TAKE    1 // The opener: the answer came and the SYN went to the host, whose listener has not taken it yet
#define NODE_SPLIT_DIALING 2 // The peer's end: its dial to the real destination runs
#define NODE_SPLIT_RUN     3 // The flow carries its stream
#define NODE_SPLIT_FAILED  4 // The opener: its peer did not reach the destination; the SYNs of the host on it are dropped
#define NODE_SPLIT_DONE    5 // It ended: it stays NODE_SPLIT_LINGER for the last segments of the host

// A key of an address of a peer in a Network that splits TCP
typedef struct NODE_SPLIT_KEY {
	UINT VrfId;       // The VRF
	UCHAR Address[4]; // The address
} NODE_SPLIT_KEY;

// A prefix that the host routes into a VRF of the node
typedef struct NODE_SPLIT_PREFIX {
	UCHAR Address[4]; // The prefix
	UINT Length;      // ... and its length, 1 to 32
} NODE_SPLIT_PREFIX;

// An address of the node in a Network that splits TCP, and the listener on it that terminates the connections of the host
typedef struct NODE_SPLIT_ADDRESS {
	UINT VrfId;       // The VRF
	UCHAR Address[4]; // The address
	SOCKET Listener;  // The listener, INVALID_SOCKET until it is bound
	UINT Port;        // ... its port, 0 until then
	UINT64 NextBind;  // When the thread tries to bind it next
	bool Failed;      // The last attempt failed, and the node log said so
	UINT64 Permit;    // The filter that lets the connections of the host reach it, 0 for none
} NODE_SPLIT_ADDRESS;

// A split flow
typedef struct NODE_SPLIT_FLOW {
	struct NODE_SPLIT_FLOW *Prev; // The flows of the module, a list ...
	struct NODE_SPLIT_FLOW *Next;
	struct NODE_SPLIT_FLOW *NextById;    // ... the chain of its bucket by its peer and its id ...
	struct NODE_SPLIT_FLOW *NextByHost;  // ... the opener: by the two ends of its host's connection ...
	struct NODE_SPLIT_FLOW *NextByProxy; // ... and by the destination as the listener sees it
	void *Peer;                          // The peer of the overlay at the other end, a next hop of the tables; NULL once it went
	const void *HashPeer;                // ... and the peer that it had at first, which its bucket by id is of
	bool Opener;                         // The node opened it for its host; else it opened it to the real destination for the peer
	UINT Id;                             // The id that the opener gave it
	UINT VrfId;                          // The VRF
	UCHAR Src[4];                        // The end of the opener's host ...
	UINT SrcPort;
	UCHAR Dst[4]; // ... and the real destination
	UINT DstPort;
	UCHAR Local[4]; // The opener: the address of its listener ...
	UINT LocalPort; // ... its port ...
	UINT ProxyPort; // ... and the port of the destination as the listener sees it
	UINT State;     // NODE_SPLIT_*
	UINT64 Since;   // When it came into its state
	UCHAR *Syn;     // The opener: the SYN of its host, until the answer
	UINT SynSize;
	bool SendOpen;  // The opener: its OPEN waits for the thread
	bool PeerReset; // The peer reset it, or went
	bool PeerFin;   // The peer sent all that it sends
	bool Abort;     // The node ends it with a reset to the peer
	SOCKET Sock;    // The connection: the one that the listener took, or the dial to the real destination
	SHORT Events;   // The events of Sock in the last wait of the thread
	UINT64 Credit;  // Bytes that the peer takes more
	UCHAR *In;      // Bytes of the peer that wait for Sock, NODE_SPLIT_WINDOW at most ...
	UINT NumIn;     // ... their number
	UINT Granted;   // Bytes written to Sock that the peer was not granted again yet
	bool SockEnd;   // Sock sent all that it sends
	bool FinSent;   // ... and the peer heard it
	bool Shut;      // The sending side of Sock is shut, once the peer sent all and Sock took it
} NODE_SPLIT_FLOW;

// A record without a flow that waits for the thread: an answer that refuses an OPEN, or a reset of a flow that the node does
// not know
typedef struct NODE_SPLIT_PENDING {
	struct NODE_SPLIT_PENDING *Next;
	void *Peer;
	UINT Size;
	UCHAR Record[NODE_SPLIT_OPEN_SIZE];
} NODE_SPLIT_PENDING;

// TCP splitting of a node while its overlay runs
struct NODE_SPLIT {
	NODE *Node;                                   // The node
	NODE_ADAPTER_PROC *Adapter;                   // Puts packets into the adapter of a VRF for the host ...
	void *AdapterParam;                           // ... with its parameter
	SRWLOCK Lock;                                 // What the data path, the thread of the overlay and the thread share: everything below
	CONDITION_VARIABLE Sent;                      // A send of the thread returned
	void *Sending;                                // The peer that the thread sends to now, NULL for none
	volatile LONG Active;                         // The Generation gives the node an address in a Network that splits TCP
	volatile LONG Live;                           // The flows, NumFlows, which the data path reads without the lock
	UINT NumNetworks;                             // The Networks that split TCP in the Generation applied last
	UINT NumWanted;                               // The addresses of the node in them, which the thread listens on
	NODE_SPLIT_KEY Wanted[CONTROL_MAX_ADDRESSES]; // ...
	UINT NumPeerAddresses;                        // The addresses of the peers in them, sorted
	NODE_SPLIT_KEY *PeerAddresses;                // ...
	UINT NumInside;                               // The prefixes that the host routes into a VRF of the node
	NODE_SPLIT_PREFIX *Inside;                    // ...
	volatile LONG Changed;                        // A Generation changed the addresses: the thread takes them
	UINT NumAddresses;                            // The listeners
	NODE_SPLIT_ADDRESS Addresses[CONTROL_MAX_ADDRESSES];
	NODE_SPLIT_FLOW *First;      // The flows, the newest first
	NODE_SPLIT_FLOW **ById;      // ... by their peer and their id, NODE_SPLIT_BUCKETS chains
	NODE_SPLIT_FLOW **ByHost;    // ... the opener's by the two ends of the host's connection
	NODE_SPLIT_FLOW **ByProxy;   // ... and by the destination as the listener sees it
	UINT NumFlows;               // ... their number
	NODE_SPLIT_PENDING *Pending; // The records without a flow, the oldest first ...
	UINT NumPending;             // ... their number
	UINT NextId;                 // The id of the next flow that the node opens
	UINT Seed;                   // Picks the port of a new flow
	NODE_SPLIT_DIAL_PROC *Dial;  // Where the node dials the real destination of a flow, NULL for there (NodeSplitSetDial)
	void *DialParam;
	UINT DialTimeout;   // ms of a dial
	HANDLE Thread;      // The thread, NULL until a Generation has a Network that splits TCP
	volatile LONG Halt; // Ends the thread
	SOCKET Wake;        // The thread's UDP socket on the loopback, which wakes it ...
	SOCKET WakeOut;     // ... from this one
	UCHAR *Record;      // The thread's: the record that it sends
	UINT NumWaits;      // The thread's: the sockets that it waits for ...
	UINT MaxWaits;
	WSAPOLLFD *Fds;
	NODE_SPLIT_FLOW **WaitFlows; // ... the flow of each, NULL for a listener or the wake socket
	UINT *WaitAddresses;         // ... the listener of each, by index
	HANDLE Engine;               // The thread's: the dynamic session of the filters of the listeners
	GUID SubLayer;               // ... and its sublayer
	bool EngineFailed;           // ... could not be had, and the node log said so
	volatile LONG64 Opened;      // The counters of NODE_SPLIT_STATUS
	volatile LONG64 Connected;
	volatile LONG64 Refused;
	volatile LONG64 Failed;
	volatile LONG64 Served;
	volatile LONG64 Denied;
	volatile LONG64 BytesOut;
	volatile LONG64 BytesIn;
	volatile LONG64 Fins;
	volatile LONG64 Resets;
	volatile LONG64 Dropped;
};

//
// Records and packets
//

// Write the kind, the flags and the id of a record into buf
static void NodeSplitHeader(UCHAR *buf, UINT kind, bool from_opener, UINT id) {
	buf[0] = (UCHAR)kind;
	buf[1] = (UCHAR)(from_opener ? NODE_SPLIT_FROM_OPENER : 0);
	WRITE_UINT(buf + 2, id);
}

// Read the control record of size bytes at data as a record of a split flow into r: false for any other record, one of another
// kind, size or flags, an OPEN without both ports, an ANSWER of an unknown status, or DATA of no byte or more than
// NODE_SPLIT_CHUNK. The data of a DATA record stays in data.
bool NodeSplitParseRecord(const UCHAR *data, UINT size, NODE_SPLIT_RECORD *r) {
	if (data == NULL || r == NULL || size < NODE_SPLIT_HEADER || (data[1] & ~NODE_SPLIT_FROM_OPENER) != 0)
		return false;

	Zero(r, sizeof(NODE_SPLIT_RECORD));
	r->Kind = data[0];
	r->FromOpener = ((data[1] & NODE_SPLIT_FROM_OPENER) != 0);
	r->Id = READ_UINT(data + 2);

	const UCHAR *b = data + NODE_SPLIT_HEADER;
	UINT rest = size - NODE_SPLIT_HEADER;

	switch (r->Kind) {
	case NODE_SPLIT_RECORD_OPEN:
		if (size != NODE_SPLIT_OPEN_SIZE || r->FromOpener == false)
			return false;
		r->VrfId = READ_UINT(b);
		Copy(r->Src, b + 4, 4);
		r->SrcPort = READ_USHORT(b + 8);
		Copy(r->Dst, b + 10, 4);
		r->DstPort = READ_USHORT(b + 14);
		r->Window = READ_UINT(b + 16);
		return (r->SrcPort != 0 && r->DstPort != 0);
	case NODE_SPLIT_RECORD_ANSWER:
		if (size != NODE_SPLIT_ANSWER_SIZE || r->FromOpener)
			return false;
		r->Status = b[0];
		r->Window = READ_UINT(b + 1);
		return (r->Status <= NODE_SPLIT_ANSWER_MAX);
	case NODE_SPLIT_RECORD_DATA:
		if (rest == 0 || rest > NODE_SPLIT_CHUNK)
			return false;
		r->Data = b;
		r->Size = rest;
		return true;
	case NODE_SPLIT_RECORD_WINDOW:
		if (size != NODE_SPLIT_WINDOW_SIZE)
			return false;
		r->Window = READ_UINT(b);
		return true;
	case NODE_SPLIT_RECORD_FIN:
	case NODE_SPLIT_RECORD_RESET:
		return (rest == 0);
	default:
		return false;
	}
}

// Write the record r into buf of size bytes: its size, 0 when buf has no room for it or r is no record that
// NodeSplitParseRecord reads
UINT NodeSplitWriteRecord(UCHAR *buf, UINT size, const NODE_SPLIT_RECORD *r) {
	UINT need = NODE_SPLIT_HEADER;

	if (buf == NULL || r == NULL)
		return 0;

	switch (r->Kind) {
	case NODE_SPLIT_RECORD_OPEN:
		need = NODE_SPLIT_OPEN_SIZE;
		break;
	case NODE_SPLIT_RECORD_ANSWER:
		need = NODE_SPLIT_ANSWER_SIZE;
		break;
	case NODE_SPLIT_RECORD_DATA:
		if (r->Data == NULL || r->Size == 0 || r->Size > NODE_SPLIT_CHUNK)
			return 0;
		need = NODE_SPLIT_HEADER + r->Size;
		break;
	case NODE_SPLIT_RECORD_WINDOW:
		need = NODE_SPLIT_WINDOW_SIZE;
		break;
	case NODE_SPLIT_RECORD_FIN:
	case NODE_SPLIT_RECORD_RESET:
		break;
	default:
		return 0;
	}
	if (need > size)
		return 0;

	NodeSplitHeader(buf, r->Kind, r->FromOpener, r->Id);
	UCHAR *b = buf + NODE_SPLIT_HEADER;

	switch (r->Kind) {
	case NODE_SPLIT_RECORD_OPEN:
		WRITE_UINT(b, r->VrfId);
		Copy(b + 4, r->Src, 4);
		WRITE_USHORT(b + 8, r->SrcPort);
		Copy(b + 10, r->Dst, 4);
		WRITE_USHORT(b + 14, r->DstPort);
		WRITE_UINT(b + 16, r->Window);
		break;
	case NODE_SPLIT_RECORD_ANSWER:
		b[0] = (UCHAR)r->Status;
		WRITE_UINT(b + 1, r->Window);
		break;
	case NODE_SPLIT_RECORD_DATA:
		Copy(b, r->Data, r->Size);
		break;
	case NODE_SPLIT_RECORD_WINDOW:
		WRITE_UINT(b, r->Window);
		break;
	default:
		break;
	}

	return need;
}

// The sum of size bytes at data as big-endian 16-bit words, on top of sum; an odd last byte is the high half of a word
static UINT NodeSplitSum(UINT sum, const UCHAR *data, UINT size) {
	UINT i = 0;

	for (; i + 1 < size; i += 2)
		sum += READ_USHORT(data + i);
	if (i < size)
		sum += (UINT)data[i] << 8;

	return sum;
}

// The checksum of a sum, its carries added back in (RFC 1071)
static USHORT NodeSplitChecksum(UINT sum) {
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);

	return (USHORT)~sum;
}

// Write into buf, of 40 bytes at least, an IPv4 packet of a TCP segment without options from src:src_port to dst:dst_port
// with the flags, the sequence and the acknowledgement numbers, and its checksums: its size
static UINT NodeSplitSegment(UCHAR *buf, const UCHAR *src, UINT src_port, const UCHAR *dst, UINT dst_port, UINT flags, UINT seq, UINT ack) {
	Zero(buf, 40);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, 40);
	buf[8] = 64;
	buf[9] = NODE_EGRESS_TCP;
	Copy(buf + 12, src, 4);
	Copy(buf + 16, dst, 4);
	WRITE_USHORT(buf + 10, NodeSplitChecksum(NodeSplitSum(0, buf, 20)));

	UCHAR *tcp = buf + 20;
	WRITE_USHORT(tcp, src_port);
	WRITE_USHORT(tcp + 2, dst_port);
	WRITE_UINT(tcp + 4, seq);
	WRITE_UINT(tcp + 8, ack);
	tcp[12] = 5 << 4;
	tcp[13] = (UCHAR)flags;
	WRITE_USHORT(tcp + 14, 65535);

	// The pseudo-header: the two addresses, the protocol and the length of the segment
	UINT sum = NodeSplitSum(0, buf + 12, 8) + NODE_EGRESS_TCP + 20;
	WRITE_USHORT(tcp + 16, NodeSplitChecksum(NodeSplitSum(sum, tcp, 20)));

	return 40;
}

// Write into buf, of size bytes, the reset that refuses the TCP SYN of syn_size bytes at syn, from its destination to its
// source, which acknowledges the SYN, so the connect of its sender fails as a refused one: its size, 40, or 0 when buf has no
// room or syn is no IPv4 TCP segment
UINT NodeSplitReset(UCHAR *buf, UINT size, const UCHAR *syn, UINT syn_size) {
	NODE_EGRESS_PACKET p;

	if (buf == NULL || size < 40 || NodeEgressParse(syn, syn_size, &p) == false || p.Protocol != NODE_EGRESS_TCP)
		return 0;

	UINT seq = READ_UINT(syn + p.HeaderSize + 4);

	return NodeSplitSegment(buf, p.Dst, p.DstPort, p.Src, p.SrcPort, NODE_EGRESS_RST | NODE_EGRESS_ACK, 0, seq + 1);
}

//
// The flows
//

// FNV-1a of size bytes on top of h
static UINT NodeSplitHash(UINT h, const void *data, UINT size) {
	const UCHAR *b = (const UCHAR *)data;

	for (UINT i = 0; i < size; i++)
		h = (h ^ b[i]) * 16777619U;

	return h;
}

static UINT NodeSplitBucketId(const void *peer, bool opener, UINT id) {
	UINT h = NodeSplitHash(2166136261U, &peer, sizeof(peer));

	h = NodeSplitHash(h, &opener, sizeof(opener));
	h = NodeSplitHash(h, &id, sizeof(id));

	return h & (NODE_SPLIT_BUCKETS - 1);
}

static UINT NodeSplitBucketHost(UINT vrf_id, const UCHAR *src, UINT src_port, const UCHAR *dst, UINT dst_port) {
	UINT h = NodeSplitHash(2166136261U, &vrf_id, sizeof(vrf_id));

	h = NodeSplitHash(h, src, 4);
	h = NodeSplitHash(h, &src_port, sizeof(src_port));
	h = NodeSplitHash(h, dst, 4);
	h = NodeSplitHash(h, &dst_port, sizeof(dst_port));

	return h & (NODE_SPLIT_BUCKETS - 1);
}

static UINT NodeSplitBucketProxy(UINT vrf_id, const UCHAR *dst, UINT port) {
	UINT h = NodeSplitHash(2166136261U, &vrf_id, sizeof(vrf_id));

	h = NodeSplitHash(h, dst, 4);
	h = NodeSplitHash(h, &port, sizeof(port));

	return h & (NODE_SPLIT_BUCKETS - 1);
}

// The flow of the peer and the id that its opener gave it, the node's own when opener, NULL for none. The caller holds the
// lock.
static NODE_SPLIT_FLOW *NodeSplitFindId(NODE_SPLIT *s, const void *peer, bool opener, UINT id) {
	for (NODE_SPLIT_FLOW *f = s->ById[NodeSplitBucketId(peer, opener, id)]; f != NULL; f = f->NextById)
		if (f->Peer == peer && f->Opener == opener && f->Id == id)
			return f;

	return NULL;
}

// The newest flow of the host's connection between the two ends in the VRF, NULL for none. The caller holds the lock.
static NODE_SPLIT_FLOW *NodeSplitFindHost(NODE_SPLIT *s, UINT vrf_id, const UCHAR *src, UINT src_port, const UCHAR *dst, UINT dst_port) {
	for (NODE_SPLIT_FLOW *f = s->ByHost[NodeSplitBucketHost(vrf_id, src, src_port, dst, dst_port)]; f != NULL; f = f->NextByHost)
		if (f->VrfId == vrf_id && f->SrcPort == src_port && f->DstPort == dst_port && Cmp(f->Src, src, 4) == 0 && Cmp(f->Dst, dst, 4) == 0)
			return f;

	return NULL;
}

// The newest flow whose destination the listener of the VRF sees as dst:port, NULL for none. The caller holds the lock.
static NODE_SPLIT_FLOW *NodeSplitFindProxy(NODE_SPLIT *s, UINT vrf_id, const UCHAR *dst, UINT port) {
	for (NODE_SPLIT_FLOW *f = s->ByProxy[NodeSplitBucketProxy(vrf_id, dst, port)]; f != NULL; f = f->NextByProxy)
		if (f->VrfId == vrf_id && f->ProxyPort == port && Cmp(f->Dst, dst, 4) == 0)
			return f;

	return NULL;
}

// A new flow with what f holds: into the list and the hashes, the newest first. The caller holds the lock.
static NODE_SPLIT_FLOW *NodeSplitLink(NODE_SPLIT *s, const NODE_SPLIT_FLOW *f) {
	NODE_SPLIT_FLOW *n = ZeroMalloc(sizeof(NODE_SPLIT_FLOW));

	Copy(n, f, sizeof(NODE_SPLIT_FLOW));
	n->HashPeer = n->Peer;
	n->Sock = INVALID_SOCKET;
	n->Prev = NULL;
	n->Next = s->First;
	if (s->First != NULL)
		s->First->Prev = n;
	s->First = n;

	UINT b = NodeSplitBucketId(n->HashPeer, n->Opener, n->Id);
	n->NextById = s->ById[b];
	s->ById[b] = n;

	if (n->Opener) {
		b = NodeSplitBucketHost(n->VrfId, n->Src, n->SrcPort, n->Dst, n->DstPort);
		n->NextByHost = s->ByHost[b];
		s->ByHost[b] = n;
		b = NodeSplitBucketProxy(n->VrfId, n->Dst, n->ProxyPort);
		n->NextByProxy = s->ByProxy[b];
		s->ByProxy[b] = n;
	}

	s->NumFlows++;
	InterlockedIncrement(&s->Live);
	return n;
}

// Take f out of the chains of its buckets. The caller holds the lock.
static void NodeSplitUnchain(NODE_SPLIT *s, NODE_SPLIT_FLOW *f) {
	NODE_SPLIT_FLOW **link = &s->ById[NodeSplitBucketId(f->HashPeer, f->Opener, f->Id)];

	while (*link != NULL && *link != f)
		link = &(*link)->NextById;
	if (*link == f)
		*link = f->NextById;

	if (f->Opener == false)
		return;

	link = &s->ByHost[NodeSplitBucketHost(f->VrfId, f->Src, f->SrcPort, f->Dst, f->DstPort)];
	while (*link != NULL && *link != f)
		link = &(*link)->NextByHost;
	if (*link == f)
		*link = f->NextByHost;

	link = &s->ByProxy[NodeSplitBucketProxy(f->VrfId, f->Dst, f->ProxyPort)];
	while (*link != NULL && *link != f)
		link = &(*link)->NextByProxy;
	if (*link == f)
		*link = f->NextByProxy;
}

// Close a socket at once, with a reset of a TCP connection that is open
static void NodeSplitAbort(SOCKET k) {
	struct linger l;

	if (k == INVALID_SOCKET)
		return;

	l.l_onoff = 1;
	l.l_linger = 0;
	setsockopt(k, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
	closesocket(k);
}

// Take the flow f out of the list and the hashes and free it, with its socket, which closes at once. The caller holds the
// lock, and is the thread: no other frees a flow.
static void NodeSplitFree(NODE_SPLIT *s, NODE_SPLIT_FLOW *f) {
	NodeSplitUnchain(s, f);

	if (f->Prev != NULL)
		f->Prev->Next = f->Next;
	else
		s->First = f->Next;
	if (f->Next != NULL)
		f->Next->Prev = f->Prev;
	s->NumFlows--;
	InterlockedDecrement(&s->Live);

	NodeSplitAbort(f->Sock);
	Free(f->Syn);
	Free(f->In);
	Free(f);
}

// The flow f ends at now: its socket closes, at once with a reset of its connection when abort, and it stays
// NODE_SPLIT_LINGER for the last segments of the host. The caller holds the lock.
static void NodeSplitEnd(NODE_SPLIT_FLOW *f, bool abort, UINT64 now) {
	if (abort)
		NodeSplitAbort(f->Sock);
	else if (f->Sock != INVALID_SOCKET)
		closesocket(f->Sock);

	f->Sock = INVALID_SOCKET;
	Free(f->In);
	f->In = NULL;
	f->NumIn = 0;
	Free(f->Syn);
	f->Syn = NULL;
	f->SynSize = 0;
	f->State = NODE_SPLIT_DONE;
	f->Since = now;
}

// The flows of the peer now. The caller holds the lock.
static UINT NodeSplitPeerFlows(NODE_SPLIT *s, const void *peer) {
	UINT num = 0;

	for (NODE_SPLIT_FLOW *f = s->First; f != NULL; f = f->Next)
		if (f->Peer == peer && f->State != NODE_SPLIT_DONE)
			num++;

	return num;
}

// The listener on the node's address in the VRF, NULL for none. The caller holds the lock.
static NODE_SPLIT_ADDRESS *NodeSplitAddressOf(NODE_SPLIT *s, UINT vrf_id, const UCHAR *address) {
	for (UINT i = 0; i < s->NumAddresses; i++)
		if (s->Addresses[i].VrfId == vrf_id && Cmp(s->Addresses[i].Address, address, 4) == 0)
			return &s->Addresses[i];

	return NULL;
}

// Queue a record without a flow for the peer: dropped when NODE_SPLIT_MAX_PENDING wait. The caller holds the lock.
static void NodeSplitPend(NODE_SPLIT *s, void *peer, const NODE_SPLIT_RECORD *r) {
	if (s->NumPending >= NODE_SPLIT_MAX_PENDING) {
		InterlockedIncrement64(&s->Dropped);
		return;
	}

	NODE_SPLIT_PENDING *p = ZeroMalloc(sizeof(NODE_SPLIT_PENDING));
	p->Peer = peer;
	p->Size = NodeSplitWriteRecord(p->Record, sizeof(p->Record), r);

	NODE_SPLIT_PENDING **last = &s->Pending;
	while (*last != NULL)
		last = &(*last)->Next;
	*last = p;
	s->NumPending++;
}

// Wake the thread out of its wait
static void NodeSplitWake(NODE_SPLIT *s) {
	if (s->WakeOut != INVALID_SOCKET)
		send(s->WakeOut, "w", 1, 0);
}

//
// The data path
//

// Put a copy of the TCP segment that p read at packet into the adapter of the VRF for the host, from src:src_port to
// dst:dst_port
static void NodeSplitInject(NODE_SPLIT *s, UINT vrf_id, const UCHAR *packet, const NODE_EGRESS_PACKET *p, const UCHAR *src, UINT src_port, const UCHAR *dst,
                            UINT dst_port) {
	UCHAR stack[NODE_SPLIT_STACK];

	if (s->Adapter == NULL)
		return;

	UCHAR *buf = (p->Total <= sizeof(stack) ? stack : Malloc(p->Total));
	Copy(buf, packet, p->Total);
	NodeEgressRewrite(buf, p, src, src_port, dst, dst_port);
	s->Adapter(s->Node, s->AdapterParam, vrf_id, buf, p->Total);
	if (buf != stack)
		Free(buf);
}

// A packet of the host in the VRF vrf_id, before the overlay forwards it: a segment of a split flow goes back into the adapter
// of the VRF for the host, and true; false for any other packet, which the overlay forwards. A segment of a listener goes from
// the destination of its flow to the host's end of the connection, and one of the host's end to the listener from the
// destination as the listener sees it; a segment of a listener that is of no flow is dropped. A flow keeps its way back while
// it lives, also once its Network no longer splits TCP. The caller is an online reader of the node's table snapshot: the I/O
// thread of the adapter of the VRF.
bool NodeSplitFromHost(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	NODE_EGRESS_PACKET p;
	UCHAR src[4], dst[4];
	UINT src_port = 0, dst_port = 0;
	bool take = false;
	bool back = false;

	if (s == NULL || (ReadAcquire(&s->Active) == 0 && ReadAcquire(&s->Live) == 0) || packet == NULL || size < 40 || (packet[0] >> 4) != 4 ||
	    packet[9] != NODE_EGRESS_TCP)
		return false;
	if (NodeEgressParse(packet, size, &p) == false || p.Protocol != NODE_EGRESS_TCP)
		return false;

	Zero(src, sizeof(src));
	Zero(dst, sizeof(dst));

	AcquireSRWLockShared(&s->Lock);
	{
		NODE_SPLIT_FLOW *f = NodeSplitFindProxy(s, vrf_id, p.Dst, p.DstPort);
		NODE_SPLIT_ADDRESS *a = NodeSplitAddressOf(s, vrf_id, p.Src);

		if (f != NULL && f->LocalPort == p.SrcPort && Cmp(f->Local, p.Src, 4) == 0) {
			// A segment of the listener of the flow: to the host's end, from the destination that it dialled
			Copy(src, f->Dst, 4);
			src_port = f->DstPort;
			Copy(dst, f->Src, 4);
			dst_port = f->SrcPort;
			take = true;
			back = true;
		} else if (a != NULL && a->Port != 0 && p.SrcPort == a->Port) {
			// A segment of a listener that is of no flow
			take = true;
		} else {
			// A segment of the host's end of a flow: to the listener, from the destination as the listener sees it. Its SYNs wait
			// while the peer has not answered, or failed; a SYN of a flow that ended opens a new one.
			NODE_SPLIT_FLOW *h = NodeSplitFindHost(s, vrf_id, p.Src, p.SrcPort, p.Dst, p.DstPort);
			bool syn = ((p.TcpFlags & (NODE_EGRESS_SYN | NODE_EGRESS_ACK | NODE_EGRESS_RST)) == NODE_EGRESS_SYN);

			if (h != NULL && (h->State == NODE_SPLIT_DONE && syn) == false) {
				take = true;
				if (h->State != NODE_SPLIT_WAIT && h->State != NODE_SPLIT_FAILED && h->State != NODE_SPLIT_DIALING) {
					Copy(src, h->Dst, 4);
					src_port = h->ProxyPort;
					Copy(dst, h->Local, 4);
					dst_port = h->LocalPort;
					back = true;
				}
			}
		}
	}
	ReleaseSRWLockShared(&s->Lock);

	if (back)
		NodeSplitInject(s, vrf_id, packet, &p, src, src_port, dst, dst_port);
	else if (take && (p.TcpFlags & NODE_EGRESS_SYN) == 0)
		InterlockedIncrement64(&s->Dropped);

	return take;
}

// The SYN of a TCP connection of the host in the VRF vrf_id that the overlay forwards to the peer peer, a next hop of the
// tables v that has its Noise session: packet as the host sent it, and overlay, size bytes, as the overlay sees it once the
// 1:1 NAT rules translated it. True when it opened a split flow in place of going to the peer: the host's end is an address of
// the node in a Network that splits TCP whose listener is bound, no 1:1 NAT rule translated the packet, and the flows of the
// node and of the peer are below their limits. The node holds the SYN until the peer answers. The caller is an online reader
// of the tables v, which counts itself on the peer as a sender.
bool NodeSplitTake(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, void *peer, const UCHAR *packet, const UCHAR *overlay, UINT size) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	NODE_EGRESS_PACKET p;
	NODE_SPLIT_FLOW f;
	bool taken = false;

	UNREFERENCED_PARAMETER(v);

	if (s == NULL || ReadAcquire(&s->Active) == 0 || peer == NULL || packet == NULL || overlay == NULL || size < 40 || (packet[0] >> 4) != 4 || (overlay[0] >> 4) != 4)
		return false;
	if (NodeEgressParse(overlay, size, &p) == false || p.Protocol != NODE_EGRESS_TCP ||
	    (p.TcpFlags & (NODE_EGRESS_SYN | NODE_EGRESS_ACK | NODE_EGRESS_RST | NODE_EGRESS_FIN)) != NODE_EGRESS_SYN || p.Total > NODE_SPLIT_MAX_SYN)
		return false;

	// No 1:1 NAT rule translated it: the host sent the two ends that the overlay sees. A rule of IPv4 keeps the size and the
	// headers of the packet, so the host's packet holds the bytes that are compared.
	if (READ_USHORT(packet + 2) != p.Total || (UINT)(packet[0] & 0x0F) * 4 != p.HeaderSize || Cmp(packet + 12, overlay + 12, 8) != 0 ||
	    Cmp(packet + p.HeaderSize, overlay + p.HeaderSize, 4) != 0)
		return false;

	Zero(&f, sizeof(f));

	AcquireSRWLockExclusive(&s->Lock);
	{
		NODE_SPLIT_ADDRESS *a = NodeSplitAddressOf(s, vrf_id, p.Src);
		UINT port = p.SrcPort;

		if (a != NULL && a->Port != 0 && s->NumFlows < NODE_SPLIT_MAX_FLOWS && NodeSplitPeerFlows(s, peer) < NODE_SPLIT_PEER_FLOWS) {
			// The destination as the listener sees it keeps the port of the host's end, unless another flow to it holds it
			if (NodeSplitFindProxy(s, vrf_id, p.Dst, port) != NULL) {
				s->Seed = s->Seed * 1103515245U + 12345U;
				UINT start = s->Seed >> 8;

				port = 0;
				for (UINT i = 0; i < NODE_SPLIT_PORT_TRIES && port == 0; i++) {
					UINT candidate = 1024 + (start + i * 7919U) % (65536 - 1024);

					if (NodeSplitFindProxy(s, vrf_id, p.Dst, candidate) == NULL)
						port = candidate;
				}
			}

			if (port != 0) {
				f.Peer = peer;
				f.Opener = true;
				f.Id = ++s->NextId;
				f.VrfId = vrf_id;
				Copy(f.Src, p.Src, 4);
				f.SrcPort = p.SrcPort;
				Copy(f.Dst, p.Dst, 4);
				f.DstPort = p.DstPort;
				Copy(f.Local, a->Address, 4);
				f.LocalPort = a->Port;
				f.ProxyPort = port;
				f.State = NODE_SPLIT_WAIT;
				f.Since = GetTickCount64();
				f.SendOpen = true;
				f.Syn = Clone(overlay, p.Total);
				f.SynSize = p.Total;
				NodeSplitLink(s, &f);
				taken = true;
			}
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	if (taken) {
		InterlockedIncrement64(&s->Opened);
		NodeSplitWake(s);
	}

	return taken;
}

//
// The records of the peers
//

// Whether the host routes the address into a VRF of the node. The caller holds the lock.
static bool NodeSplitInside(NODE_SPLIT *s, const UCHAR *address) {
	UINT a = READ_UINT(address);

	for (UINT i = 0; i < s->NumInside; i++) {
		UINT mask = 0xFFFFFFFFU << (32 - s->Inside[i].Length);

		if ((a & mask) == (READ_UINT(s->Inside[i].Address) & mask))
			return true;
	}

	return false;
}

static int NodeSplitCompareKeys(const void *a, const void *b) {
	const NODE_SPLIT_KEY *x = (const NODE_SPLIT_KEY *)a;
	const NODE_SPLIT_KEY *y = (const NODE_SPLIT_KEY *)b;

	if (x->VrfId != y->VrfId)
		return (x->VrfId < y->VrfId ? -1 : 1);

	int c = Cmp(x->Address, y->Address, 4);

	return (c < 0 ? -1 : (c > 0 ? 1 : 0));
}

// Whether the address is an address of a peer in a Network that splits TCP in the VRF. The caller holds the lock.
static bool NodeSplitPeerAddress(NODE_SPLIT *s, UINT vrf_id, const UCHAR *address) {
	NODE_SPLIT_KEY k;

	if (s->NumPeerAddresses == 0)
		return false;

	Zero(&k, sizeof(k));
	k.VrfId = vrf_id;
	Copy(k.Address, address, 4);

	return (bsearch(&k, s->PeerAddresses, s->NumPeerAddresses, sizeof(NODE_SPLIT_KEY), NodeSplitCompareKeys) != NULL);
}

// The OPEN r of the peer peer: the node opens the flow to its real destination, or answers why it does not. The caller is the
// thread of the overlay, an online reader of the node's table snapshot.
static void NodeSplitOpenOf(NODE_SPLIT *s, void *peer, const NODE_SPLIT_RECORD *r) {
	NODE_TABLES *t = NodeGetTables(s->Node);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, r->VrfId);
	UCHAR syn[40];
	UCHAR nat[NODE_SPLIT_NAT_ROOM];
	UINT status = NODE_SPLIT_ANSWER_DENIED;
	UINT from = (vt != NULL ? NodeVrfLookup(vt, r->Src, 4) : NODE_VRF_NONE);

	// The source is the peer's and the destination the host's, and a destination of the default route alone, an internet exit,
	// is no address of the host that the egress refuses
	bool ok = (vt != NULL && from < v->NumHops && v->Hops[from] == peer && NodeVrfLookup(vt, r->Dst, 4) == NODE_VRF_LOCAL && NodeEgressRefuses(r->Dst) == false);

	// The session profiles and the policy of the VRF judge a SYN between the two ends as the peer would have sent it, and a 1:1
	// NAT rule translates its destination for the host
	const UCHAR *packet = syn;
	UINT packet_size = NodeSplitSegment(syn, r->Src, r->SrcPort, r->Dst, r->DstPort, NODE_EGRESS_SYN, 0, 0);
	ok = ok && NodeProfileInbound(s->Node, v, r->VrfId, from, syn, packet_size) && NodePolicyInbound(s->Node, v, r->VrfId, from, syn, packet_size);
	ok = ok && NodeNatInbound(v, r->VrfId, &packet, &packet_size, nat, sizeof(nat)) && packet_size >= 40 && (packet[0] >> 4) == 4;

	AcquireSRWLockExclusive(&s->Lock);
	{
		NODE_SPLIT_FLOW f;

		ok = ok && NodeSplitPeerAddress(s, r->VrfId, r->Src) && (NodeVrfDefault(vt, r->Dst, 4) == false || NodeSplitInside(s, r->Dst) == false);
		if (ok && (s->NumFlows >= NODE_SPLIT_MAX_FLOWS || NodeSplitPeerFlows(s, peer) >= NODE_SPLIT_PEER_FLOWS))
			status = NODE_SPLIT_ANSWER_FULL;
		else if (ok && NodeSplitFindId(s, peer, false, r->Id) == NULL) {
			Zero(&f, sizeof(f));
			f.Peer = peer;
			f.Id = r->Id;
			f.VrfId = r->VrfId;
			Copy(f.Src, r->Src, 4);
			f.SrcPort = r->SrcPort;
			Copy(f.Dst, packet + 16, 4);
			f.DstPort = READ_USHORT(packet + (UINT)(packet[0] & 0x0F) * 4 + 2);
			f.State = NODE_SPLIT_DIALING;
			f.Since = GetTickCount64();
			f.Credit = MIN((UINT64)r->Window, (UINT64)NODE_SPLIT_MAX_CREDIT);
			NodeSplitLink(s, &f);
			status = NODE_SPLIT_ANSWER_OK;
		} else if (ok) {
			// The OPEN of a flow that the node has already
			status = NODE_SPLIT_ANSWER_MAX + 1;
		}

		if (status <= NODE_SPLIT_ANSWER_MAX && status != NODE_SPLIT_ANSWER_OK) {
			NODE_SPLIT_RECORD a;

			Zero(&a, sizeof(a));
			a.Kind = NODE_SPLIT_RECORD_ANSWER;
			a.Id = r->Id;
			a.Status = status;
			NodeSplitPend(s, peer, &a);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	if (status != NODE_SPLIT_ANSWER_OK && status <= NODE_SPLIT_ANSWER_MAX)
		InterlockedIncrement64(&s->Denied);
	NodeSplitWake(s);
}

// The ANSWER r of the peer to a flow f that the node opened for its host, which waits for it, at now: with OK the SYN of the
// host goes to the listener, with REFUSED a reset of the destination goes to the host's end, and else the flow fails, so the
// host's connect times out. The packet that goes into the adapter goes into buf (40 bytes at least), its size into *size.
// The caller holds the lock.
static void NodeSplitAnswered(NODE_SPLIT *s, NODE_SPLIT_FLOW *f, const NODE_SPLIT_RECORD *r, UINT64 now, UCHAR *buf, UINT max, UINT *size) {
	NODE_EGRESS_PACKET p;

	*size = 0;
	if (r->Status == NODE_SPLIT_ANSWER_OK && f->Syn != NULL && f->SynSize <= max && NodeEgressParse(f->Syn, f->SynSize, &p)) {
		Copy(buf, f->Syn, f->SynSize);
		NodeEgressRewrite(buf, &p, f->Dst, f->ProxyPort, f->Local, f->LocalPort);
		*size = f->SynSize;
		f->Credit = MIN((UINT64)r->Window, (UINT64)NODE_SPLIT_MAX_CREDIT);
		f->State = NODE_SPLIT_TAKE;
		f->Since = now;
		InterlockedIncrement64(&s->Connected);
		return;
	}

	if (r->Status == NODE_SPLIT_ANSWER_REFUSED && f->Syn != NULL) {
		*size = NodeSplitReset(buf, max, f->Syn, f->SynSize);
		NodeSplitEnd(f, false, now);
		InterlockedIncrement64(&s->Refused);
		return;
	}

	Free(f->Syn);
	f->Syn = NULL;
	f->SynSize = 0;
	f->State = NODE_SPLIT_FAILED;
	InterlockedIncrement64(&s->Failed);
}

// A control record of the Noise session of the peer peer of the overlay: true when it is a record of a split flow, which the
// node takes here; false for any other record, which the gateway HA takes (NodeGateway.c). A record that does not read as one
// of a split flow, or of a flow that the node does not know, is dropped, and the peer hears a reset of an unknown flow that it
// sends data on. On the thread of the overlay, an online reader of the node's table snapshot.
bool NodeSplitControl(NODE *n, void *peer, const UCHAR *data, UINT size) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	NODE_SPLIT_RECORD r;
	UCHAR packet[NODE_SPLIT_MAX_SYN];
	UINT packet_size = 0;
	UINT vrf_id = 0;

	if (data == NULL || size == 0 || data[0] < NODE_SPLIT_RECORD_OPEN || data[0] > NODE_SPLIT_RECORD_RESET)
		return false;
	if (s == NULL || peer == NULL || NodeSplitParseRecord(data, size, &r) == false) {
		if (s != NULL)
			InterlockedIncrement64(&s->Dropped);
		return true;
	}

	if (r.Kind == NODE_SPLIT_RECORD_OPEN) {
		NodeSplitOpenOf(s, peer, &r);
		return true;
	}

	UINT64 now = GetTickCount64();

	AcquireSRWLockExclusive(&s->Lock);
	{
		// The sender's flow: the node opened it when the sender did not
		NODE_SPLIT_FLOW *f = NodeSplitFindId(s, peer, r.FromOpener == false, r.Id);

		if (f == NULL || f->State == NODE_SPLIT_DONE) {
			// A flow that the node does not know, or that ended: data and a half-close on it hear a reset
			if (r.Kind == NODE_SPLIT_RECORD_DATA || r.Kind == NODE_SPLIT_RECORD_FIN || (r.Kind == NODE_SPLIT_RECORD_ANSWER && r.Status == NODE_SPLIT_ANSWER_OK)) {
				NODE_SPLIT_RECORD x;

				Zero(&x, sizeof(x));
				x.Kind = NODE_SPLIT_RECORD_RESET;
				x.FromOpener = (r.FromOpener == false);
				x.Id = r.Id;
				NodeSplitPend(s, peer, &x);
			}
			InterlockedIncrement64(&s->Dropped);
		} else if (r.Kind == NODE_SPLIT_RECORD_ANSWER) {
			if (f->Opener && f->State == NODE_SPLIT_WAIT) {
				vrf_id = f->VrfId;
				NodeSplitAnswered(s, f, &r, now, packet, sizeof(packet), &packet_size);
			}
		} else if (r.Kind == NODE_SPLIT_RECORD_DATA) {
			// Within the window that the node granted: the bytes that wait and those written but not granted again
			if (f->PeerFin || f->NumIn + r.Size > NODE_SPLIT_WINDOW - f->Granted) {
				f->Abort = true;
			} else {
				if (f->In == NULL)
					f->In = Malloc(NODE_SPLIT_WINDOW);
				Copy(f->In + f->NumIn, r.Data, r.Size);
				f->NumIn += r.Size;
				InterlockedAdd64(&s->BytesIn, r.Size);
			}
		} else if (r.Kind == NODE_SPLIT_RECORD_WINDOW) {
			f->Credit = MIN(f->Credit + r.Window, (UINT64)NODE_SPLIT_MAX_CREDIT);
		} else if (r.Kind == NODE_SPLIT_RECORD_FIN) {
			f->PeerFin = true;
		} else if (r.Kind == NODE_SPLIT_RECORD_RESET) {
			f->PeerReset = true;
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	if (packet_size != 0 && s->Adapter != NULL)
		s->Adapter(n, s->AdapterParam, vrf_id, packet, packet_size);
	NodeSplitWake(s);

	return true;
}

// The Noise session of the peer peer of the overlay closed, or the peer went: each of its flows is reset, and once this returns
// the thread sends the peer nothing more. On the thread of the overlay.
void NodeSplitPeerDown(NODE *n, void *peer) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	NODE_SPLIT_PENDING *gone = NULL;

	if (s == NULL || peer == NULL)
		return;

	AcquireSRWLockExclusive(&s->Lock);
	{
		for (NODE_SPLIT_FLOW *f = s->First; f != NULL; f = f->Next) {
			if (f->Peer == peer) {
				f->Peer = NULL;
				f->PeerReset = true;
			}
		}

		for (NODE_SPLIT_PENDING **link = &s->Pending; *link != NULL;) {
			NODE_SPLIT_PENDING *p = *link;

			if (p->Peer == peer) {
				*link = p->Next;
				p->Next = gone;
				gone = p;
				s->NumPending--;
			} else {
				link = &p->Next;
			}
		}

		// A send to the peer that runs ends before the peer goes
		while (s->Sending == peer)
			SleepConditionVariableSRW(&s->Sent, &s->Lock, INFINITE, 0);
	}
	ReleaseSRWLockExclusive(&s->Lock);

	while (gone != NULL) {
		NODE_SPLIT_PENDING *p = gone;

		gone = p->Next;
		Free(p);
	}

	NodeSplitWake(s);
}

//
// The thread
//

// Map the error of a dial to an answer
static UINT NodeSplitDialAnswer(int err) {
	switch (err) {
	case WSAECONNREFUSED:
		return NODE_SPLIT_ANSWER_REFUSED;
	case WSAETIMEDOUT:
		return NODE_SPLIT_ANSWER_TIMEOUT;
	default:
		return NODE_SPLIT_ANSWER_UNREACHABLE;
	}
}

// The dial of the peer's flow f to its real destination at now: started when it has no socket, then what it gave from the
// events of its socket: NODE_SPLIT_ANSWER_*, or NODE_SPLIT_ANSWER_MAX + 1 while it runs. The caller holds the lock.
static UINT NodeSplitDialStep(NODE_SPLIT *s, NODE_SPLIT_FLOW *f, UINT64 now) {
	if (f->Sock == INVALID_SOCKET) {
		SOCKADDR_IN to;
		UCHAR address[4];
		UINT port = f->DstPort;
		u_long nonblock = 1;

		Copy(address, f->Dst, 4);
		if (s->Dial != NULL)
			s->Dial(s->DialParam, address, &port);

		SOCKET k = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (k == INVALID_SOCKET)
			return NODE_SPLIT_ANSWER_UNREACHABLE;

		Zero(&to, sizeof(to));
		to.sin_family = AF_INET;
		Copy(&to.sin_addr, address, 4);
		to.sin_port = htons((u_short)port);

		if (ioctlsocket(k, FIONBIO, &nonblock) != 0 || (connect(k, (SOCKADDR *)&to, sizeof(to)) != 0 && WSAGetLastError() != WSAEWOULDBLOCK)) {
			int err = WSAGetLastError();

			closesocket(k);
			return NodeSplitDialAnswer(err);
		}

		f->Sock = k;
		f->Events = 0;
		return NODE_SPLIT_ANSWER_MAX + 1;
	}

	if ((f->Events & (POLLERR | POLLHUP)) != 0) {
		int err = 0;
		int len = sizeof(err);

		getsockopt(f->Sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
		return NodeSplitDialAnswer(err);
	}
	if ((f->Events & POLLWRNORM) != 0)
		return NODE_SPLIT_ANSWER_OK;
	if (now > f->Since + s->DialTimeout)
		return NODE_SPLIT_ANSWER_TIMEOUT;

	return NODE_SPLIT_ANSWER_MAX + 1;
}

// The reset of the flow f to its peer into rec once its socket closed at once: its size, or 0 when the peer reset it or
// went. The caller holds the lock.
static UINT NodeSplitResetFlow(NODE_SPLIT *s, NODE_SPLIT_FLOW *f, UINT64 now, UCHAR *rec) {
	NODE_SPLIT_RECORD r;
	bool tell = (f->Peer != NULL && f->PeerReset == false);

	NodeSplitEnd(f, true, now);
	if (tell == false)
		return 0;

	Zero(&r, sizeof(r));
	r.Kind = NODE_SPLIT_RECORD_RESET;
	r.FromOpener = f->Opener;
	r.Id = f->Id;
	InterlockedIncrement64(&s->Resets);

	return NodeSplitWriteRecord(rec, NODE_SPLIT_MAX_RECORD, &r);
}

// What the thread does next for the flow f at now, with the socket of the flow, which does not wait: the record that it sends
// the peer for it into rec (NODE_SPLIT_MAX_RECORD bytes), its size, or 0 when the flow has nothing to send now. The caller
// holds the lock.
static UINT NodeSplitStep(NODE_SPLIT *s, NODE_SPLIT_FLOW *f, UINT64 now, UCHAR *rec) {
	NODE_SPLIT_RECORD r;

	if (f->State == NODE_SPLIT_DONE)
		return 0;

	// The peer went or reset the flow, or the node ends it: its connection is reset
	if (f->Peer == NULL || f->PeerReset || f->Abort)
		return NodeSplitResetFlow(s, f, now, rec);

	Zero(&r, sizeof(r));
	r.FromOpener = f->Opener;
	r.Id = f->Id;

	if (f->State == NODE_SPLIT_WAIT) {
		if (f->SendOpen == false)
			return 0;

		f->SendOpen = false;
		r.Kind = NODE_SPLIT_RECORD_OPEN;
		r.VrfId = f->VrfId;
		Copy(r.Src, f->Src, 4);
		r.SrcPort = f->SrcPort;
		Copy(r.Dst, f->Dst, 4);
		r.DstPort = f->DstPort;
		r.Window = NODE_SPLIT_WINDOW;
		return NodeSplitWriteRecord(rec, NODE_SPLIT_MAX_RECORD, &r);
	}

	if (f->State == NODE_SPLIT_DIALING) {
		UINT answer = NodeSplitDialStep(s, f, now);

		if (answer > NODE_SPLIT_ANSWER_MAX)
			return 0;

		r.Kind = NODE_SPLIT_RECORD_ANSWER;
		r.Status = answer;
		r.Window = NODE_SPLIT_WINDOW;
		if (answer == NODE_SPLIT_ANSWER_OK) {
			f->State = NODE_SPLIT_RUN;
			f->Since = now;
			InterlockedIncrement64(&s->Served);
		} else {
			NodeSplitEnd(f, true, now);
		}
		return NodeSplitWriteRecord(rec, NODE_SPLIT_MAX_RECORD, &r);
	}

	if (f->State != NODE_SPLIT_RUN)
		return 0;

	// The bytes of the peer into the socket, as far as it takes them
	while (f->NumIn != 0) {
		int sent = send(f->Sock, (const char *)f->In, (int)f->NumIn, 0);

		if (sent <= 0) {
			if (sent < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
				break;
			return NodeSplitResetFlow(s, f, now, rec);
		}

		memmove(f->In, f->In + sent, f->NumIn - (UINT)sent);
		f->NumIn -= (UINT)sent;
		f->Granted += (UINT)sent;
	}

	// ... which the peer may send again once a part of the window is written, or all that waited
	if (f->Granted >= NODE_SPLIT_UPDATE || (f->Granted != 0 && f->NumIn == 0)) {
		r.Kind = NODE_SPLIT_RECORD_WINDOW;
		r.Window = f->Granted;
		f->Granted = 0;
		return NodeSplitWriteRecord(rec, NODE_SPLIT_MAX_RECORD, &r);
	}

	// The peer sent all that it sends and the socket took it: the other end hears it
	if (f->PeerFin && f->NumIn == 0 && f->Shut == false) {
		shutdown(f->Sock, SD_SEND);
		f->Shut = true;
	}

	// The bytes of the socket to the peer, within its window
	if (f->SockEnd == false && f->Credit != 0) {
		UINT max = (UINT)MIN(f->Credit, (UINT64)NODE_SPLIT_CHUNK);
		int got = recv(f->Sock, (char *)rec + NODE_SPLIT_HEADER, (int)max, 0);

		if (got > 0) {
			NodeSplitHeader(rec, NODE_SPLIT_RECORD_DATA, f->Opener, f->Id);
			f->Credit -= (UINT)got;
			InterlockedAdd64(&s->BytesOut, got);
			return NODE_SPLIT_HEADER + (UINT)got;
		}
		if (got == 0)
			f->SockEnd = true;
		else if (WSAGetLastError() != WSAEWOULDBLOCK)
			return NodeSplitResetFlow(s, f, now, rec);
	}

	if (f->SockEnd && f->FinSent == false) {
		f->FinSent = true;
		r.Kind = NODE_SPLIT_RECORD_FIN;
		InterlockedIncrement64(&s->Fins);
		return NodeSplitWriteRecord(rec, NODE_SPLIT_MAX_RECORD, &r);
	}

	// Both ends sent all that they send: the connection closes
	if (f->FinSent && f->Shut)
		NodeSplitEnd(f, false, now);

	return 0;
}

// Send size bytes of the record rec to the peer of the flow, or of a pending record, out of the lock, which the caller holds
// and holds again after: the peer stays until the send returned (NodeSplitPeerDown). False when it went nowhere.
static bool NodeSplitSend(NODE_SPLIT *s, void *peer, const UCHAR *rec, UINT size) {
	if (peer == NULL || size == 0)
		return false;

	s->Sending = peer;
	ReleaseSRWLockExclusive(&s->Lock);
	bool ok = NodeOverlaySendControl(s->Node, peer, rec, size);
	AcquireSRWLockExclusive(&s->Lock);
	s->Sending = NULL;
	WakeAllConditionVariable(&s->Sent);

	return ok;
}

// The records without a flow, then each flow for a few records. The flows are freed by the thread alone, so a flow stays while
// the lock is out for a send.
static void NodeSplitServeFlows(NODE_SPLIT *s, UINT64 now) {
	AcquireSRWLockExclusive(&s->Lock);

	while (s->Pending != NULL) {
		NODE_SPLIT_PENDING *p = s->Pending;

		s->Pending = p->Next;
		s->NumPending--;
		Copy(s->Record, p->Record, p->Size);
		NodeSplitSend(s, p->Peer, s->Record, p->Size);
		Free(p);
	}

	for (NODE_SPLIT_FLOW *f = s->First; f != NULL; f = f->Next) {
		for (UINT turn = 0; turn < NODE_SPLIT_TURNS; turn++) {
			UINT size = NodeSplitStep(s, f, now, s->Record);

			if (size == 0)
				break;
			if (NodeSplitSend(s, f->Peer, s->Record, size) == false)
				InterlockedIncrement64(&s->Dropped);
		}
		f->Events = 0;
	}

	ReleaseSRWLockExclusive(&s->Lock);
}

// The connections that the host's stack made to the listener of the address a: each is the flow of the destination that it
// came from, which waits for it; a connection of no flow closes with a reset
static void NodeSplitAccept(NODE_SPLIT *s, NODE_SPLIT_ADDRESS *a, UINT64 now) {
	for (UINT i = 0; i < NODE_SPLIT_BATCH; i++) {
		SOCKADDR_IN from;
		int size = sizeof(from);
		u_long nonblock = 1;
		bool taken = false;

		SOCKET k = accept(a->Listener, (SOCKADDR *)&from, &size);
		if (k == INVALID_SOCKET)
			return;

		ioctlsocket(k, FIONBIO, &nonblock);

		AcquireSRWLockExclusive(&s->Lock);
		{
			NODE_SPLIT_FLOW *f = NodeSplitFindProxy(s, a->VrfId, (const UCHAR *)&from.sin_addr, ntohs(from.sin_port));

			if (f != NULL && f->State == NODE_SPLIT_TAKE) {
				f->Sock = k;
				f->Events = 0;
				f->State = NODE_SPLIT_RUN;
				f->Since = now;
				taken = true;
			}
		}
		ReleaseSRWLockExclusive(&s->Lock);

		if (taken == false) {
			NodeSplitAbort(k);
			InterlockedIncrement64(&s->Dropped);
		}
	}
}

// The filters of the listeners in a dynamic session of the filter engine, which the thread opens with the first listener: in a
// sublayer of its own above the ones of Windows Firewall, a permit of a listener that clears the right of a lower sublayer to
// block, so the connections of the host reach it whatever the network profile of the adapter of its VRF. NULL when it cannot
// be had (the node log says so once).
static HANDLE NodeSplitEngine(NODE_SPLIT *s) {
	FWPM_SESSION0 session;
	FWPM_SUBLAYER0 sub;
	HANDLE engine = NULL;

	if (s->Engine != NULL || s->EngineFailed)
		return s->Engine;

	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"Ranz VPN: the listeners of TCP splitting";

	DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err == ERROR_SUCCESS) {
		Zero(&sub, sizeof(sub));
		Rand(&sub.subLayerKey, sizeof(GUID));
		sub.displayData.name = L"Ranz VPN: the listeners of TCP splitting";
		sub.weight = 0xFFFF;
		err = FwpmSubLayerAdd0(engine, &sub, NULL);
		if (err == ERROR_SUCCESS) {
			s->SubLayer = sub.subLayerKey;
		} else {
			FwpmEngineClose0(engine);
			engine = NULL;
		}
	}

	if (engine == NULL) {
		s->EngineFailed = true;
		NodeLog(s->Node, "TCP splitting: the filter engine could not be opened (error 0x%x): a firewall that blocks the listeners blocks the split flows", (UINT)err);
		return NULL;
	}

	s->Engine = engine;
	return engine;
}

// Let the connections of the host reach the listener on address:port: the id of its filter, 0 when it could not be added
static UINT64 NodeSplitPermit(NODE_SPLIT *s, const UCHAR *address, UINT port) {
	FWPM_FILTER_CONDITION0 cond[3];
	FWPM_FILTER0 filter;
	UINT64 id = 0;
	HANDLE engine = NodeSplitEngine(s);

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
	cond[2].conditionValue.uint8 = (UINT8)NODE_EGRESS_TCP;

	Zero(&filter, sizeof(filter));
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	filter.subLayerKey = s->SubLayer;
	filter.displayData.name = L"Ranz VPN: the host reaches the listener of TCP splitting";
	filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 15;
	filter.numFilterConditions = 3;
	filter.filterCondition = cond;

	DWORD err = FwpmFilterAdd0(engine, &filter, NULL, &id);
	if (err != ERROR_SUCCESS) {
		NodeLog(s->Node, "TCP splitting: the filter of the listener on port %u could not be added (error 0x%x)", port, (UINT)err);
		return 0;
	}

	return id;
}

// Take the addresses of the Generation applied last: an address that stays keeps its listener, one that goes closes it, and a
// new one waits for its listener. The flows stay: each has its own connection.
static void NodeSplitReconcile(NODE_SPLIT *s, UINT64 now) {
	NODE_SPLIT_ADDRESS next[CONTROL_MAX_ADDRESSES];
	SOCKET closing[CONTROL_MAX_ADDRESSES];
	UINT64 permits[CONTROL_MAX_ADDRESSES];
	UINT num = 0, num_closing = 0, num_permits = 0;

	AcquireSRWLockExclusive(&s->Lock);
	{
		for (UINT i = 0; i < s->NumWanted && num < CONTROL_MAX_ADDRESSES; i++) {
			NODE_SPLIT_ADDRESS *old = NodeSplitAddressOf(s, s->Wanted[i].VrfId, s->Wanted[i].Address);
			NODE_SPLIT_ADDRESS *a = &next[num++];

			if (old != NULL) {
				Copy(a, old, sizeof(NODE_SPLIT_ADDRESS));
				old->VrfId = 0;
				continue;
			}

			Zero(a, sizeof(NODE_SPLIT_ADDRESS));
			a->VrfId = s->Wanted[i].VrfId;
			Copy(a->Address, s->Wanted[i].Address, 4);
			a->Listener = INVALID_SOCKET;
			a->NextBind = now;
		}

		for (UINT i = 0; i < s->NumAddresses; i++) {
			NODE_SPLIT_ADDRESS *old = &s->Addresses[i];

			if (old->VrfId == 0)
				continue;
			if (old->Listener != INVALID_SOCKET)
				closing[num_closing++] = old->Listener;
			if (old->Permit != 0)
				permits[num_permits++] = old->Permit;
		}

		Copy(s->Addresses, next, sizeof(NODE_SPLIT_ADDRESS) * num);
		s->NumAddresses = num;
	}
	ReleaseSRWLockExclusive(&s->Lock);

	for (UINT i = 0; i < num_closing; i++)
		closesocket(closing[i]);
	for (UINT i = 0; i < num_permits && s->Engine != NULL; i++)
		FwpmFilterDeleteById0(s->Engine, permits[i]);
}

// Bind the listener of each address that has none, once NODE_SPLIT_BIND passed since its last attempt at now. Before the
// adapter of the VRF holds the address it cannot be had, and the next attempt follows.
static void NodeSplitBind(NODE_SPLIT *s, UINT64 now) {
	for (UINT i = 0; i < s->NumAddresses; i++) {
		NODE_SPLIT_ADDRESS *a = &s->Addresses[i];
		SOCKADDR_IN in;
		int size = sizeof(in);
		u_long nonblock = 1;
		BOOL exclusive = TRUE;
		char text[64];

		if (a->Listener != INVALID_SOCKET || now < a->NextBind)
			continue;

		a->NextBind = now + NODE_SPLIT_BIND;
		Format(text, sizeof(text), "%u.%u.%u.%u", (UINT)a->Address[0], (UINT)a->Address[1], (UINT)a->Address[2], (UINT)a->Address[3]);

		SOCKET k = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		Zero(&in, sizeof(in));
		in.sin_family = AF_INET;
		Copy(&in.sin_addr, a->Address, 4);
		if (k != INVALID_SOCKET)
			setsockopt(k, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive));

		if (k == INVALID_SOCKET || bind(k, (SOCKADDR *)&in, sizeof(in)) != 0 || listen(k, SOMAXCONN) != 0 || ioctlsocket(k, FIONBIO, &nonblock) != 0 ||
		    getsockname(k, (SOCKADDR *)&in, &size) != 0) {
			UINT err = (UINT)WSAGetLastError();

			if (k != INVALID_SOCKET)
				closesocket(k);
			if (a->Failed == false)
				NodeLog(s->Node, "TCP splitting: the listener of VRF %u cannot listen on %s yet (error %u): the node tries again", a->VrfId, text, err);
			a->Failed = true;
			continue;
		}

		// The firewall lets the connections of the host reach it before the data path sends it any
		UINT port = ntohs(in.sin_port);
		UINT64 permit = NodeSplitPermit(s, a->Address, port);

		AcquireSRWLockExclusive(&s->Lock);
		a->Listener = k;
		a->Port = port;
		a->Permit = permit;
		a->Failed = false;
		ReleaseSRWLockExclusive(&s->Lock);

		NodeLog(s->Node, "TCP splitting: the listener of VRF %u listens on %s, TCP port %u", a->VrfId, text, port);
	}
}

// The flows whose time is up at now: a flow of the host whose peer did not answer, or whose SYN the host did not take, within
// NODE_SPLIT_OPEN; a flow whose peer failed once that time passed too; and one that ended once NODE_SPLIT_LINGER passed
static void NodeSplitExpire(NODE_SPLIT *s, UINT64 now) {
	AcquireSRWLockExclusive(&s->Lock);
	for (NODE_SPLIT_FLOW *f = s->First, *after = NULL; f != NULL; f = after) {
		after = f->Next;

		if (f->State == NODE_SPLIT_DONE && now > f->Since + NODE_SPLIT_LINGER) {
			NodeSplitFree(s, f);
			continue;
		}
		if (now <= f->Since + NODE_SPLIT_OPEN)
			continue;

		if (f->State == NODE_SPLIT_WAIT) {
			InterlockedIncrement64(&s->Failed);
			f->Abort = true;
		} else if (f->State == NODE_SPLIT_TAKE) {
			f->Abort = true;
		} else if (f->State == NODE_SPLIT_FAILED) {
			NodeSplitEnd(f, true, now);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);
}

// Add the socket k with the events to the sockets that the thread waits for, with the flow f or the listener of index address
static void NodeSplitWaitFor(NODE_SPLIT *s, SOCKET k, SHORT events, NODE_SPLIT_FLOW *f, UINT address) {
	if (k == INVALID_SOCKET || events == 0)
		return;

	if (s->NumWaits == s->MaxWaits) {
		s->MaxWaits = MAX(s->MaxWaits * 2, 64);
		s->Fds = (s->Fds == NULL ? Malloc(sizeof(WSAPOLLFD) * s->MaxWaits) : ReAlloc(s->Fds, sizeof(WSAPOLLFD) * s->MaxWaits));
		s->WaitFlows = (s->WaitFlows == NULL ? Malloc(sizeof(NODE_SPLIT_FLOW *) * s->MaxWaits) : ReAlloc(s->WaitFlows, sizeof(NODE_SPLIT_FLOW *) * s->MaxWaits));
		s->WaitAddresses = (s->WaitAddresses == NULL ? Malloc(sizeof(UINT) * s->MaxWaits) : ReAlloc(s->WaitAddresses, sizeof(UINT) * s->MaxWaits));
	}

	s->Fds[s->NumWaits].fd = k;
	s->Fds[s->NumWaits].events = events;
	s->Fds[s->NumWaits].revents = 0;
	s->WaitFlows[s->NumWaits] = f;
	s->WaitAddresses[s->NumWaits] = address;
	s->NumWaits++;
}

// The sockets that the thread waits for now: the wake socket, the listeners, a dial that runs, and each flow's connection for
// what it can do
static void NodeSplitWaits(NODE_SPLIT *s) {
	s->NumWaits = 0;
	NodeSplitWaitFor(s, s->Wake, POLLRDNORM, NULL, INFINITE);

	AcquireSRWLockShared(&s->Lock);
	for (UINT i = 0; i < s->NumAddresses; i++)
		NodeSplitWaitFor(s, s->Addresses[i].Listener, POLLRDNORM, NULL, i);

	for (NODE_SPLIT_FLOW *f = s->First; f != NULL; f = f->Next) {
		SHORT events = 0;

		if (f->State == NODE_SPLIT_DIALING)
			events = POLLWRNORM;
		else if (f->State == NODE_SPLIT_RUN) {
			if (f->SockEnd == false && f->Credit != 0)
				events |= POLLRDNORM;
			if (f->NumIn != 0)
				events |= POLLWRNORM;
		}
		NodeSplitWaitFor(s, f->Sock, events, f, INFINITE);
	}
	ReleaseSRWLockShared(&s->Lock);
}

// The thread: the listeners of the addresses of each Generation, the connections that they take, the dials, the bytes of the
// flows and their records, and the flows whose time is up, until the module stops
static DWORD WINAPI NodeSplitThread(LPVOID param) {
	NODE_SPLIT *s = (NODE_SPLIT *)param;
	char drain[64];

	while (ReadAcquire(&s->Halt) == 0) {
		UINT64 now = GetTickCount64();

		if (InterlockedExchange(&s->Changed, 0) != 0)
			NodeSplitReconcile(s, now);
		NodeSplitBind(s, now);
		NodeSplitExpire(s, now);
		NodeSplitServeFlows(s, now);

		NodeSplitWaits(s);
		int ret = WSAPoll(s->Fds, s->NumWaits, NODE_SPLIT_POLL);
		if (ret < 0) {
			Sleep(NODE_SPLIT_POLL);
			continue;
		}

		now = GetTickCount64();
		for (UINT i = 0; i < s->NumWaits; i++) {
			SHORT events = s->Fds[i].revents;

			if (events == 0)
				continue;
			if (s->Fds[i].fd == s->Wake) {
				while (recv(s->Wake, drain, sizeof(drain), 0) > 0);
			} else if (s->WaitFlows[i] == NULL) {
				NodeSplitAccept(s, &s->Addresses[s->WaitAddresses[i]], now);
			} else {
				s->WaitFlows[i]->Events = events;
			}
		}
	}

	// The end: every flow closes at once, every listener closes, and the filters go with their session
	AcquireSRWLockExclusive(&s->Lock);
	while (s->First != NULL)
		NodeSplitFree(s, s->First);
	while (s->Pending != NULL) {
		NODE_SPLIT_PENDING *p = s->Pending;

		s->Pending = p->Next;
		Free(p);
	}
	s->NumPending = 0;
	s->NumWanted = 0;
	ReleaseSRWLockExclusive(&s->Lock);
	NodeSplitReconcile(s, GetTickCount64());
	if (s->Engine != NULL) {
		FwpmEngineClose0(s->Engine);
		s->Engine = NULL;
	}

	return 0;
}

// The two UDP sockets on the loopback that wake the thread: false when they cannot be had, and the thread then wakes every
// NODE_SPLIT_POLL alone
static bool NodeSplitWakeSockets(NODE_SPLIT *s) {
	SOCKADDR_IN a;
	int size = sizeof(a);
	u_long nonblock = 1;

	s->Wake = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	s->WakeOut = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (s->Wake == INVALID_SOCKET || s->WakeOut == INVALID_SOCKET || bind(s->Wake, (SOCKADDR *)&a, sizeof(a)) != 0 || ioctlsocket(s->Wake, FIONBIO, &nonblock) != 0 ||
	    ioctlsocket(s->WakeOut, FIONBIO, &nonblock) != 0 || getsockname(s->Wake, (SOCKADDR *)&a, &size) != 0 || connect(s->WakeOut, (SOCKADDR *)&a, sizeof(a)) != 0) {
		if (s->Wake != INVALID_SOCKET)
			closesocket(s->Wake);
		if (s->WakeOut != INVALID_SOCKET)
			closesocket(s->WakeOut);
		s->Wake = INVALID_SOCKET;
		s->WakeOut = INVALID_SOCKET;
		return false;
	}

	return true;
}

//
// The module
//

// Start the TCP splitting of a node with its overlay (NodeOverlayStart): it puts the packets that go to the host into the
// adapters of the configuration, and its thread starts with the first Generation that has a Network that splits TCP
void NodeSplitStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg) {
	if (n == NULL || cfg == NULL || n->Split != NULL)
		return;

	NODE_SPLIT *s = ZeroMalloc(sizeof(NODE_SPLIT));
	s->Node = n;
	s->Adapter = cfg->Adapter;
	s->AdapterParam = cfg->AdapterParam;
	InitializeSRWLock(&s->Lock);
	InitializeConditionVariable(&s->Sent);
	s->ById = ZeroMalloc(sizeof(NODE_SPLIT_FLOW *) * NODE_SPLIT_BUCKETS);
	s->ByHost = ZeroMalloc(sizeof(NODE_SPLIT_FLOW *) * NODE_SPLIT_BUCKETS);
	s->ByProxy = ZeroMalloc(sizeof(NODE_SPLIT_FLOW *) * NODE_SPLIT_BUCKETS);
	s->Record = Malloc(NODE_SPLIT_MAX_RECORD);
	s->Wake = INVALID_SOCKET;
	s->WakeOut = INVALID_SOCKET;
	s->DialTimeout = NODE_SPLIT_DIAL;
	s->Seed = (UINT)GetTickCount64() ^ (UINT)GetCurrentProcessId();

	n->Split = s;
}

// Stop the TCP splitting of a node with its overlay (NodeOverlayStop), once no packet of the host and no record of a peer
// reaches it any more: the thread resets every flow and closes every listener
void NodeSplitStop(NODE *n) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);

	if (s == NULL)
		return;

	InterlockedExchange(&s->Halt, 1);
	NodeSplitWake(s);
	if (s->Thread != NULL) {
		WaitForSingleObject(s->Thread, INFINITE);
		CloseHandle(s->Thread);
	}

	n->Split = NULL;

	// A thread that never ran leaves the flows and the records that it would have freed
	while (s->First != NULL)
		NodeSplitFree(s, s->First);
	while (s->Pending != NULL) {
		NODE_SPLIT_PENDING *p = s->Pending;

		s->Pending = p->Next;
		Free(p);
	}

	if (s->Wake != INVALID_SOCKET)
		closesocket(s->Wake);
	if (s->WakeOut != INVALID_SOCKET)
		closesocket(s->WakeOut);
	Free(s->PeerAddresses);
	Free(s->Inside);
	Free(s->Fds);
	Free(s->WaitFlows);
	Free(s->WaitAddresses);
	Free(s->Record);
	Free(s->ById);
	Free(s->ByHost);
	Free(s->ByProxy);
	Free(s);
}

// Whether the Network of the address a of the state st splits TCP
static bool NodeSplitNetwork(const CONTROL_STATE *st, const CONTROL_ADDRESS *a) {
	for (UINT i = 0; i < st->NumSplits && i < CONTROL_MAX_SPLITS; i++)
		if (st->Splits[i].VrfId == a->VrfId && StrCmp(st->Splits[i].Network, a->Network) == 0)
			return true;

	return false;
}

// Add the IPv4 prefix of length bits at address to the prefixes, which have room for it: a prefix of another family, or /0,
// does not go in
static void NodeSplitAddInside(NODE_SPLIT_PREFIX *inside, UINT *num, const UCHAR *address, UINT size, UINT length) {
	if (size != 4 || length == 0 || length > 32)
		return;

	Copy(inside[*num].Address, address, 4);
	inside[*num].Length = length;
	(*num)++;
}

// The Generation that the overlay applied, once the adapters of its VRFs took it: the addresses of the node in the Networks
// that split TCP, where the thread listens; the addresses of the peers in them, whose OPEN the node takes; and the prefixes
// that the host routes into a VRF of the node. The thread starts with the first Generation that has a Network that splits TCP.
void NodeSplitApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	UINT num_keys = 0, num_inside = 0, max = 0;

	if (s == NULL || st == NULL)
		return;

	// The addresses of the peers in the Networks that split TCP, and the prefixes that the host routes into a VRF of the node:
	// those of the addresses of the node and of its peers, the routes of the peers but a default route, and the LAN subnets
	for (UINT i = 0; i < st->NumPeers; i++)
		max += MIN(st->Peers[i].NumAddresses, CONTROL_MAX_ADDRESSES);
	NODE_SPLIT_KEY *keys = ZeroMalloc(sizeof(NODE_SPLIT_KEY) * MAX(max, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *p = &st->Peers[i];

		for (UINT j = 0; j < p->NumAddresses && j < CONTROL_MAX_ADDRESSES; j++) {
			if (p->Addresses[j].AddressSize == 4 && NodeSplitNetwork(st, &p->Addresses[j])) {
				keys[num_keys].VrfId = p->Addresses[j].VrfId;
				Copy(keys[num_keys].Address, p->Addresses[j].Address, 4);
				num_keys++;
			}
		}
	}
	qsort(keys, num_keys, sizeof(NODE_SPLIT_KEY), NodeSplitCompareKeys);

	max = MIN(st->NumAddresses, CONTROL_MAX_ADDRESSES) + MIN(st->NumLanSubnets, CONTROL_MAX_ROUTES);
	for (UINT i = 0; i < st->NumPeers; i++)
		max += MIN(st->Peers[i].NumAddresses, CONTROL_MAX_ADDRESSES) + MIN(st->Peers[i].NumRoutes, CONTROL_MAX_ROUTES);
	NODE_SPLIT_PREFIX *inside = ZeroMalloc(sizeof(NODE_SPLIT_PREFIX) * MAX(max, 1));
	for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES; i++)
		NodeSplitAddInside(inside, &num_inside, st->Addresses[i].Address, st->Addresses[i].AddressSize, st->Addresses[i].Length);
	for (UINT i = 0; i < st->NumLanSubnets && i < CONTROL_MAX_ROUTES; i++)
		NodeSplitAddInside(inside, &num_inside, st->LanSubnets[i].Address, st->LanSubnets[i].AddressSize, st->LanSubnets[i].Length);
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *p = &st->Peers[i];

		for (UINT j = 0; j < p->NumAddresses && j < CONTROL_MAX_ADDRESSES; j++)
			NodeSplitAddInside(inside, &num_inside, p->Addresses[j].Address, p->Addresses[j].AddressSize, p->Addresses[j].Length);
		for (UINT j = 0; j < p->NumRoutes && j < CONTROL_MAX_ROUTES; j++)
			NodeSplitAddInside(inside, &num_inside, p->Routes[j].Address, p->Routes[j].AddressSize, p->Routes[j].Length);
	}

	AcquireSRWLockExclusive(&s->Lock);
	{
		s->NumNetworks = MIN(st->NumSplits, CONTROL_MAX_SPLITS);
		s->NumWanted = 0;
		for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES; i++) {
			const CONTROL_ADDRESS *a = &st->Addresses[i];

			if (a->AddressSize == 4 && NodeSplitNetwork(st, a)) {
				s->Wanted[s->NumWanted].VrfId = a->VrfId;
				Copy(s->Wanted[s->NumWanted].Address, a->Address, 4);
				s->NumWanted++;
			}
		}

		Free(s->PeerAddresses);
		s->PeerAddresses = keys;
		s->NumPeerAddresses = num_keys;
		Free(s->Inside);
		s->Inside = inside;
		s->NumInside = num_inside;
		InterlockedExchange(&s->Active, s->NumWanted != 0 ? 1 : 0);
	}
	ReleaseSRWLockExclusive(&s->Lock);

	if (st->NumSplits != 0 || s->Thread != NULL)
		NodeLog(n, "TCP splitting: generation %I64u: %u Networks split TCP, %u addresses of the node in them, %u of its peers", st->Generation, st->NumSplits, s->NumWanted,
		        num_keys);

	if (s->Thread == NULL && st->NumSplits != 0) {
		DWORD id = 0;

		NodeSplitWakeSockets(s);
		s->Thread = CreateThread(NULL, 0, NodeSplitThread, s, 0, &id);
		if (s->Thread == NULL)
			NodeLog(n, "TCP splitting: the thread could not start (error %u)", (UINT)GetLastError());
	}

	InterlockedExchange(&s->Changed, 1);
	NodeSplitWake(s);
}

// Dial the real destinations of the flows that the node opens for its peers where proc says, and give each dial timeout ms (0
// for NODE_SPLIT_DIAL): for a test whose nodes share one host, so that the dial does not go back into the adapter of the host
void NodeSplitSetDial(NODE *n, NODE_SPLIT_DIAL_PROC *proc, void *param, UINT timeout) {
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);

	if (s == NULL)
		return;

	AcquireSRWLockExclusive(&s->Lock);
	s->Dial = proc;
	s->DialParam = param;
	s->DialTimeout = (timeout != 0 ? timeout : NODE_SPLIT_DIAL);
	ReleaseSRWLockExclusive(&s->Lock);
}

// The state of the TCP splitting of a node
void NodeSplitGetStatus(NODE *n, NODE_SPLIT_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_SPLIT_STATUS));
	NODE_SPLIT *s = (n != NULL ? n->Split : NULL);
	if (s == NULL)
		return;

	AcquireSRWLockShared(&s->Lock);
	{
		st->NumNetworks = s->NumNetworks;
		st->NumAddresses = s->NumAddresses;
		for (UINT i = 0; i < s->NumAddresses; i++)
			if (s->Addresses[i].Port != 0)
				st->NumReady++;
		for (NODE_SPLIT_FLOW *f = s->First; f != NULL; f = f->Next)
			if (f->State != NODE_SPLIT_DONE)
				st->NumFlows++;
	}
	ReleaseSRWLockShared(&s->Lock);

	st->Opened = (UINT64)ReadAcquire64(&s->Opened);
	st->Connected = (UINT64)ReadAcquire64(&s->Connected);
	st->Refused = (UINT64)ReadAcquire64(&s->Refused);
	st->Failed = (UINT64)ReadAcquire64(&s->Failed);
	st->Served = (UINT64)ReadAcquire64(&s->Served);
	st->Denied = (UINT64)ReadAcquire64(&s->Denied);
	st->BytesOut = (UINT64)ReadAcquire64(&s->BytesOut);
	st->BytesIn = (UINT64)ReadAcquire64(&s->BytesIn);
	st->Fins = (UINT64)ReadAcquire64(&s->Fins);
	st->Resets = (UINT64)ReadAcquire64(&s->Resets);
	st->Dropped = (UINT64)ReadAcquire64(&s->Dropped);
}
