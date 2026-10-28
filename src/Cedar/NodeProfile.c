// NodeProfile.c
// The session profiles of the overlay of a node (SDN-40, #233; spec #224 "Session profiles"): the limits of the sessions of
// the devices of a User, the successor of the POLICY of a user or a group of the slim fork. A node that a User owns runs
// under the effective SessionProfile of that User, which the controller compiles into its NodeConfig and into the Peer
// object of the node that every other node holds (CONTROL_PROFILE of Core/Control.h). A node enforces the profile of each
// peer on its Noise session with that peer, and the flags of its own profile on itself:
//
// - Upload and download limits: the packets that the node takes from the session of the peer (NodeProfileInbound) and the
//   ones that it sends to it (NodeProfileOutbound) pass a token bucket of the rate of the profile each, or are dropped. A
//   bucket runs GCRA with bytes for cells on the performance counter, as the rate limits of the overlay do (NodeShape.c),
//   and holds NODE_PROFILE_BURST ms of its rate, NODE_PROFILE_MIN_BURST bytes at least.
// - The most sessions of a User: the sessions of the devices of one User that the node holds at once. The overlay asks
//   before it takes a session (NodeProfileUp), and the session of one device more is refused while the others are up.
// - The most IPv4 and IPv6 addresses: the source addresses that the session of the peer sends from in each VRF, the first
//   ones that it sends from; a packet from one address more is dropped. A new session of the peer starts with none.
// - The idle timeout and the automatic disconnect: the overlay asks about each session that it holds (NodeProfileExpired)
//   and ends the one that carried no packet in either direction for the idle timeout, or that came up the automatic
//   disconnect ago. The device dials again, as after a session that ended for any reason.
// - No-routing: the peer sends from and takes at its own addresses only, the addresses of its Peer object in the VRF of the
//   packet, so no outside prefix of a 1:1 NAT rule of the device and no route that a VRF of it leaks passes its session.
//   A node under no-routing sends from and takes at its own addresses only.
// - No-server: no TCP connection to the device. A TCP SYN to the peer and a SYN-ACK from it are dropped; a node under
//   no-server takes no SYN for its host and sends no SYN-ACK of it. A TCP header that the packet cuts short before its
//   flags, and a later fragment that overlaps them, could hide a SYN (RFC 1858) and are dropped too.
// - Privacy filter: no packet passes between the node and a peer when the profiles of both have it (client isolation).
// - The MAC addresses and no-bridge hold in an L2 Network, whose frames the policy engine of its switch judges by the
//   member of each session there (ADR-0019 decision 1): the profile is the guard of that member (NodeProfileMember),
//   under the security of the Network (Core/SwitchSecurity.h). The overlay carries no frame of an L2 Network yet
//   (NodeLink.c): the L2 data path that carries them makes the member of each session with it.
//
// Each Generation that the overlay applies gets a profile table beside its forwarding tables (NodeProfileAttach): the
// profile of the peer of each next hop with its own addresses, and the flags and addresses of the node itself. The two go
// in together (NodeSwapVrfs) and are freed together, so a packet meets the profiles of the Generation that routes it. The
// session of a peer, its buckets, the time of its last packet and the addresses that it sent from, outlives the Generations
// while a table holds it. A packet is judged as the overlay sees it, before the policy of its VRF: after the 1:1 NAT rules
// of the node on the way out, before them on the way in. A Generation in which neither the node nor a peer runs under a
// profile has no table, and its packets pass at once.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"

#include "NodeInternal.h"
#include "NodeProfile.h"

#define NODE_PROFILE_NS 1000000000ULL // ns in a second

// What NodeProfileTcp finds of a packet besides the flags of its TCP header
#define NODE_PROFILE_NOT_TCP 0x100 // No TCP segment, or a later fragment of one that holds no part of its flags
#define NODE_PROFILE_HIDDEN  0x200 // A TCP header that the packet cuts short before its flags, or a later fragment over them

// The name and the static key of a peer: the first member of the session of a peer and of a session that is up, by which
// the lists of the profiles are sorted
typedef struct NODE_PROFILE_KEY {
	char Name[PEER_NAME_SIZE];
	UCHAR Key[PEER_KEY_SIZE];
} NODE_PROFILE_KEY;

// The addresses that the session of a peer sent from in one VRF, under the limits of its profile
typedef struct NODE_PROFILE_SOURCES {
	UINT VrfId;                                 // The VRF
	UINT NumIpv4;                               // Its IPv4 addresses, in the order of their first packet ...
	UCHAR Ipv4[NODE_PROFILE_MAX_ADDRESSES][4];  // ...
	UINT NumIpv6;                               // ... and its IPv6 addresses
	UCHAR Ipv6[NODE_PROFILE_MAX_ADDRESSES][16]; // ...
} NODE_PROFILE_SOURCES;

// The session of a peer that runs under a profile, while a profile table holds it
typedef struct NODE_PROFILE_PEER {
	NODE_PROFILE_KEY Id;         // The peer
	UINT Refs;                   // The next hops of the profile tables that hold it, under the lock of the profiles
	CONTROL_PROFILE Profile;     // Its profile in the state attached last, under that lock: what NodeProfileUp and NodeProfileExpired go by
	bool Refusing;               // NodeProfileUp refuses its sessions, which the node log said once, under that lock
	volatile LONG64 UploadTat;   // The theoretical arrival time of the bucket of what the node takes from it, in ns ...
	volatile LONG64 DownloadTat; // ... and of the one of what the node sends to it
	volatile LONG64 LastPacket;  // The GetTickCount64 of the last packet of its session in either direction, or of its start
	SRWLOCK Lock;                // Sources
	LIST *Sources;               // The addresses that its session sent from, one entry for each VRF (NODE_PROFILE_SOURCES)
} NODE_PROFILE_PEER;

// A session that the overlay holds now
typedef struct NODE_PROFILE_UP {
	NODE_PROFILE_KEY Id; // Its peer
} NODE_PROFILE_UP;

// The session profiles of the overlay of a node, while the overlay runs
struct NODE_PROFILE {
	LOCK *Lock;                   // Peers, Up, Own, NumPeers and the fields of the sessions that name it
	LIST *Peers;                  // The sessions of the peers that a profile table holds (NODE_PROFILE_PEER), by their peer
	LIST *Up;                     // The sessions that the overlay holds (NODE_PROFILE_UP), by their peer
	CONTROL_PROFILE Own;          // The profile of the node itself in the state attached last; not Set for none
	UINT NumPeers;                // The peers of that state that run under a profile
	UINT64 Frequency;             // The frequency of the performance counter
	volatile LONG Timed;          // The peers of that state whose profile has an idle timeout or an automatic disconnect
	volatile LONG64 Upload;       // What the profiles dropped and ended (NODE_PROFILE_STATUS)
	volatile LONG64 Download;     // ...
	volatile LONG64 Addresses;    // ...
	volatile LONG64 Routing;      // ...
	volatile LONG64 Server;       // ...
	volatile LONG64 Isolated;     // ...
	volatile LONG64 Refused;      // ...
	volatile LONG64 Idle;         // ...
	volatile LONG64 Disconnected; // ...
};

// A rate limit of one Generation on a bucket of the session of a peer
typedef struct NODE_PROFILE_LIMIT {
	UINT64 Rate;          // Bits per second, 0 for no limit
	LONG64 Burst;         // What the bucket holds, in ns at the rate
	volatile LONG64 *Tat; // The theoretical arrival time of the bucket
} NODE_PROFILE_LIMIT;

// An address of a node or of a peer in one of its VRFs, which no-routing lets through
typedef struct NODE_PROFILE_ADDRESS {
	UINT VrfId;        // The VRF
	UINT Size;         // 4 for IPv4, 16 for IPv6
	UCHAR Address[16]; // The address
} NODE_PROFILE_ADDRESS;

// One next hop of a profile table: the session of the peer that it leads to, and the profile of the peer in the Generation
typedef struct NODE_PROFILE_HOP {
	NODE_PROFILE_PEER *Peer;               // The session of the peer, NULL when the peer runs under no profile
	NODE_PROFILE_LIMIT Upload;             // The bucket of what the node takes from it ...
	NODE_PROFILE_LIMIT Download;           // ... and of what it sends to it
	UINT MaxIpv4;                          // The IPv4 addresses that its session sends from in a VRF at most, 0 for no limit ...
	UINT MaxIpv6;                          // ... and the IPv6 addresses
	bool NoRouting;                        // Its flags
	bool NoServer;                         // ...
	bool PrivacyFilter;                    // ...
	UINT NumAddresses;                     // Its own addresses in the VRFs that it shares with the node ...
	const NODE_PROFILE_ADDRESS *Addresses; // ... in Addresses of the table
} NODE_PROFILE_HOP;

// The profile table of one Generation, on its forwarding tables (NODE_VRF_TABLES)
struct NODE_PROFILE_TABLE {
	NODE_PROFILE *Profile;                                    // The profiles of the node, which outlive their tables
	UINT64 Frequency;                                         // The frequency of the performance counter
	bool Own;                                                 // The node runs under a profile, whose flags follow
	bool NoRouting;                                           // ...
	bool NoServer;                                            // ...
	bool PrivacyFilter;                                       // ...
	UINT NumOwn;                                              // The addresses of the node itself
	NODE_PROFILE_ADDRESS OwnAddresses[CONTROL_MAX_ADDRESSES]; // ...
	UINT NumHops;                                             // The next hops of the Generation ...
	NODE_PROFILE_HOP *Hops;                                   // ... in the order of its forwarding tables
	NODE_PROFILE_ADDRESS *Addresses;                          // The own addresses of the peers of the hops
};

//
// The sessions of the peers
//

static int NodeProfileCompare(void *p1, void *p2) {
	const NODE_PROFILE_KEY *a = *(const NODE_PROFILE_KEY **)p1;
	const NODE_PROFILE_KEY *b = *(const NODE_PROFILE_KEY **)p2;
	int ret = StrCmp(a->Name, b->Name);

	return (ret != 0 ? ret : Cmp(a->Key, b->Key, PEER_KEY_SIZE));
}

// The entry of the peer name and key in the list o of the profiles, sorted by NodeProfileCompare: NULL for none. The caller
// holds the lock of the profiles.
static void *NodeProfileFind(LIST *o, const char *name, const UCHAR *key) {
	NODE_PROFILE_KEY k;

	Zero(&k, sizeof(k));
	StrCpy(k.Name, sizeof(k.Name), name);
	Copy(k.Key, key, PEER_KEY_SIZE);

	return Search(o, &k);
}

// Forget the addresses that the session of s sent from
static void NodeProfileForget(NODE_PROFILE_PEER *s) {
	AcquireSRWLockExclusive(&s->Lock);
	for (UINT i = 0; i < LIST_NUM(s->Sources); i++)
		Free(LIST_DATA(s->Sources, i));
	DeleteAll(s->Sources);
	ReleaseSRWLockExclusive(&s->Lock);
}

// Free the session of a peer that no table holds any more
static void NodeProfileFreePeer(NODE_PROFILE_PEER *s) {
	NodeProfileForget(s);
	ReleaseList(s->Sources);
	Free(s);
}

// The session of the peer cp, which runs under a profile, that the table that is built holds from now on: the one that the
// profiles have, or a new one, with the profile of cp. The caller holds the lock of the profiles.
static NODE_PROFILE_PEER *NodeProfileHold(NODE_PROFILE *pr, const CONTROL_PEER *cp) {
	NODE_PROFILE_PEER *s = NodeProfileFind(pr->Peers, cp->Name, cp->Key);

	if (s == NULL) {
		s = ZeroMalloc(sizeof(NODE_PROFILE_PEER));
		StrCpy(s->Id.Name, sizeof(s->Id.Name), cp->Name);
		Copy(s->Id.Key, cp->Key, PEER_KEY_SIZE);
		InitializeSRWLock(&s->Lock);
		s->Sources = NewListFast(NULL);
		Insert(pr->Peers, s);
	}

	Copy(&s->Profile, &cp->Profile, sizeof(CONTROL_PROFILE));
	s->Refs++;

	return s;
}

//
// The buckets
//

// The time of the buckets: ns of the performance counter, whose frequency is freq
static LONG64 NodeProfileNow(UINT64 freq) {
	LARGE_INTEGER counter;

	QueryPerformanceCounter(&counter);

	UINT64 ticks = (UINT64)counter.QuadPart;
	return (LONG64)((ticks / freq) * NODE_PROFILE_NS + (ticks % freq) * NODE_PROFILE_NS / freq);
}

// The ns that size bytes take at rate bits per second (not 0), rounded up; size is at most NODE_PROFILE_MIN_BURST, so the
// product stays far inside 64 bits
static LONG64 NodeProfileCost(UINT64 rate, UINT size) {
	UINT64 bits_ns = (UINT64)size * 8 * NODE_PROFILE_NS;

	return (LONG64)(bits_ns / rate + (bits_ns % rate != 0 ? 1 : 0));
}

// The limit of rate bits per second, 0 for none, on the bucket whose theoretical arrival time is at tat
static void NodeProfileLimit(NODE_PROFILE_LIMIT *l, UINT64 rate, volatile LONG64 *tat) {
	Zero(l, sizeof(NODE_PROFILE_LIMIT));
	l->Tat = tat;
	if (rate == 0)
		return;

	l->Rate = rate;
	l->Burst = MAX(NodeProfileCost(rate, NODE_PROFILE_MIN_BURST), (LONG64)NODE_PROFILE_BURST * 1000000);
}

// GCRA on the bucket of l: a packet of size bytes passes when the bucket, with the packet in it, holds no more than its
// burst, and its theoretical arrival time moves on by the packet. Without a limit every packet passes.
static bool NodeProfileTake(const NODE_PROFILE_LIMIT *l, UINT size, UINT64 freq) {
	if (l->Rate == 0)
		return true;
	if (size > NODE_PROFILE_MIN_BURST)
		return false;

	LONG64 now = NodeProfileNow(freq);
	LONG64 cost = NodeProfileCost(l->Rate, size);

	while (true) {
		LONG64 tat = ReadAcquire64(l->Tat);
		LONG64 next = MAX(tat, now) + cost;

		if (next - now > l->Burst)
			return false;

		if (InterlockedCompareExchange64(l->Tat, next, tat) == tat)
			return true;
	}
}

//
// The packets
//

// The source and the destination of an IP packet, 4 bytes each for IPv4 and 16 for IPv6, and their size; false for
// anything else
static bool NodeProfileEnds(const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size) {
	if (packet == NULL || size < 20)
		return false;

	if ((packet[0] >> 4) == 4) {
		*addr_size = 4;
		Copy(src, packet + 12, 4);
		Copy(dst, packet + 16, 4);
		return true;
	}

	if ((packet[0] >> 4) == 6 && size >= 40) {
		*addr_size = 16;
		Copy(src, packet + 8, 16);
		Copy(dst, packet + 24, 16);
		return true;
	}

	return false;
}

// The flags of the TCP header of the IPv4 or IPv6 packet of size bytes; NODE_PROFILE_NOT_TCP for a packet that is no TCP
// segment, or a later fragment of one that does not reach into its first 14 bytes, and NODE_PROFILE_HIDDEN for a TCP
// header that the packet cuts short before its flags, a later fragment that overlaps them, and a header chain of IPv6 that
// the node cannot follow to its end. The extension headers of IPv6 are followed as the Mirrors follow them (NodeMirror.c).
static UINT NodeProfileTcp(const UCHAR *packet, UINT size) {
	UINT offset, proto, fragment = 0;

	if (packet == NULL || size < 20)
		return NODE_PROFILE_NOT_TCP;

	switch (packet[0] >> 4) {
	case 4:
		if (packet[9] != IP_PROTO_TCP)
			return NODE_PROFILE_NOT_TCP;

		offset = (packet[0] & 0x0F) * 4;
		fragment = ((((UINT)packet[6] & 0x1F) << 8) | packet[7]) * 8;
		if (offset < 20 || offset > size)
			return NODE_PROFILE_HIDDEN;
		break;
	case 6:
		if (size < 40)
			return NODE_PROFILE_NOT_TCP;

		proto = packet[6];
		offset = 40;
		for (UINT i = 0; proto == IPV6_HEADER_HOP || proto == IPV6_HEADER_ROUTING || proto == IPV6_HEADER_ENDPOINT || proto == IPV6_HEADER_FRAGMENT; i++) {
			UINT length = 8;

			// Every extension header has 8 bytes at least: the next header, then its length in units of 8 bytes past the
			// first 8, but a fragment header, which is 8 bytes and holds the offset of the fragment
			if (i == NODE_PROFILE_MAX_HEADERS || size - offset < 8)
				return NODE_PROFILE_HIDDEN;

			if (proto == IPV6_HEADER_FRAGMENT)
				fragment = ((((UINT)packet[offset + 2] << 8) | packet[offset + 3]) & 0xFFF8);
			else
				length = ((UINT)packet[offset + 1] + 1) * 8;

			if (length > size - offset)
				return NODE_PROFILE_HIDDEN;

			proto = packet[offset];
			offset += length;
		}

		if (proto != IP_PROTO_TCP)
			return NODE_PROFILE_NOT_TCP;
		break;
	default:
		return NODE_PROFILE_NOT_TCP;
	}

	// A later fragment holds no flags, unless it starts at or before them: then it may write over them (RFC 1858)
	if (fragment != 0)
		return (fragment <= 13 ? NODE_PROFILE_HIDDEN : NODE_PROFILE_NOT_TCP);

	// The flags are byte 13 of the TCP header
	if (size - offset < 14)
		return NODE_PROFILE_HIDDEN;

	return packet[offset + 13];
}

// Whether a packet with the TCP flags tcp (NodeProfileTcp) to a device (to) or from it opens a TCP connection to the
// device: a SYN to it, a SYN-ACK from it, or a header that may hide either
static bool NodeProfileServes(UINT tcp, bool to) {
	if (tcp == NODE_PROFILE_NOT_TCP)
		return false;
	if (tcp == NODE_PROFILE_HIDDEN)
		return true;
	if ((tcp & TCP_SYN) == 0)
		return false;

	return (to ? (tcp & TCP_ACK) == 0 : (tcp & TCP_ACK) != 0);
}

// Whether the address addr of size bytes is one of the num addresses of list in the VRF vrf_id
static bool NodeProfileOwns(const NODE_PROFILE_ADDRESS *list, UINT num, UINT vrf_id, const UCHAR *addr, UINT size) {
	for (UINT i = 0; i < num; i++)
		if (list[i].VrfId == vrf_id && list[i].Size == size && Cmp(list[i].Address, addr, size) == 0)
			return true;

	return false;
}

// Address i of the family of size bytes among the addresses of a VRF that a session sent from
static UCHAR *NodeProfileSlot(NODE_PROFILE_SOURCES *e, UINT size, UINT i) {
	return (size == 4 ? e->Ipv4[i] : e->Ipv6[i]);
}

// Whether the session of the peer s may send from the address src of size bytes in the VRF vrf_id: an address that it sent
// from before, or a new one while it sent from fewer than max of its family, which it takes then. Without a limit every
// address may.
static bool NodeProfileSource(NODE_PROFILE_PEER *s, UINT vrf_id, const UCHAR *src, UINT size, UINT max) {
	bool ok = false;

	if (max == 0)
		return true;

	max = MIN(max, NODE_PROFILE_MAX_ADDRESSES);

	AcquireSRWLockExclusive(&s->Lock);
	{
		NODE_PROFILE_SOURCES *e = NULL;

		for (UINT i = 0; i < LIST_NUM(s->Sources) && e == NULL; i++) {
			NODE_PROFILE_SOURCES *f = LIST_DATA(s->Sources, i);

			if (f->VrfId == vrf_id)
				e = f;
		}

		// A VRF of the node: there are CONTROL_MAX_VRFS of them at most
		if (e == NULL && LIST_NUM(s->Sources) < CONTROL_MAX_VRFS) {
			e = ZeroMalloc(sizeof(NODE_PROFILE_SOURCES));
			e->VrfId = vrf_id;
			Add(s->Sources, e);
		}

		if (e != NULL) {
			UINT *num = (size == 4 ? &e->NumIpv4 : &e->NumIpv6);

			for (UINT i = 0; i < *num && ok == false; i++)
				ok = (Cmp(NodeProfileSlot(e, size, i), src, size) == 0);

			if (ok == false && *num < max) {
				Copy(NodeProfileSlot(e, size, *num), src, size);
				(*num)++;
				ok = true;
			}
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	return ok;
}

// Judge a packet of the VRF vrf_id between the host and the peer of next hop hop of the tables v, from the host to the peer
// when out is set, as the overlay sees it: the profile of the peer, then the flags of the node's own, then the addresses
// that the session of the peer sends from, then the bucket of the session. False drops it, counted by its reason.
static bool NodeProfileJudge(NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size, bool out) {
	NODE_PROFILE_TABLE *t = (v != NULL ? v->Profile : NULL);
	UCHAR src[16], dst[16];
	UINT addr_size = 0;
	volatile LONG64 *dropped = NULL;

	if (t == NULL)
		return true;

	NODE_PROFILE *pr = t->Profile;
	const NODE_PROFILE_HOP *h = (hop < t->NumHops && t->Hops[hop].Peer != NULL ? &t->Hops[hop] : NULL);

	// Neither the peer nor the node runs under a profile
	if (h == NULL && t->Own == false)
		return true;

	if (NodeProfileEnds(packet, size, src, dst, &addr_size) == false)
		return false;

	// The end of the packet at the peer and the end at the host of the node, and the flags of its TCP header
	const UCHAR *at_peer = (out ? dst : src), *at_host = (out ? src : dst);
	UINT tcp = ((h != NULL && h->NoServer) || (t->Own && t->NoServer) ? NodeProfileTcp(packet, size) : NODE_PROFILE_NOT_TCP);

	if (h != NULL) {
		InterlockedExchange64(&h->Peer->LastPacket, (LONG64)GetTickCount64());

		if (h->PrivacyFilter && t->Own && t->PrivacyFilter)
			dropped = &pr->Isolated;
		else if (h->NoRouting && NodeProfileOwns(h->Addresses, h->NumAddresses, vrf_id, at_peer, addr_size) == false)
			dropped = &pr->Routing;
		else if (h->NoServer && NodeProfileServes(tcp, out))
			dropped = &pr->Server;
	}

	if (dropped == NULL && t->Own) {
		if (t->NoRouting && NodeProfileOwns(t->OwnAddresses, t->NumOwn, vrf_id, at_host, addr_size) == false)
			dropped = &pr->Routing;
		else if (t->NoServer && NodeProfileServes(tcp, out == false))
			dropped = &pr->Server;
	}

	if (dropped == NULL && h != NULL && out == false && NodeProfileSource(h->Peer, vrf_id, src, addr_size, (addr_size == 4 ? h->MaxIpv4 : h->MaxIpv6)) == false)
		dropped = &pr->Addresses;

	if (dropped == NULL && h != NULL && NodeProfileTake(out ? &h->Download : &h->Upload, size, t->Frequency) == false)
		dropped = (out ? &pr->Download : &pr->Upload);

	if (dropped == NULL)
		return true;

	InterlockedIncrement64(dropped);
	return false;
}

// A packet of the host in the VRF vrf_id on its way to the peer of next hop hop, as the overlay sends it after the 1:1 NAT
// rules (NodeOverlayInput): false when the session profile of the peer, or the node's own, drops it. The caller is an online
// reader of the node's table snapshot, which holds v.
bool NodeProfileOutbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size) {
	return NodeProfileJudge(v, vrf_id, hop, packet, size, true);
}

// A packet that the peer of next hop hop sent in the VRF vrf_id, before the 1:1 NAT rules of the node (NodeOverlayDeliver):
// false when the session profile of the peer, or the node's own, drops it. The caller is an online reader of the node's
// table snapshot, which holds v.
bool NodeProfileInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size) {
	return NodeProfileJudge(v, vrf_id, hop, packet, size, false);
}

//
// The Generations
//

// Start the session profiles of the overlay of a node (NodeOverlayStart)
void NodeProfileStart(NODE *n) {
	LARGE_INTEGER freq;

	if (n == NULL || n->Profile != NULL)
		return;

	NODE_PROFILE *pr = ZeroMalloc(sizeof(NODE_PROFILE));
	QueryPerformanceFrequency(&freq);
	pr->Frequency = MAX((UINT64)freq.QuadPart, 1);
	pr->Lock = NewLock();
	pr->Peers = NewListFast(NodeProfileCompare);
	pr->Up = NewListFast(NodeProfileCompare);

	n->Profile = pr;
}

// Stop the session profiles of the overlay of a node (NodeOverlayStop), once no forwarding tables are left whose profile
// tables hold a session and the thread of the overlay, which asks about the sessions, ended
void NodeProfileStop(NODE *n) {
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);

	if (pr == NULL)
		return;

	n->Profile = NULL;

	for (UINT i = 0; i < LIST_NUM(pr->Peers); i++)
		NodeProfileFreePeer(LIST_DATA(pr->Peers, i));
	ReleaseList(pr->Peers);
	for (UINT i = 0; i < LIST_NUM(pr->Up); i++)
		Free(LIST_DATA(pr->Up, i));
	ReleaseList(pr->Up);
	DeleteLock(pr->Lock);
	Free(pr);
}

// The own addresses of the peer cp, of IPv4 and IPv6, into list from next on: their number
static UINT NodeProfileAddressesOf(NODE_PROFILE_ADDRESS *list, UINT next, const CONTROL_ADDRESS *src, UINT num) {
	UINT ret = 0;

	for (UINT i = 0; i < num && i < CONTROL_MAX_ADDRESSES; i++) {
		if (src[i].AddressSize != 4 && src[i].AddressSize != 16)
			continue;

		NODE_PROFILE_ADDRESS *a = &list[next + ret++];
		a->VrfId = src[i].VrfId;
		a->Size = src[i].AddressSize;
		Copy(a->Address, src[i].Address, src[i].AddressSize);
	}

	return ret;
}

// The profile table of the Generation of st onto its forwarding tables v, before they go in: the profile of the peer of each
// next hop, on its session that outlives the Generations, and the profile of the node itself. No table for a state in which
// neither the node nor a peer runs under a profile.
void NodeProfileAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);
	UINT num_profiles = 0, num_timed = 0, num_addresses = 0;

	if (pr == NULL || v == NULL || st == NULL)
		return;

	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PROFILE *p = &st->Peers[i].Profile;

		if (p->Set == false)
			continue;

		num_profiles++;
		num_addresses += MIN(st->Peers[i].NumAddresses, CONTROL_MAX_ADDRESSES);
		if (p->IdleTimeout != 0 || p->AutoDisconnect != 0)
			num_timed++;
	}

	NODE_PROFILE_TABLE *t = NULL;
	if (st->Profile.Set || num_profiles != 0) {
		t = ZeroMalloc(sizeof(NODE_PROFILE_TABLE));
		t->Profile = pr;
		t->Frequency = pr->Frequency;
		t->Own = st->Profile.Set;
		t->NoRouting = st->Profile.NoRouting;
		t->NoServer = st->Profile.NoServer;
		t->PrivacyFilter = st->Profile.PrivacyFilter;
		t->NumOwn = NodeProfileAddressesOf(t->OwnAddresses, 0, st->Addresses, st->NumAddresses);
		t->NumHops = v->NumHops;
		t->Hops = ZeroMalloc(sizeof(NODE_PROFILE_HOP) * MAX(v->NumHops, 1));
		t->Addresses = ZeroMalloc(sizeof(NODE_PROFILE_ADDRESS) * MAX(num_addresses, 1));
	}

	Lock(pr->Lock);
	{
		UINT next = 0;

		Copy(&pr->Own, &st->Profile, sizeof(CONTROL_PROFILE));
		pr->NumPeers = num_profiles;

		// Next hop i is the peer of st->Peers[i]
		for (UINT i = 0; t != NULL && i < st->NumPeers && i < t->NumHops; i++) {
			const CONTROL_PEER *cp = &st->Peers[i];
			NODE_PROFILE_HOP *h = &t->Hops[i];

			if (cp->Profile.Set == false)
				continue;

			h->Peer = NodeProfileHold(pr, cp);
			NodeProfileLimit(&h->Upload, cp->Profile.UploadLimit, &h->Peer->UploadTat);
			NodeProfileLimit(&h->Download, cp->Profile.DownloadLimit, &h->Peer->DownloadTat);
			h->MaxIpv4 = cp->Profile.MaxIpv4;
			h->MaxIpv6 = cp->Profile.MaxIpv6;
			h->NoRouting = cp->Profile.NoRouting;
			h->NoServer = cp->Profile.NoServer;
			h->PrivacyFilter = cp->Profile.PrivacyFilter;
			h->Addresses = &t->Addresses[next];
			h->NumAddresses = NodeProfileAddressesOf(t->Addresses, next, cp->Addresses, cp->NumAddresses);
			next += h->NumAddresses;
		}

		// The next hop of a route that a VRF of a peer leaks leads to that peer, after the peers (NodeLeak.c)
		for (UINT k = st->NumPeers; t != NULL && k < t->NumHops; k++) {
			for (UINT i = 0; i < st->NumPeers && i < t->NumHops; i++) {
				if (v->Hops[k] != v->Hops[i])
					continue;

				Copy(&t->Hops[k], &t->Hops[i], sizeof(NODE_PROFILE_HOP));
				if (t->Hops[k].Peer != NULL)
					t->Hops[k].Peer->Refs++;
				break;
			}
		}
	}
	Unlock(pr->Lock);

	InterlockedExchange(&pr->Timed, (LONG)num_timed);

	if (t != NULL && st->Profile.Set)
		NodeLog(n, "Profile: generation %I64u: the node runs under SessionProfile %s of User %s, and %u of its peers under one", st->Generation, st->Profile.Name, st->Profile.User, num_profiles);
	else if (t != NULL)
		NodeLog(n, "Profile: generation %I64u: %u of the peers run under a session profile", st->Generation, num_profiles);

	NodeProfileFreeTable(v->Profile);
	v->Profile = t;
}

// Free a profile table: a session of a peer that no table holds any more goes
void NodeProfileFreeTable(NODE_PROFILE_TABLE *t) {
	if (t == NULL)
		return;

	NODE_PROFILE *pr = t->Profile;
	LIST *gone = NewListFast(NULL);

	Lock(pr->Lock);
	{
		for (UINT i = 0; i < t->NumHops; i++) {
			NODE_PROFILE_PEER *s = t->Hops[i].Peer;

			if (s != NULL && --s->Refs == 0) {
				Delete(pr->Peers, s);
				Add(gone, s);
			}
		}
	}
	Unlock(pr->Lock);

	for (UINT i = 0; i < LIST_NUM(gone); i++)
		NodeProfileFreePeer(LIST_DATA(gone, i));
	ReleaseList(gone);

	Free(t->Hops);
	Free(t->Addresses);
	Zero(t, sizeof(NODE_PROFILE_TABLE));
	Free(t);
}

//
// The sessions
//

// The overlay takes a session to the peer name and key, which has none (NodeOverlayAttach): false when the profile of the
// peer refuses it, as the node holds the most sessions of the devices of its User that the profile allows. A session that
// the node takes starts with no address that it sent from and its idle time anew. The overlay calls it on its thread under
// its own lock: the lock of the profiles is taken after that one, never before it.
bool NodeProfileUp(NODE *n, const char *name, const UCHAR *key) {
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);
	char user[CONTROL_NAME_SIZE] = {0}, profile[CONTROL_NAME_SIZE] = {0};
	UINT held = 0;
	bool ok = true, say = false;

	if (pr == NULL || name == NULL || key == NULL)
		return true;

	Lock(pr->Lock);
	{
		NODE_PROFILE_PEER *s = NodeProfileFind(pr->Peers, name, key);

		if (s != NULL && s->Profile.Set && s->Profile.MaxSessions != 0) {
			// The sessions that the node holds of the devices of the same User
			for (UINT i = 0; i < LIST_NUM(pr->Up); i++) {
				NODE_PROFILE_UP *u = LIST_DATA(pr->Up, i);
				NODE_PROFILE_PEER *o = NodeProfileFind(pr->Peers, u->Id.Name, u->Id.Key);

				if (o != NULL && o->Profile.Set && StrCmp(o->Profile.User, s->Profile.User) == 0)
					held++;
			}
			ok = (held < s->Profile.MaxSessions);
		}

		if (ok && NodeProfileFind(pr->Up, name, key) == NULL) {
			NODE_PROFILE_UP *u = ZeroMalloc(sizeof(NODE_PROFILE_UP));

			StrCpy(u->Id.Name, sizeof(u->Id.Name), name);
			Copy(u->Id.Key, key, PEER_KEY_SIZE);
			Insert(pr->Up, u);
		}

		if (ok && s != NULL) {
			s->Refusing = false;
			InterlockedExchange64(&s->LastPacket, (LONG64)GetTickCount64());
			NodeProfileForget(s);
		} else if (ok == false && s != NULL) {
			say = (s->Refusing == false);
			s->Refusing = true;
			StrCpy(user, sizeof(user), s->Profile.User);
			StrCpy(profile, sizeof(profile), s->Profile.Name);
		}
	}
	Unlock(pr->Lock);

	if (ok == false)
		InterlockedIncrement64(&pr->Refused);
	if (say)
		NodeLog(n, "Profile: the session of %s refused: the node holds %u sessions of the devices of User %s, the most that SessionProfile %s allows", name, held, user, profile);

	return ok;
}

// The overlay closed the session of the peer name and key (NodeOverlayClose): it counts towards the most sessions of its
// User no more
void NodeProfileDown(NODE *n, const char *name, const UCHAR *key) {
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);
	NODE_PROFILE_UP *u = NULL;

	if (pr == NULL || name == NULL || key == NULL)
		return;

	Lock(pr->Lock);
	{
		u = NodeProfileFind(pr->Up, name, key);
		if (u != NULL)
			Delete(pr->Up, u);
	}
	Unlock(pr->Lock);

	Free(u);
}

// Whether the profile of the peer name and key ends its session, which came up at the GetTickCount64 since, at now: the
// automatic disconnect, once it came up that long ago, else the idle timeout, once it carried no packet for that long.
// NODE_PROFILE_LIVE while it goes on. The overlay asks on its thread about each session that it holds, and closes the one
// that a profile ends.
UINT NodeProfileExpired(NODE *n, const char *name, const UCHAR *key, UINT64 since, UINT64 now) {
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);
	char profile[CONTROL_NAME_SIZE] = {0};
	UINT ret = NODE_PROFILE_LIVE, seconds = 0;

	if (pr == NULL || name == NULL || key == NULL || ReadAcquire(&pr->Timed) == 0)
		return NODE_PROFILE_LIVE;

	Lock(pr->Lock);
	{
		NODE_PROFILE_PEER *s = NodeProfileFind(pr->Peers, name, key);

		if (s != NULL && s->Profile.Set) {
			UINT64 last = MAX(since, (UINT64)ReadAcquire64(&s->LastPacket));

			if (s->Profile.AutoDisconnect != 0 && now >= since + (UINT64)s->Profile.AutoDisconnect * 1000) {
				ret = NODE_PROFILE_AUTO;
				seconds = s->Profile.AutoDisconnect;
			} else if (s->Profile.IdleTimeout != 0 && now >= last + (UINT64)s->Profile.IdleTimeout * 1000) {
				ret = NODE_PROFILE_IDLE;
				seconds = s->Profile.IdleTimeout;
			}

			if (ret != NODE_PROFILE_LIVE)
				StrCpy(profile, sizeof(profile), s->Profile.Name);
		}
	}
	Unlock(pr->Lock);

	if (ret == NODE_PROFILE_AUTO) {
		InterlockedIncrement64(&pr->Disconnected);
		NodeLog(n, "Profile: the session of %s ends %u s after it came up: the automatic disconnect of SessionProfile %s", name, seconds, profile);
	} else if (ret == NODE_PROFILE_IDLE) {
		InterlockedIncrement64(&pr->Idle);
		NodeLog(n, "Profile: the session of %s ends after %u s without a packet: the idle timeout of SessionProfile %s", name, seconds, profile);
	}

	return ret;
}

// The guard of the member of the session of a device in an L2 Network (Core/Policy.h), from the session profile p of the
// device, onto the member configuration m: the MAC check with the most MAC addresses of p, or with one address, the first
// that the session sends from, under no-bridge; client isolation under the privacy filter. The rest of m stays as it is,
// and so does all of it for a device that runs under no profile. The member then goes to SwitchSecurityMember, which adds
// the protections of the Network, and its limits where the profile sets none.
void NodeProfileMember(const CONTROL_PROFILE *p, POLICY_MEMBER_CONFIG *m) {
	if (p == NULL || m == NULL || p->Set == false)
		return;

	if (p->NoBridge || p->MaxMacs != 0) {
		m->Guard |= POLICY_GUARD_CHECK_MAC;
		m->MaxMacs = (p->NoBridge ? 1 : MIN(p->MaxMacs, POLICY_MAX_BOUND));
	}
	if (p->PrivacyFilter)
		m->Guard |= POLICY_GUARD_ISOLATE;
}

// What the session profiles of the overlay of a node did, and the profile that it runs under
void NodeProfileGetStatus(NODE *n, NODE_PROFILE_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_PROFILE_STATUS));
	NODE_PROFILE *pr = (n != NULL ? n->Profile : NULL);
	if (pr == NULL)
		return;

	Lock(pr->Lock);
	Copy(&st->Own, &pr->Own, sizeof(CONTROL_PROFILE));
	st->NumPeers = pr->NumPeers;
	Unlock(pr->Lock);

	st->Upload = (UINT64)ReadAcquire64(&pr->Upload);
	st->Download = (UINT64)ReadAcquire64(&pr->Download);
	st->Addresses = (UINT64)ReadAcquire64(&pr->Addresses);
	st->Routing = (UINT64)ReadAcquire64(&pr->Routing);
	st->Server = (UINT64)ReadAcquire64(&pr->Server);
	st->Isolated = (UINT64)ReadAcquire64(&pr->Isolated);
	st->Refused = (UINT64)ReadAcquire64(&pr->Refused);
	st->Idle = (UINT64)ReadAcquire64(&pr->Idle);
	st->Disconnected = (UINT64)ReadAcquire64(&pr->Disconnected);
}
