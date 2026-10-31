// NodePeering.c
// The BGP peering of the standard mode (SDN-77, #357; ADR-0010, ADR-0022). In a VRF whose links are of kind vxlan or geneve and
// whose peering is bgp, the nodes exchange their routes by BGP, as routers do, in a full mesh, on the network that the operator
// trusts. Each node runs a sidecar of its own for it: ranz bgp (GoBGP) of ranz.exe next to the executable of the node
// (NODE.BgpSidecar), as the sidecar of NodeBgp.c, on a pipe of its own with the same JSON messages (the protocol of
// ranz-bgp/internal/sidecar and its peering of the standard mode). The Controller gives the settings of the sidecar in the
// NodeConfig (CONTROL_STATE.Peering): the AS of the overlay, the router id of the node, its address on the network that the
// operator trusts, where the sidecar listens on TCP 179 and connects from, and the LAN subnets that the node announces; and in
// the Peer object of each peer that shares such a VRF the address of the sidecar of that peer, the hold time of their session,
// its VRFs and what the peer may announce there (CONTROL_PEER.Peering). The Controller writes nothing else: the routes go
// between the sidecars, and the Controller is not in their path.
//
// The node announces its addresses in each VRF that peers by BGP and its LAN subnets there. It takes a route that its sidecar
// learned as a route of the peer that announced it (CONTROL_PEER.Routes): the forwarding table of the VRF leads it to that peer,
// and the adapter of the VRF of the host takes it with the other routes of the peer, through IP Helper (NodeVrfAdapter.c). The
// learned routes go in with each Generation (NodePeeringWith), and when they change, the worker of the peering builds the
// forwarding tables of the Generation in force anew with them (NodeOverlayRebuild), from the copy of its state that the
// peering keeps. The LAN subnets that the node announces lead to its host with the other LAN subnets behind it
// (CONTROL_STATE.LanSubnets, NodeGateway.c; SDN-19, #195). The sidecar takes a session only from the address of a peer that the
// Controller named; it refuses any other, and the node counts each.
//
// The node reports the peers of its sidecar, the state of each session and the prefixes learned from each, with the sessions
// refused, on its control stream (ControlSetPeeringReport), which ranz explain shows. A sidecar that ends by itself, or does
// not start, starts again after NODE_PEERING_RESTART; the routes that it learned go with it.
//
// What the review of SDN-77 asked of the node (SDN-77-R1, #531):
// - No change of the learned routes is lost: the worker never waits for an apply of the overlay, whose lock it only tries. A
//   rebuild that meets an apply tries again once the apply is done, and one that finds another Generation in force then leaves
//   Dirty set, so that the next pass, which the apply woke, builds the tables of that Generation with the routes of its time. A
//   copy of the state or a rebuild that fails is logged and leaves Dirty set too, for another try after NODE_PEERING_RETRY.
// - The sidecar reports a route only when it is exactly a prefix of the accept list of its peer in its VRF, so each peer holds what
//   it may announce and nothing more, and the node keeps every route that the sidecar reports: no peer takes room from another, and
//   no route is dropped. The tables of a Generation take a learned route only while the accept list of its peer there holds it.
// - A message that does not reach the sidecar, a full pipe or a line too long, ends it: the reader hears the pipe close, the
//   routes go, and another sidecar starts with the full state of the Generation in force. The peers go in peers messages of one
//   line each at most (protocol 4), so a mesh of any size fits, and the node holds and counts every peer, beyond the 64 of a report.
// - The node asks the sidecar every NODE_PEERING_PING whether it runs (ping), and the sidecar answers once GoBGP answers it (pong):
//   one that does not answer within NODE_PEERING_ANSWER hangs, and the node ends it as above, so its routes do not stay.
// - The halt is answered at once: every wait of the worker ends at the halt, and a sidecar that stops is not waited for at the
//   halt: a wait of the thread pool gives it NODE_PEERING_EXIT_WAIT to stop BGP, which sends the peers a Cease, and exit, then its
//   job ends it. So NodeOverlayStop waits for no sidecar, also under the lock of the node (NodeClientFree).

#include "NodePeering.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#include <AclAPI.h>
#include <WinDNS.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <sddl.h>

#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

// The strict DACL of the pipe, as the one of the sidecar of NodeBgp.c (ADR-0039 decision 3): the owner alone, the account of
// the node, which its sidecar runs as
#define NODE_PEERING_PIPE_SDDL L"D:P(A;;GA;;;OW)"

#define NODE_PEERING_CONNECT_WAIT 30000  // How long the worker waits for the sidecar to connect to its pipe (ms)
#define NODE_PEERING_WRITE_WAIT   5000   // How long one message may take to reach the pipe (ms)
#define NODE_PEERING_EXIT_WAIT    10000  // How long the sidecar may take to stop BGP and exit after the pipe closes (ms)
#define NODE_PEERING_READ_SIZE    4096   // Bytes of one read of the pipe
#define NODE_PEERING_BUSY         20     // ms between two tries of a rebuild for the lock of an apply that runs
#define NODE_PEERING_RETRY        1000   // ms before the worker tries again a rebuild that failed
#define NODE_PEERING_PEERS_HEAD   64     // Bytes of a peers message besides its peers at most, with its newline
#define NODE_PEERING_IDLE         "idle" // The state of the session of a peer before the sidecar names one

// What NodePeeringInject made of a learned route
#define NODE_PEERING_IN      0 // It is a route of its peer now
#define NODE_PEERING_SKIP    1 // The state does not take it: its peer or its VRF is none of the peering, or it is an address of the peer
#define NODE_PEERING_FULL    2 // The routes of its peer are full
#define NODE_PEERING_OUTSIDE 3 // Its peer may not announce it in the state: the accept list of the peer there does not hold it

// A route that the sidecar learned: a prefix of a VRF, from the peer of an address
typedef struct NODE_PEERING_ROUTE {
	UINT VrfId;        // The VRF
	UCHAR Address[16]; // The prefix: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
	UINT Length;       // ... and its length
	UCHAR Peer[16];    // The address of the sidecar of the peer that announced it
	UINT PeerSize;     // ... the number of its bytes
} NODE_PEERING_ROUTE;

// A peer of the sidecar, with the state of its session that the sidecar named last
typedef struct NODE_PEERING_PEER {
	UCHAR Address[16];                      // The address of the sidecar of the peer
	UINT AddressSize;                       // ... the number of its bytes
	char State[CONTROL_PEERING_STATE_SIZE]; // idle, connect, active, opensent, openconfirm or established
	bool Named;                             // The sidecar that runs named a state of the session: it has the peer
} NODE_PEERING_PEER;

// A prefix that the node announces, as the sidecar names it
typedef struct NODE_PEERING_PREFIX {
	UINT VrfId;            // Its VRF
	char Prefix[MAX_SIZE]; // ... and the prefix
} NODE_PEERING_PREFIX;

// The process of a sidecar of the peering, which the worker starts and stops
typedef struct NODE_PEERING_SIDECAR {
	wchar_t PipeName[MAX_PATH]; // The name of its pipe
	HANDLE Pipe;                // The server end of the pipe, overlapped
	char PipeAcl[MAX_SIZE];     // The DACL of the pipe as the system holds it, in SDDL
	HANDLE WriteEvent;          // The event of a write
	HANDLE StopEvent;           // Ends the reader thread
	HANDLE Job;                 // The job of the sidecar: it ends with the node, also when the node does not stop
	HANDLE Process;             // The sidecar
	UINT ProcessId;             // ... its process id
	HANDLE Reader;              // The thread that reads its messages
	char *Line;                 // The reader thread: the message read so far
	UINT LineSize;              // ... its bytes
	UINT Asn;                   // The settings that it runs with: the AS, the router id and the address of the node
	UCHAR RouterId[4];
	UCHAR Address[16];
	UINT AddressSize;
	char *Peers; // The peers that it took last, as the JSON array of the protocol
	bool Dead;   // The worker's: it gets no message any more, as one did not reach it, it hangs, or the overlay stops
} NODE_PEERING_SIDECAR;

// A sidecar that stopped and that the worker does not wait for (NodePeeringLetGo): a wait of the thread pool closes its handles
// once it exits, or ends it through its job after NODE_PEERING_EXIT_WAIT. It is memory of the heap of the process, so that
// nothing of it is left to the node, which may be gone by then.
typedef struct NODE_PEERING_EXITING {
	HANDLE Process; // The sidecar
	HANDLE Job;     // ... and its job, which ends it when it closes
} NODE_PEERING_EXITING;

// The peering of a node
struct NODE_PEERING {
	NODE *Node;
	LOCK *Lock;                     // What follows, but what is the worker's own
	HANDLE Wake;                    // The worker has something to do (an auto-reset event)
	HANDLE Halt;                    // Ends the worker (a manual-reset event)
	HANDLE Worker;                  // The worker, which starts and stops the sidecar and builds the forwarding tables anew
	bool Halted;                    // The peering takes no state any more: NodePeeringHalt ran, or the worker did not start
	CONTROL_PEERING_REPORT *Report; // What the control stream reports of the peering

	CONTROL_STATE *State; // A copy of the Generation in force while it has a peering of the node, NULL for none
	bool Changed;         // State changed since the worker settled the sidecar on it, or a sidecar has to start again
	bool Dirty;           // The learned routes changed since the forwarding tables took them
	UINT64 NextRebuild;   // ... and no rebuild goes before this tick, after one that failed
	bool Reported;        // The peers, their sessions, the learned routes or the refused sessions changed since the report
	UINT64 Pinged;        // When the worker asked the sidecar whether it runs (ping), 0 while it has the answer
	UINT64 Answered;      // When the sidecar answered last (pong), or started

	NODE_PEERING_SIDECAR *Sidecar; // The sidecar that runs, NULL for none: the worker's, which the reader thread reads
	bool Ready;                    // ... it sent ready: BGP runs
	bool Exited;                   // ... it closed the pipe by itself
	UINT64 NextStart;              // The worker's: no sidecar starts before this tick
	char Version[MAX_SIZE];        // What the sidecar named in ready
	UINT NumStarts;                // The sidecars that started
	UINT NumErrors;                // Error messages of the sidecars
	UINT NumRebuilds;              // The forwarding tables built anew with the learned routes
	UINT NumDeferred;              // ... rebuilds that met an apply
	UINT NumFailed;                // ... rebuilds that failed: no copy of the Generation in force, or no tables
	UINT FailCopies;               // A test's (NodePeeringFailNext): the copies of the state for a rebuild that fail next ...
	UINT FailRebuilds;             // ... and then the rebuilds that fail
	UINT NumUnsent;                // The sidecars ended because a message did not reach them
	UINT NumHung;                  // The sidecars ended because they did not answer a ping
	UINT NumAnnounced;             // The prefixes that the node announces
	UINT64 Refused;                // The sessions that the sidecars refused
	LIST *Peers;                   // The peers of the sidecar (NODE_PEERING_PEER)
	LIST *Routes;                  // The learned routes (NODE_PEERING_ROUTE)
	LIST *Announced;               // The prefixes that the node announces (NODE_PEERING_PREFIX): the worker's
};

//
// Addresses and prefixes
//

// The text of the address of addr_size bytes at addr into str: an IPv4 or an IPv6 address
static void NodePeeringAddrText(char *str, UINT size, const UCHAR *addr, UINT addr_size) {
	IP ip;

	if (addr_size == 4) {
		Format(str, size, "%u.%u.%u.%u", (UINT)addr[0], (UINT)addr[1], (UINT)addr[2], (UINT)addr[3]);
		return;
	}

	Zero(&ip, sizeof(ip));
	SetIP6(&ip, addr);
	IPToStr(str, size, &ip);
}

// The text of a prefix into str: its address with the host bits cleared, then its length
static void NodePeeringPrefixText(char *str, UINT size, const UCHAR *addr, UINT addr_size, UINT length) {
	UCHAR masked[16];
	char text[MAX_SIZE];

	Zero(masked, sizeof(masked));
	Copy(masked, addr, MIN(addr_size, 16));
	for (UINT i = 0; i < 16; i++) {
		UINT bits = (length > i * 8 ? length - i * 8 : 0);

		if (bits < 8)
			masked[i] &= (UCHAR)(0xFF00 >> bits);
	}

	NodePeeringAddrText(text, sizeof(text), masked, addr_size);
	Format(str, size, "%s/%u", text, length);
}

// The address of the text str, or with types NET_STRING_IP_NETWORK its prefix, into addr (16 bytes) with the number of its
// bytes and its length: false for anything else
static bool NodePeeringParse(const char *str, DWORD types, UCHAR *addr, UINT *size, UINT *length) {
	wchar_t tmp[MAX_SIZE];
	NET_ADDRESS_INFO info;
	BYTE len = 0;

	Zero(addr, 16);
	*size = 0;
	if (length != NULL)
		*length = 0;
	if (IsEmptyStr(str) || StrLen(str) >= MAX_SIZE)
		return false;

	StrToUni(tmp, sizeof(tmp), str);
	Zero(&info, sizeof(info));
	if (ParseNetworkString(tmp, types, &info, NULL, (types == NET_STRING_IP_NETWORK ? &len : NULL)) != ERROR_SUCCESS)
		return false;

	if (info.Format == NET_ADDRESS_IPV4) {
		Copy(addr, &info.Ipv4Address.sin_addr, 4);
		*size = 4;
	} else if (info.Format == NET_ADDRESS_IPV6) {
		Copy(addr, &info.Ipv6Address.sin6_addr, 16);
		*size = 16;
	} else {
		return false;
	}

	if (length != NULL)
		*length = len;

	return true;
}

// Whether the VRF vrf_id of the state peers by BGP
static bool NodePeeringVrfPeers(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return st->Vrfs[i].Peering;

	return false;
}

// Whether vrf_id is a VRF of the session of the peering c
static bool NodePeeringHasVrf(const CONTROL_PEER_PEERING *c, UINT vrf_id) {
	for (UINT i = 0; i < c->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (c->VrfIds[i] == vrf_id)
			return true;

	return false;
}

// Whether the sidecar of the node takes the peer of the peering c of the state: a peer of an address of the family of the
// node's own and another, with a VRF of the session that is not 0
static bool NodePeeringTakes(const CONTROL_STATE *st, const CONTROL_PEER_PEERING *c) {
	const CONTROL_PEERING *own = st->Peering;

	if (own == NULL || c == NULL || c->AddressSize != own->AddressSize || Cmp(c->Address, own->Address, own->AddressSize) == 0)
		return false;

	for (UINT i = 0; i < c->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (c->VrfIds[i] != 0)
			return true;

	return false;
}

// Whether two prefixes are one: of one family and one length, with the same bits up to that length
static bool NodePeeringSamePrefix(const UCHAR *a, UINT a_size, UINT a_length, const UCHAR *b, UINT b_size, UINT b_length) {
	if (a_size != b_size || a_length != b_length || (a_size != 4 && a_size != 16) || a_length > a_size * 8)
		return false;

	UINT bytes = a_length / 8;
	UINT bits = a_length % 8;

	if (Cmp(a, b, bytes) != 0)
		return false;

	return (bits == 0 || ((a[bytes] ^ b[bytes]) & (UCHAR)(0xFF00 >> bits)) == 0);
}

// Whether the peering c of a peer accepts the prefix addr/length of the VRF vrf_id from it: one of the prefixes that the peer may
// announce there, exactly, as the sidecar takes them (accepts of ranz-bgp/internal/sidecar/peering.go)
static bool NodePeeringAccepts(const CONTROL_PEER_PEERING *c, UINT vrf_id, const UCHAR *addr, UINT size, UINT length) {
	for (UINT i = 0; i < c->NumAccept && i < CONTROL_MAX_ACCEPT; i++) {
		const CONTROL_ROUTE *a = &c->Accept[i];

		if (a->VrfId == vrf_id && NodePeeringSamePrefix(a->Address, a->AddressSize, a->Length, addr, size, length))
			return true;
	}

	return false;
}

//
// The learned routes, the peers and the report. The callers hold the lock.
//

// The peer of the address addr among the peers of the sidecar, NULL for none
static NODE_PEERING_PEER *NodePeeringFindPeer(NODE_PEERING *p, const UCHAR *addr, UINT size) {
	for (UINT i = 0; i < LIST_NUM(p->Peers); i++) {
		NODE_PEERING_PEER *q = LIST_DATA(p->Peers, i);

		if (q->AddressSize == size && Cmp(q->Address, addr, size) == 0)
			return q;
	}

	return NULL;
}

// The learned route of a prefix of a VRF, NULL for none
static NODE_PEERING_ROUTE *NodePeeringFindRoute(NODE_PEERING *p, UINT vrf_id, const UCHAR *addr, UINT size, UINT length) {
	for (UINT i = 0; i < LIST_NUM(p->Routes); i++) {
		NODE_PEERING_ROUTE *r = LIST_DATA(p->Routes, i);

		if (r->VrfId == vrf_id && r->AddressSize == size && r->Length == length && Cmp(r->Address, addr, size) == 0)
			return r;
	}

	return NULL;
}

// Remove every learned route: their number. The forwarding tables take it when there were any.
static UINT NodePeeringClearRoutes(NODE_PEERING *p) {
	UINT num = LIST_NUM(p->Routes);

	for (UINT i = 0; i < num; i++)
		Free(LIST_DATA(p->Routes, i));
	DeleteAll(p->Routes);

	if (num != 0) {
		p->Dirty = true;
		p->Reported = true;
	}

	return num;
}

// Remove the peers of the sidecar
static void NodePeeringClearPeers(NODE_PEERING *p) {
	for (UINT i = 0; i < LIST_NUM(p->Peers); i++)
		Free(LIST_DATA(p->Peers, i));
	DeleteAll(p->Peers);
	p->Reported = true;
}

static int NodePeeringComparePeer(const void *p1, const void *p2) {
	const CONTROL_PEERING_PEER *a = (const CONTROL_PEERING_PEER *)p1;
	const CONTROL_PEERING_PEER *b = (const CONTROL_PEERING_PEER *)p2;

	if (a->AddressSize != b->AddressSize)
		return (a->AddressSize < b->AddressSize ? -1 : 1);

	return memcmp(a->Address, b->Address, a->AddressSize);
}

static int NodePeeringCompareRoute(const void *p1, const void *p2) {
	const CONTROL_ROUTE *a = (const CONTROL_ROUTE *)p1;
	const CONTROL_ROUTE *b = (const CONTROL_ROUTE *)p2;

	if (a->VrfId != b->VrfId)
		return (a->VrfId < b->VrfId ? -1 : 1);
	if (a->AddressSize != b->AddressSize)
		return (a->AddressSize < b->AddressSize ? -1 : 1);

	int c = memcmp(a->Address, b->Address, a->AddressSize);
	if (c != 0)
		return c;
	if (a->Length != b->Length)
		return (a->Length < b->Length ? -1 : 1);

	return 0;
}

// The peers of the sidecar, every one, each with the routes learned from it, into a new array in the order of their address, each
// route in the order of its VRF, then prefix: their number. The report on the control stream holds the first
// CONTROL_MAX_PEERING_PEERS of them (ControlSetPeeringReport); the node holds and counts them all (SDN-77-R1, #531).
static UINT NodePeeringReportPeers(NODE_PEERING *p, CONTROL_PEERING_PEER **out) {
	UINT num = LIST_NUM(p->Peers);
	CONTROL_PEERING_PEER *list = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * MAX(num, 1));

	for (UINT i = 0; i < num; i++) {
		NODE_PEERING_PEER *q = LIST_DATA(p->Peers, i);
		CONTROL_PEERING_PEER *c = &list[i];

		Copy(c->Address, q->Address, sizeof(c->Address));
		c->AddressSize = q->AddressSize;
		StrCpy(c->State, sizeof(c->State), q->State);

		for (UINT j = 0; j < LIST_NUM(p->Routes) && c->NumLearned < CONTROL_MAX_LEARNED; j++) {
			NODE_PEERING_ROUTE *r = LIST_DATA(p->Routes, j);
			CONTROL_ROUTE *l = &c->Learned[c->NumLearned];

			if (r->PeerSize != q->AddressSize || Cmp(r->Peer, q->Address, r->PeerSize) != 0)
				continue;

			l->VrfId = r->VrfId;
			Copy(l->Address, r->Address, sizeof(l->Address));
			l->AddressSize = r->AddressSize;
			l->Length = r->Length;
			c->NumLearned++;
		}

		qsort(c->Learned, c->NumLearned, sizeof(CONTROL_ROUTE), NodePeeringCompareRoute);
	}

	qsort(list, num, sizeof(CONTROL_PEERING_PEER), NodePeeringComparePeer);
	*out = list;

	return num;
}

//
// The messages of the sidecar
//

// The string member name of a JSON object; "" when it has none
static const char *NodePeeringJsonStr(const cJSON *o, const char *name) {
	const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));

	return (s != NULL ? s : "");
}

// The number member name of a JSON object as a UINT; 0 when it has none or it is out of range
static UINT NodePeeringJsonUint(const cJSON *o, const char *name) {
	const cJSON *item = cJSON_GetObjectItemCaseSensitive(o, name);

	if (cJSON_IsNumber(item) == false || item->valuedouble < 0 || item->valuedouble > 4294967295.0)
		return 0;

	return (UINT)item->valuedouble;
}

// A learned message: the route of the prefix of a VRF comes from the peer of an address now. Whether the routes changed. The node
// takes every route that the sidecar reports: the sidecar reports one only when it is exactly a prefix of the accept list of its
// peer in its VRF, so a peer holds what it may announce, CONTROL_MAX_ACCEPT routes at most, and no peer takes the room of another
// peer or VRF (SDN-77-R1, #531).
static bool NodePeeringLearned(NODE_PEERING *p, UINT vrf_id, const UCHAR *addr, UINT size, UINT length, const UCHAR *peer, UINT peer_size) {
	bool changed = false;

	Lock(p->Lock);
	{
		NODE_PEERING_ROUTE *r = NodePeeringFindRoute(p, vrf_id, addr, size, length);
		bool fresh = (r == NULL);

		if (fresh) {
			r = ZeroMalloc(sizeof(NODE_PEERING_ROUTE));
			r->VrfId = vrf_id;
			Copy(r->Address, addr, size);
			r->AddressSize = size;
			r->Length = length;
			Add(p->Routes, r);
		}

		// A new route, or one whose best path moved to another peer
		if (fresh || r->PeerSize != peer_size || Cmp(r->Peer, peer, peer_size) != 0) {
			Copy(r->Peer, peer, peer_size);
			r->PeerSize = peer_size;
			p->Dirty = true;
			p->Reported = true;
			changed = true;
		}
	}
	Unlock(p->Lock);

	return changed;
}

// A withdrawn message: no peer has a route to the prefix of a VRF any more. Whether the routes changed.
static bool NodePeeringWithdrawn(NODE_PEERING *p, UINT vrf_id, const UCHAR *addr, UINT size, UINT length) {
	bool changed = false;

	Lock(p->Lock);
	{
		NODE_PEERING_ROUTE *r = NodePeeringFindRoute(p, vrf_id, addr, size, length);

		if (r != NULL) {
			Delete(p->Routes, r);
			Free(r);
			p->Dirty = true;
			p->Reported = true;
			changed = true;
		}
	}
	Unlock(p->Lock);

	return changed;
}

// One message of the sidecar, on the reader thread
static void NodePeeringOnMessage(NODE_PEERING *p, const char *line) {
	UCHAR prefix[16];
	UCHAR peer[16];
	char peer_text[MAX_SIZE];
	UINT prefix_size = 0;
	UINT length = 0;
	UINT peer_size = 0;
	bool wake = false;
	cJSON *m = cJSON_Parse(line);
	const char *type = NodePeeringJsonStr(m, "type");

	StrCpy(peer_text, sizeof(peer_text), NodePeeringJsonStr(m, "peer"));
	bool has_peer = NodePeeringParse(peer_text, NET_STRING_IP_ADDRESS_NO_SCOPE, peer, &peer_size, NULL);

	if (cJSON_IsObject(m) == false) {
		NodeLog(p->Node, "BGP peering: a message of the sidecar that is not a JSON object");
	} else if (StrCmp(type, "ready") == 0) {
		Lock(p->Lock);
		{
			p->Ready = true;
			StrCpy(p->Version, sizeof(p->Version), NodePeeringJsonStr(m, "version"));
		}
		Unlock(p->Lock);

		NodeLog(p->Node, "BGP peering: the sidecar is ready: %s (protocol %u)", NodePeeringJsonStr(m, "version"), NodePeeringJsonUint(m, "protocol"));
	} else if (StrCmp(type, "peer") == 0) {
		Lock(p->Lock);
		{
			NODE_PEERING_PEER *q = (has_peer ? NodePeeringFindPeer(p, peer, peer_size) : NULL);

			if (q != NULL) {
				StrCpy(q->State, sizeof(q->State), NodePeeringJsonStr(m, "state"));
				q->Named = true;
				p->Reported = true;
				wake = true;
			}
		}
		Unlock(p->Lock);

		NodeLog(p->Node, "BGP peering: peer %s (AS %u): %s%s", peer_text, NodePeeringJsonUint(m, "asn"), NodePeeringJsonStr(m, "state"), wake ? "" : " (not a peer that the Controller named)");
	} else if (StrCmp(type, "learned") == 0 || StrCmp(type, "withdrawn") == 0) {
		bool learned = (StrCmp(type, "learned") == 0);
		UINT vrf_id = NodePeeringJsonUint(m, "vrf");
		const char *text = NodePeeringJsonStr(m, "prefix");

		if (vrf_id == 0 || NodePeeringParse(text, NET_STRING_IP_NETWORK, prefix, &prefix_size, &length) == false || (learned && has_peer == false)) {
			NodeLog(p->Node, "BGP peering: a %s message of the sidecar without a VRF, a prefix or a peer: VRF %u, prefix \"%s\", peer \"%s\"", type, vrf_id, text, peer_text);
		} else if (learned) {
			wake = NodePeeringLearned(p, vrf_id, prefix, prefix_size, length, peer, peer_size);
			NodeLog(p->Node, "BGP peering: route %s of VRF %u learned from %s, via %s", text, vrf_id, peer_text, NodePeeringJsonStr(m, "next_hop"));
		} else {
			wake = NodePeeringWithdrawn(p, vrf_id, prefix, prefix_size, length);
			NodeLog(p->Node, "BGP peering: route %s of VRF %u withdrawn%s%s", text, vrf_id, has_peer ? " by " : "", peer_text);
		}
	} else if (StrCmp(type, "refused") == 0) {
		Lock(p->Lock);
		{
			p->Refused++;
			p->Reported = true;
		}
		Unlock(p->Lock);

		NodeLog(p->Node, "BGP peering: a session from %s refused: the Controller named no peer of that address", peer_text);
		wake = true;
	} else if (StrCmp(type, "error") == 0) {
		const char *text = NodePeeringJsonStr(m, "prefix");

		Lock(p->Lock);
		{
			p->NumErrors++;
		}
		Unlock(p->Lock);

		NodeLog(p->Node, "BGP peering: sidecar error%s%s: %s", IsEmptyStr(text) ? "" : " for ", text, NodePeeringJsonStr(m, "error"));
	} else if (StrCmp(type, "pong") == 0) {
		// The answer to the question of the worker whether the sidecar runs (NodePeeringCheck): it runs, and GoBGP answers it
		Lock(p->Lock);
		{
			p->Pinged = 0;
			p->Answered = GetTickCount64();
		}
		Unlock(p->Lock);
	} else {
		NodeLog(p->Node, "BGP peering: a message of the unknown type \"%s\" of the sidecar ignored", type);
	}

	cJSON_Delete(m);

	if (wake)
		SetEvent(p->Wake);
}

// The thread that reads the messages of the sidecar until its stop event, or until the sidecar closes the pipe; then the
// learned routes go, because BGP is gone, and the worker starts another sidecar after NODE_PEERING_RESTART
static DWORD WINAPI NodePeeringReaderThread(void *param) {
	NODE_PEERING *p = (NODE_PEERING *)param;
	// The worker set the sidecar before it started the thread, and stops the thread before it takes the sidecar away
	NODE_PEERING_SIDECAR *s = p->Sidecar;
	UCHAR buf[NODE_PEERING_READ_SIZE];
	OVERLAPPED ov;
	HANDLE events[2];
	bool stopped = false;

	HANDLE read_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (read_event == NULL)
		return 0;

	// The stop event first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = s->StopEvent;
	events[1] = read_event;

	while (true) {
		DWORD got = 0;

		Zero(&ov, sizeof(ov));
		ov.hEvent = read_event;
		ResetEvent(read_event);

		if (ReadFile(s->Pipe, buf, sizeof(buf), NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
			break;

		if (WaitForMultipleObjects(2, events, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
			CancelIoEx(s->Pipe, &ov);
			GetOverlappedResult(s->Pipe, &ov, &got, TRUE);
			stopped = true;
			break;
		}

		if (GetOverlappedResult(s->Pipe, &ov, &got, FALSE) == FALSE)
			break;

		bool too_long = false;

		for (DWORD i = 0; i < got && too_long == false; i++) {
			if (buf[i] != '\n') {
				if (s->LineSize >= NODE_BGP_MAX_LINE)
					too_long = true;
				else
					s->Line[s->LineSize++] = (char)buf[i];
				continue;
			}

			s->Line[s->LineSize] = 0;
			if (s->LineSize != 0)
				NodePeeringOnMessage(p, s->Line);
			s->LineSize = 0;
		}

		if (too_long) {
			NodeLog(p->Node, "BGP peering: a message of the sidecar longer than %u bytes, the node stops reading", (UINT)NODE_BGP_MAX_LINE);
			break;
		}
	}

	CloseHandle(read_event);

	if (stopped == false) {
		UINT num = 0;

		Lock(p->Lock);
		{
			p->Exited = true;
			p->Ready = false;
			num = NodePeeringClearRoutes(p);
			for (UINT i = 0; i < LIST_NUM(p->Peers); i++) {
				NODE_PEERING_PEER *q = LIST_DATA(p->Peers, i);

				StrCpy(q->State, sizeof(q->State), NODE_PEERING_IDLE);
				q->Named = false;
			}
			p->Reported = true;
		}
		Unlock(p->Lock);

		NodeLog(p->Node, "BGP peering: the sidecar closed the pipe: BGP stopped, %u learned routes go", num);
		SetEvent(p->Wake);
	}

	return 0;
}

//
// The sidecar
//

// End the sidecar s, which the worker gives up on: it gets no message any more, and its job ends it, so the reader thread hears
// the pipe close, the routes that it learned go, and another sidecar starts after NODE_PEERING_RESTART with the full state of the
// Generation in force (NodePeeringSettle)
static void NodePeeringEnd(NODE_PEERING_SIDECAR *s) {
	if (s->Dead)
		return;

	s->Dead = true;
	TerminateJobObject(s->Job, 1);
}

// A message did not reach the sidecar s, for the reason why: the worker counts it and ends the sidecar (NodePeeringEnd), so that
// the next one has the peers, the announced prefixes and the withdrawn ones of the Generation in force, and not the ones that this
// one missed
static void NodePeeringUnsent(NODE_PEERING *p, NODE_PEERING_SIDECAR *s, const char *why) {
	Lock(p->Lock);
	p->NumUnsent++;
	Unlock(p->Lock);

	NodeLog(p->Node, "BGP peering: a message did not reach the sidecar (%s), so the node ends it and starts another with the state of the Generation in force", why);
	NodePeeringEnd(s);
}

// Send the line text to the sidecar s, on the worker, the one writer of the pipe. A line longer than the protocol allows, or that
// does not reach the pipe within NODE_PEERING_WRITE_WAIT, a full pipe, ends the sidecar (NodePeeringUnsent). The halt ends the
// wait at once: the sidecar then gets no message any more, as it stops anyway. False when the line did not reach the sidecar, and
// for a sidecar that gets no message any more.
static bool NodePeeringSendLine(NODE_PEERING *p, NODE_PEERING_SIDECAR *s, const char *text) {
	OVERLAPPED ov;
	DWORD done = 0;
	bool ret = false;
	bool halted = false;

	if (s->Dead)
		return false;

	UINT len = StrLen(text);
	if (len + 1 > NODE_BGP_MAX_LINE) {
		NodePeeringUnsent(p, s, "a line longer than the protocol allows");
		return false;
	}

	char *line = Malloc(len + 1);
	Copy(line, text, len);
	line[len] = '\n';

	Zero(&ov, sizeof(ov));
	ov.hEvent = s->WriteEvent;
	ResetEvent(s->WriteEvent);

	if (WriteFile(s->Pipe, line, len + 1, NULL, &ov) || GetLastError() == ERROR_IO_PENDING) {
		// The write first: WaitForMultipleObjects reports the lowest signalled index
		HANDLE waits[2] = {s->WriteEvent, p->Halt};
		DWORD w = WaitForMultipleObjects(2, waits, FALSE, NODE_PEERING_WRITE_WAIT);

		if (w != WAIT_OBJECT_0)
			CancelIoEx(s->Pipe, &ov);
		halted = (w == WAIT_OBJECT_0 + 1);

		ret = (GetOverlappedResult(s->Pipe, &ov, &done, TRUE) && done == len + 1);
	}

	Free(line);

	if (ret == false && halted)
		s->Dead = true;
	else if (ret == false)
		NodePeeringUnsent(p, s, "the pipe did not take it in time, or it broke");

	return ret;
}

// Send one message to the sidecar s (NodePeeringSendLine)
static bool NodePeeringSend(NODE_PEERING *p, NODE_PEERING_SIDECAR *s, const cJSON *m) {
	if (s->Dead)
		return false;

	char *text = cJSON_PrintUnformatted(m);
	if (text == NULL) {
		NodePeeringUnsent(p, s, "no memory for the message");
		return false;
	}

	bool ret = NodePeeringSendLine(p, s, text);
	cJSON_free(text);

	return ret;
}

// Free a sidecar whose reader thread ended or never started; its process is gone or ends with its job
static void NodePeeringFreeSidecar(NODE_PEERING_SIDECAR *s) {
	if (s == NULL)
		return;

	if (s->Pipe != INVALID_HANDLE_VALUE)
		CloseHandle(s->Pipe);
	if (s->Process != NULL)
		CloseHandle(s->Process);
	// Closing the job ends the sidecar if it still runs (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if (s->Job != NULL)
		CloseHandle(s->Job);
	if (s->WriteEvent != NULL)
		CloseHandle(s->WriteEvent);
	if (s->StopEvent != NULL)
		CloseHandle(s->StopEvent);

	Free(s->Line);
	Free(s->Peers);
	Free(s);
}

// The wait of the thread pool for a sidecar that stopped (NodePeeringLetGo) ended: it exited, or it did not within
// NODE_PEERING_EXIT_WAIT and its job ends it. It touches only what NODE_PEERING_EXITING holds.
static VOID CALLBACK NodePeeringExited(PTP_CALLBACK_INSTANCE instance, PVOID param, PTP_WAIT wait, TP_WAIT_RESULT result) {
	NODE_PEERING_EXITING *e = (NODE_PEERING_EXITING *)param;

	if (result != WAIT_OBJECT_0)
		TerminateJobObject(e->Job, 1);

	CloseHandle(e->Process);
	// Closing the job ends the sidecar if it still runs (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	CloseHandle(e->Job);
	HeapFree(GetProcessHeap(), 0, e);

	// The wait goes once this callback returns
	CloseThreadpoolWait(wait);
}

// Let the sidecar of the process process and the job job exit without the worker: a wait of the thread pool closes their handles
// once it exits, or ends it through its job after NODE_PEERING_EXIT_WAIT. The handles are the wait's then. False when the wait
// cannot be set, and the caller keeps them.
static bool NodePeeringLetGo(HANDLE process, HANDLE job) {
	LARGE_INTEGER due;
	FILETIME ft;

	NODE_PEERING_EXITING *e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NODE_PEERING_EXITING));
	if (e == NULL)
		return false;

	e->Process = process;
	e->Job = job;

	PTP_WAIT wait = CreateThreadpoolWait(NodePeeringExited, e, NULL);
	if (wait == NULL) {
		HeapFree(GetProcessHeap(), 0, e);
		return false;
	}

	// A time from now: negative, in units of 100 ns
	due.QuadPart = -((LONGLONG)NODE_PEERING_EXIT_WAIT * 10000);
	ft.dwLowDateTime = due.LowPart;
	ft.dwHighDateTime = (DWORD)due.HighPart;
	SetThreadpoolWait(wait, process, &ft);

	return true;
}

// Create the pipe of the sidecar, start the sidecar in its job and wait until it connects, as NodeBgp.c does, but not past the
// event halt. False when one step fails, or at the halt; the caller frees s.
static bool NodePeeringLaunch(NODE *n, NODE_PEERING_SIDECAR *s, HANDLE halt) {
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_ATTRIBUTES sa;
	OVERLAPPED ov;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t log_path[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];
	DWORD done = 0;
	ULONG client = 0;
	UINT nonce = 0;
	bool ret = false;

	// A name that another process cannot guess ahead of the node
	BCryptGenRandom(NULL, (UCHAR *)&nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	UniFormat(s->PipeName, sizeof(s->PipeName), L"\\\\.\\pipe\\ranz-bgp-peering-%u-%u", (UINT)GetCurrentProcessId(), nonce);

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_PEERING_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE) {
		NodeLog(n, "BGP peering not started: no security descriptor for the pipe (error %u)", (UINT)GetLastError());
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
	DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
	s->Pipe = CreateNamedPipeW(s->PipeName, open_mode, pipe_mode, 1, NODE_BGP_MAX_LINE, NODE_BGP_MAX_LINE, 0, &sa);
	LocalFree(sd);

	if (s->Pipe == INVALID_HANDLE_VALUE) {
		NodeLog(n, "BGP peering not started: the pipe %S cannot be created (error %u)", s->PipeName, (UINT)GetLastError());
		return false;
	}

	// The DACL that the pipe got, read back for NodePeeringGetStatus
	PSECURITY_DESCRIPTOR pipe_sd = NULL;
	char *pipe_acl = NULL;

	if (GetSecurityInfo(s->Pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pipe_sd) == ERROR_SUCCESS) {
		if (ConvertSecurityDescriptorToStringSecurityDescriptorA(pipe_sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pipe_acl, NULL)) {
			StrCpy(s->PipeAcl, sizeof(s->PipeAcl), pipe_acl);
			LocalFree(pipe_acl);
		}
		LocalFree(pipe_sd);
	}

	HANDLE connect_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (connect_event == NULL)
		return false;

	// Wait for the client before the sidecar exists, so that it cannot connect too early
	Zero(&ov, sizeof(ov));
	ov.hEvent = connect_event;
	bool pending = false;
	bool connected = false;

	if (ConnectNamedPipe(s->Pipe, &ov) == FALSE) {
		DWORD err = GetLastError();

		pending = (err == ERROR_IO_PENDING);
		connected = (err == ERROR_PIPE_CONNECTED);
	}

	// The job ends the sidecar with the node, also when the node does not stop
	s->Job = CreateJobObjectW(NULL, NULL);
	Zero(&limit, sizeof(limit));
	limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (s->Job == NULL || SetInformationJobObject(s->Job, JobObjectExtendedLimitInformation, &limit, sizeof(limit)) == FALSE) {
		NodeLog(n, "BGP peering not started: no job for the sidecar (error %u)", (UINT)GetLastError());
	} else if (pending == false) {
		NodeLog(n, "BGP peering not started: the pipe %S cannot wait for the sidecar%s", s->PipeName, connected ? " (a client connected before the sidecar started)" : "");
	} else {
		ConbinePathW(log_path, sizeof(log_path), n->DataDir, NODE_LOG_DIR_NAME);
		ConbinePathW(log_path, sizeof(log_path), log_path, NODE_PEERING_LOG_NAME);

		// The sidecar keeps its log within the limits of the node log (SDN-54, #247)
		UINT log_days;
		UINT log_mb;
		NodeGetLogLimits(n, &log_days, &log_mb);
		UniFormat(cmd, sizeof(cmd), L"\"%s\" bgp -pipe %s -log \"%s\" -log-days %u -log-mb %u", n->BgpSidecar, s->PipeName, log_path, log_days, log_mb);

		Zero(&si, sizeof(si));
		si.cb = sizeof(si);
		Zero(&pi, sizeof(pi));

		// Suspended until it is in the job, so that no child of it can escape the job
		if (CreateProcessW(n->BgpSidecar, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE) {
			NodeLog(n, "BGP peering not started: %S cannot be started (error %u)", n->BgpSidecar, (UINT)GetLastError());
		} else {
			s->Process = pi.hProcess;
			s->ProcessId = pi.dwProcessId;

			if (AssignProcessToJobObject(s->Job, pi.hProcess) == FALSE) {
				NodeLog(n, "BGP peering not started: the sidecar cannot join its job (error %u)", (UINT)GetLastError());
				TerminateProcess(pi.hProcess, 1);
			} else {
				ResumeThread(pi.hThread);

				// The halt ends the wait too (SDN-77-R1, #531)
				HANDLE waits[3] = {connect_event, pi.hProcess, halt};
				DWORD w = WaitForMultipleObjects(3, waits, FALSE, NODE_PEERING_CONNECT_WAIT);

				if (w == WAIT_OBJECT_0 && GetOverlappedResult(s->Pipe, &ov, &done, FALSE)) {
					GetNamedPipeClientProcessId(s->Pipe, &client);

					if (client == pi.dwProcessId) {
						ret = true;
						pending = false;
					} else {
						NodeLog(n, "BGP peering not started: process %u connected to the pipe, not the sidecar %u", (UINT)client, (UINT)pi.dwProcessId);
					}
				} else if (w == WAIT_OBJECT_0 + 2) {
					NodeLog(n, "BGP peering not started: the overlay stops");
				} else {
					NodeLog(n, "BGP peering not started: the sidecar did not connect to the pipe%s", w == WAIT_OBJECT_0 + 1 ? " (it exited)" : "");
				}

				if (ret == false)
					TerminateJobObject(s->Job, 1);
			}

			CloseHandle(pi.hThread);
		}
	}

	if (pending) {
		CancelIoEx(s->Pipe, &ov);
		GetOverlappedResult(s->Pipe, &ov, &done, TRUE);
	}

	CloseHandle(connect_event);

	return ret;
}

// The peers of the state for the sidecar, as the JSON array of the protocol: each peer that the sidecar takes
// (NodePeeringTakes), in the AS of the node, with the hold time of the session and its VRFs, each with what the peer may
// announce there
static cJSON *NodePeeringPeersJson(const CONTROL_STATE *st) {
	char text[MAX_SIZE];
	cJSON *peers = cJSON_CreateArray();

	for (UINT i = 0; peers != NULL && i < st->NumPeers; i++) {
		const CONTROL_PEER_PEERING *c = st->Peers[i].Peering;

		if (NodePeeringTakes(st, c) == false)
			continue;

		cJSON *peer = cJSON_CreateObject();
		cJSON *vrfs = cJSON_CreateArray();

		NodePeeringAddrText(text, sizeof(text), c->Address, c->AddressSize);
		cJSON_AddStringToObject(peer, "address", text);
		cJSON_AddNumberToObject(peer, "asn", st->Peering->Asn);
		if (c->HoldTime != 0)
			cJSON_AddNumberToObject(peer, "hold_time", c->HoldTime);

		for (UINT j = 0; j < c->NumVrfs && j < CONTROL_MAX_VRFS; j++) {
			if (c->VrfIds[j] == 0)
				continue;

			cJSON *vrf = cJSON_CreateObject();
			cJSON *accept = cJSON_CreateArray();

			cJSON_AddNumberToObject(vrf, "id", c->VrfIds[j]);
			for (UINT k = 0; k < c->NumAccept && k < CONTROL_MAX_ACCEPT; k++) {
				const CONTROL_ROUTE *a = &c->Accept[k];

				if (a->VrfId != c->VrfIds[j] || (a->AddressSize != 4 && a->AddressSize != 16) || a->Length > a->AddressSize * 8)
					continue;

				NodePeeringPrefixText(text, sizeof(text), a->Address, a->AddressSize, a->Length);
				cJSON_AddItemToArray(accept, cJSON_CreateString(text));
			}

			cJSON_AddItemToObject(vrf, "accept", accept);
			cJSON_AddItemToArray(vrfs, vrf);
		}

		cJSON_AddItemToObject(peer, "vrfs", vrfs);
		cJSON_AddItemToArray(peers, peer);
	}

	return peers;
}

// Send the peers of the JSON array peers to the sidecar s in peers messages of one line each, NODE_BGP_MAX_LINE bytes at most:
// each but the last says that more come, and the sidecar takes all of them in place of the ones before with the last (protocol 4;
// SDN-77-R1, #531), so the peers of a mesh of any size reach it, and an empty list is one message. False when one did not reach the
// sidecar, which ends it (NodePeeringSendLine).
static bool NodePeeringSendPeers(NODE_PEERING *p, NODE_PEERING_SIDECAR *s, const cJSON *peers) {
	const cJSON *item = (peers != NULL ? peers->child : NULL);
	bool more = true;
	bool ok = (s->Dead == false);

	while (ok && more) {
		BUF *b = NewBuf();
		UINT num = 0;

		// As many peers as fit into one line with the rest of the message, one at least
		while (item != NULL) {
			char *text = cJSON_PrintUnformatted(item);

			if (text == NULL) {
				ok = false;
				break;
			}

			UINT len = StrLen(text);
			bool fits = (num == 0 || b->Size + 1 + len + NODE_PEERING_PEERS_HEAD <= NODE_BGP_MAX_LINE);

			if (fits) {
				if (num != 0)
					WriteBuf(b, ",", 1);
				WriteBuf(b, text, len);
				num++;
				item = item->next;
			}
			cJSON_free(text);

			if (fits == false)
				break;
		}

		more = (item != NULL);

		if (ok) {
			BUF *line = NewBuf();
			const char *head = (more ? "{\"type\":\"peers\",\"more\":true,\"peers\":[" : "{\"type\":\"peers\",\"peers\":[");

			WriteBuf(line, head, StrLen(head));
			WriteBufBuf(line, b);
			// ... with the terminating NUL
			WriteBuf(line, "]}", 3);
			ok = NodePeeringSendLine(p, s, (const char *)line->Buf);
			FreeBuf(line);
		} else {
			NodePeeringUnsent(p, s, "no memory for the peers");
		}

		FreeBuf(b);
	}

	return ok;
}

// The peers of the sidecar from the state, every one that it takes: a peer that stays keeps the state of its session, a new one is
// idle. The node holds and counts each of them, beyond the CONTROL_MAX_PEERING_PEERS that a report holds (SDN-77-R1, #531).
static void NodePeeringSetPeers(NODE_PEERING *p, const CONTROL_STATE *st) {
	LIST *next = NewListFast(NULL);

	Lock(p->Lock);
	{
		for (UINT i = 0; i < st->NumPeers; i++) {
			const CONTROL_PEER_PEERING *c = st->Peers[i].Peering;

			if (NodePeeringTakes(st, c) == false)
				continue;

			NODE_PEERING_PEER *q = ZeroMalloc(sizeof(NODE_PEERING_PEER));
			NODE_PEERING_PEER *old = NodePeeringFindPeer(p, c->Address, c->AddressSize);

			Copy(q->Address, c->Address, sizeof(q->Address));
			q->AddressSize = c->AddressSize;
			StrCpy(q->State, sizeof(q->State), old != NULL ? old->State : NODE_PEERING_IDLE);
			q->Named = (old != NULL && old->Named);
			Add(next, q);
		}

		NodePeeringClearPeers(p);
		ReleaseList(p->Peers);
		p->Peers = next;
	}
	Unlock(p->Lock);
}

// Whether the sidecar s runs with the settings own of the node
static bool NodePeeringSameSettings(const NODE_PEERING_SIDECAR *s, const CONTROL_PEERING *own) {
	return (s->Asn == own->Asn && Cmp(s->RouterId, own->RouterId, sizeof(s->RouterId)) == 0 && s->AddressSize == own->AddressSize &&
	        Cmp(s->Address, own->Address, own->AddressSize) == 0);
}

// Stop the sidecar: closing the pipe ends the session, so the sidecar stops BGP, which tells the peers with a Cease, and exits;
// the routes that it learned go, and the forwarding tables take that. The worker waits NODE_PEERING_EXIT_WAIT for the exit, but
// not past the halt: then a wait of the thread pool takes over (NodePeeringLetGo), so that the halt and NodeOverlayStop wait
// for no sidecar (SDN-77-R1, #531).
static void NodePeeringStopSidecar(NODE_PEERING *p, const char *why) {
	NODE_PEERING_SIDECAR *s = p->Sidecar;
	DWORD code = 0;
	UINT num = 0;

	if (s == NULL)
		return;

	// The reader thread ends at its stop event
	SetEvent(s->StopEvent);
	WaitForSingleObject(s->Reader, INFINITE);
	CloseHandle(s->Reader);
	s->Reader = NULL;

	CloseHandle(s->Pipe);
	s->Pipe = INVALID_HANDLE_VALUE;

	// The exit first: WaitForMultipleObjects reports the lowest signalled index
	HANDLE waits[2] = {s->Process, p->Halt};
	DWORD w = WaitForMultipleObjects(2, waits, FALSE, NODE_PEERING_EXIT_WAIT);
	bool exited = (w == WAIT_OBJECT_0);
	bool let_go = false;

	if (exited) {
		GetExitCodeProcess(s->Process, &code);
	} else if (w == WAIT_OBJECT_0 + 1 && NodePeeringLetGo(s->Process, s->Job)) {
		// The handles are the thread pool's now
		s->Process = NULL;
		s->Job = NULL;
		let_go = true;
	} else {
		TerminateJobObject(s->Job, 1);
	}

	Lock(p->Lock);
	{
		p->Sidecar = NULL;
		p->Ready = false;
		p->Exited = false;
		p->Pinged = 0;
		p->NumAnnounced = 0;
		num = NodePeeringClearRoutes(p);
		NodePeeringClearPeers(p);
	}
	Unlock(p->Lock);

	for (UINT i = 0; i < LIST_NUM(p->Announced); i++)
		Free(LIST_DATA(p->Announced, i));
	DeleteAll(p->Announced);

	NodePeeringFreeSidecar(s);

	if (exited)
		NodeLog(p->Node, "BGP peering stopped, %s: the sidecar exited with code %u, %u learned routes go", why, (UINT)code, num);
	else if (let_go)
		NodeLog(p->Node, "BGP peering stopped, %s: the sidecar has %u ms to stop BGP and exit before its job ends it, and %u learned routes go", why, (UINT)NODE_PEERING_EXIT_WAIT, num);
	else
		NodeLog(p->Node, "BGP peering stopped, %s: the sidecar did not exit within %u ms and was ended, %u learned routes go", why, (UINT)NODE_PEERING_EXIT_WAIT, num);
}

static void NodePeeringUpdatePeers(NODE_PEERING *p, const CONTROL_STATE *st);

// Start a sidecar with the settings of the state st, which has a peering of the node: its pipe, its process in its job, the
// start message, the thread that reads it, and then the peers of st (NodePeeringUpdatePeers). False when a step before the peers
// fails, and nothing of it is left; peers that do not reach it end it, and another starts after NODE_PEERING_RESTART.
static bool NodePeeringStartSidecar(NODE_PEERING *p, const CONTROL_STATE *st) {
	NODE *n = p->Node;
	const CONTROL_PEERING *own = st->Peering;
	char text[MAX_SIZE];
	char address[MAX_SIZE];
	DWORD thread_id = 0;

	if (IsFileExistsW(n->BgpSidecar) == false) {
		NodeLog(n, "BGP peering not started: ranz.exe, which holds the sidecar, is not installed at %S", n->BgpSidecar);
		return false;
	}

	NODE_PEERING_SIDECAR *s = ZeroMalloc(sizeof(NODE_PEERING_SIDECAR));
	s->Pipe = INVALID_HANDLE_VALUE;
	s->Line = Malloc(NODE_BGP_MAX_LINE + 1);
	s->WriteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->Asn = own->Asn;
	Copy(s->RouterId, own->RouterId, sizeof(s->RouterId));
	Copy(s->Address, own->Address, sizeof(s->Address));
	s->AddressSize = own->AddressSize;
	// It has no peers before the peers messages that follow the start
	s->Peers = CopyStr("[]");

	// The start: the AS, the router id and the address of the node, where the sidecar listens on TCP 179 and connects from. The
	// peers follow in peers messages, as many as they need (NodePeeringSendPeers), so that no start is longer than a line.
	cJSON *m = cJSON_CreateObject();

	cJSON_AddStringToObject(m, "type", "start");
	cJSON_AddNumberToObject(m, "asn", own->Asn);
	Format(text, sizeof(text), "%u.%u.%u.%u", (UINT)own->RouterId[0], (UINT)own->RouterId[1], (UINT)own->RouterId[2], (UINT)own->RouterId[3]);
	cJSON_AddStringToObject(m, "router_id", text);
	NodePeeringAddrText(address, sizeof(address), own->Address, own->AddressSize);
	cJSON_AddStringToObject(m, "address", address);

	bool ok = (s->WriteEvent != NULL && s->StopEvent != NULL && NodePeeringLaunch(n, s, p->Halt));
	if (ok && NodePeeringSend(p, s, m) == false) {
		NodeLog(n, "BGP peering not started: the settings did not reach the sidecar");
		ok = false;
	}
	cJSON_Delete(m);

	if (ok) {
		Lock(p->Lock);
		{
			p->Sidecar = s;
			p->Ready = false;
			p->Exited = false;
			p->Pinged = 0;
			p->Answered = GetTickCount64();
		}
		Unlock(p->Lock);

		s->Reader = CreateThread(NULL, 0, NodePeeringReaderThread, p, 0, &thread_id);
		if (s->Reader == NULL) {
			NodeLog(n, "BGP peering not started: no reader thread (error %u)", (UINT)GetLastError());
			TerminateJobObject(s->Job, 1);

			Lock(p->Lock);
			p->Sidecar = NULL;
			Unlock(p->Lock);
			ok = false;
		}
	}

	if (ok == false) {
		NodePeeringFreeSidecar(s);
		return false;
	}

	Lock(p->Lock);
	p->NumStarts++;
	Unlock(p->Lock);

	NodeLog(n, "BGP peering: sidecar %S bgp started: process %u, AS %u, router id %s, listening on TCP 179 of %s, pipe %S", n->BgpSidecar, s->ProcessId, own->Asn, text, address,
	        s->PipeName);

	NodePeeringUpdatePeers(p, st);

	return true;
}

// The peers of a sidecar that runs follow the state: when they changed, the node takes them first, so that it knows each peer
// whose session the sidecar names, and then the sidecar, in peers messages (NodePeeringSendPeers), with which a peer that stays
// keeps its session, a new one starts one, and the session of one that went ends, with its routes. Peers that do not reach the
// sidecar end it, and the next one takes the peers of the Generation in force with its start.
static void NodePeeringUpdatePeers(NODE_PEERING *p, const CONTROL_STATE *st) {
	NODE_PEERING_SIDECAR *s = p->Sidecar;

	if (s == NULL || s->Dead)
		return;

	cJSON *peers = NodePeeringPeersJson(st);
	char *text = (peers != NULL ? cJSON_PrintUnformatted(peers) : NULL);

	if (text == NULL) {
		NodePeeringUnsent(p, s, "no memory for the peers");
	} else if (StrCmp(text, s->Peers) != 0) {
		NodePeeringSetPeers(p, st);

		if (NodePeeringSendPeers(p, s, peers)) {
			Free(s->Peers);
			s->Peers = CopyStr(text);
			NodeLog(p->Node, "BGP peering: the sidecar has %u peers now", LIST_NUM(p->Peers));
		}
	}

	cJSON_Delete(peers);
	if (text != NULL)
		cJSON_free(text);
}

// Add the prefix of a VRF to a list of NODE_PEERING_PREFIX, once
static void NodePeeringWant(LIST *o, UINT vrf_id, const UCHAR *addr, UINT size, UINT length) {
	char text[MAX_SIZE];

	if ((size != 4 && size != 16) || length > size * 8)
		return;

	NodePeeringPrefixText(text, sizeof(text), addr, size, length);
	for (UINT i = 0; i < LIST_NUM(o); i++) {
		NODE_PEERING_PREFIX *a = LIST_DATA(o, i);

		if (a->VrfId == vrf_id && StrCmp(a->Prefix, text) == 0)
			return;
	}

	NODE_PEERING_PREFIX *a = ZeroMalloc(sizeof(NODE_PEERING_PREFIX));
	a->VrfId = vrf_id;
	StrCpy(a->Prefix, sizeof(a->Prefix), text);
	Add(o, a);
}

// Whether a list of NODE_PEERING_PREFIX holds the prefix a
static bool NodePeeringHasPrefix(LIST *o, const NODE_PEERING_PREFIX *a) {
	for (UINT i = 0; i < LIST_NUM(o); i++) {
		NODE_PEERING_PREFIX *b = LIST_DATA(o, i);

		if (b->VrfId == a->VrfId && StrCmp(b->Prefix, a->Prefix) == 0)
			return true;
	}

	return false;
}

// Send an announce or a withdraw of the prefix a to the sidecar s (NodePeeringSend)
static bool NodePeeringSendPrefix(NODE_PEERING *p, NODE_PEERING_SIDECAR *s, const char *type, const NODE_PEERING_PREFIX *a) {
	cJSON *m = cJSON_CreateObject();

	cJSON_AddStringToObject(m, "type", type);
	cJSON_AddNumberToObject(m, "vrf", a->VrfId);
	cJSON_AddStringToObject(m, "prefix", a->Prefix);

	bool ok = NodePeeringSend(p, s, m);
	cJSON_Delete(m);

	return ok;
}

// What the node announces follows the state: its addresses in each VRF that peers by BGP, as host routes, and its LAN subnets
// there. A prefix that it announces no more is withdrawn, and a new one announced. A message that does not reach the sidecar ends
// it (NodePeeringSend), and the node stops there: the next sidecar announces what the Generation in force has, so that no prefix
// that the node withdrew stays announced, and none that it announces is missing (SDN-77-R1, #531).
static void NodePeeringAnnounce(NODE_PEERING *p, const CONTROL_STATE *st) {
	NODE_PEERING_SIDECAR *s = p->Sidecar;
	LIST *want = NewListFast(NULL);

	for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES; i++) {
		const CONTROL_ADDRESS *a = &st->Addresses[i];

		if (NodePeeringVrfPeers(st, a->VrfId))
			NodePeeringWant(want, a->VrfId, a->Address, a->AddressSize, a->AddressSize * 8);
	}
	for (UINT i = 0; i < st->Peering->NumAnnounce && i < CONTROL_MAX_ANNOUNCE; i++) {
		const CONTROL_ROUTE *r = &st->Peering->Announce[i];

		if (NodePeeringVrfPeers(st, r->VrfId))
			NodePeeringWant(want, r->VrfId, r->Address, r->AddressSize, r->Length);
	}

	for (UINT i = 0; i < LIST_NUM(p->Announced) && s->Dead == false;) {
		NODE_PEERING_PREFIX *a = LIST_DATA(p->Announced, i);

		if (NodePeeringHasPrefix(want, a)) {
			i++;
			continue;
		}

		if (NodePeeringSendPrefix(p, s, "withdraw", a) == false)
			break;

		NodeLog(p->Node, "BGP peering: prefix %s of VRF %u withdrawn", a->Prefix, a->VrfId);
		Delete(p->Announced, a);
		Free(a);
	}

	for (UINT i = 0; i < LIST_NUM(want) && s->Dead == false; i++) {
		NODE_PEERING_PREFIX *a = LIST_DATA(want, i);

		if (NodePeeringHasPrefix(p->Announced, a))
			continue;

		if (NodePeeringSendPrefix(p, s, "announce", a) == false)
			break;

		NODE_PEERING_PREFIX *copy = ZeroMalloc(sizeof(NODE_PEERING_PREFIX));
		Copy(copy, a, sizeof(NODE_PEERING_PREFIX));
		Add(p->Announced, copy);
		NodeLog(p->Node, "BGP peering: prefix %s of VRF %u announced", a->Prefix, a->VrfId);
	}

	FreeListItems(want);

	Lock(p->Lock);
	p->NumAnnounced = LIST_NUM(p->Announced);
	Unlock(p->Lock);
}

//
// The worker
//

// A sidecar that ended by itself, or that the worker ended (NodePeeringEnd), goes, and another starts after NODE_PEERING_RESTART
// with the state of the Generation in force
static void NodePeeringReap(NODE_PEERING *p) {
	bool exited = false;
	bool dead = false;

	Lock(p->Lock);
	{
		exited = (p->Sidecar != NULL && p->Exited);
		dead = (p->Sidecar != NULL && p->Sidecar->Dead);
	}
	Unlock(p->Lock);

	if (exited == false && dead == false)
		return;

	NodePeeringStopSidecar(p, dead ? "the node ended it" : "it ended by itself");
	p->NextStart = GetTickCount64() + NODE_PEERING_RESTART;

	Lock(p->Lock);
	p->Changed = true;
	Unlock(p->Lock);
}

// Settle the sidecar on the Generation in force: no sidecar while it has no peering of the node, else one with its settings
// and its peers, which announces what the node announces there. A sidecar that ended by itself, or that the worker ended, goes,
// and one starts again after NODE_PEERING_RESTART.
static void NodePeeringSettle(NODE_PEERING *p) {
	UINT64 now = GetTickCount64();
	bool changed = false;
	bool none = false;
	CONTROL_STATE *st = NULL;

	NodePeeringReap(p);

	Lock(p->Lock);
	{
		changed = p->Changed;
		p->Changed = false;
		none = (changed && p->State == NULL);
		st = (changed && p->State != NULL ? ControlCopyState(p->State) : NULL);
	}
	Unlock(p->Lock);

	if (none) {
		NodePeeringStopSidecar(p, "no VRF of the node peers by BGP any more");
		return;
	}
	if (st == NULL)
		return;

	// A sidecar whose own settings changed starts again with the new ones
	if (p->Sidecar != NULL && NodePeeringSameSettings(p->Sidecar, st->Peering) == false)
		NodePeeringStopSidecar(p, "the AS, the router id or the address of the node changed");

	if (p->Sidecar == NULL) {
		if (now < p->NextStart || NodePeeringStartSidecar(p, st) == false) {
			if (now >= p->NextStart)
				p->NextStart = now + NODE_PEERING_RESTART;

			Lock(p->Lock);
			p->Changed = true;
			Unlock(p->Lock);
		}
	} else {
		NodePeeringUpdatePeers(p, st);
	}

	if (p->Sidecar != NULL)
		NodePeeringAnnounce(p, st);

	ControlFreeStateCopy(st);

	// A sidecar that a message did not reach goes at once
	NodePeeringReap(p);
}

// Whether the sidecar runs (protocol 4): NODE_PEERING_PING after its last answer the worker asks it again (ping), and the sidecar
// answers once GoBGP answered it too (pong). A sidecar that does not answer within NODE_PEERING_ANSWER hangs: the worker ends it
// (NodePeeringEnd), so the routes that it learned go, and another starts, as for one that ends by itself (SDN-77-R1, #531).
static void NodePeeringCheck(NODE_PEERING *p) {
	NODE_PEERING_SIDECAR *s = p->Sidecar;
	UINT64 now = GetTickCount64();
	bool ping = false;
	bool hung = false;

	if (s == NULL || s->Dead)
		return;

	Lock(p->Lock);
	{
		if (p->Exited == false && p->Pinged != 0)
			hung = (now >= p->Pinged + NODE_PEERING_ANSWER);
		else if (p->Exited == false)
			ping = (now >= p->Answered + NODE_PEERING_PING);

		if (ping)
			p->Pinged = now;
		if (hung)
			p->NumHung++;
	}
	Unlock(p->Lock);

	if (hung) {
		NodeLog(p->Node, "BGP peering: the sidecar did not answer within %u ms whether it runs, so it hangs: the node ends it, its learned routes go, and another starts", (UINT)NODE_PEERING_ANSWER);
		NodePeeringEnd(s);
	} else if (ping) {
		cJSON *m = cJSON_CreateObject();

		cJSON_AddStringToObject(m, "type", "ping");
		NodePeeringSend(p, s, m);
		cJSON_Delete(m);
	}
}

// Build the forwarding tables of the Generation in force anew when the learned routes changed. The worker never waits for an apply
// of the overlay (SDN-77-R1, #531): a rebuild that meets one tries again every NODE_PEERING_BUSY ms while the halt allows, and one
// that then finds another Generation in force leaves Dirty set, so that the next pass, which the apply woke, builds the tables of
// that Generation with the routes of now. So a learned or withdrawn message during an apply is in the tables of the Generation that
// it put in force. A copy of the state or a rebuild that fails is logged, counted (NumFailed) and leaves Dirty set too, and the
// worker tries again after NODE_PEERING_RETRY.
static void NodePeeringRebuild(NODE_PEERING *p) {
	CONTROL_STATE *base = NULL;
	UINT64 now = GetTickCount64();
	bool due = false;
	bool fail = false;
	bool waited = false;
	UINT num = 0;

	Lock(p->Lock);
	{
		due = (p->Dirty && p->State != NULL && p->Halted == false && now >= p->NextRebuild);
		// A test may make the copy fail, as when there is no memory for it, and then the rebuild (NodePeeringFailNext)
		if (due && p->FailCopies != 0)
			p->FailCopies--;
		else if (due)
			base = ControlCopyState(p->State);
		fail = (base != NULL && p->FailRebuilds != 0);
		if (fail)
			p->FailRebuilds--;

		// The copy takes the routes of now: a change from here on sets Dirty again
		if (base != NULL) {
			p->Dirty = false;
		} else if (due) {
			p->NextRebuild = now + NODE_PEERING_RETRY;
			p->NumFailed++;
		}
	}
	Unlock(p->Lock);

	if (due && base == NULL)
		NodeLog(p->Node, "BGP peering: the forwarding tables are not built anew with the learned routes: no memory for a copy of the Generation in force; the node tries again in %u ms",
		        (UINT)NODE_PEERING_RETRY);
	if (base == NULL)
		return;

	UINT64 gen = base->Generation;
	const CONTROL_STATE *with = NodePeeringWith(p->Node, base);
	UINT ret = (fail ? NODE_REBUILD_FAILED : NodeOverlayRebuild(p->Node, with));

	// A rebuild that meets an apply counts at once, while the apply still runs
	if (ret == NODE_REBUILD_BUSY || ret == NODE_REBUILD_STALE) {
		Lock(p->Lock);
		p->NumDeferred++;
		Unlock(p->Lock);
	}

	// An apply runs: try again when it is done, but not past the halt
	while (ret == NODE_REBUILD_BUSY && WaitForSingleObject(p->Halt, NODE_PEERING_BUSY) == WAIT_TIMEOUT) {
		waited = true;
		ret = NodeOverlayRebuild(p->Node, with);
	}

	NodePeeringDone(with, base);
	ControlFreeStateCopy(base);

	Lock(p->Lock);
	{
		if (ret == NODE_REBUILD_DONE) {
			p->NumRebuilds++;
			num = LIST_NUM(p->Routes);
		} else if (p->State != NULL) {
			// The routes of the copy did not go in: the next pass takes them, with the Generation in force then
			p->Dirty = true;
			if (ret == NODE_REBUILD_FAILED)
				p->NextRebuild = GetTickCount64() + NODE_PEERING_RETRY;
		}
		if (ret == NODE_REBUILD_FAILED)
			p->NumFailed++;
	}
	Unlock(p->Lock);

	if (ret == NODE_REBUILD_DONE)
		NodeLog(p->Node, "BGP peering: the forwarding tables of generation %I64u built anew with %u learned routes%s", gen, num, waited ? ", after the apply that ran" : "");
	else if (ret == NODE_REBUILD_STALE)
		NodeLog(p->Node, "BGP peering: generation %I64u went out of force while its forwarding tables were built anew, so they are built anew with the one that went in", gen);
	else if (ret == NODE_REBUILD_FAILED)
		NodeLog(p->Node, "BGP peering: the forwarding tables of generation %I64u could not be built anew with the learned routes; the node tries again in %u ms", gen, (UINT)NODE_PEERING_RETRY);
}

// The report of the control stream takes the peers, their sessions, the learned routes and the refused sessions when they
// changed
static void NodePeeringUpdateReport(NODE_PEERING *p) {
	CONTROL_PEERING_PEER *peers = NULL;
	UINT num = 0;
	UINT64 refused = 0;
	bool reported = false;

	Lock(p->Lock);
	{
		reported = p->Reported;
		p->Reported = false;
		if (reported)
			num = NodePeeringReportPeers(p, &peers);
		refused = p->Refused;
	}
	Unlock(p->Lock);

	if (reported)
		ControlSetPeeringReport(p->Report, peers, num, refused);

	Free(peers);
}

// How long the worker waits for its events: until a sidecar may start again while one has to, until a rebuild that failed may go
// again, and until the sidecar is to be asked whether it runs, or has to have answered; else for them alone
static DWORD NodePeeringWait(NODE_PEERING *p) {
	UINT64 now = GetTickCount64();
	UINT64 due = MAXUINT64;

	Lock(p->Lock);
	{
		if (p->Changed && p->State != NULL && p->Sidecar == NULL)
			due = MIN(due, p->NextStart);
		if (p->Dirty && p->State != NULL)
			due = MIN(due, p->NextRebuild);
		if (p->Sidecar != NULL && p->Sidecar->Dead == false && p->Exited == false)
			due = MIN(due, (p->Pinged != 0 ? p->Pinged + NODE_PEERING_ANSWER : p->Answered + NODE_PEERING_PING));
	}
	Unlock(p->Lock);

	if (due == MAXUINT64)
		return INFINITE;

	return (now >= due ? 0 : (DWORD)MIN(due - now, (UINT64)NODE_PEERING_ANSWER));
}

// The worker of the peering: it settles the sidecar on each Generation, asks it whether it runs, builds the forwarding tables anew
// when the learned routes change and updates the report, until the halt, which stops the sidecar. Each wait of a step ends at the
// halt, so the worker answers it at once (SDN-77-R1, #531).
static DWORD WINAPI NodePeeringWorker(void *param) {
	NODE_PEERING *p = (NODE_PEERING *)param;
	HANDLE events[2];

	// The halt first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = p->Halt;
	events[1] = p->Wake;

	while (true) {
		DWORD w = WaitForMultipleObjects(2, events, FALSE, NodePeeringWait(p));

		if (w != WAIT_OBJECT_0 + 1 && w != WAIT_TIMEOUT)
			break;

		NodePeeringSettle(p);
		NodePeeringCheck(p);
		NodePeeringRebuild(p);
		NodePeeringUpdateReport(p);
	}

	NodePeeringStopSidecar(p, "the overlay stops");

	return 0;
}

//
// The overlay
//

// Start the peering of the overlay of a node (NodeOverlayStart): its worker, which starts a sidecar once a Generation has a
// peering of the node. The report that the control stream sends, NULL for none.
CONTROL_PEERING_REPORT *NodePeeringStart(NODE *n) {
	DWORD thread_id = 0;

	if (n == NULL || n->Peering != NULL)
		return NULL;

	NODE_PEERING *p = ZeroMalloc(sizeof(NODE_PEERING));
	p->Node = n;
	p->Lock = NewLock();
	p->Peers = NewListFast(NULL);
	p->Routes = NewListFast(NULL);
	p->Announced = NewListFast(NULL);
	p->Report = ControlNewPeeringReport();
	p->Wake = CreateEventW(NULL, FALSE, FALSE, NULL);
	p->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	n->Peering = p;

	p->Worker = (p->Wake != NULL && p->Halt != NULL ? CreateThread(NULL, 0, NodePeeringWorker, p, 0, &thread_id) : NULL);
	if (p->Worker == NULL) {
		p->Halted = true;
		NodeLog(n, "BGP peering: its worker could not start (error %u), so no VRF of the node peers by BGP", (UINT)GetLastError());
	}

	return p->Report;
}

// Halt the peering of a node, first thing in NodeOverlayStop: the worker ends, after it stopped the sidecar, and the peering
// takes no state any more, so nothing of it calls into the overlay or its adapters afterwards. The worker answers the halt at
// once: each of its waits ends at it, a rebuild does not wait for an apply past it, and the sidecar that it stops is left to the
// thread pool (NodePeeringStopSidecar), so the halt waits for no sidecar, also under the lock of the node (SDN-77-R1, #531).
void NodePeeringHalt(NODE *n) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);
	CONTROL_STATE *st = NULL;

	if (p == NULL)
		return;

	Lock(p->Lock);
	p->Halted = true;
	Unlock(p->Lock);

	if (p->Worker != NULL) {
		SetEvent(p->Halt);
		WaitForSingleObject(p->Worker, INFINITE);
		CloseHandle(p->Worker);
		p->Worker = NULL;
	}

	Lock(p->Lock);
	{
		st = p->State;
		p->State = NULL;
	}
	Unlock(p->Lock);

	ControlFreeStateCopy(st);
}

// Free the peering of a node once the control stream that sent its report stopped (NodeOverlayStop)
void NodePeeringFree(NODE *n) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);

	if (p == NULL)
		return;

	NodePeeringHalt(n);
	n->Peering = NULL;

	ControlFreePeeringReport(p->Report);
	FreeListItems(p->Peers);
	FreeListItems(p->Routes);
	FreeListItems(p->Announced);
	if (p->Wake != NULL)
		CloseHandle(p->Wake);
	if (p->Halt != NULL)
		CloseHandle(p->Halt);
	DeleteLock(p->Lock);
	Free(p);
}

// Put the learned route r into the routes of its peer in st: the peer whose Peer object names the address of the sidecar that
// announced it, while the VRF of the route peers by BGP and is one of their session, and the accept list of the peer there holds
// the route (NODE_PEERING_IN, NODE_PEERING_SKIP, NODE_PEERING_FULL or NODE_PEERING_OUTSIDE)
static UINT NodePeeringInject(CONTROL_STATE *st, const NODE_PEERING_ROUTE *r) {
	if (NodePeeringVrfPeers(st, r->VrfId) == false)
		return NODE_PEERING_SKIP;

	for (UINT i = 0; i < st->NumPeers; i++) {
		CONTROL_PEER *cp = &st->Peers[i];
		const CONTROL_PEER_PEERING *c = cp->Peering;

		if (c == NULL || c->AddressSize != r->PeerSize || Cmp(c->Address, r->Peer, r->PeerSize) != 0 || NodePeeringHasVrf(c, r->VrfId) == false)
			continue;

		// What the peer may announce in this Generation, which may be less than what the sidecar took the route with, until the
		// sidecar starts the session again with the peers of this Generation (SDN-77-R1, #531)
		if (NodePeeringAccepts(c, r->VrfId, r->Address, r->AddressSize, r->Length) == false)
			return NODE_PEERING_OUTSIDE;

		// A host route of an address of the peer: the forwarding tables lead that address to the peer already
		for (UINT j = 0; j < cp->NumAddresses && j < CONTROL_MAX_ADDRESSES; j++) {
			const CONTROL_ADDRESS *a = &cp->Addresses[j];

			if (a->VrfId == r->VrfId && a->AddressSize == r->AddressSize && r->Length == r->AddressSize * 8 && Cmp(a->Address, r->Address, r->AddressSize) == 0)
				return NODE_PEERING_SKIP;
		}

		if (cp->NumRoutes >= CONTROL_MAX_ROUTES)
			return NODE_PEERING_FULL;

		CONTROL_ROUTE *route = &cp->Routes[cp->NumRoutes++];
		Zero(route, sizeof(CONTROL_ROUTE));
		route->VrfId = r->VrfId;
		Copy(route->Address, r->Address, sizeof(route->Address));
		route->AddressSize = r->AddressSize;
		route->Length = r->Length;

		return NODE_PEERING_IN;
	}

	return NODE_PEERING_SKIP;
}

// The state st with the routes that the sidecar learned among the routes of their peers, for the forwarding tables and the
// adapters of a Generation: a copy of st, which NodePeeringDone frees, or st itself while there are none or it has no peering of
// the node
const CONTROL_STATE *NodePeeringWith(NODE *n, const CONTROL_STATE *st) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);
	CONTROL_STATE *with = NULL;
	UINT full = 0;
	UINT outside = 0;

	if (p == NULL || st == NULL || st->Peering == NULL)
		return st;

	Lock(p->Lock);
	{
		if (p->Halted == false && LIST_NUM(p->Routes) != 0)
			with = ControlCopyState(st);

		for (UINT i = 0; with != NULL && i < LIST_NUM(p->Routes); i++) {
			UINT ret = NodePeeringInject(with, LIST_DATA(p->Routes, i));

			if (ret == NODE_PEERING_FULL)
				full++;
			else if (ret == NODE_PEERING_OUTSIDE)
				outside++;
		}
	}
	Unlock(p->Lock);

	if (full != 0)
		NodeLog(n, "BGP peering: %u learned routes not in the forwarding tables of generation %I64u: the routes of their peers are full (%u each)", full, st->Generation, (UINT)CONTROL_MAX_ROUTES);
	if (outside != 0)
		NodeLog(n, "BGP peering: %u learned routes not in the forwarding tables of generation %I64u: their peers may not announce them in it", outside, st->Generation);

	return (with != NULL ? with : st);
}

// Free what NodePeeringWith made of st
void NodePeeringDone(const CONTROL_STATE *with, const CONTROL_STATE *st) {
	if (with != NULL && with != st)
		ControlFreeStateCopy((CONTROL_STATE *)with);
}

// The Generation of st went in (swapped), or its swap failed and the one before stays: the peering keeps a copy of the one in
// force while it has a peering of the node, and the worker settles the sidecar on it
void NodePeeringApplied(NODE *n, const CONTROL_STATE *st, bool swapped) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);
	CONTROL_STATE *copy = NULL;
	CONTROL_STATE *old = NULL;
	bool wake = false;

	if (p == NULL || st == NULL || swapped == false)
		return;

	if (st->Peering != NULL) {
		copy = ControlCopyState(st);
		if (copy == NULL)
			NodeLog(n, "BGP peering: generation %I64u could not be kept: no memory, so the sidecar stops", st->Generation);
	}

	Lock(p->Lock);
	{
		if (p->Halted == false && (copy != NULL || p->State != NULL)) {
			old = p->State;
			p->State = copy;
			copy = NULL;
			p->Changed = true;
			wake = true;
		}
	}
	Unlock(p->Lock);

	ControlFreeStateCopy(old);
	ControlFreeStateCopy(copy);

	if (wake)
		SetEvent(p->Wake);
}

//
// The status
//

// The state of the peering of the node
void NodePeeringGetStatus(NODE *n, NODE_PEERING_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_PEERING_STATUS));

	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);
	if (p == NULL)
		return;

	Lock(p->Lock);
	{
		st->Configured = (p->State != NULL);
		st->Running = (p->Sidecar != NULL && p->Ready && p->Exited == false);
		st->ProcessId = (p->Sidecar != NULL && p->Exited == false ? p->Sidecar->ProcessId : 0);
		st->NumStarts = p->NumStarts;
		st->NumPeers = LIST_NUM(p->Peers);
		st->NumAnnounced = p->NumAnnounced;
		st->NumLearned = LIST_NUM(p->Routes);
		st->NumRebuilds = p->NumRebuilds;
		st->NumDeferred = p->NumDeferred;
		st->NumFailed = p->NumFailed;
		st->NumUnsent = p->NumUnsent;
		st->NumHung = p->NumHung;
		st->Refused = p->Refused;
		st->NumErrors = p->NumErrors;
		StrCpy(st->Version, sizeof(st->Version), p->Version);
		if (p->Sidecar != NULL)
			StrCpy(st->PipeAcl, sizeof(st->PipeAcl), p->Sidecar->PipeAcl);

		for (UINT i = 0; i < LIST_NUM(p->Peers); i++) {
			NODE_PEERING_PEER *q = LIST_DATA(p->Peers, i);

			if (StrCmp(q->State, "established") == 0)
				st->NumEstablished++;
			if (q->Named)
				st->NumNamed++;
		}
	}
	Unlock(p->Lock);
}

// The peers of the sidecar of the node, as its report holds them, at most max into list: their number
UINT NodePeeringGetPeers(NODE *n, CONTROL_PEERING_PEER *list, UINT max) {
	CONTROL_PEERING_PEER *peers = NULL;
	UINT num = 0;

	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);
	if (p == NULL || list == NULL)
		return 0;

	Lock(p->Lock);
	num = NodePeeringReportPeers(p, &peers);
	Unlock(p->Lock);

	num = MIN(num, max);
	if (num != 0)
		Copy(list, peers, sizeof(CONTROL_PEERING_PEER) * num);
	Free(peers);

	return num;
}

// The report that the control stream of the node sends (NodePeeringStart), NULL while the overlay does not run. A test without
// a control stream reads it and writes it as the client does (ControlGetPeeringReport, ControlWritePeeringReport).
CONTROL_PEERING_REPORT *NodePeeringGetReport(NODE *n) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);

	return (p != NULL ? p->Report : NULL);
}

// A test makes the next copies copies of the Generation in force for a rebuild of the forwarding tables fail, as when there is no
// memory for one, and then the next rebuilds rebuilds, as when the tables cannot be built or installed (NodePeeringRebuild;
// SDN-77-R1, #531)
void NodePeeringFailNext(NODE *n, UINT copies, UINT rebuilds) {
	NODE_PEERING *p = (n != NULL ? n->Peering : NULL);

	if (p == NULL)
		return;

	Lock(p->Lock);
	{
		p->FailCopies = copies;
		p->FailRebuilds = rebuilds;
	}
	Unlock(p->Lock);
}
