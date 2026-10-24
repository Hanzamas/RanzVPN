// Policy.c
// The policy engine of the new core (Policy.h): the members of its Networks and their guard, the document of rules in
// force, the verdict of each frame with the conntrack fast path (PolicyInput), the ages of the flows and the counters.
//
// No lock serialises the engine on the data path (ADR-0022, Threading):
// - The document in force (POLICY_STATE: the document, the tables of its Networks with their conntrack tables, and its
//   number) and the record of each member are read through pointers that a change replaces and never changes. A
//   frame holds the shared lock of its slot of processors (POLICY_SLOTS of them, each on a cache line of its own) from
//   its start to its verdict. A change publishes its new pointer, then takes the lock of every slot exclusive once
//   (PolicyQuiesce): after that no frame still reads what the pointer pointed to before, which the change then frees. So
//   each frame is judged by one document from its start to its verdict, and a rule change never tears a frame.
// - A conntrack table has a lock per shard (PolicyTrack.c), which a frame holds while it finds, adds or changes its flow.
// - The addresses that the members of a Network own are a sorted list of the Network under its LearnLock, which a frame
//   holds shared to look up its source and exclusive to take a new one. A Network whose members own nothing, and a member
//   under no check, take no lock for it.
// - The changes (members, their addresses, documents) hold ConfigLock, which the data path never takes. A frame takes the
//   lock of its slot, then the LearnLock of its Network or the lock of a shard, never both at once; a change takes
//   ConfigLock, then one of those, and waits for the slots with none of them held.

#include "Core/PolicyInternal.h"

#include <stdio.h>
#include <string.h>

#define POLICY_FIRST_OWNERS 64     // Room for owned addresses that a Network gets first
#define POLICY_MAX_HEADERS  8      // IPv6 extension headers that a packet may have before its transport header
#define POLICY_ETH_HEADER   14     // The two MAC addresses and the EtherType of an Ethernet frame
#define POLICY_TAG_SIZE     4      // A VLAN tag
#define POLICY_ARP_SIZE     28     // An ARP packet for Ethernet and IPv4
#define POLICY_NO_RULE      0xFFFF // No rule: what PolicyRejudge returns for a flow that a member left

// The EtherTypes that the engine reads
#define POLICY_ETHERTYPE_IPV4 0x0800
#define POLICY_ETHERTYPE_ARP  0x0806
#define POLICY_ETHERTYPE_IPV6 0x86DD

// The states of a flow (POLICY_FLOW.State)
#define POLICY_FLOW_OPEN        0 // One side sent on it
#define POLICY_FLOW_ESTABLISHED 1 // Both sides sent on it, and neither ended a TCP flow
#define POLICY_FLOW_CLOSING     2 // A TCP flow after a FIN
#define POLICY_FLOW_CLOSED      3 // A TCP flow after a reset

// The TCP flags that the engine reads
#define POLICY_TCP_FIN 0x01
#define POLICY_TCP_SYN 0x02
#define POLICY_TCP_RST 0x04
#define POLICY_TCP_ACK 0x10

// What the segment needs and the rules do not judge (POLICY_PACKET.Control)
#define POLICY_CTL_NONE        0 // A frame for the rules
#define POLICY_CTL_ARP         1 // ARP
#define POLICY_CTL_ND          2 // IPv6 neighbour discovery: ICMPv6 types 133 to 137
#define POLICY_CTL_DHCP        3 // A DHCP or DHCPv6 message of a client
#define POLICY_CTL_DHCP_SERVER 4 // ... of a server

// The ICMP types that the engine reads
#define POLICY_ICMP4_ECHO_REPLY 0
#define POLICY_ICMP4_ECHO       8
#define POLICY_ICMP6_ECHO       128
#define POLICY_ICMP6_ECHO_REPLY 129
#define POLICY_ICMP6_RS         133
#define POLICY_ICMP6_RA         134
#define POLICY_ICMP6_REDIRECT   137

// What a frame reads of a member: made when it joins, never changed, and freed once no frame can still read it
typedef struct POLICY_RECORD {
	POLICY_NET *Net;    // Its Network
	UINT Gen;           // The generation of its slot when it joined: the flows of an earlier member of the slot are not its own
	UINT Guard;         // POLICY_GUARD_*
	UINT MaxMacs;       // MAC addresses that it may own
	UINT MaxIps;        // ... and IP addresses
	POLICY_IDENTITY Id; // Its identity, whose lists and strings follow the record in its block
} POLICY_RECORD;

// The slot of a member, on a cache line of its own
typedef union POLICY_SLOT {
	struct {
		POLICY_RECORD *volatile Record; // The member that holds it, NULL for none
		UINT NextGen;                   // The generation of the next member that joins, under ConfigLock
		UINT NumMacs;                   // The MAC addresses that the member owns, under the LearnLock of its Network
		UINT NumIps;                    // ... and the IP addresses
	};
	UCHAR Line[POLICY_CACHE_LINE];
} POLICY_SLOT;

// The lock of a slot of processors, on a cache line of its own: shared while a frame of a processor of the slot is
// judged, exclusive once for each change (PolicyQuiesce)
typedef union POLICY_READER {
	SRWLOCK Lock;
	UCHAR Line[POLICY_CACHE_LINE];
} POLICY_READER;

// The counters of the frames of one slot of processors, on cache lines of their own: the frames, then the frames by the
// reason of their verdict
typedef union POLICY_FRAME_COUNTS {
	volatile LONG64 Count[1 + POLICY_NUM_REASONS];
	UCHAR Lines[3 * POLICY_CACHE_LINE];
} POLICY_FRAME_COUNTS;

// A document in force
typedef struct POLICY_STATE {
	UINT64 Gen;                               // Its number: 1 for the first document of the engine
	POLICY_DOC *Doc;                          // The document, with its tables in its arena
	POLICY_TABLE *Tables;                     // The tables, in the order of its Networks
	POLICY_TABLE *ByNet[POLICY_MAX_NETWORKS]; // The table of each Network of the engine by its index, NULL for none
} POLICY_STATE;

// The policy engine of a Node
struct POLICY_ENGINE {
	POLICY_READER Readers[POLICY_SLOTS];      // The locks of the slots of processors: first, at the start of a cache line
	POLICY_FRAME_COUNTS Counts[POLICY_SLOTS]; // The counters of the frames, per slot of processors
	void *Block;                              // The memory block that holds the engine
	UINT MaxMembers;                          // Members at most
	POLICY_SLOT *Slots;                       // The slots of the members
	void *SlotBlock;                          // ... the memory block that holds them
	SRWLOCK ConfigLock;                       // The changes: never taken on the data path
	UINT NumMembers;                          // The members, under ConfigLock
	volatile LONG NumNets;                    // The Networks
	POLICY_NET *Nets[POLICY_MAX_NETWORKS];    // ... by index, each kept until the engine is freed
	POLICY_STATE *volatile State;             // The document in force, NULL before the first
};

// What PolicyInput reads of a frame
typedef struct POLICY_PACKET {
	const UCHAR *Smac;   // L2: the source MAC address; NULL in an L3 Network
	UINT EtherType;      // The EtherType after a tag; that of the family for a packet of an L3 Network
	bool Group;          // To a group address: an L2 destination with the multicast bit, an IP broadcast or multicast destination
	UINT Family;         // POLICY_IPV4 or POLICY_IPV6, 0 for a frame that is not IP
	UCHAR Src[16];       // The source IP address, IPv4 in the first 4 bytes
	UCHAR Dst[16];       // ... and the destination
	UINT Protocol;       // The IP protocol, after the extension headers of IPv6
	UINT Class;          // POLICY_CLASS_*
	bool Later;          // A later fragment, which has no transport header
	const UCHAR *L4;     // The transport header
	UINT L4Size;         // ... and the bytes from it to the end of the IP packet
	bool HasPort;        // TCP or UDP with its ports
	UINT SrcPort;        // ... the source port
	UINT DstPort;        // ... and the destination port
	UINT TcpFlags;       // The flags of a TCP segment
	bool Echo;           // An ICMP echo request or reply
	UINT EchoId;         // ... its id
	bool Error;          // An ICMP error, which quotes the packet it is about
	UINT IcmpType;       // The type of an ICMP message
	UINT Control;        // POLICY_CTL_*
	const UCHAR *ArpSha; // ARP: the sender MAC address
	UCHAR ArpSpa[16];    // ... and the sender IPv4 address
} POLICY_PACKET;

static const UCHAR policy_zero[16] = {0};

// A 16-bit value at p, big-endian
static UINT PolicyGet16(const UCHAR *p) {
	return ((UINT)p[0] << 8) | p[1];
}

//
// The engine, its slots of processors and its members
//

// The slot of processors of the calling thread
static UINT PolicySlotNow(void) {
	return GetCurrentProcessorNumber() & (POLICY_SLOTS - 1);
}

// Wait until no frame reads what a change replaced: every slot of processors is taken exclusive once. The caller holds
// ConfigLock and no lock of a slot, a Network or a shard.
static void PolicyQuiesce(POLICY_ENGINE *p) {
	for (UINT i = 0; i < POLICY_SLOTS; i++) {
		AcquireSRWLockExclusive(&p->Readers[i].Lock);
		ReleaseSRWLockExclusive(&p->Readers[i].Lock);
	}
}

// The document in force, NULL before the first. The caller holds the lock of a slot of processors or ConfigLock.
static POLICY_STATE *PolicyStateOf(POLICY_ENGINE *p) {
	return (POLICY_STATE *)ReadPointerAcquire((PVOID const volatile *)&p->State);
}

// The record of a member, NULL when no member holds the slot. The caller holds the lock of a slot of processors or
// ConfigLock.
static const POLICY_RECORD *PolicyRecordOf(POLICY_ENGINE *p, UINT member) {
	if (p == NULL || member >= p->MaxMembers)
		return NULL;

	return (const POLICY_RECORD *)ReadPointerAcquire((PVOID const volatile *)&p->Slots[member].Record);
}

// The Network of a name, made when create is set and the engine has room; NULL for none. The caller holds ConfigLock
// exclusive when create is set.
static POLICY_NET *PolicyNetOf(POLICY_ENGINE *p, const char *name, bool create) {
	UINT num = (UINT)ReadAcquire(&p->NumNets);

	for (UINT i = 0; i < num && i < POLICY_MAX_NETWORKS; i++) {
		if (strcmp(p->Nets[i]->Name, name) == 0)
			return p->Nets[i];
	}
	if (create == false || num >= POLICY_MAX_NETWORKS)
		return NULL;

	POLICY_NET *net = (POLICY_NET *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_NET));
	if (net == NULL)
		return NULL;

	PolicyCopyName(net->Name, name);
	net->Index = num;
	InitializeSRWLock(&net->LearnLock);

	// The pointer before the number, so that a reader of the number finds the Network
	p->Nets[num] = net;
	WriteRelease(&p->NumNets, (LONG)(num + 1));

	return net;
}

// A new policy engine of max_members members at most (0 for POLICY_DEFAULT_MEMBERS); NULL for more than
// POLICY_MAX_MEMBERS, or when there is no memory
POLICY_ENGINE *PolicyNew(UINT max_members) {
	if (max_members == 0)
		max_members = POLICY_DEFAULT_MEMBERS;
	if (max_members > POLICY_MAX_MEMBERS)
		return NULL;

	// The engine and the slots at the start of a cache line of their blocks
	UCHAR *block = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_ENGINE) + POLICY_CACHE_LINE);
	UCHAR *slots = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_SLOT) * (SIZE_T)max_members + POLICY_CACHE_LINE);
	if (block == NULL || slots == NULL) {
		if (block != NULL)
			HeapFree(GetProcessHeap(), 0, block);
		if (slots != NULL)
			HeapFree(GetProcessHeap(), 0, slots);
		return NULL;
	}

	POLICY_ENGINE *p = (POLICY_ENGINE *)(block + POLICY_CACHE_LINE - ((UINT_PTR)block & (POLICY_CACHE_LINE - 1)));
	p->Block = block;
	p->SlotBlock = slots;
	p->Slots = (POLICY_SLOT *)(slots + POLICY_CACHE_LINE - ((UINT_PTR)slots & (POLICY_CACHE_LINE - 1)));
	p->MaxMembers = max_members;
	InitializeSRWLock(&p->ConfigLock);
	for (UINT i = 0; i < POLICY_SLOTS; i++)
		InitializeSRWLock(&p->Readers[i].Lock);

	return p;
}

// Free a document in force with its tables, and the conntrack tables that keep, NULL for none, does not hold
static void PolicyFreeState(POLICY_STATE *st, const POLICY_STATE *keep) {
	if (st == NULL)
		return;

	for (UINT i = 0; i < st->Doc->NumNets; i++) {
		POLICY_TRACK *track = st->Tables[i].Track;
		bool kept = false;

		for (UINT j = 0; keep != NULL && j < keep->Doc->NumNets && kept == false; j++)
			kept = (keep->Tables[j].Track == track);
		if (kept == false)
			PolicyFreeTrack(track);
	}

	PolicyFreeDoc(st->Doc);
	HeapFree(GetProcessHeap(), 0, st);
}

// Free a policy engine. No thread may use it any more.
void PolicyFree(POLICY_ENGINE *p) {
	if (p == NULL)
		return;

	PolicyFreeState(p->State, NULL);

	for (UINT i = 0; i < p->MaxMembers; i++) {
		POLICY_RECORD *rec = p->Slots[i].Record;

		if (rec != NULL)
			HeapFree(GetProcessHeap(), 0, rec);
	}

	for (UINT i = 0; i < (UINT)p->NumNets && i < POLICY_MAX_NETWORKS; i++) {
		POLICY_NET *net = p->Nets[i];

		if (net->Owners != NULL)
			HeapFree(GetProcessHeap(), 0, net->Owners);
		HeapFree(GetProcessHeap(), 0, net);
	}

	HeapFree(GetProcessHeap(), 0, p->SlotBlock);
	HeapFree(GetProcessHeap(), 0, p->Block);
}

//
// The addresses that the members own
//

// The owner entry of an address of a kind, its unused bytes 0
static void PolicyOwnerKey(POLICY_OWNER *o, UINT kind, const UCHAR *addr) {
	UINT len = (kind == POLICY_OWN_MAC ? 6 : (kind == POLICY_OWN_IPV4 ? 4 : 16));

	ZeroMemory(o, sizeof(POLICY_OWNER));
	o->Kind = (UCHAR)kind;
	CopyMemory(o->Addr, addr, len);
	o->Member = POLICY_NO_MEMBER;
}

// The order of two owner entries: by kind, then by address
static int PolicyOwnerCompare(const POLICY_OWNER *a, const POLICY_OWNER *b) {
	if (a->Kind != b->Kind)
		return (a->Kind < b->Kind ? -1 : 1);

	return memcmp(a->Addr, b->Addr, sizeof(a->Addr));
}

// Where the address of o is among the owned addresses of a Network, or would be; *found tells which. The caller holds
// the LearnLock of the Network.
static UINT PolicyOwnerIndex(const POLICY_NET *net, const POLICY_OWNER *o, bool *found) {
	UINT lo = 0;
	UINT hi = (UINT)net->NumOwners;

	*found = false;
	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;
		int c = PolicyOwnerCompare(&net->Owners[mid], o);

		if (c == 0) {
			*found = true;
			return mid;
		}
		if (c > 0)
			hi = mid;
		else
			lo = mid + 1;
	}

	return lo;
}

// The member that owns an address of a kind in a Network, POLICY_NO_MEMBER for none
static UINT PolicyOwnerOf(POLICY_NET *net, UINT kind, const UCHAR *addr) {
	POLICY_OWNER o;
	bool found = false;
	UINT member = POLICY_NO_MEMBER;

	PolicyOwnerKey(&o, kind, addr);
	AcquireSRWLockShared(&net->LearnLock);
	UINT i = PolicyOwnerIndex(net, &o, &found);
	if (found)
		member = net->Owners[i].Member;
	ReleaseSRWLockShared(&net->LearnLock);

	return member;
}

// Give member, whose record is rec, an address of a kind: true when it owns it now or did before; false when another
// member owns it, the member owns its limit of the kind, it left, or there is no memory. The caller holds the LearnLock
// of the Network exclusive.
static bool PolicyOwnerAdd(POLICY_ENGINE *p, POLICY_NET *net, UINT member, const POLICY_RECORD *rec, UINT kind, const UCHAR *addr) {
	POLICY_SLOT *s = &p->Slots[member];
	POLICY_OWNER o;
	bool found = false;

	// A member that left owns nothing: PolicyDelMember took out what it owned under this lock
	if (s->Record != rec)
		return false;

	PolicyOwnerKey(&o, kind, addr);
	UINT i = PolicyOwnerIndex(net, &o, &found);
	if (found)
		return net->Owners[i].Member == member;

	UINT *num = (kind == POLICY_OWN_MAC ? &s->NumMacs : &s->NumIps);
	if (*num >= (kind == POLICY_OWN_MAC ? rec->MaxMacs : rec->MaxIps))
		return false;

	UINT count = (UINT)net->NumOwners;
	if (count == net->MaxOwners) {
		UINT max = (net->MaxOwners == 0 ? POLICY_FIRST_OWNERS : net->MaxOwners * 2);
		POLICY_OWNER *owners = (POLICY_OWNER *)HeapAlloc(GetProcessHeap(), 0, sizeof(POLICY_OWNER) * max);

		if (owners == NULL)
			return false;
		if (net->Owners != NULL) {
			CopyMemory(owners, net->Owners, sizeof(POLICY_OWNER) * count);
			HeapFree(GetProcessHeap(), 0, net->Owners);
		}
		net->Owners = owners;
		net->MaxOwners = max;
	}

	MoveMemory(&net->Owners[i + 1], &net->Owners[i], sizeof(POLICY_OWNER) * (count - i));
	o.Member = member;
	net->Owners[i] = o;
	InterlockedIncrement(&net->NumOwners);
	(*num)++;

	return true;
}

// Take out every address that a member owns in a Network. The caller holds the LearnLock of the Network exclusive.
static void PolicyOwnerDropMember(POLICY_ENGINE *p, POLICY_NET *net, UINT member) {
	UINT count = (UINT)net->NumOwners;
	UINT kept = 0;

	for (UINT i = 0; i < count; i++) {
		if (net->Owners[i].Member != member) {
			net->Owners[kept] = net->Owners[i];
			kept++;
		}
	}

	InterlockedExchange(&net->NumOwners, (LONG)kept);
	p->Slots[member].NumMacs = 0;
	p->Slots[member].NumIps = 0;
}

// Whether a member may send from an address of a kind: it owns it; or no member owns it and the member is under no check
// of the kind; or it is under the check (check), no member owns the address, and the member takes it within its limit
static bool PolicySourceOk(POLICY_ENGINE *p, UINT member, const POLICY_RECORD *rec, UINT kind, const UCHAR *addr, bool check) {
	POLICY_NET *net = rec->Net;

	if (check == false && ReadAcquire(&net->NumOwners) == 0)
		return true;

	UINT owner = PolicyOwnerOf(net, kind, addr);
	if (owner == member)
		return true;
	if (owner != POLICY_NO_MEMBER)
		return false;
	if (check == false)
		return true;

	// Another frame may have taken it since: the exclusive lock looks again
	AcquireSRWLockExclusive(&net->LearnLock);
	bool ok = PolicyOwnerAdd(p, net, member, rec, kind, addr);
	ReleaseSRWLockExclusive(&net->LearnLock);

	return ok;
}

//
// The members
//

// Whether the names of a list of identities are names
static bool PolicyIdsOk(const char *const *names, UINT num) {
	if (num > POLICY_MAX_IDS || (num != 0 && names == NULL))
		return false;

	for (UINT i = 0; i < num; i++) {
		if (PolicyNameOk(names[i], true) == false)
			return false;
	}

	return true;
}

// Copy a list of names to the strings at *pos of a block of a record, the pointers into list
static void PolicyCopyIds(const char **list, const char *const *names, UINT num, char **pos) {
	for (UINT i = 0; i < num; i++) {
		SIZE_T len = strlen(names[i]);

		CopyMemory(*pos, names[i], len + 1);
		list[i] = *pos;
		*pos += len + 1;
	}
}

// The record of a member of a configuration, in one block of the heap of the process; NULL when there is no memory
static POLICY_RECORD *PolicyNewRecord(const POLICY_MEMBER_CONFIG *cfg, POLICY_NET *net, UINT gen) {
	SIZE_T strings = (cfg->User != NULL ? strlen(cfg->User) + 1 : 0);

	for (UINT i = 0; i < cfg->NumGroups; i++)
		strings += strlen(cfg->Groups[i]) + 1;
	for (UINT i = 0; i < cfg->NumTags; i++)
		strings += strlen(cfg->Tags[i]) + 1;

	SIZE_T lists = sizeof(char *) * ((SIZE_T)cfg->NumGroups + cfg->NumTags);
	POLICY_RECORD *rec = (POLICY_RECORD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_RECORD) + lists + strings);
	if (rec == NULL)
		return NULL;

	const char **ids = (const char **)(rec + 1);
	char *pos = (char *)(rec + 1) + lists;

	rec->Net = net;
	rec->Gen = gen;
	rec->Guard = cfg->Guard;
	rec->MaxMacs = (cfg->MaxMacs != 0 ? cfg->MaxMacs : POLICY_DEFAULT_MACS);
	rec->MaxIps = (cfg->MaxIps != 0 ? cfg->MaxIps : POLICY_DEFAULT_IPS);
	if (cfg->User != NULL) {
		const char *user[1] = {cfg->User};
		const char *copy[1] = {NULL};

		PolicyCopyIds(copy, user, 1, &pos);
		rec->Id.User = copy[0];
	}
	rec->Id.NumGroups = cfg->NumGroups;
	rec->Id.Groups = ids;
	PolicyCopyIds(ids, cfg->Groups, cfg->NumGroups, &pos);
	rec->Id.NumTags = cfg->NumTags;
	rec->Id.Tags = ids + cfg->NumGroups;
	PolicyCopyIds(ids + cfg->NumGroups, cfg->Tags, cfg->NumTags, &pos);

	return rec;
}

// Add a member: its number, POLICY_NO_MEMBER when its configuration is none (a name that is none, an unknown guard flag,
// a limit above POLICY_MAX_BOUND), the engine has its members or POLICY_MAX_NETWORKS Networks, or there is no memory. A
// member takes the lowest free number; its frames are judged by the document in force from the next one on.
UINT PolicyAddMember(POLICY_ENGINE *p, const POLICY_MEMBER_CONFIG *cfg) {
	UINT member = POLICY_NO_MEMBER;

	if (p == NULL || cfg == NULL || PolicyNameOk(cfg->Network, false) == false || (cfg->User != NULL && PolicyNameOk(cfg->User, true) == false) ||
	    PolicyIdsOk(cfg->Groups, cfg->NumGroups) == false || PolicyIdsOk(cfg->Tags, cfg->NumTags) == false || (cfg->Guard & ~(UINT)POLICY_GUARD_ALL) != 0 ||
	    cfg->MaxMacs > POLICY_MAX_BOUND || cfg->MaxIps > POLICY_MAX_BOUND)
		return POLICY_NO_MEMBER;

	AcquireSRWLockExclusive(&p->ConfigLock);
	if (p->NumMembers < p->MaxMembers) {
		POLICY_NET *net = PolicyNetOf(p, cfg->Network, true);

		for (UINT i = 0; i < p->MaxMembers && net != NULL; i++) {
			POLICY_SLOT *s = &p->Slots[i];

			if (s->Record != NULL)
				continue;

			POLICY_RECORD *rec = PolicyNewRecord(cfg, net, s->NextGen);
			if (rec != NULL) {
				s->NumMacs = 0;
				s->NumIps = 0;
				InterlockedExchangePointer((PVOID volatile *)&s->Record, rec);
				p->NumMembers++;
				InterlockedIncrement(&net->NumMembers);
				member = i;
			}
			break;
		}
	}
	ReleaseSRWLockExclusive(&p->ConfigLock);

	return member;
}

// Take out a member: its addresses, its flows (which no frame takes any more) and its record; false when no member has
// the number. When it returns, no frame of the member or to it is still being judged.
bool PolicyDelMember(POLICY_ENGINE *p, UINT member) {
	POLICY_RECORD *rec = NULL;

	if (p == NULL || member >= p->MaxMembers)
		return false;

	AcquireSRWLockExclusive(&p->ConfigLock);
	rec = p->Slots[member].Record;
	if (rec != NULL) {
		POLICY_NET *net = rec->Net;

		InterlockedExchangePointer((PVOID volatile *)&p->Slots[member].Record, NULL);
		p->Slots[member].NextGen++;

		AcquireSRWLockExclusive(&net->LearnLock);
		PolicyOwnerDropMember(p, net, member);
		ReleaseSRWLockExclusive(&net->LearnLock);

		PolicyQuiesce(p);
		p->NumMembers--;
		InterlockedDecrement(&net->NumMembers);
		HeapFree(GetProcessHeap(), 0, rec);
	}
	ReleaseSRWLockExclusive(&p->ConfigLock);

	return rec != NULL;
}

// Give a member an address of a kind; false when no member has the number, or PolicyOwnerAdd refuses
static bool PolicyBind(POLICY_ENGINE *p, UINT member, UINT kind, const UCHAR *addr) {
	bool ok = false;

	if (p == NULL || addr == NULL || member >= p->MaxMembers)
		return false;

	AcquireSRWLockExclusive(&p->ConfigLock);
	const POLICY_RECORD *rec = p->Slots[member].Record;
	if (rec != NULL) {
		AcquireSRWLockExclusive(&rec->Net->LearnLock);
		ok = PolicyOwnerAdd(p, rec->Net, member, rec, kind, addr);
		ReleaseSRWLockExclusive(&rec->Net->LearnLock);
	}
	ReleaseSRWLockExclusive(&p->ConfigLock);

	return ok;
}

// Give a member a MAC address: it owns it from now on, and no other member of its Network may send from it. False when
// no member has the number, another member owns the address, the member owns its MAC limit, or there is no memory.
bool PolicyBindMac(POLICY_ENGINE *p, UINT member, const UCHAR *mac) {
	return PolicyBind(p, member, POLICY_OWN_MAC, mac);
}

// Give a member an IP address of a family (POLICY_IPV4, the address in its first 4 bytes, or POLICY_IPV6), as
// PolicyBindMac gives a MAC address
bool PolicyBindIp(POLICY_ENGINE *p, UINT member, UINT family, const UCHAR *ip) {
	if (family != POLICY_IPV4 && family != POLICY_IPV6)
		return false;

	return PolicyBind(p, member, family == POLICY_IPV4 ? POLICY_OWN_IPV4 : POLICY_OWN_IPV6, ip);
}

//
// The frames
//

// The class of the packets of an IP protocol of a family (POLICY_CLASS_*)
static UINT PolicyClassOf(UINT family, UINT protocol) {
	if (protocol == 6)
		return POLICY_CLASS_TCP;
	if (protocol == 17)
		return POLICY_CLASS_UDP;
	if ((family == POLICY_IPV4 && protocol == 1) || (family == POLICY_IPV6 && protocol == 58))
		return POLICY_CLASS_ICMP;

	return POLICY_CLASS_OTHER;
}

// The transport header of an IP packet into pk: its class, its ports, its ICMP type and what the segment needs of it;
// false when it is shorter than its header
static bool PolicyParseTransport(POLICY_PACKET *pk) {
	pk->Class = PolicyClassOf(pk->Family, pk->Protocol);

	// A later fragment has no transport header
	if (pk->Later)
		return true;

	if (pk->Class == POLICY_CLASS_TCP || pk->Class == POLICY_CLASS_UDP) {
		if (pk->L4Size < (pk->Class == POLICY_CLASS_TCP ? 20u : 8u))
			return false;

		pk->HasPort = true;
		pk->SrcPort = PolicyGet16(pk->L4);
		pk->DstPort = PolicyGet16(pk->L4 + 2);
		if (pk->Class == POLICY_CLASS_TCP) {
			pk->TcpFlags = pk->L4[13];
			return true;
		}

		// DHCP (UDP 68 to 67, 67 to 68 or 67) and DHCPv6 (UDP 546 to 547, 547 to 546)
		if (pk->Family == POLICY_IPV4 && pk->SrcPort == 68 && pk->DstPort == 67)
			pk->Control = POLICY_CTL_DHCP;
		else if (pk->Family == POLICY_IPV4 && pk->SrcPort == 67 && (pk->DstPort == 68 || pk->DstPort == 67))
			pk->Control = POLICY_CTL_DHCP_SERVER;
		else if (pk->Family == POLICY_IPV6 && pk->SrcPort == 546 && pk->DstPort == 547)
			pk->Control = POLICY_CTL_DHCP;
		else if (pk->Family == POLICY_IPV6 && pk->SrcPort == 547 && pk->DstPort == 546)
			pk->Control = POLICY_CTL_DHCP_SERVER;
		return true;
	}

	if (pk->Class != POLICY_CLASS_ICMP)
		return true;

	// ICMP: the type, the code and the checksum, then 4 bytes: the id and sequence of an echo
	if (pk->L4Size < 8)
		return false;

	pk->IcmpType = pk->L4[0];
	if (pk->Family == POLICY_IPV4) {
		pk->Echo = (pk->IcmpType == POLICY_ICMP4_ECHO || pk->IcmpType == POLICY_ICMP4_ECHO_REPLY);
		pk->Error = (pk->IcmpType == 3 || pk->IcmpType == 4 || pk->IcmpType == 5 || pk->IcmpType == 11 || pk->IcmpType == 12);
	} else {
		pk->Echo = (pk->IcmpType == POLICY_ICMP6_ECHO || pk->IcmpType == POLICY_ICMP6_ECHO_REPLY);
		pk->Error = (pk->IcmpType >= 1 && pk->IcmpType <= 4);
		if (pk->IcmpType >= POLICY_ICMP6_RS && pk->IcmpType <= POLICY_ICMP6_REDIRECT)
			pk->Control = POLICY_CTL_ND;
	}
	if (pk->Echo)
		pk->EchoId = PolicyGet16(pk->L4 + 4);

	return true;
}

// The IPv4 header at ip, size bytes, into pk; quoted: the packet that an ICMP error quotes, whose length is that of the
// packet it was, not of what the error holds. False when it is no IPv4 header.
static bool PolicyParseIpv4(const UCHAR *ip, UINT size, bool quoted, POLICY_PACKET *pk) {
	if (size < 20 || (ip[0] >> 4) != 4)
		return false;

	UINT ihl = (ip[0] & 0x0F) * 4;
	UINT total = PolicyGet16(ip + 2);
	if (ihl < 20 || ihl > size || total < ihl)
		return false;
	if (quoted)
		total = size;
	else if (total > size)
		return false;

	pk->Family = POLICY_IPV4;
	pk->Protocol = ip[9];
	pk->Later = ((PolicyGet16(ip + 6) & 0x1FFF) != 0);
	CopyMemory(pk->Src, ip + 12, 4);
	CopyMemory(pk->Dst, ip + 16, 4);
	pk->Group = (memcmp(pk->Dst, "\xFF\xFF\xFF\xFF", 4) == 0 || (pk->Dst[0] & 0xF0) == 0xE0);
	pk->L4 = ip + ihl;
	pk->L4Size = total - ihl;

	return true;
}

// The IPv6 header at ip, size bytes, and its extension headers into pk, as PolicyParseIpv4. A packet with more than
// POLICY_MAX_HEADERS extension headers has the next one as its protocol.
static bool PolicyParseIpv6(const UCHAR *ip, UINT size, bool quoted, POLICY_PACKET *pk) {
	if (size < 40 || (ip[0] >> 4) != 6)
		return false;

	UINT end = 40 + PolicyGet16(ip + 4);
	if (quoted || end > size)
		end = (quoted ? size : 0);
	if (end == 0)
		return false;

	UINT next = ip[6];
	UINT off = 40;

	pk->Family = POLICY_IPV6;
	CopyMemory(pk->Src, ip + 8, 16);
	CopyMemory(pk->Dst, ip + 24, 16);
	pk->Group = (pk->Dst[0] == 0xFF);

	// Hop-by-hop options, routing, fragment and destination options
	for (UINT n = 0; n < POLICY_MAX_HEADERS; n++) {
		if (next == 44) {
			if (off + 8 > end)
				return false;
			pk->Later = ((PolicyGet16(ip + off + 2) & 0xFFF8) != 0);
			next = ip[off];
			off += 8;
		} else if (next == 0 || next == 43 || next == 60) {
			if (off + 2 > end)
				return false;
			UINT len = ((UINT)ip[off + 1] + 1) * 8;
			next = ip[off];
			if (off + len > end)
				return false;
			off += len;
		} else {
			break;
		}
		if (pk->Later)
			break;
	}

	pk->Protocol = next;
	pk->L4 = ip + off;
	pk->L4Size = end - off;

	return true;
}

// The frame of a Network of the kind mode (POLICY_L2 or POLICY_L3), size bytes, into pk; false when it is malformed
static bool PolicyParse(const UCHAR *frame, UINT size, UINT mode, POLICY_PACKET *pk) {
	const UCHAR *ip = frame;
	UINT ip_size = size;

	ZeroMemory(pk, sizeof(POLICY_PACKET));
	if (frame == NULL || size == 0)
		return false;

	if (mode == POLICY_L2) {
		UINT off = POLICY_ETH_HEADER;

		// The two addresses, then the EtherType after one tag (0x8100, 0x88A8 or 0x9100, as the VLAN of the frame is the
		// caller's); a group address is no source
		if (size < POLICY_ETH_HEADER || (frame[6] & 1) != 0)
			return false;
		pk->Smac = frame + 6;
		pk->Group = ((frame[0] & 1) != 0);
		pk->EtherType = PolicyGet16(frame + 12);
		if (pk->EtherType == 0x8100 || pk->EtherType == 0x88A8 || pk->EtherType == 0x9100) {
			if (size < POLICY_ETH_HEADER + POLICY_TAG_SIZE)
				return false;
			pk->EtherType = PolicyGet16(frame + 16);
			off += POLICY_TAG_SIZE;
		}
		ip = frame + off;
		ip_size = size - off;

		if (pk->EtherType == POLICY_ETHERTYPE_ARP) {
			// ARP for Ethernet and IPv4: the sender's MAC and IPv4 addresses
			if (ip_size < POLICY_ARP_SIZE || PolicyGet16(ip + 2) != POLICY_ETHERTYPE_IPV4 || ip[4] != 6 || ip[5] != 4)
				return false;
			pk->Control = POLICY_CTL_ARP;
			pk->ArpSha = ip + 8;
			CopyMemory(pk->ArpSpa, ip + 14, 4);
			return true;
		}
		if (pk->EtherType != POLICY_ETHERTYPE_IPV4 && pk->EtherType != POLICY_ETHERTYPE_IPV6) {
			pk->Class = POLICY_CLASS_NON_IP;
			return true;
		}
	} else {
		pk->EtherType = ((frame[0] >> 4) == 6 ? POLICY_ETHERTYPE_IPV6 : POLICY_ETHERTYPE_IPV4);
	}

	bool ok = (pk->EtherType == POLICY_ETHERTYPE_IPV4 ? PolicyParseIpv4(ip, ip_size, false, pk) : PolicyParseIpv6(ip, ip_size, false, pk));
	if (ok && mode == POLICY_L2) {
		// An L2 frame goes to a group by its MAC destination as well
		pk->Group = (pk->Group || (frame[0] & 1) != 0);
	}

	return ok && PolicyParseTransport(pk);
}

// The filters of a guard that hold for the frames that a member gets as well as for those it sends, as the fork's Hub
// applies the policy of a session on both sides (StorePacketFilterByPolicy and PolicyDropsPacket of Hub.c): the filters
// of IPv4, IPv6 and non-IP frames, ARP and DHCP only, and no router advertisements. POLICY_PASS_RULE when they let the
// frame through, else the reason to drop it.
static UINT PolicyFilters(UINT guard, const POLICY_PACKET *pk) {
	bool v4 = (pk->EtherType == POLICY_ETHERTYPE_IPV4 || pk->EtherType == POLICY_ETHERTYPE_ARP);

	if (((guard & POLICY_GUARD_NO_IPV4) != 0 && v4) || ((guard & POLICY_GUARD_NO_IPV6) != 0 && pk->EtherType == POLICY_ETHERTYPE_IPV6) ||
	    ((guard & POLICY_GUARD_NO_NON_IP) != 0 && pk->Class == POLICY_CLASS_NON_IP))
		return POLICY_DROP_PROTOCOL;

	// Frames to a group address: ARP, DHCP and neighbour discovery only
	if ((guard & POLICY_GUARD_ARP_DHCP_ONLY) != 0 && pk->Group && pk->Control == POLICY_CTL_NONE)
		return POLICY_DROP_BROADCAST;
	if ((guard & POLICY_GUARD_NO_RA) != 0 && pk->Control == POLICY_CTL_ND && pk->IcmpType == POLICY_ICMP6_RA)
		return POLICY_DROP_RA;

	return POLICY_PASS_RULE;
}

// The guard of a member over a frame of it: POLICY_PASS_RULE when the frame goes on, else the reason to drop it
static UINT PolicyGuard(POLICY_ENGINE *p, UINT from, const POLICY_RECORD *rec, const POLICY_PACKET *pk) {
	UINT guard = rec->Guard;
	UINT reason = PolicyFilters(guard, pk);

	if (reason != POLICY_PASS_RULE)
		return reason;
	if ((guard & POLICY_GUARD_NO_DHCP_SERVER) != 0 && pk->Control == POLICY_CTL_DHCP_SERVER)
		return POLICY_DROP_DHCP_SERVER;

	// The source MAC address, and the sender of an ARP frame
	if (pk->Smac != NULL) {
		bool check = ((guard & POLICY_GUARD_CHECK_MAC) != 0);

		if (PolicySourceOk(p, from, rec, POLICY_OWN_MAC, pk->Smac, check) == false)
			return POLICY_DROP_MAC;
		if (pk->ArpSha != NULL && memcmp(pk->ArpSha, pk->Smac, 6) != 0 && PolicySourceOk(p, from, rec, POLICY_OWN_MAC, pk->ArpSha, check) == false)
			return POLICY_DROP_MAC;
	}

	// The source IP address, and the sender of an ARP frame; the unspecified address of DHCP and of duplicate address
	// detection is nobody's
	bool check_ip = ((guard & POLICY_GUARD_CHECK_IP) != 0);
	if (pk->Family != 0 && memcmp(pk->Src, policy_zero, pk->Family == POLICY_IPV4 ? 4 : 16) != 0 &&
	    PolicySourceOk(p, from, rec, pk->Family == POLICY_IPV4 ? POLICY_OWN_IPV4 : POLICY_OWN_IPV6, pk->Src, check_ip) == false)
		return POLICY_DROP_IP;
	if (pk->Control == POLICY_CTL_ARP && memcmp(pk->ArpSpa, policy_zero, 4) != 0 &&
	    PolicySourceOk(p, from, rec, POLICY_OWN_IPV4, pk->ArpSpa, check_ip) == false)
		return POLICY_DROP_IP;

	return POLICY_PASS_RULE;
}

//
// The rules and the conntrack tables
//

// Count a frame of size bytes on rule index of table t (NumRules: its default action), in a slot of processors; flow:
// the frame started a flow that the conntrack table took
static void PolicyCount(const POLICY_TABLE *t, UINT slot, UINT index, bool flow, UINT size) {
	volatile LONG64 *c = &t->Counters[(SIZE_T)slot * t->Stride + (SIZE_T)index * POLICY_NUM_COUNTS];

	if (flow)
		InterlockedIncrement64(&c[POLICY_COUNT_FLOWS]);
	InterlockedIncrement64(&c[POLICY_COUNT_PACKETS]);
	InterlockedExchangeAdd64(&c[POLICY_COUNT_BYTES], (LONG64)size);
}

// The action of rule index of table t, its default action for NumRules
static UINT PolicyActionOf(const POLICY_TABLE *t, UINT index) {
	return (index < t->NumRules ? t->Rules[index]->Action : t->Config.DefaultAction);
}

// The verdict of a frame that rule index of table t judged (NumRules: its default action): its counters, the name of the
// rule in r, and the reason; flow: the frame started a flow that the conntrack table took
static UINT PolicyVerdict(const POLICY_TABLE *t, UINT slot, UINT index, bool flow, UINT size, POLICY_RESULT *r) {
	bool rule = (index < t->NumRules);
	UINT action = PolicyActionOf(t, index);

	PolicyCount(t, slot, rule ? index : t->NumRules, flow, size);
	if (rule)
		PolicyCopyName(r->Rule, t->Rules[index]->Name);
	else
		PolicyCopyName(r->Rule, t->Config.DefaultAction == POLICY_ALLOW ? "default:allow" : "default:deny");

	if (action == POLICY_ALLOW)
		return rule ? POLICY_PASS_RULE : POLICY_PASS_DEFAULT;

	return rule ? POLICY_DROP_RULE : POLICY_DROP_DEFAULT;
}

// The first rule of table t that matches a frame of the VLAN vlan from the member rf to the member rt (NULL for an end
// outside the Network): its index, NumRules for none
static UINT PolicyMatchPacket(const POLICY_TABLE *t, const POLICY_PACKET *pk, UINT vlan, const POLICY_RECORD *rf, const POLICY_RECORD *rt) {
	POLICY_MATCH m;

	ZeroMemory(&m, sizeof(m));
	m.Class = pk->Class;
	m.Family = pk->Family;
	m.Protocol = pk->Protocol;
	m.Src = pk->Src;
	m.Dst = pk->Dst;
	m.HasPort = pk->HasPort;
	m.DstPort = pk->DstPort;
	m.Vlan = vlan;
	m.From = &rf->Id;
	m.To = (rt != NULL ? &rt->Id : NULL);

	return PolicyMatch(t, &m);
}

// The key of the flow of a packet from src, port sport, to dst, port dport; *side is the side of its source
static void PolicyKeyOf(const UCHAR *src, UINT sport, const UCHAR *dst, UINT dport, UINT family, UINT protocol, UINT vlan, POLICY_KEY *k, UINT *side) {
	int c = memcmp(src, dst, 16);
	UINT s = ((c < 0 || (c == 0 && sport <= dport)) ? 0 : 1);

	ZeroMemory(k, sizeof(POLICY_KEY));
	CopyMemory(k->Addr[s], src, 16);
	CopyMemory(k->Addr[1 - s], dst, 16);
	k->Port[s] = (USHORT)sport;
	k->Port[1 - s] = (USHORT)dport;
	k->Family = (UCHAR)family;
	k->Protocol = (UCHAR)protocol;
	k->Vlan = (USHORT)vlan;
	*side = s;
}

// The ports of the key of the flow of a packet: TCP and UDP ports, the id of an ICMP echo on both sides, 0 else
static void PolicyFlowPorts(const POLICY_PACKET *pk, UINT *sport, UINT *dport) {
	*sport = 0;
	*dport = 0;
	if (pk->HasPort) {
		*sport = pk->SrcPort;
		*dport = pk->DstPort;
	} else if (pk->Echo) {
		*sport = pk->EchoId;
		*dport = pk->EchoId;
	}
}

// Whether a packet is of a flow that the conntrack table tracks: an IP packet to one address that is no later fragment,
// of TCP, UDP, an ICMP echo or another protocol (PolicyJudgeFlow starts no flow with a TCP reset)
static bool PolicyTracks(const POLICY_PACKET *pk) {
	if (pk->Family == 0 || pk->Group || pk->Later)
		return false;

	return pk->Class != POLICY_CLASS_ICMP || pk->Echo;
}

// Whether flow f is the flow of a frame whose source is its side s, from the member from (record rf) to the member to
// (record rt, NULL for an end outside the Network)
static bool PolicyFlowOf(const POLICY_FLOW *f, UINT s, UINT from, const POLICY_RECORD *rf, UINT to, const POLICY_RECORD *rt) {
	return f->Member[s] == from && f->MemberGen[s] == rf->Gen && f->Member[1 - s] == to && f->MemberGen[1 - s] == (rt != NULL ? rt->Gen : 0);
}

// Whether a member of flow f has left: its slot is free, or another member holds it
static bool PolicyFlowStale(POLICY_ENGINE *p, const POLICY_FLOW *f) {
	for (UINT s = 0; s < 2; s++) {
		const POLICY_RECORD *rec = NULL;

		if (f->Member[s] == POLICY_NO_MEMBER)
			continue;
		rec = PolicyRecordOf(p, f->Member[s]);
		if (rec == NULL || rec->Gen != f->MemberGen[s])
			return true;
	}

	return false;
}

// Judge flow f again under table t, in the direction of its first frame: the index of the rule, NumRules for the default
// action, POLICY_NO_RULE when a member of it left
static UINT PolicyRejudge(POLICY_ENGINE *p, const POLICY_TABLE *t, const POLICY_FLOW *f) {
	const POLICY_KEY *k = &f->Key;
	UINT o = f->Origin;
	const POLICY_RECORD *rf = PolicyRecordOf(p, f->Member[o]);
	const POLICY_RECORD *rt = (f->Member[1 - o] != POLICY_NO_MEMBER ? PolicyRecordOf(p, f->Member[1 - o]) : NULL);
	POLICY_MATCH m;

	if (rf == NULL || (f->Member[1 - o] != POLICY_NO_MEMBER && rt == NULL))
		return POLICY_NO_RULE;

	ZeroMemory(&m, sizeof(m));
	m.Class = PolicyClassOf(k->Family, k->Protocol);
	m.Family = k->Family;
	m.Protocol = k->Protocol;
	m.Src = k->Addr[o];
	m.Dst = k->Addr[1 - o];
	m.HasPort = (m.Class == POLICY_CLASS_TCP || m.Class == POLICY_CLASS_UDP);
	m.DstPort = k->Port[1 - o];
	m.Vlan = k->Vlan;
	m.From = &rf->Id;
	m.To = (rt != NULL ? &rt->Id : NULL);

	return PolicyMatch(t, &m);
}

// A frame of side s of flow f at now: what the sides sent, the state of the flow and its timeout, from the timeouts of
// table t
static void PolicyFlowUpdate(POLICY_FLOW *f, UINT s, const POLICY_PACKET *pk, const POLICY_TABLE *t, UINT64 now) {
	const UINT *timeouts = t->Config.Timeouts;

	if (now > f->Last)
		f->Last = now;
	f->Sent |= (UCHAR)(1u << s);

	if (pk->Class == POLICY_CLASS_TCP) {
		if ((pk->TcpFlags & POLICY_TCP_RST) != 0) {
			f->State = POLICY_FLOW_CLOSED;
		} else if ((pk->TcpFlags & POLICY_TCP_FIN) != 0 && f->State != POLICY_FLOW_CLOSED) {
			f->Fin |= (UCHAR)(1u << s);
			f->State = POLICY_FLOW_CLOSING;
		} else if (f->State == POLICY_FLOW_OPEN && f->Sent == 3) {
			f->State = POLICY_FLOW_ESTABLISHED;
		}

		if (f->State == POLICY_FLOW_CLOSED)
			f->Timeout = POLICY_TCP_CLOSED;
		else if (f->State == POLICY_FLOW_ESTABLISHED)
			f->Timeout = timeouts[POLICY_TIMEOUT_TCP_ESTABLISHED];
		else
			f->Timeout = timeouts[POLICY_TIMEOUT_TCP_TRANSITORY];
		return;
	}

	if (f->Sent == 3)
		f->State = POLICY_FLOW_ESTABLISHED;
	if (pk->Class == POLICY_CLASS_UDP)
		f->Timeout = timeouts[POLICY_TIMEOUT_UDP];
	else if (pk->Class == POLICY_CLASS_ICMP)
		f->Timeout = timeouts[POLICY_TIMEOUT_ICMP];
	else
		f->Timeout = timeouts[POLICY_TIMEOUT_OTHER];
}

// Count what left a full shard for a new flow (POLICY_LEFT_*) on a Network
static void PolicyCountLeft(POLICY_NET *net, UINT left) {
	if (left == POLICY_LEFT_EVICTED)
		InterlockedIncrement64(&net->Evicted);
	else if (left == POLICY_LEFT_EXPIRED)
		InterlockedIncrement64(&net->Expired);
}

// A trackable frame from the member from (record rf) to the member to (record rt, NULL for an end outside the Network)
// under the document st and its table t: the fast path of its flow, or its rules as the first frame of a flow, which the
// conntrack table then takes when they allow it
static UINT PolicyJudgeFlow(POLICY_ENGINE *p, const POLICY_STATE *st, const POLICY_TABLE *t, UINT slot, UINT64 now, UINT from, const POLICY_RECORD *rf,
                            UINT to, const POLICY_RECORD *rt, UINT vlan, const POLICY_PACKET *pk, UINT size, POLICY_RESULT *r) {
	POLICY_TRACK *track = t->Track;
	POLICY_KEY k;
	UINT s = 0;
	UINT sport = 0;
	UINT dport = 0;
	UINT index = 0;
	bool started = false;

	PolicyFlowPorts(pk, &sport, &dport);
	PolicyKeyOf(pk->Src, sport, pk->Dst, dport, pk->Family, pk->Protocol, vlan, &k, &s);

	UINT64 h = PolicyTrackHash(track, &k);
	POLICY_SHARD *sh = PolicyTrackShard(track, h);

	AcquireSRWLockExclusive(&sh->Lock);
	POLICY_FLOW *f = PolicyTrackFind(sh, &k, h);

	// A flow that expired, or of a member that left, is no more; a TCP SYN on a flow that ended opens a new one
	if (f != NULL && now >= f->Last + f->Timeout) {
		PolicyTrackDel(track, sh, f);
		InterlockedIncrement64(&t->Net->Expired);
		f = NULL;
	}
	if (f != NULL && (PolicyFlowStale(p, f) ||
	                  (pk->Class == POLICY_CLASS_TCP && (pk->TcpFlags & (POLICY_TCP_SYN | POLICY_TCP_ACK)) == POLICY_TCP_SYN && f->State >= POLICY_FLOW_CLOSING))) {
		PolicyTrackDel(track, sh, f);
		f = NULL;
	}

	// The fast path. A flow that an earlier document allowed is judged again first, as its first frame was.
	if (f != NULL && PolicyFlowOf(f, s, from, rf, to, rt)) {
		bool keep = true;

		if (f->Gen != st->Gen) {
			index = PolicyRejudge(p, t, f);
			keep = (index != POLICY_NO_RULE && PolicyActionOf(t, index) == POLICY_ALLOW);
			if (keep) {
				f->Gen = st->Gen;
				f->Rule = index;
			}
		}

		if (keep) {
			PolicyFlowUpdate(f, s, pk, t, now);
			PolicyTrackTouch(sh, f);
			index = f->Rule;
			ReleaseSRWLockExclusive(&sh->Lock);

			PolicyCount(t, slot, index, false, size);
			PolicyCopyName(r->Rule, index < t->NumRules ? t->Rules[index]->Name : "default:allow");
			return POLICY_PASS_FLOW;
		}

		// The new rules end the flow: the frame is the first frame of a flow of its own
		PolicyTrackDel(track, sh, f);
		f = NULL;
	}

	// The first frame of a flow, unless it is a TCP reset, which ends a flow and starts none. A flow of the same key
	// between other members is taken over when the rules allow the frame.
	index = PolicyMatchPacket(t, pk, vlan, rf, rt);
	if (PolicyActionOf(t, index) == POLICY_ALLOW && (pk->Class != POLICY_CLASS_TCP || (pk->TcpFlags & POLICY_TCP_RST) == 0)) {
		if (f == NULL) {
			UINT left = POLICY_LEFT_NONE;

			f = PolicyTrackAdd(track, sh, &k, h, now, &left);
			PolicyCountLeft(t->Net, left);
		}
		if (f != NULL) {
			f->Member[s] = from;
			f->MemberGen[s] = rf->Gen;
			f->Member[1 - s] = to;
			f->MemberGen[1 - s] = (rt != NULL ? rt->Gen : 0);
			f->Origin = (UCHAR)s;
			f->Gen = st->Gen;
			f->Rule = index;
			f->State = POLICY_FLOW_OPEN;
			f->Sent = 0;
			f->Fin = 0;
			f->Last = now;
			PolicyFlowUpdate(f, s, pk, t, now);
			PolicyTrackTouch(sh, f);
			InterlockedIncrement64(&t->Net->Tracked);
			started = true;
		}
	}
	ReleaseSRWLockExclusive(&sh->Lock);

	return PolicyVerdict(t, slot, index, started, size, r);
}

// An ICMP error to the member to (record rt, NULL for an end outside the Network) about a flow of the table t of the
// document st: the rule of that flow, which counts the error, or POLICY_NO_RULE when it is about no flow of the member.
// The error goes to the member of the side that sent the packet it quotes.
static UINT PolicyRelated(POLICY_ENGINE *p, const POLICY_STATE *st, const POLICY_TABLE *t, UINT64 now, UINT to, const POLICY_RECORD *rt, UINT vlan,
                          const POLICY_PACKET *pk) {
	POLICY_PACKET in;
	POLICY_KEY k;
	UINT s = 0;
	UINT sport = 0;
	UINT dport = 0;
	UINT index = POLICY_NO_RULE;
	const UCHAR *q = pk->L4 + 8;
	UINT q_size = pk->L4Size - 8;

	// The packet that the error quotes, of the family of the error: its header and the first 8 bytes after it, which hold
	// the ports of TCP and UDP and the id of an ICMP echo
	ZeroMemory(&in, sizeof(in));
	if ((pk->Family == POLICY_IPV4 ? PolicyParseIpv4(q, q_size, true, &in) : PolicyParseIpv6(q, q_size, true, &in)) == false || in.Later ||
	    in.L4Size < 8)
		return POLICY_NO_RULE;

	in.Class = PolicyClassOf(in.Family, in.Protocol);
	if (in.Class == POLICY_CLASS_TCP || in.Class == POLICY_CLASS_UDP) {
		sport = PolicyGet16(in.L4);
		dport = PolicyGet16(in.L4 + 2);
	} else if (in.Class == POLICY_CLASS_ICMP) {
		UINT type = in.L4[0];
		bool echo = (in.Family == POLICY_IPV4 ? (type == POLICY_ICMP4_ECHO || type == POLICY_ICMP4_ECHO_REPLY)
		                                      : (type == POLICY_ICMP6_ECHO || type == POLICY_ICMP6_ECHO_REPLY));

		if (echo == false)
			return POLICY_NO_RULE;
		sport = PolicyGet16(in.L4 + 4);
		dport = sport;
	}
	PolicyKeyOf(in.Src, sport, in.Dst, dport, in.Family, in.Protocol, vlan, &k, &s);

	UINT64 h = PolicyTrackHash(t->Track, &k);
	POLICY_SHARD *sh = PolicyTrackShard(t->Track, h);

	AcquireSRWLockShared(&sh->Lock);
	const POLICY_FLOW *f = PolicyTrackFind(sh, &k, h);
	if (f != NULL && now < f->Last + f->Timeout && f->Gen == st->Gen && f->Member[s] == to && f->MemberGen[s] == (rt != NULL ? rt->Gen : 0) &&
	    PolicyFlowStale(p, f) == false)
		index = f->Rule;
	ReleaseSRWLockShared(&sh->Lock);

	return index;
}

// The verdict of a frame under the document st, NULL before the first; the reason of the verdict
static UINT PolicyJudge(POLICY_ENGINE *p, const POLICY_STATE *st, UINT slot, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size,
                        POLICY_RESULT *r) {
	const POLICY_RECORD *rf = PolicyRecordOf(p, from);
	const POLICY_RECORD *rt = NULL;
	POLICY_PACKET pk;

	if (rf == NULL)
		return POLICY_DROP_MEMBER;
	if (to != POLICY_NO_MEMBER) {
		rt = PolicyRecordOf(p, to);
		if (rt == NULL || rt->Net != rf->Net)
			return POLICY_DROP_MEMBER;
	}
	if (st == NULL || st->ByNet[rf->Net->Index] == NULL)
		return POLICY_DROP_NETWORK;

	const POLICY_TABLE *t = st->ByNet[rf->Net->Index];
	r->Document = st->Gen;

	if (vlan > 4094 || PolicyParse(frame, size, t->Config.Mode, &pk) == false)
		return POLICY_DROP_MALFORMED;

	UINT reason = PolicyGuard(p, from, rf, &pk);
	if (reason == POLICY_PASS_RULE && rt != NULL)
		reason = PolicyFilters(rt->Guard, &pk);
	if (reason != POLICY_PASS_RULE)
		return reason;
	if (rt != NULL && (rf->Guard & POLICY_GUARD_ISOLATE) != 0 && (rt->Guard & POLICY_GUARD_ISOLATE) != 0)
		return POLICY_DROP_ISOLATED;
	if (pk.Control != POLICY_CTL_NONE)
		return POLICY_PASS_CONTROL;

	if (PolicyTracks(&pk))
		return PolicyJudgeFlow(p, st, t, slot, now, from, rf, to, rt, vlan, &pk, size, r);

	// An ICMP error about a flow passes with it
	if (pk.Error) {
		UINT index = PolicyRelated(p, st, t, now, to, rt, vlan, &pk);

		if (index != POLICY_NO_RULE) {
			PolicyCount(t, slot, index, false, size);
			PolicyCopyName(r->Rule, index < t->NumRules ? t->Rules[index]->Name : "default:allow");
			return POLICY_PASS_RELATED;
		}
	}

	// A frame that is no flow's: judged alone
	return PolicyVerdict(t, slot, PolicyMatchPacket(t, &pk, vlan, rf, rt), false, size, r);
}

// Judge a frame of the VLAN vlan (0 for none, or in an L3 Network) that the member from sends to the member to
// (POLICY_NO_MEMBER for an end outside the Network, or a frame to a group address): an Ethernet frame in an L2 Network, an
// IP packet in an L3 Network. True when it passes; the verdict goes to r, which may be NULL.
bool PolicyInput(POLICY_ENGINE *p, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size, POLICY_RESULT *r) {
	POLICY_RESULT local;

	if (r == NULL)
		r = &local;
	ZeroMemory(r, sizeof(POLICY_RESULT));
	r->Reason = POLICY_DROP_MEMBER;
	if (p == NULL)
		return false;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	r->Reason = PolicyJudge(p, PolicyStateOf(p), slot, now, from, to, vlan, frame, size, r);
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	InterlockedIncrement64(&p->Counts[slot].Count[0]);
	if (r->Reason < POLICY_NUM_REASONS)
		InterlockedIncrement64(&p->Counts[slot].Count[1 + r->Reason]);
	r->Pass = (r->Reason <= POLICY_PASS_CONTROL);

	return r->Pass;
}

// Whether a frame from the member from that passed PolicyInput, size bytes, may be delivered to the member to: both are
// members of one Network that the document in force defines, they are not both under client isolation, and the filters
// that hold for the frames a member gets (PolicyFilters) let it through. The switch asks it for each member that a frame
// to a group address reaches.
bool PolicyDeliver(POLICY_ENGINE *p, UINT from, UINT to, const UCHAR *frame, UINT size) {
	bool ok = false;

	if (p == NULL)
		return false;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	{
		const POLICY_RECORD *rf = PolicyRecordOf(p, from);
		const POLICY_RECORD *rt = PolicyRecordOf(p, to);
		const POLICY_STATE *st = PolicyStateOf(p);
		const POLICY_TABLE *t = (st != NULL && rf != NULL ? st->ByNet[rf->Net->Index] : NULL);
		POLICY_PACKET pk;

		ok = (rf != NULL && rt != NULL && t != NULL && rf->Net == rt->Net &&
		      ((rf->Guard & POLICY_GUARD_ISOLATE) == 0 || (rt->Guard & POLICY_GUARD_ISOLATE) == 0 || from == to) &&
		      PolicyParse(frame, size, t->Config.Mode, &pk) && PolicyFilters(rt->Guard, &pk) == POLICY_PASS_RULE);
	}
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	return ok;
}

// Take out the flows that expired at now from the conntrack tables of the document in force; their number
UINT PolicyAge(POLICY_ENGINE *p, UINT64 now) {
	UINT num = 0;

	if (p == NULL)
		return 0;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	{
		const POLICY_STATE *st = PolicyStateOf(p);

		for (UINT i = 0; st != NULL && i < st->Doc->NumNets; i++) {
			const POLICY_TABLE *t = &st->Tables[i];
			UINT n = PolicyTrackAge(t->Track, now);

			if (n != 0)
				InterlockedExchangeAdd64(&t->Net->Expired, n);
			num += n;
		}
	}
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	return num;
}

//
// The documents
//

// The sum of counter k of entry index of table t over its slots of processors
static UINT64 PolicySumOf(const POLICY_TABLE *t, UINT index, UINT k) {
	UINT64 sum = 0;

	for (UINT slot = 0; slot < POLICY_SLOTS; slot++)
		sum += (UINT64)ReadNoFence64(&t->Counters[(SIZE_T)slot * t->Stride + (SIZE_T)index * POLICY_NUM_COUNTS + k]);

	return sum;
}

// Add the counters of entry from of table old to entry to of table t
static void PolicyCarry(const POLICY_TABLE *old, UINT from, const POLICY_TABLE *t, UINT to) {
	for (UINT k = 0; k < POLICY_NUM_COUNTS; k++) {
		UINT64 sum = PolicySumOf(old, from, k);

		if (sum != 0)
			InterlockedExchangeAdd64(&t->Counters[(SIZE_T)to * POLICY_NUM_COUNTS + k], (LONG64)sum);
	}
}

// The counters of the rules of document old that document st keeps: those of a rule of the same Network and name, and
// those of the default action of each Network that both define
static void PolicyCarryCounters(const POLICY_STATE *old, const POLICY_STATE *st) {
	for (UINT i = 0; i < st->Doc->NumNets; i++) {
		const POLICY_TABLE *t = &st->Tables[i];
		const POLICY_TABLE *prev = old->ByNet[t->Net->Index];

		if (prev == NULL)
			continue;

		for (UINT r = 0; r < t->NumRules; r++) {
			for (UINT q = 0; q < prev->NumRules; q++) {
				if (strcmp(prev->Rules[q]->Name, t->Rules[r]->Name) == 0) {
					PolicyCarry(prev, q, t, r);
					break;
				}
			}
		}
		PolicyCarry(prev, prev->NumRules, t, t->NumRules);
	}
}

// Put a document of rules in force (Policy.h, and the comment of PolicyRules.c): its tables replace those of the one
// before at once. False with the reason in error when json is no document, it names more Networks than the engine may
// have, or there is no memory; the document in force stays then.
bool PolicySetRules(POLICY_ENGINE *p, const char *json, UINT size, char *error, UINT error_size) {
	POLICY_STATE *st = NULL;
	bool ok = true;

	if (error != NULL && error_size != 0)
		error[0] = 0;
	if (p == NULL)
		return false;

	POLICY_DOC *d = PolicyNewDoc(json, size, error, error_size);
	if (d == NULL)
		return false;

	POLICY_TABLE *tables = PolicyCompile(d, error, error_size);
	st = (POLICY_STATE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_STATE));
	if (tables == NULL || st == NULL) {
		if (st != NULL)
			HeapFree(GetProcessHeap(), 0, st);
		else if (error != NULL && error_size != 0 && error[0] == 0)
			strcpy_s(error, error_size, "the document: takes more memory than there is");
		PolicyFreeDoc(d);
		return false;
	}
	st->Doc = d;
	st->Tables = tables;

	AcquireSRWLockExclusive(&p->ConfigLock);
	POLICY_STATE *old = p->State;

	// The Networks of the document, and their conntrack tables: that of the document before when it has the same bound
	for (UINT i = 0; i < d->NumNets && ok; i++) {
		POLICY_TABLE *t = &tables[i];
		POLICY_NET *net = PolicyNetOf(p, t->Config.Name, true);
		const POLICY_TABLE *prev = (net != NULL && old != NULL ? old->ByNet[net->Index] : NULL);

		if (net == NULL) {
			if (error != NULL && error_size != 0)
				snprintf(error, error_size, "networks[%u]: the engine has %u Networks, or no memory for one more", i, POLICY_MAX_NETWORKS);
			ok = false;
			break;
		}
		t->Net = net;
		t->Track = (prev != NULL && prev->Config.MaxFlows == t->Config.MaxFlows ? prev->Track : PolicyNewTrack(t->Config.MaxFlows));
		if (t->Track == NULL) {
			if (error != NULL && error_size != 0)
				snprintf(error, error_size, "networks[%u]: no memory for its conntrack table of %u flows", i, t->Config.MaxFlows);
			ok = false;
			break;
		}
		st->ByNet[net->Index] = t;
	}

	if (ok == false) {
		// The conntrack tables that this document made
		PolicyFreeState(st, old);
		ReleaseSRWLockExclusive(&p->ConfigLock);
		return false;
	}

	st->Gen = (old != NULL ? old->Gen : 0) + 1;
	InterlockedExchangePointer((PVOID volatile *)&p->State, st);
	PolicyQuiesce(p);

	if (old != NULL) {
		PolicyCarryCounters(old, st);
		PolicyFreeState(old, st);
	}
	ReleaseSRWLockExclusive(&p->ConfigLock);

	return true;
}

//
// The counters
//

// The counters of an engine
void PolicyGetStats(POLICY_ENGINE *p, POLICY_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(POLICY_STATS));
	if (p == NULL)
		return;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	{
		const POLICY_STATE *state = PolicyStateOf(p);

		st->Document = (state != NULL ? state->Gen : 0);
	}
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	st->NumMembers = p->NumMembers;
	st->NumNetworks = (UINT)ReadAcquire(&p->NumNets);
	for (UINT i = 0; i < POLICY_SLOTS; i++) {
		st->Frames += (UINT64)ReadNoFence64(&p->Counts[i].Count[0]);
		for (UINT k = 0; k < POLICY_NUM_REASONS; k++)
			st->Reasons[k] += (UINT64)ReadNoFence64(&p->Counts[i].Count[1 + k]);
	}
}

// The state of a Network of a name; false when no member or document named it
bool PolicyGetNetworkStats(POLICY_ENGINE *p, const char *network, POLICY_NETWORK_STATS *st) {
	if (st != NULL)
		ZeroMemory(st, sizeof(POLICY_NETWORK_STATS));
	if (p == NULL || network == NULL || st == NULL)
		return false;

	POLICY_NET *net = PolicyNetOf(p, network, false);
	if (net == NULL)
		return false;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	{
		const POLICY_STATE *state = PolicyStateOf(p);
		const POLICY_TABLE *t = (state != NULL ? state->ByNet[net->Index] : NULL);

		st->DefaultAction = POLICY_DENY;
		if (t != NULL) {
			st->Defined = true;
			st->Mode = t->Config.Mode;
			st->DefaultAction = t->Config.DefaultAction;
			st->NumRules = t->NumRules;
			st->Flows = (UINT)ReadNoFence(&t->Track->NumFlows);
			st->MaxFlows = t->Track->MaxFlows;
		}
	}
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	st->NumMembers = (UINT)ReadNoFence(&net->NumMembers);
	st->Tracked = (UINT64)ReadNoFence64(&net->Tracked);
	st->Evicted = (UINT64)ReadNoFence64(&net->Evicted);
	st->Expired = (UINT64)ReadNoFence64(&net->Expired);

	return true;
}

// The counters of the rules and the default actions of the document in force, max of them at most into list: for each
// Network in the order of the document, its rules by priority, then its default action. The number there are, which may
// be more than max; with list NULL, only that number.
UINT PolicyGetCounters(POLICY_ENGINE *p, POLICY_COUNTERS *list, UINT max) {
	UINT num = 0;

	if (p == NULL)
		return 0;

	UINT slot = PolicySlotNow();

	AcquireSRWLockShared(&p->Readers[slot].Lock);
	{
		const POLICY_STATE *state = PolicyStateOf(p);

		for (UINT i = 0; state != NULL && i < state->Doc->NumNets; i++) {
			const POLICY_TABLE *t = &state->Tables[i];

			for (UINT r = 0; r <= t->NumRules; r++) {
				if (list != NULL && num < max) {
					POLICY_COUNTERS *c = &list[num];

					ZeroMemory(c, sizeof(POLICY_COUNTERS));
					PolicyCopyName(c->Network, t->Config.Name);
					if (r < t->NumRules) {
						PolicyCopyName(c->Rule, t->Rules[r]->Name);
						c->Priority = t->Rules[r]->Priority;
						c->Action = t->Rules[r]->Action;
					} else {
						PolicyCopyName(c->Rule, t->Config.DefaultAction == POLICY_ALLOW ? "default:allow" : "default:deny");
						c->Default = true;
						c->Action = t->Config.DefaultAction;
					}
					c->Flows = PolicySumOf(t, r, POLICY_COUNT_FLOWS);
					c->Packets = PolicySumOf(t, r, POLICY_COUNT_PACKETS);
					c->Bytes = PolicySumOf(t, r, POLICY_COUNT_BYTES);
				}
				num++;
			}
		}
	}
	ReleaseSRWLockShared(&p->Readers[slot].Lock);

	return num;
}
