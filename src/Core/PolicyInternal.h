// PolicyInternal.h
// The parts of the policy engine (Policy.h) that its files share: a document of rules as PolicyRules.c parses it, the
// table that it compiles for each Network and the match of a flow against one; the identity of a member; and the
// conntrack table of a Network (PolicyTrack.c).

#ifndef CORE_POLICY_INTERNAL_H
#define CORE_POLICY_INTERNAL_H

#include "Core/Policy.h"

#define POLICY_CACHE_LINE     64        // The cache line that a member, a shard and a slot of processors keep to themselves
#define POLICY_SLOTS          16        // The slots of processors of the counters and the readers, a power of 2
#define POLICY_MAX_GROUP_SIZE 1024      // Addresses of an address group at most
#define POLICY_MAX_CANDIDATES 4194304   // Entries of the indexes of one table at most, over its intervals of ports
#define POLICY_ARENA_BLOCK    65536     // Bytes of a block of an arena, unless one allocation takes more
#define POLICY_MAX_ALLOC      268435456 // Bytes of one allocation from an arena at most

// The protocols of a rule besides the IP protocol numbers 0 to 255
#define POLICY_PROTO_ANY  256 // Any frame
#define POLICY_PROTO_IP   257 // Any IP packet
#define POLICY_PROTO_ICMP 258 // ICMP of the family of the packet: IPv4 protocol 1, IPv6 protocol 58

// The classes of frames, each with an index of its own in a table
#define POLICY_CLASS_TCP    0 // TCP
#define POLICY_CLASS_UDP    1 // UDP
#define POLICY_CLASS_ICMP   2 // ICMP of IPv4, ICMPv6 of IPv6
#define POLICY_CLASS_OTHER  3 // Another IP protocol
#define POLICY_CLASS_NON_IP 4 // A frame of another EtherType
#define POLICY_NUM_CLASSES  5

// The counters of a rule
#define POLICY_COUNT_FLOWS   0 // The flows it allowed
#define POLICY_COUNT_PACKETS 1 // The frames it matched
#define POLICY_COUNT_BYTES   2 // ... their bytes
#define POLICY_NUM_COUNTS    3

// What left a full shard of a conntrack table for a new flow (PolicyTrackAdd)
#define POLICY_LEFT_NONE    0 // Nothing: the shard had room
#define POLICY_LEFT_EVICTED 1 // Its least recently used flow, which was still live
#define POLICY_LEFT_EXPIRED 2 // ... which had expired

// The timeouts of a Network
#define POLICY_TIMEOUT_TCP_ESTABLISHED 0
#define POLICY_TIMEOUT_TCP_TRANSITORY  1
#define POLICY_TIMEOUT_UDP             2
#define POLICY_TIMEOUT_ICMP            3
#define POLICY_TIMEOUT_OTHER           4
#define POLICY_NUM_TIMEOUTS            5

// The memory of a document and of its tables: blocks freed at once (PolicyRules.c)
typedef struct POLICY_ARENA {
	void *Blocks; // The blocks, the newest first
} POLICY_ARENA;

// An IP prefix of a rule or of an address group
typedef struct POLICY_PREFIX {
	UINT Family;    // POLICY_IPV4 or POLICY_IPV6
	UINT Length;    // The length of the prefix
	UCHAR Addr[16]; // The address, its host bits 0; IPv4 in the first 4 bytes
} POLICY_PREFIX;

// A range of ports of a rule
typedef struct POLICY_RANGE {
	UINT Low;  // The first port
	UINT High; // ... and the last
} POLICY_RANGE;

// A named list of prefixes of a document
typedef struct POLICY_ADDR_GROUP {
	char Name[POLICY_MAX_NAME + 1]; // Its name
	UINT NumPrefixes;               // Its prefixes
	POLICY_PREFIX *Prefixes;        // ...
} POLICY_ADDR_GROUP;

// One end of a rule: each list that it has must hold the end, and an end of a list holds it when it has one of its values
typedef struct POLICY_SIDE {
	UINT NumUsers;                        // The users
	char **Users;                         // ...
	UINT NumGroups;                       // The groups
	char **Groups;                        // ...
	UINT NumTags;                         // The tags of the node
	char **Tags;                          // ...
	UINT NumPrefixes;                     // The addresses
	POLICY_PREFIX *Prefixes;              // ...
	UINT NumAddrGroups;                   // The address groups, which hold the end like its addresses
	const POLICY_ADDR_GROUP **AddrGroups; // ...
} POLICY_SIDE;

// A rule of a document
typedef struct POLICY_RULE {
	char Name[POLICY_MAX_NAME + 1]; // Its name, unique in the document
	UINT Priority;                  // Its priority: the lowest first
	UINT Order;                     // Its place in the document, which orders the rules of one priority
	UINT Action;                    // POLICY_ALLOW or POLICY_DENY
	UINT Protocol;                  // An IP protocol number, or POLICY_PROTO_*
	bool Both;                      // Direction both: it also matches from its to end to its from end
	UINT NumNets;                   // The Networks whose tables take it; none for every Network of the document
	char **Nets;                    // ...
	UINT NumVlans;                  // The VLANs of the frames it matches; none for any
	UINT *Vlans;                    // ...
	UINT NumPorts;                  // The destination ports it matches, TCP or UDP only; none for any
	POLICY_RANGE *Ports;            // ...
	POLICY_SIDE From;               // The end that sends the first frame of the flow
	POLICY_SIDE To;                 // ... and the end it goes to
} POLICY_RULE;

// A Network of a document
typedef struct POLICY_NET_CONFIG {
	char Name[POLICY_MAX_NAME + 1];     // Its name
	UINT Mode;                          // POLICY_L2 or POLICY_L3
	UINT DefaultAction;                 // POLICY_DENY, for every Network (ADR-0019 amendment of 2026-10-21)
	UINT MaxFlows;                      // The bound of its conntrack table
	UINT Timeouts[POLICY_NUM_TIMEOUTS]; // The timeouts of its flows (ms)
} POLICY_NET_CONFIG;

// A document of rules, in the memory of its arena
typedef struct POLICY_DOC {
	POLICY_ARENA Arena;            // Its memory, with that of its tables
	UINT NumNets;                  // Its Networks
	POLICY_NET_CONFIG *Nets;       // ...
	UINT NumAddrGroups;            // Its address groups
	POLICY_ADDR_GROUP *AddrGroups; // ...
	UINT NumRules;                 // Its rules, in its order
	POLICY_RULE *Rules;            // ...
} POLICY_DOC;

// A rule as it matches one way: forward, or from its to end to its from end for a rule of direction both
typedef struct POLICY_ENTRY {
	const POLICY_RULE *Rule; // The rule
	UINT Index;              // Its index in the table, which is that of its counters
	const POLICY_SIDE *From; // The end that the source of the frame must be
	const POLICY_SIDE *To;   // ... and the destination
} POLICY_ENTRY;

// The entries of a table that a class of frames may match, by the interval of the destination port
typedef struct POLICY_INDEX {
	UINT NumBounds; // The intervals of destination ports; 1 for a class without ports
	UINT *Starts;   // ... the first port of each, ascending, the first 0
	UINT *Offsets;  // ... where its entries start in Cands; NumBounds + 1 of them
	UINT *Cands;    // The entries of each interval in the order of the rules
} POLICY_INDEX;

// The compiled rules of one Network
typedef struct POLICY_TABLE {
	POLICY_NET_CONFIG Config;               // The Network as the document has it
	struct POLICY_NET *Net;                 // ... and as the engine has it (Policy.c)
	struct POLICY_TRACK *Track;             // Its conntrack table, which the next document keeps while it bounds it alike (Policy.c)
	UINT NumRules;                          // Its rules: by priority, then in the order of the document
	const POLICY_RULE **Rules;              // ...
	UINT NumEntries;                        // Its entries, in the order of the rules
	POLICY_ENTRY *Entries;                  // ...
	POLICY_INDEX Index[POLICY_NUM_CLASSES]; // The entries by class and destination port
	UINT Stride;                            // The counters of one slot of processors: POLICY_NUM_COUNTS per rule, then the default action's, on whole cache lines
	volatile LONG64 *Counters;              // The counters, POLICY_SLOTS times Stride
} POLICY_TABLE;

// The identity of a member
typedef struct POLICY_IDENTITY {
	const char *User;    // Its user, NULL for none
	UINT NumGroups;      // Its groups
	const char **Groups; // ...
	UINT NumTags;        // The tags of its node
	const char **Tags;   // ...
} POLICY_IDENTITY;

// What a rule matches of a flow or of a frame
typedef struct POLICY_MATCH {
	UINT Class;                  // POLICY_CLASS_*
	UINT Family;                 // POLICY_IPV4 or POLICY_IPV6; 0 for a frame that is not IP
	UINT Protocol;               // The IP protocol
	const UCHAR *Src;            // The source address (16 bytes)
	const UCHAR *Dst;            // ... and the destination
	bool HasPort;                // The frame has ports: TCP or UDP, not a later fragment
	UINT DstPort;                // ... the destination port
	UINT Vlan;                   // The VLAN of the frame, 0 for none
	const POLICY_IDENTITY *From; // The member that sent it, NULL for an end outside the Network
	const POLICY_IDENTITY *To;   // ... and the member it goes to
} POLICY_MATCH;

// The key of a flow: its two sides in a fixed order, so that both directions find it
typedef struct POLICY_KEY {
	UCHAR Addr[2][16]; // The addresses of the sides, the lower first
	USHORT Port[2];    // ... their ports: TCP or UDP, the id of an ICMP echo, 0 for another protocol and for the fragments of a flow
	UCHAR Family;      // POLICY_IPV4 or POLICY_IPV6
	UCHAR Protocol;    // The IP protocol
	USHORT Vlan;       // The VLAN, 0 for none
} POLICY_KEY;

// A flow of a conntrack table. The links are indexes plus 1, 0 for none.
typedef struct POLICY_FLOW {
	POLICY_KEY Key;    // Its key
	UINT Next;         // The next flow of its bucket
	UINT Newer;        // The flow used after it, 0 for the most recently used
	UINT Older;        // ... before it, 0 for the least recently used
	UINT Timeout;      // ms after Last that it expires
	UINT64 Last;       // The time of its last frame (ms)
	UINT64 Gen;        // The generation of the document whose table allowed it
	UINT Rule;         // ... the index of the counters that it counts on in that table
	UINT Member[2];    // The members of its sides, POLICY_NO_MEMBER for a side outside the Network
	UINT MemberGen[2]; // ... their generations
	UCHAR Origin;      // The side that opened it
	UCHAR State;       // POLICY_FLOW_* (Policy.c)
	UCHAR Sent;        // The sides that sent on it: bit 0 and bit 1
	UCHAR Fin;         // The sides that sent a TCP FIN
} POLICY_FLOW;

// A shard of a conntrack table, on a cache line of its own: a hash table with chains, and the list of its flows by use
typedef union POLICY_SHARD {
	struct {
		SRWLOCK Lock;       // Every use of the shard
		UINT Num;           // Its flows
		UINT Max;           // ... at most
		UINT Used;          // The flows of its part of the table that were handed out once
		UINT Free;          // The first free flow of the ones handed out
		UINT Newest;        // The most recently used flow
		UINT Oldest;        // ... the least
		UINT Mask;          // Its buckets less 1, a power of 2 less 1
		UINT *Buckets;      // The first flow of each bucket
		POLICY_FLOW *Flows; // Its part of the table
	};
	UCHAR Line[POLICY_CACHE_LINE];
} POLICY_SHARD;

// The conntrack table of a Network: its memory is taken once, at its bound
typedef struct POLICY_TRACK {
	UINT MaxFlows;         // Its bound: the shards times the flows of each
	UINT NumShards;         // Its shards, a power of 2
	UINT ShardBits;         // ... as bits of the hash
	UINT64 Seed;            // The random key of its hash
	POLICY_SHARD *Shards;   // The shards
	POLICY_FLOW *Flows;     // The flows of every shard
	UINT *Buckets;          // The buckets of every shard
	volatile LONG NumFlows; // Its flows
} POLICY_TRACK;

// The kinds of address that a member owns (POLICY_OWNER)
#define POLICY_OWN_MAC  1 // A MAC address, in the first 6 bytes
#define POLICY_OWN_IPV4 4 // An IPv4 address, in the first 4 bytes
#define POLICY_OWN_IPV6 6 // An IPv6 address

// An address that a member of a Network owns (Policy.c)
typedef struct POLICY_OWNER {
	UCHAR Kind;     // POLICY_OWN_*
	UCHAR Addr[16]; // The address, the bytes after it 0
	UINT Member;    // The member that owns it
} POLICY_OWNER;

// A Network of an engine, made by the first member or document that names it and kept until the engine is freed
typedef struct POLICY_NET {
	char Name[POLICY_MAX_NAME + 1]; // Its name
	UINT Index;                     // Its index in the engine
	SRWLOCK LearnLock;              // The addresses that its members own: shared to look one up, exclusive to add or take out
	volatile LONG NumOwners;        // ... their number
	UINT MaxOwners;                 // ... room for them
	POLICY_OWNER *Owners;           // ... in ascending order of their kind and address
	volatile LONG NumMembers;       // Its members
	volatile LONG64 Tracked;        // Flows that its tables took
	volatile LONG64 Evicted;        // ... that left them as the least recently used of a full table
	volatile LONG64 Expired;        // ... that left them after their timeout
} POLICY_NET;

// PolicyRules.c
bool PolicyNameOk(const char *s, bool identity);
void PolicyCopyName(char *dst, const char *src);
void *PolicyAlloc(POLICY_ARENA *a, SIZE_T size);
void PolicyFreeArena(POLICY_ARENA *a);
POLICY_DOC *PolicyNewDoc(const char *json, UINT size, char *error, UINT error_size);
void PolicyFreeDoc(POLICY_DOC *d);
POLICY_TABLE *PolicyCompile(POLICY_DOC *d, char *error, UINT error_size);
UINT PolicyMatch(const POLICY_TABLE *t, const POLICY_MATCH *m);

// PolicyTrack.c
POLICY_TRACK *PolicyNewTrack(UINT max_flows);
void PolicyFreeTrack(POLICY_TRACK *t);
UINT64 PolicyTrackHash(const POLICY_TRACK *t, const POLICY_KEY *k);
POLICY_SHARD *PolicyTrackShard(POLICY_TRACK *t, UINT64 h);
POLICY_FLOW *PolicyTrackFind(POLICY_SHARD *s, const POLICY_KEY *k, UINT64 h);
POLICY_FLOW *PolicyTrackAdd(POLICY_TRACK *t, POLICY_SHARD *s, const POLICY_KEY *k, UINT64 h, UINT64 now, UINT *left);
void PolicyTrackDel(POLICY_TRACK *t, POLICY_SHARD *s, POLICY_FLOW *f);
void PolicyTrackTouch(POLICY_SHARD *s, POLICY_FLOW *f);
UINT PolicyTrackAge(POLICY_TRACK *t, UINT64 now);

#endif // CORE_POLICY_INTERNAL_H
