// NodeDns.c
// Overlay DNS of a node (SDN-11, #187; ADR-0028 decisions 6 to 8). A VRF with overlay DNS on carries its zone in its Vrf
// object (CONTROL_DNS_ZONE of Core/Control.h): the suffix, and the DnsRecord resources of the VRF with the addresses
// that each answers. The name of each node of the VRF answers that node's addresses there, which the state holds: the
// node's own (CONTROL_STATE.Addresses) and the ones of its peers (CONTROL_PEER.Addresses). A stub resolver answers each
// zone on UDP port 53 of the node's addresses in its VRF, the addresses of the Wintun adapter of that VRF
// (NodeVrfAdapter.c), and a rule of the Name Resolution Policy Table of Windows (NRPT) sends the names under the suffix,
// and only those, to them, so the host's own DNS keeps every other name. A zone belongs to one VRF, so the same name
// answers different hosts in two VRFs.
// - In a VRF whose IPv4 the host reaches through 4via6 (the state gives the node the 4via6 of the VRF, ADR-0025 decision
//   4), a name answers the 4via6 address of each of its IPv4 addresses in an AAAA record and has no A record, and the
//   stub resolver listens on the 4via6 address of the node in place of its IPv4 address, which another VRF of the host
//   may hold too.
// - A name of the zone without an address of the type asked is answered with none (NODATA), a name under the suffix that
//   the zone does not have with NXDOMAIN, both with the SOA of the zone for their negative caching (RFC 2308); a name
//   outside the suffix is refused. The stub resolver recurses for no one and answers at most NODE_DNS_MAX_ANSWER bytes.
// - The rules are keys of the local NRPT, one per VRF, named after the node's static key and the VRF id
//   (NodeDnsRuleName), so the rules of two nodes on one host stay apart and a node finds the rules that a run of its
//   own left behind: it removes them when it starts and when it stops. While the NRPT of Group Policy holds a rule, the
//   DNS client of Windows reads the rules of Group Policy alone, so the node writes its rules there too and has Group
//   Policy refreshed. After a change of the rules the node flushes the cache of the DNS client.

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#include <ws2tcpip.h>
#include <mstcpip.h>

#define NODE_DNS_HEADER      12     // The header of a DNS message (RFC 1035 4.1.1)
#define NODE_DNS_MAX_WIRE    255    // Bytes of a name in its wire form at most
#define NODE_DNS_MAX_LABELS  128    // ... and its labels
#define NODE_DNS_MAX_QUERY   1500   // Bytes of a query that the stub resolver takes at most; a longer datagram is dropped
#define NODE_DNS_MAX_SOCKETS 16     // Addresses that the stub resolver listens on at most: the addresses of a node (CONTROL_MAX_ADDRESSES)
#define NODE_DNS_SERVERS     1024   // Characters of the DNS servers of an NRPT rule at most, with the NUL
#define NODE_DNS_MAX_LOGGED  16     // Refused queries that the node log names at most
#define NODE_DNS_TYPE_A      1      // The types of a record ...
#define NODE_DNS_TYPE_SOA    6
#define NODE_DNS_TYPE_AAAA   28
#define NODE_DNS_TYPE_ANY    255    // ... and the type of a query for all of them
#define NODE_DNS_CLASS_IN    1      // The class of the internet ...
#define NODE_DNS_CLASS_ANY   255    // ... and the class of a query for any
#define NODE_DNS_POINTER     0xC000 // A compression pointer (RFC 1035 4.1.4): the offset of the name that it points at follows
#define NODE_DNS_SOA_SIZE    24     // The data of the SOA of a zone: two pointers and five numbers
#define NODE_DNS_REFRESH     3600   // The REFRESH, RETRY and EXPIRE of the SOA of a zone, which no secondary server reads
#define NODE_DNS_RETRY       600
#define NODE_DNS_EXPIRE      86400

// The local NRPT and the NRPT of Group Policy, under HKEY_LOCAL_MACHINE: one key per rule (MS-GPNRPT 2.2)
#define NODE_DNS_NRPT_LOCAL   L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"
#define NODE_DNS_NRPT_GP      L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig"
#define NODE_DNS_NRPT_VERSION 2   // The Version of a rule
#define NODE_DNS_NRPT_GENERIC 0x8 // Its ConfigOptions: the names go to the DNS servers of GenericDNSServers
#define NODE_DNS_RP_FORCE     1   // RP_FORCE of RefreshPolicyEx (userenv.h): every policy is applied again

typedef BOOL(WINAPI NODE_DNS_FLUSH_FUNC)(void);
typedef BOOL(WINAPI NODE_DNS_REFRESH_FUNC)(BOOL machine, DWORD options);

// An address that the stub resolver listens on: UDP port 53 of an address of the node in a VRF
typedef struct NODE_DNS_LISTEN {
	UINT VrfId;        // The VRF
	UCHAR Address[16]; // The address: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
} NODE_DNS_LISTEN;

// A socket of the thread of the stub resolver
typedef struct NODE_DNS_SOCKET {
	NODE_DNS_LISTEN Listen; // Its address
	SOCKET Sock;            // INVALID_SOCKET while it is not bound
	UINT Error;             // The error of its last bind that failed, 0 for none: the node log names a new one
} NODE_DNS_SOCKET;

// An NRPT rule of the node: the names under the suffix of the zone of a VRF go to the addresses of the node there
typedef struct NODE_DNS_RULE {
	wchar_t Name[NODE_DNS_RULE_NAME_SIZE]; // The name of its key (NodeDnsRuleName)
	wchar_t Suffix[NODE_DNS_NAME_SIZE];    // The suffix
	wchar_t Servers[NODE_DNS_SERVERS];     // The addresses, separated by ';'
} NODE_DNS_RULE;

// Overlay DNS of a node
struct NODE_DNS {
	NODE *Node;                                     // The node
	wchar_t Prefix[NODE_DNS_RULE_NAME_SIZE];        // What the names of the node's NRPT rules begin with
	LOCK *Lock;                                     // Apply and Free, one at a time; the rules
	UINT NumRules;                                  // The rules that the node wrote, of the state applied last
	NODE_DNS_RULE *Rules;                           // ...
	bool GroupPolicy;                               // ... at the NRPT of Group Policy too
	SRWLOCK ZoneLock;                               // The zones, the addresses and Version, which the thread reads
	UINT NumZones;                                  // The zones of the state applied last
	NODE_DNS_ZONE *Zones;                           // ...
	UINT NumListen;                                 // The addresses that the stub resolver listens on
	NODE_DNS_LISTEN Listen[NODE_DNS_MAX_SOCKETS];   // ...
	LONG Version;                                   // ... counted by each state applied
	HANDLE Halt;                                    // Stops the thread (a manual-reset event)
	HANDLE Thread;                                  // The thread of the stub resolver, which alone changes the sockets
	UINT NumSockets;                                // Its sockets
	NODE_DNS_SOCKET Sockets[NODE_DNS_MAX_SOCKETS];  // ...
	volatile LONG Bound;                            // The Version whose addresses the sockets are of
	volatile LONG Listening;                        // ... and the sockets that are bound
	volatile LONG LastError;                        // The error of the last bind that failed, 0 for none
	volatile LONG64 Queries;                        // What NodeDnsGetStatus reports
	volatile LONG64 NameErrors;
	volatile LONG64 Refused;
	volatile LONG64 Dropped;
	volatile LONG Logged;                           // The refused queries that the node log named
};

//
// The answer to a query
//

// Write a resource record at *pos of the answer a of max bytes: its owner as a pointer to the name at the offset owner,
// its type, the class IN, its TTL and its data. False when it does not fit.
static bool NodeDnsRecord(UCHAR *a, UINT max, UINT *pos, UINT owner, UINT type, UINT ttl, const UCHAR *data, UINT data_size) {
	UINT p = *pos;

	if (p + 12 + data_size > max)
		return false;

	WRITE_USHORT(a + p, NODE_DNS_POINTER | owner);
	WRITE_USHORT(a + p + 2, type);
	WRITE_USHORT(a + p + 4, NODE_DNS_CLASS_IN);
	WRITE_UINT(a + p + 6, ttl);
	WRITE_USHORT(a + p + 10, data_size);
	if (data_size != 0)
		Copy(a + p + 12, data, data_size);
	*pos = p + 12 + data_size;

	return true;
}

// Write the SOA record of the zone z at *pos of the answer a: the zone is the name at the offset apex, and so are its
// primary server and the mailbox of its administrator. False when it does not fit.
static bool NodeDnsSoa(const NODE_DNS_ZONE *z, UCHAR *a, UINT max, UINT *pos, UINT apex, UINT ttl) {
	UCHAR data[NODE_DNS_SOA_SIZE];

	WRITE_USHORT(data, NODE_DNS_POINTER | apex);
	WRITE_USHORT(data + 2, NODE_DNS_POINTER | apex);
	WRITE_UINT(data + 4, z->Serial);
	WRITE_UINT(data + 8, NODE_DNS_REFRESH);
	WRITE_UINT(data + 12, NODE_DNS_RETRY);
	WRITE_UINT(data + 16, NODE_DNS_EXPIRE);
	WRITE_UINT(data + 20, NODE_DNS_NEGATIVE_TTL);

	return NodeDnsRecord(a, max, pos, apex, NODE_DNS_TYPE_SOA, ttl, data, sizeof(data));
}

// The name of the zone z that is name, NULL for none
static const NODE_DNS_NAME *NodeDnsFind(const NODE_DNS_ZONE *z, const char *name) {
	for (UINT i = 0; i < z->NumNames; i++)
		if (StrCmp(z->Names[i].Name, name) == 0)
			return &z->Names[i];

	return NULL;
}

// Whether a name of the zone z lies under name, which the zone does not have itself: an empty non-terminal (RFC 8020),
// which has no record but is no NXDOMAIN
static bool NodeDnsUnder(const NODE_DNS_ZONE *z, const char *name) {
	UINT len = StrLen(name);

	for (UINT i = 0; i < z->NumNames; i++) {
		UINT n = StrLen(z->Names[i].Name);

		if (n > len + 1 && z->Names[i].Name[n - len - 1] == '.' && StrCmp(z->Names[i].Name + n - len, name) == 0)
			return true;
	}

	return false;
}

// The answer of the zone z to the DNS query of size bytes into answer, which holds max bytes: its size, 0 for a datagram
// that gets none (a response, or a query whose question does not fit max). rcode takes the RCODE of the answer
// (NODE_DNS_RCODE_*) and name, when it is not NULL, the name of the question, dotted and in lower case. The question goes
// back as it came; the records of the answer name it by a pointer, and the SOA names the suffix inside it.
UINT NodeDnsAnswer(const NODE_DNS_ZONE *z, const UCHAR *query, UINT size, UCHAR *answer, UINT max, UINT *rcode, char *name, UINT name_size) {
	UINT label_at[NODE_DNS_MAX_LABELS] = {0};  // The offset of each label of the question in the query ...
	UINT dotted_at[NODE_DNS_MAX_LABELS] = {0}; // ... and in dotted
	bool plain[NODE_DNS_MAX_LABELS] = {0};     // ... and whether it holds neither a dot nor a NUL
	char dotted[NODE_DNS_MAX_WIRE + 1];        // The name of the question, dotted, in lower case
	char relative[NODE_DNS_MAX_WIRE + 1];      // ... and relative to the suffix
	UINT num_labels = 0;
	UINT len = 0;
	UINT pos = NODE_DNS_HEADER;
	UINT code = NODE_DNS_RCODE_FORMERR;

	if (rcode != NULL)
		*rcode = NODE_DNS_RCODE_FORMERR;
	if (name != NULL && name_size != 0)
		name[0] = 0;
	if (z == NULL || query == NULL || answer == NULL || size < NODE_DNS_HEADER || max < NODE_DNS_HEADER || (query[2] & 0x80) != 0)
		return 0;

	// The header of the answer: the id, a response of the opcode of the query, authoritative, RD as the query asked
	UINT opcode = (query[2] >> 3) & 0x0F;
	Zero(answer, NODE_DNS_HEADER);
	answer[0] = query[0];
	answer[1] = query[1];
	answer[2] = (UCHAR)(0x80 | (opcode << 3) | 0x04 | (query[2] & 0x01));

	if (opcode != 0)
		code = NODE_DNS_RCODE_NOTIMP;

	// The name of the question: labels of 63 bytes at most, no pointer, 255 bytes in all
	dotted[0] = 0;
	while (code == NODE_DNS_RCODE_FORMERR && READ_USHORT(query + 4) == 1) {
		if (pos >= size)
			break;

		UINT n = query[pos];
		if (n == 0) {
			pos++;
			if (pos + 4 <= size)
				code = NODE_DNS_RCODE_NOERROR;
			break;
		}
		if (n > 63 || num_labels >= NODE_DNS_MAX_LABELS || pos + 1 + n > size || pos + 2 + n - NODE_DNS_HEADER > NODE_DNS_MAX_WIRE || len + 1 + n >= sizeof(dotted))
			break;

		label_at[num_labels] = pos;
		plain[num_labels] = true;
		if (num_labels != 0)
			dotted[len++] = '.';
		dotted_at[num_labels] = len;
		for (UINT i = 0; i < n; i++) {
			UCHAR c = query[pos + 1 + i];

			if (c == '.' || c == 0) {
				plain[num_labels] = false;
				c = '?';
			}
			dotted[len++] = (char)((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
		}
		dotted[len] = 0;
		num_labels++;
		pos += 1 + n;
	}

	if (code != NODE_DNS_RCODE_NOERROR) {
		// No question that the answer can repeat
		answer[3] = (UCHAR)code;
		if (rcode != NULL)
			*rcode = code;
		return NODE_DNS_HEADER;
	}

	UINT qtype = READ_USHORT(query + pos);
	UINT qclass = READ_USHORT(query + pos + 2);
	UINT out = pos + 4;
	if (out > max)
		return 0;

	Copy(answer + NODE_DNS_HEADER, query + NODE_DNS_HEADER, out - NODE_DNS_HEADER);
	WRITE_USHORT(answer + 4, 1);
	if (name != NULL && name_size != 0)
		StrCpy(name, name_size, dotted);

	// The labels of the suffix end the name, each of them plain
	UINT suffix_labels = (z->Suffix[0] != 0 ? 1 : 0);
	for (UINT i = 0; z->Suffix[i] != 0; i++)
		if (z->Suffix[i] == '.')
			suffix_labels++;

	bool under = (suffix_labels != 0 && num_labels >= suffix_labels);
	UINT first = (under ? num_labels - suffix_labels : 0);
	for (UINT i = first; under && i < num_labels; i++)
		under = plain[i];
	under = under && StrCmp(dotted + dotted_at[first], z->Suffix) == 0;

	if (under == false || (qclass != NODE_DNS_CLASS_IN && qclass != NODE_DNS_CLASS_ANY)) {
		answer[3] = NODE_DNS_RCODE_REFUSED;
		if (rcode != NULL)
			*rcode = NODE_DNS_RCODE_REFUSED;
		return out;
	}

	// The name relative to the suffix, "" for the suffix itself; one whose labels are not plain is no name of the zone
	bool rel_plain = true;
	for (UINT i = 0; i < first; i++)
		rel_plain = rel_plain && plain[i];
	relative[0] = 0;
	if (first != 0)
		StrCpy(relative, MIN((UINT)sizeof(relative), dotted_at[first]), dotted);

	UINT apex = label_at[first];
	const NODE_DNS_NAME *found = (rel_plain ? NodeDnsFind(z, relative) : NULL);
	UINT num_answers = 0;
	code = NODE_DNS_RCODE_NOERROR;

	if (found != NULL) {
		for (UINT i = 0; i < found->NumAddresses && i < NODE_DNS_MAX_ADDRESSES; i++) {
			const UCHAR *addr = found->Addresses[i];
			UCHAR mapped[16];
			bool written = true;

			if (found->AddressSizes[i] == 4 && z->Via6 && (qtype == NODE_DNS_TYPE_AAAA || qtype == NODE_DNS_TYPE_ANY)) {
				// 4via6: the IPv4 address after the /96 of the VRF
				Copy(mapped, z->Via6Prefix, 12);
				Copy(mapped + 12, addr, 4);
				written = NodeDnsRecord(answer, max, &out, NODE_DNS_HEADER, NODE_DNS_TYPE_AAAA, NODE_DNS_TTL, mapped, 16);
				num_answers += (written ? 1 : 0);
			} else if (found->AddressSizes[i] == 4 && z->Via6 == false && (qtype == NODE_DNS_TYPE_A || qtype == NODE_DNS_TYPE_ANY)) {
				written = NodeDnsRecord(answer, max, &out, NODE_DNS_HEADER, NODE_DNS_TYPE_A, NODE_DNS_TTL, addr, 4);
				num_answers += (written ? 1 : 0);
			} else if (found->AddressSizes[i] == 16 && (qtype == NODE_DNS_TYPE_AAAA || qtype == NODE_DNS_TYPE_ANY)) {
				written = NodeDnsRecord(answer, max, &out, NODE_DNS_HEADER, NODE_DNS_TYPE_AAAA, NODE_DNS_TTL, addr, 16);
				num_answers += (written ? 1 : 0);
			}

			if (written == false)
				break;
		}
	} else if (first == 0) {
		// The suffix itself: its SOA, and no address
		if ((qtype == NODE_DNS_TYPE_SOA || qtype == NODE_DNS_TYPE_ANY) && NodeDnsSoa(z, answer, max, &out, apex, NODE_DNS_TTL))
			num_answers++;
	} else if (rel_plain == false || NodeDnsUnder(z, relative) == false) {
		code = NODE_DNS_RCODE_NXDOMAIN;
	}

	WRITE_USHORT(answer + 6, num_answers);
	if (num_answers == 0 && NodeDnsSoa(z, answer, max, &out, apex, NODE_DNS_NEGATIVE_TTL))
		WRITE_USHORT(answer + 8, 1);

	answer[3] = (UCHAR)code;
	if (rcode != NULL)
		*rcode = code;

	return out;
}

//
// The zones of a state
//

// Whether the state st gives the node the 4via6 of the VRF vrf_id (SDN-6, #182), its rule from the IPv6 /96 inside to
// the IPv4 0.0.0.0/0 outside; prefix, when it is not NULL, takes the 12 bytes of that /96
bool NodeDnsVia6(const CONTROL_STATE *st, UINT vrf_id, UCHAR *prefix) {
	if (st == NULL)
		return false;

	for (UINT i = 0; i < st->NumNats && i < CONTROL_MAX_NATS; i++) {
		const CONTROL_NAT *r = &st->Nats[i];

		if (r->VrfId != vrf_id || r->InsideSize != 16 || r->InsideLength != 96 || r->OutsideSize != 4 || r->OutsideLength != 0)
			continue;

		if (prefix != NULL)
			Copy(prefix, r->Inside, 12);
		return true;
	}

	return false;
}

// Add the name with the num addresses of addrs that are of the VRF of the zone z (vrf: their VRFs, NULL when they all
// are) to z, once: the first of a name stays. A name without an address of the VRF is left out.
static void NodeDnsAdd(NODE_DNS_ZONE *z, const char *name, UCHAR (*addrs)[16], const UINT *sizes, const UINT *vrfs, UINT num) {
	NODE_DNS_NAME *e = &z->Names[z->NumNames];

	if (IsEmptyStr(name))
		return;

	Zero(e, sizeof(NODE_DNS_NAME));
	StrCpy(e->Name, sizeof(e->Name), name);
	StrLower(e->Name);
	if (NodeDnsFind(z, e->Name) != NULL)
		return;

	for (UINT i = 0; i < num && e->NumAddresses < NODE_DNS_MAX_ADDRESSES; i++) {
		if ((vrfs != NULL && vrfs[i] != z->VrfId) || (sizes[i] != 4 && sizes[i] != 16))
			continue;

		Copy(e->Addresses[e->NumAddresses], addrs[i], sizes[i]);
		e->AddressSizes[e->NumAddresses++] = sizes[i];
	}

	if (e->NumAddresses != 0)
		z->NumNames++;
}

// Add the node name with its num addresses of the state in the VRF of the zone z to z
static void NodeDnsAddNode(NODE_DNS_ZONE *z, const char *name, const CONTROL_ADDRESS *addrs, UINT num) {
	UCHAR list[CONTROL_MAX_ADDRESSES][16];
	UINT sizes[CONTROL_MAX_ADDRESSES];
	UINT vrfs[CONTROL_MAX_ADDRESSES];
	UINT n = 0;

	for (UINT i = 0; i < num && n < CONTROL_MAX_ADDRESSES; i++) {
		Zero(list[n], 16);
		Copy(list[n], addrs[i].Address, MIN(addrs[i].AddressSize, 16));
		sizes[n] = addrs[i].AddressSize;
		vrfs[n] = addrs[i].VrfId;
		n++;
	}

	NodeDnsAdd(z, name, list, sizes, vrfs, n);
}

// Whether the VRF v of a state has a zone with a suffix: a rule of an empty suffix would be the namespace of every name
static bool NodeDnsHasZone(const CONTROL_VRF *v) {
	return v->Dns != NULL && IsEmptyStr(v->Dns->Suffix) == false && v->Dns->Suffix[0] != '.';
}

// The zone of the VRF v of the state st, which has one: its records, then the name of the node and of each of its peers
static void NodeDnsZoneOf(NODE_DNS_ZONE *z, const CONTROL_STATE *st, const CONTROL_VRF *v) {
	const CONTROL_DNS_ZONE *c = v->Dns;

	Zero(z, sizeof(NODE_DNS_ZONE));
	z->VrfId = v->Id;
	StrCpy(z->Suffix, sizeof(z->Suffix), c->Suffix);
	StrLower(z->Suffix);
	z->Serial = (UINT)st->Generation;
	z->Via6 = NodeDnsVia6(st, v->Id, z->Via6Prefix);
	z->Names = ZeroMalloc(sizeof(NODE_DNS_NAME) * (MIN(c->NumRecords, CONTROL_MAX_DNS_RECORDS) + 1 + st->NumPeers));

	for (UINT i = 0; i < c->NumRecords && i < CONTROL_MAX_DNS_RECORDS; i++) {
		const CONTROL_DNS_RECORD *r = &c->Records[i];
		UCHAR list[CONTROL_MAX_DNS_ADDRESSES][16];

		Zero(list, sizeof(list));
		for (UINT j = 0; j < r->NumAddresses && j < CONTROL_MAX_DNS_ADDRESSES; j++)
			Copy(list[j], r->Addresses[j], MIN(r->AddressSizes[j], 16));
		NodeDnsAdd(z, r->Name, list, r->AddressSizes, NULL, MIN(r->NumAddresses, CONTROL_MAX_DNS_ADDRESSES));
	}

	NodeDnsAddNode(z, st->Name, st->Addresses, MIN(st->NumAddresses, CONTROL_MAX_ADDRESSES));
	for (UINT i = 0; i < st->NumPeers; i++)
		NodeDnsAddNode(z, st->Peers[i].Name, st->Peers[i].Addresses, MIN(st->Peers[i].NumAddresses, CONTROL_MAX_ADDRESSES));
}

// Add the addresses of the node in the VRF of the zone z of the state st to the num addresses of list, once: the
// 4via6 address of an IPv4 address in a VRF of 4via6
static void NodeDnsListenOf(NODE_DNS_LISTEN *list, UINT *num, const CONTROL_STATE *st, const NODE_DNS_ZONE *z) {
	for (UINT i = 0; i < st->NumAddresses && i < CONTROL_MAX_ADDRESSES && *num < NODE_DNS_MAX_SOCKETS; i++) {
		const CONTROL_ADDRESS *a = &st->Addresses[i];
		NODE_DNS_LISTEN l;
		bool held = false;

		if (a->VrfId != z->VrfId || (a->AddressSize != 4 && a->AddressSize != 16))
			continue;

		Zero(&l, sizeof(l));
		l.VrfId = z->VrfId;
		if (a->AddressSize == 4 && z->Via6) {
			Copy(l.Address, z->Via6Prefix, 12);
			Copy(l.Address + 12, a->Address, 4);
			l.AddressSize = 16;
		} else {
			Copy(l.Address, a->Address, a->AddressSize);
			l.AddressSize = a->AddressSize;
		}

		for (UINT j = 0; j < *num && held == false; j++)
			held = (list[j].VrfId == l.VrfId && list[j].AddressSize == l.AddressSize && Cmp(list[j].Address, l.Address, l.AddressSize) == 0);
		if (held == false)
			list[(*num)++] = l;
	}
}

static void NodeDnsFreeZones(NODE_DNS_ZONE *zones, UINT num) {
	if (zones == NULL)
		return;

	for (UINT i = 0; i < num; i++)
		Free(zones[i].Names);
	Free(zones);
}

//
// The NRPT rules
//

// What the names of the NRPT rules of the node of the static key key begin with: NODE_DNS_RULE_LABEL, the first 8 bytes
// of the SHA-256 of the key in hex, and a hyphen
static void NodeDnsRulePrefix(wchar_t *prefix, UINT size, const UCHAR *key) {
	UCHAR copy[PEER_KEY_SIZE];
	UCHAR hash[SHA256_SIZE];

	Copy(copy, key, PEER_KEY_SIZE);
	Sha2_256(hash, copy, PEER_KEY_SIZE);
	UniFormat(prefix, size, L"%S%02X%02X%02X%02X%02X%02X%02X%02X-", NODE_DNS_RULE_LABEL, (UINT)hash[0], (UINT)hash[1], (UINT)hash[2], (UINT)hash[3],
	          (UINT)hash[4], (UINT)hash[5], (UINT)hash[6], (UINT)hash[7]);
}

// The name of the key of the NRPT rule of the VRF vrf_id of the node of the static key key: the prefix of the node's
// rules, then the VRF id
void NodeDnsRuleName(wchar_t *name, UINT size, const UCHAR *key, UINT vrf_id) {
	wchar_t prefix[NODE_DNS_RULE_NAME_SIZE];

	if (name == NULL || key == NULL)
		return;

	NodeDnsRulePrefix(prefix, sizeof(prefix), key);
	UniFormat(name, size, L"%s%u", prefix, vrf_id);
}

static LSTATUS NodeDnsSetString(HKEY key, const wchar_t *name, const wchar_t *value) {
	return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (DWORD)((UniStrLen(value) + 1) * sizeof(wchar_t)));
}

// Write the rule r as a key under base: the names under its suffix go to its servers. 0, or the error of the registry.
static UINT NodeDnsWriteRule(const wchar_t *base, const NODE_DNS_RULE *r) {
	wchar_t path[MAX_PATH];
	wchar_t names[NODE_DNS_NAME_SIZE + 2];
	wchar_t comment[MAX_SIZE];
	DWORD version = NODE_DNS_NRPT_VERSION;
	DWORD options = NODE_DNS_NRPT_GENERIC;
	HKEY key = NULL;

	UniFormat(path, sizeof(path), L"%s\\%s", base, r->Name);
	LSTATUS err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
	if (err != ERROR_SUCCESS)
		return (UINT)err;

	// Name holds the namespaces of the rule (REG_MULTI_SZ): the suffix after a dot, which every name under it ends with
	Zero(names, sizeof(names));
	UniFormat(names, sizeof(names) - sizeof(wchar_t), L".%s", r->Suffix);
	UniFormat(comment, sizeof(comment), L"Ranz VPN: the names under %s go to the stub resolver of the node", r->Suffix);

	err = RegSetValueExW(key, L"Version", 0, REG_DWORD, (const BYTE *)&version, sizeof(version));
	if (err == ERROR_SUCCESS)
		err = RegSetValueExW(key, L"Name", 0, REG_MULTI_SZ, (const BYTE *)names, (DWORD)((UniStrLen(names) + 2) * sizeof(wchar_t)));
	if (err == ERROR_SUCCESS)
		err = NodeDnsSetString(key, L"GenericDNSServers", r->Servers);
	if (err == ERROR_SUCCESS)
		err = RegSetValueExW(key, L"ConfigOptions", 0, REG_DWORD, (const BYTE *)&options, sizeof(options));
	if (err == ERROR_SUCCESS)
		err = NodeDnsSetString(key, L"IPSECCARestriction", L"");
	if (err == ERROR_SUCCESS)
		err = NodeDnsSetString(key, L"Comment", comment);
	RegCloseKey(key);

	return (UINT)err;
}

// Whether name is the name of one of the num rules of list
static bool NodeDnsKept(const wchar_t *name, const NODE_DNS_RULE *list, UINT num) {
	for (UINT i = 0; i < num; i++)
		if (UniStrCmpi(list[i].Name, name) == 0)
			return true;

	return false;
}

// Remove the rules of the node under base that are none of the num rules of keep: the keys whose names begin with the
// prefix of the node, a run of its own left behind among them. The number removed.
static UINT NodeDnsRemoveRules(NODE_DNS *d, const wchar_t *base, const NODE_DNS_RULE *keep, UINT num) {
	HKEY key = NULL;
	DWORD num_keys = 0;
	UINT num_gone = 0;
	UINT removed = 0;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_READ, &key) != ERROR_SUCCESS)
		return 0;

	// The names first: the keys may not change while they are enumerated
	if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &num_keys, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		num_keys = 0;
	wchar_t *gone = ZeroMalloc(sizeof(wchar_t) * NODE_DNS_RULE_NAME_SIZE * (num_keys + 1));
	for (DWORD i = 0; i < num_keys; i++) {
		wchar_t name[MAX_PATH];
		DWORD len = MAX_PATH;

		if (RegEnumKeyExW(key, i, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
			break;
		if (len < NODE_DNS_RULE_NAME_SIZE && UniStartWith(name, d->Prefix) && NodeDnsKept(name, keep, num) == false)
			UniStrCpy(gone + NODE_DNS_RULE_NAME_SIZE * num_gone++, sizeof(wchar_t) * NODE_DNS_RULE_NAME_SIZE, name);
	}

	for (UINT i = 0; i < num_gone; i++)
		if (RegDeleteKeyW(key, gone + NODE_DNS_RULE_NAME_SIZE * i) == ERROR_SUCCESS)
			removed++;

	Free(gone);
	RegCloseKey(key);

	return removed;
}

// Whether the NRPT of Group Policy holds a rule that is not of Ranz VPN: the DNS client of Windows then reads the rules
// of Group Policy alone, so the node writes its rules there too
static bool NodeDnsGroupPolicy() {
	wchar_t label[NODE_DNS_RULE_NAME_SIZE];
	HKEY key = NULL;
	bool others = false;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NODE_DNS_NRPT_GP, 0, KEY_READ, &key) != ERROR_SUCCESS)
		return false;

	StrToUni(label, sizeof(label), NODE_DNS_RULE_LABEL);
	for (DWORD i = 0; others == false; i++) {
		wchar_t name[MAX_PATH];
		DWORD len = MAX_PATH;

		if (RegEnumKeyExW(key, i, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
			break;
		others = (UniStartWith(name, label) == false);
	}
	RegCloseKey(key);

	return others;
}

// Flush the cache of the DNS client of Windows (DnsFlushResolverCache of dnsapi.dll, as ipconfig /flushdns does), so a
// name that the client answered before a change of the rules asks again
static void NodeDnsFlush(NODE_DNS *d) {
	HMODULE dnsapi = LoadLibraryExW(L"dnsapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	NODE_DNS_FLUSH_FUNC *flush = (dnsapi != NULL ? (NODE_DNS_FLUSH_FUNC *)(void *)GetProcAddress(dnsapi, "DnsFlushResolverCache") : NULL);

	if (flush == NULL || flush() == FALSE)
		NodeLog(d->Node, "DNS: the cache of the DNS client could not be flushed (error %u)", (UINT)GetLastError());

	if (dnsapi != NULL)
		FreeLibrary(dnsapi);
}

// Have Group Policy applied again (RefreshPolicyEx of userenv.dll), so the DNS client reads the rules of Group Policy
static void NodeDnsRefreshPolicy(NODE_DNS *d) {
	HMODULE userenv = LoadLibraryExW(L"userenv.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	NODE_DNS_REFRESH_FUNC *refresh = (userenv != NULL ? (NODE_DNS_REFRESH_FUNC *)(void *)GetProcAddress(userenv, "RefreshPolicyEx") : NULL);

	if (refresh == NULL || refresh(TRUE, NODE_DNS_RP_FORCE) == FALSE)
		NodeLog(d->Node, "DNS: Group Policy could not be refreshed (error %u)", (UINT)GetLastError());

	if (userenv != NULL)
		FreeLibrary(userenv);
}

// Whether the rule r is one that the node wrote, as it is
static bool NodeDnsWritten(NODE_DNS *d, const NODE_DNS_RULE *r) {
	for (UINT i = 0; i < d->NumRules; i++) {
		const NODE_DNS_RULE *w = &d->Rules[i];

		if (UniStrCmp(w->Name, r->Name) == 0 && UniStrCmp(w->Suffix, r->Suffix) == 0 && UniStrCmp(w->Servers, r->Servers) == 0)
			return true;
	}

	return false;
}

// The rule of the zone z, whose addresses are the num addresses of list, into r: false when the node has no address in
// the VRF of the zone to answer it on
static bool NodeDnsRuleOf(NODE_DNS *d, NODE_DNS_RULE *r, const NODE_DNS_ZONE *z, const NODE_DNS_LISTEN *list, UINT num) {
	Zero(r, sizeof(NODE_DNS_RULE));
	UniFormat(r->Name, sizeof(r->Name), L"%s%u", d->Prefix, z->VrfId);
	StrToUni(r->Suffix, sizeof(r->Suffix), z->Suffix);

	for (UINT i = 0; i < num; i++) {
		wchar_t text[INET6_ADDRSTRLEN];

		if (list[i].VrfId != z->VrfId || InetNtopW(list[i].AddressSize == 4 ? AF_INET : AF_INET6, list[i].Address, text, INET6_ADDRSTRLEN) == NULL)
			continue;
		if (UniIsEmptyStr(r->Servers) == false)
			UniStrCat(r->Servers, sizeof(r->Servers), L";");
		UniStrCat(r->Servers, sizeof(r->Servers), text);
	}

	return UniIsEmptyStr(r->Servers) == false;
}

//
// The stub resolver
//

// The zone of the VRF vrf_id, NULL for none. The caller holds ZoneLock.
static const NODE_DNS_ZONE *NodeDnsZoneFor(NODE_DNS *d, UINT vrf_id) {
	for (UINT i = 0; i < d->NumZones; i++)
		if (d->Zones[i].VrfId == vrf_id)
			return &d->Zones[i];

	return NULL;
}

static bool NodeDnsSame(const NODE_DNS_LISTEN *a, const NODE_DNS_LISTEN *b) {
	return a->VrfId == b->VrfId && a->AddressSize == b->AddressSize && Cmp(a->Address, b->Address, a->AddressSize) == 0;
}

// Bind a socket of the thread to UDP port 53 of its address, which no other socket may share; the node log names the
// error of a bind that fails, once until it changes
static void NodeDnsOpen(NODE_DNS *d, NODE_DNS_SOCKET *s) {
	SOCKADDR_STORAGE sa;
	int sa_size = 0;
	BOOL exclusive = TRUE;
	BOOL reset = FALSE;
	DWORD bytes = 0;
	wchar_t text[INET6_ADDRSTRLEN];

	Zero(&sa, sizeof(sa));
	if (s->Listen.AddressSize == 4) {
		SOCKADDR_IN *in = (SOCKADDR_IN *)&sa;
		in->sin_family = AF_INET;
		in->sin_port = htons(NODE_DNS_PORT);
		Copy(&in->sin_addr, s->Listen.Address, 4);
		sa_size = sizeof(SOCKADDR_IN);
	} else {
		SOCKADDR_IN6 *in6 = (SOCKADDR_IN6 *)&sa;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(NODE_DNS_PORT);
		Copy(&in6->sin6_addr, s->Listen.Address, 16);
		sa_size = sizeof(SOCKADDR_IN6);
	}

	UINT err = 0;
	SOCKET sock = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		err = (UINT)WSAGetLastError();
	} else if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive)) != 0 || bind(sock, (const SOCKADDR *)&sa, sa_size) != 0) {
		err = (UINT)WSAGetLastError();
		closesocket(sock);
		sock = INVALID_SOCKET;
	} else {
		// An ICMP port unreachable of a client that went is no error of the socket
		WSAIoctl(sock, SIO_UDP_CONNRESET, &reset, sizeof(reset), NULL, 0, &bytes, NULL, NULL);
	}

	if (InetNtopW(s->Listen.AddressSize == 4 ? AF_INET : AF_INET6, s->Listen.Address, text, INET6_ADDRSTRLEN) == NULL)
		UniStrCpy(text, sizeof(text), L"?");

	if (sock != INVALID_SOCKET) {
		s->Sock = sock;
		s->Error = 0;
		NodeLog(d->Node, "DNS: the stub resolver of VRF %u listens on %S port %u", s->Listen.VrfId, text, (UINT)NODE_DNS_PORT);
		return;
	}

	if (err != s->Error)
		NodeLog(d->Node, "DNS: the stub resolver of VRF %u cannot listen on %S port %u yet (error %u), and tries again", s->Listen.VrfId, text, (UINT)NODE_DNS_PORT, err);
	s->Error = err;
	InterlockedExchange(&d->LastError, (LONG)err);
}

// Make the sockets of the thread the ones of the addresses of the state applied last: a socket of an address that went
// is closed, an address that came gets a socket, and a socket that is not bound tries again
static void NodeDnsBind(NODE_DNS *d) {
	NODE_DNS_LISTEN want[NODE_DNS_MAX_SOCKETS];
	UINT num_want = 0;
	LONG version = 0;
	LONG listening = 0;

	AcquireSRWLockShared(&d->ZoneLock);
	num_want = d->NumListen;
	Copy(want, d->Listen, sizeof(NODE_DNS_LISTEN) * num_want);
	version = d->Version;
	ReleaseSRWLockShared(&d->ZoneLock);

	UINT i = 0;
	while (i < d->NumSockets) {
		NODE_DNS_SOCKET *s = &d->Sockets[i];
		bool wanted = false;

		for (UINT j = 0; j < num_want && wanted == false; j++)
			wanted = NodeDnsSame(&want[j], &s->Listen);
		if (wanted) {
			i++;
			continue;
		}

		if (s->Sock != INVALID_SOCKET)
			closesocket(s->Sock);
		d->NumSockets--;
		if (i != d->NumSockets)
			Copy(s, &d->Sockets[d->NumSockets], sizeof(NODE_DNS_SOCKET));
	}

	for (UINT j = 0; j < num_want && d->NumSockets < NODE_DNS_MAX_SOCKETS; j++) {
		bool held = false;

		for (UINT k = 0; k < d->NumSockets && held == false; k++)
			held = NodeDnsSame(&want[j], &d->Sockets[k].Listen);
		if (held)
			continue;

		NODE_DNS_SOCKET *s = &d->Sockets[d->NumSockets++];
		Zero(s, sizeof(NODE_DNS_SOCKET));
		s->Listen = want[j];
		s->Sock = INVALID_SOCKET;
	}

	for (UINT j = 0; j < d->NumSockets; j++) {
		if (d->Sockets[j].Sock == INVALID_SOCKET)
			NodeDnsOpen(d, &d->Sockets[j]);
		if (d->Sockets[j].Sock != INVALID_SOCKET)
			listening++;
	}

	InterlockedExchange(&d->Listening, listening);
	InterlockedExchange(&d->Bound, version);
}

// Answer the datagram that waits on the socket s from the zone of its VRF
static void NodeDnsServe(NODE_DNS *d, NODE_DNS_SOCKET *s, UCHAR *query, UCHAR *answer) {
	SOCKADDR_STORAGE from;
	int from_size = sizeof(from);
	char name[NODE_DNS_MAX_WIRE + 1];
	UINT rcode = NODE_DNS_RCODE_FORMERR;
	UINT size = 0;

	int got = recvfrom(s->Sock, (char *)query, NODE_DNS_MAX_QUERY, 0, (SOCKADDR *)&from, &from_size);
	if (got <= 0) {
		int err = (got == SOCKET_ERROR ? WSAGetLastError() : 0);

		InterlockedIncrement64(&d->Dropped);
		if (got == SOCKET_ERROR && err != WSAEMSGSIZE && err != WSAECONNRESET) {
			// The address went from under the socket: it is bound again once the address is back
			closesocket(s->Sock);
			s->Sock = INVALID_SOCKET;
		}
		return;
	}

	AcquireSRWLockShared(&d->ZoneLock);
	const NODE_DNS_ZONE *z = NodeDnsZoneFor(d, s->Listen.VrfId);
	if (z != NULL)
		size = NodeDnsAnswer(z, query, (UINT)got, answer, NODE_DNS_MAX_ANSWER, &rcode, name, sizeof(name));
	ReleaseSRWLockShared(&d->ZoneLock);

	if (size == 0 || rcode == NODE_DNS_RCODE_FORMERR || rcode == NODE_DNS_RCODE_NOTIMP) {
		InterlockedIncrement64(&d->Dropped);
	} else if (rcode == NODE_DNS_RCODE_REFUSED) {
		InterlockedIncrement64(&d->Refused);
		if (InterlockedIncrement(&d->Logged) <= NODE_DNS_MAX_LOGGED)
			NodeLog(d->Node, "DNS: the stub resolver of VRF %u refused a query for %s, a name outside the suffix of its zone", s->Listen.VrfId, name);
	} else {
		InterlockedIncrement64(&d->Queries);
		if (rcode == NODE_DNS_RCODE_NXDOMAIN)
			InterlockedIncrement64(&d->NameErrors);
	}

	if (size != 0)
		sendto(s->Sock, (const char *)answer, (int)size, 0, (const SOCKADDR *)&from, from_size);
}

static DWORD WINAPI NodeDnsThread(LPVOID param) {
	NODE_DNS *d = (NODE_DNS *)param;
	UCHAR *query = Malloc(NODE_DNS_MAX_QUERY);
	UCHAR *answer = Malloc(NODE_DNS_MAX_ANSWER);

	while (WaitForSingleObject(d->Halt, 0) == WAIT_TIMEOUT) {
		fd_set set;
		struct timeval tv;

		NodeDnsBind(d);

		FD_ZERO(&set);
		for (UINT i = 0; i < d->NumSockets; i++)
			if (d->Sockets[i].Sock != INVALID_SOCKET)
				FD_SET(d->Sockets[i].Sock, &set);

		tv.tv_sec = 0;
		tv.tv_usec = NODE_DNS_POLL * 1000;
		if (set.fd_count == 0 || select(0, &set, NULL, NULL, &tv) == SOCKET_ERROR) {
			WaitForSingleObject(d->Halt, NODE_DNS_POLL);
			continue;
		}

		for (UINT i = 0; i < d->NumSockets; i++)
			if (d->Sockets[i].Sock != INVALID_SOCKET && FD_ISSET(d->Sockets[i].Sock, &set))
				NodeDnsServe(d, &d->Sockets[i], query, answer);
	}

	for (UINT i = 0; i < d->NumSockets; i++)
		if (d->Sockets[i].Sock != INVALID_SOCKET)
			closesocket(d->Sockets[i].Sock);
	d->NumSockets = 0;

	Free(query);
	Free(answer);
	return 0;
}

//
// Overlay DNS of a node
//

// Overlay DNS of the node n of the static key key, with no zone before the first state: the thread of its stub resolver
// runs, and the NRPT rules that a run of the node left behind are removed. NULL when the thread cannot start (the node
// log says so).
NODE_DNS *NodeDnsNew(NODE *n, const UCHAR *key) {
	DWORD thread_id = 0;

	if (n == NULL || key == NULL)
		return NULL;

	NODE_DNS *d = ZeroMalloc(sizeof(NODE_DNS));
	d->Node = n;
	NodeDnsRulePrefix(d->Prefix, sizeof(d->Prefix), key);
	d->Lock = NewLock();
	d->Rules = ZeroMalloc(sizeof(NODE_DNS_RULE));
	InitializeSRWLock(&d->ZoneLock);
	d->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (d->Halt != NULL)
		d->Thread = CreateThread(NULL, 0, NodeDnsThread, d, 0, &thread_id);

	if (d->Thread == NULL) {
		NodeLog(n, "DNS: the stub resolver of overlay DNS could not start");
		NodeDnsFree(d);
		return NULL;
	}

	UINT removed = NodeDnsRemoveRules(d, NODE_DNS_NRPT_LOCAL, NULL, 0);
	UINT removed_gp = NodeDnsRemoveRules(d, NODE_DNS_NRPT_GP, NULL, 0);
	if (removed + removed_gp != 0) {
		NodeLog(n, "DNS: %u NRPT rules that a run of the node left behind removed", removed + removed_gp);
		NodeDnsFlush(d);
	}
	if (removed_gp != 0)
		NodeDnsRefreshPolicy(d);

	return d;
}

// Stop the stub resolver and remove the NRPT rules of the node, so the names of its zones are left to the host's own DNS
void NodeDnsFree(NODE_DNS *d) {
	if (d == NULL)
		return;

	if (d->Thread != NULL) {
		SetEvent(d->Halt);
		WaitForSingleObject(d->Thread, INFINITE);
		CloseHandle(d->Thread);

		UINT removed = NodeDnsRemoveRules(d, NODE_DNS_NRPT_LOCAL, NULL, 0);
		UINT removed_gp = NodeDnsRemoveRules(d, NODE_DNS_NRPT_GP, NULL, 0);
		if (removed + removed_gp != 0)
			NodeDnsFlush(d);
		if (removed_gp != 0)
			NodeDnsRefreshPolicy(d);
		NodeLog(d->Node, "DNS: the stub resolver stops, %u NRPT rules removed", removed);
	}

	if (d->Halt != NULL)
		CloseHandle(d->Halt);
	NodeDnsFreeZones(d->Zones, d->NumZones);
	Free(d->Rules);
	DeleteLock(d->Lock);
	Free(d);
}

// Apply a state that the overlay applied, once the adapters of its VRFs hold the node's addresses: the stub resolver
// answers the zone of each VRF of the state that has one on the node's addresses there, and the NRPT rule of each such
// VRF sends the names under its suffix to those addresses. The zones and the rules of the VRFs that the state leaves
// out, or whose overlay DNS is off, go.
void NodeDnsApply(NODE_DNS *d, const CONTROL_STATE *st) {
	NODE_DNS_LISTEN listen[NODE_DNS_MAX_SOCKETS];
	UINT num_listen = 0;
	UINT num_zones = 0;
	UINT num_rules = 0;
	UINT written = 0;
	UINT failed = 0;
	UINT error = 0;

	if (d == NULL || st == NULL)
		return;

	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (NodeDnsHasZone(&st->Vrfs[i]))
			num_zones++;

	// The zones of the state, the addresses of the node in their VRFs and the rule of each
	NODE_DNS_ZONE *zones = ZeroMalloc(sizeof(NODE_DNS_ZONE) * (num_zones != 0 ? num_zones : 1));
	NODE_DNS_RULE *rules = ZeroMalloc(sizeof(NODE_DNS_RULE) * (num_zones != 0 ? num_zones : 1));
	UINT k = 0;
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		const CONTROL_VRF *v = &st->Vrfs[i];

		if (NodeDnsHasZone(v) == false)
			continue;

		NODE_DNS_ZONE *z = &zones[k++];
		UINT first = num_listen;
		NodeDnsZoneOf(z, st, v);
		NodeDnsListenOf(listen, &num_listen, st, z);
		if (NodeDnsRuleOf(d, &rules[num_rules], z, listen + first, num_listen - first))
			num_rules++;
		else
			NodeLog(d->Node, "DNS: VRF %s: the node holds no address there to answer its zone %s on", v->Name, z->Suffix);
	}

	AcquireSRWLockExclusive(&d->ZoneLock);
	NODE_DNS_ZONE *old = d->Zones;
	UINT num_old = d->NumZones;
	d->Zones = zones;
	d->NumZones = num_zones;
	d->NumListen = num_listen;
	Copy(d->Listen, listen, sizeof(NODE_DNS_LISTEN) * num_listen);
	d->Version++;
	ReleaseSRWLockExclusive(&d->ZoneLock);
	NodeDnsFreeZones(old, num_old);

	// The rules: the ones that changed are written, at the NRPT of Group Policy too while it holds rules, and the other
	// rules of the node go
	Lock(d->Lock);
	{
		bool gp = NodeDnsGroupPolicy();
		NODE_DNS_RULE *done = ZeroMalloc(sizeof(NODE_DNS_RULE) * (num_rules != 0 ? num_rules : 1));
		UINT num_done = 0;

		for (UINT i = 0; i < num_rules; i++) {
			UINT err = 0;

			if (gp != d->GroupPolicy || NodeDnsWritten(d, &rules[i]) == false) {
				err = NodeDnsWriteRule(NODE_DNS_NRPT_LOCAL, &rules[i]);
				if (err == 0 && gp)
					err = NodeDnsWriteRule(NODE_DNS_NRPT_GP, &rules[i]);
				if (err == 0)
					written++;
			}

			if (err == 0) {
				Copy(&done[num_done++], &rules[i], sizeof(NODE_DNS_RULE));
			} else {
				failed++;
				error = err;
			}
		}

		UINT removed = NodeDnsRemoveRules(d, NODE_DNS_NRPT_LOCAL, rules, num_rules);
		UINT removed_gp = NodeDnsRemoveRules(d, NODE_DNS_NRPT_GP, rules, gp ? num_rules : 0);
		bool refresh = ((gp && written != 0) || removed_gp != 0);

		Free(d->Rules);
		d->Rules = done;
		d->NumRules = num_done;
		d->GroupPolicy = gp;

		if (written + removed + removed_gp != 0)
			NodeDnsFlush(d);
		if (refresh)
			NodeDnsRefreshPolicy(d);

		NodeLog(d->Node, "DNS: generation %I64u: %u zones, the stub resolver on %u addresses, %u NRPT rules (%u written, %u removed)%s", st->Generation, num_zones, num_listen,
		        num_done, written, removed + removed_gp, gp ? ", at the NRPT of Group Policy too" : "");
	}
	Unlock(d->Lock);

	if (failed != 0)
		NodeLog(d->Node, "DNS: %u NRPT rules could not be written (error %u): the names of their zones still go to the host's own DNS", failed, error);

	Free(rules);
}

// How overlay DNS of a node stands
void NodeDnsGetStatus(NODE_DNS *d, NODE_DNS_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_DNS_STATUS));
	if (d == NULL)
		return;

	AcquireSRWLockShared(&d->ZoneLock);
	st->NumZones = d->NumZones;
	st->NumAddresses = d->NumListen;
	LONG version = d->Version;
	ReleaseSRWLockShared(&d->ZoneLock);

	st->NumListening = (UINT)ReadAcquire(&d->Listening);
	st->Ready = (ReadAcquire(&d->Bound) == version && st->NumListening == st->NumAddresses);

	Lock(d->Lock);
	st->NumRules = d->NumRules;
	st->GroupPolicy = d->GroupPolicy;
	Unlock(d->Lock);

	st->Queries = (UINT64)ReadAcquire64(&d->Queries);
	st->NameErrors = (UINT64)ReadAcquire64(&d->NameErrors);
	st->Refused = (UINT64)ReadAcquire64(&d->Refused);
	st->Dropped = (UINT64)ReadAcquire64(&d->Dropped);
	st->LastBindError = (UINT)ReadAcquire(&d->LastError);
}
