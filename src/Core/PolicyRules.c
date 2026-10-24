// PolicyRules.c
// The rules of the policy engine (Policy.h): the JSON document of the rules, parsed with cJSON into a document whose
// memory is one arena; the table that it compiles for each of its Networks, with an index per class of frames by
// destination port; the match of a flow against a table; and the counters as the JSON of the admin API.
//
// The document. Every key may be left out unless it says required. A key that is none, a key given twice or a value of
// another kind refuses the whole document: the engine does not guess at a firewall.
//   {"networks": [{"name": required,
//                  "mode": "l2" or "l3" (l3),
//                  "maxFlows": 1 to POLICY_MAX_FLOWS (POLICY_DEFAULT_FLOWS),
//                  "timeouts": {"tcpEstablished", "tcpTransitory", "udp", "icmp", "other": seconds, 1 to 604800}}],
//    "addressGroups": [{"name": required, "addresses": [address, ...]}],
//    "rules": [{"name": required,
//               "action": required, "allow" or "deny",
//               "priority": 0 to 1000000 (0), the lowest first,
//               "networks": [the name of a Network of the document, ...] (every Network),
//               "vlans": [1 to 4094, ...] (any VLAN, and none),
//               "from": end, "to": end (any end),
//               "protocol": "any", "ip", "tcp", "udp", "icmp" or 0 to 255 (any),
//               "ports": [port, or "low-high", ...] (any port; TCP or UDP only),
//               "direction": "forward" or "both" (forward)}]}
//   An end: {"users": [name, ...], "groups": [...], "tags": [...], "addresses": [address, ...],
//            "addressGroups": [the name of an address group of the document, ...]}
//   An address: an IPv4 or IPv6 address, with /length for a prefix.
// The names of Networks, rules and address groups are 1 to POLICY_MAX_NAME letters, digits, '.', '-' and '_'; those of
// users, groups and tags are 1 to POLICY_MAX_NAME printable characters other than a space, and match without case.
// A Network has no key for its default action: it is deny for every Network (ADR-0019 amendment of 2026-10-21), and an
// allow rule of the lowest priority without ends is the starter rule that lets everything through.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/PolicyInternal.h"

#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_MAX_PRIORITY 1000000 // The largest priority of a rule
#define POLICY_MAX_TIMEOUT  604800  // The longest timeout of a flow in a document (s): a week
#define POLICY_MAX_PATH     160     // Bytes of the place of a value in a document, in a refusal

// A block of an arena; what it hands out follows it
typedef struct POLICY_BLOCK {
	struct POLICY_BLOCK *Next; // The block before it
	SIZE_T Size;               // The bytes after it
	SIZE_T Used;               // ... handed out
	SIZE_T Pad;                // What it hands out on 16 bytes
} POLICY_BLOCK;

// A document on its way through the parse
typedef struct POLICY_PARSER {
	POLICY_DOC *Doc; // The document
	char *Error;     // The reason of a refusal, NULL for none
	UINT ErrorSize;  // ... its size
	UINT NumRanges;  // The port ranges of the rules so far
} POLICY_PARSER;

static const char *const policy_actions[] = {"allow", "deny"};
static const char *const policy_modes[] = {"l2", "l3"};
static const char *const policy_directions[] = {"forward", "both"};

//
// The memory of a document, and names
//

// size bytes from an arena, zeroed, on 16 bytes; NULL when there is no memory, or for more than POLICY_MAX_ALLOC
void *PolicyAlloc(POLICY_ARENA *a, SIZE_T size) {
	POLICY_BLOCK *b = (POLICY_BLOCK *)a->Blocks;

	if (size > POLICY_MAX_ALLOC)
		return NULL;
	size = (size + 15) & ~(SIZE_T)15;
	if (size == 0)
		size = 16;

	if (b == NULL || b->Size - b->Used < size) {
		SIZE_T room = (size > POLICY_ARENA_BLOCK ? size : POLICY_ARENA_BLOCK);

		b = (POLICY_BLOCK *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_BLOCK) + room);
		if (b == NULL)
			return NULL;
		b->Next = (POLICY_BLOCK *)a->Blocks;
		b->Size = room;
		a->Blocks = b;
	}

	UCHAR *p = (UCHAR *)(b + 1) + b->Used;
	b->Used += size;

	return p;
}

// Free the blocks of an arena
void PolicyFreeArena(POLICY_ARENA *a) {
	POLICY_BLOCK *b = (POLICY_BLOCK *)a->Blocks;

	while (b != NULL) {
		POLICY_BLOCK *next = b->Next;

		HeapFree(GetProcessHeap(), 0, b);
		b = next;
	}

	a->Blocks = NULL;
}

// Whether c is a letter or a digit of ASCII
static bool PolicyAlnum(UCHAR c) {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// Whether s is a name: 1 to POLICY_MAX_NAME characters; of a user, a group or a tag (identity), printable ones other
// than a space, else letters, digits, '.', '-' and '_'
bool PolicyNameOk(const char *s, bool identity) {
	UINT len = 0;

	if (s == NULL)
		return false;

	while (s[len] != 0) {
		UCHAR c = (UCHAR)s[len];

		if (len >= POLICY_MAX_NAME)
			return false;
		if (identity && (c <= ' ' || c > '~'))
			return false;
		if (identity == false && PolicyAlnum(c) == false && c != '.' && c != '-' && c != '_')
			return false;
		len++;
	}

	return len != 0;
}

// Copy a name, POLICY_MAX_NAME bytes at most, into dst, which holds POLICY_MAX_NAME + 1
void PolicyCopyName(char *dst, const char *src) {
	UINT i = 0;

	while (i < POLICY_MAX_NAME && src[i] != 0) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = 0;
}

//
// The parse
//

// Refuse the document: what is wrong with the value at where, into the error of the parse; false
static bool PolicyFail(POLICY_PARSER *ps, const char *where, const char *what) {
	if (ps->Error != NULL && ps->ErrorSize != 0)
		snprintf(ps->Error, ps->ErrorSize, "%s: %s", where, what);

	return false;
}

// The value of key in object o, NULL for none
static const cJSON *PolicyItem(const cJSON *o, const char *key) {
	return cJSON_GetObjectItemCaseSensitive(o, key);
}

// Whether the keys of object o at where are among the num keys, none twice
static bool PolicyKeys(POLICY_PARSER *ps, const cJSON *o, const char *where, const char *const *keys, UINT num) {
	char what[POLICY_MAX_PATH];
	UINT count = 0;

	for (const cJSON *c = o->child; c != NULL; c = c->next) {
		bool known = false;

		count++;
		if (count > num)
			return PolicyFail(ps, where, "has more keys than it may have");
		for (UINT i = 0; i < num && known == false && c->string != NULL; i++)
			known = (strcmp(c->string, keys[i]) == 0);
		if (known == false) {
			snprintf(what, sizeof(what), "has the key \"%.40s\", which is none of its keys", c->string != NULL ? c->string : "");
			return PolicyFail(ps, where, what);
		}
		for (const cJSON *d = o->child; d != c; d = d->next) {
			if (d->string != NULL && strcmp(d->string, c->string) == 0) {
				snprintf(what, sizeof(what), "has the key \"%s\" twice", c->string);
				return PolicyFail(ps, where, what);
			}
		}
	}

	return true;
}

// The number of values of the array a at where, NULL for none, max at most
static bool PolicyArray(POLICY_PARSER *ps, const cJSON *a, const char *where, UINT max, UINT *num) {
	char what[POLICY_MAX_PATH];
	UINT n = 0;

	*num = 0;
	if (a == NULL)
		return true;
	if (cJSON_IsArray(a) == false)
		return PolicyFail(ps, where, "is not an array");

	for (const cJSON *c = a->child; c != NULL; c = c->next) {
		n++;
		if (n > max) {
			snprintf(what, sizeof(what), "has more than %u values", max);
			return PolicyFail(ps, where, what);
		}
	}

	*num = n;
	return true;
}

// The value of item at where as a whole number from low to high
static bool PolicyNumber(POLICY_PARSER *ps, const cJSON *item, const char *where, UINT low, UINT high, UINT *out) {
	char what[POLICY_MAX_PATH];

	if (cJSON_IsNumber(item) == false || (item->valuedouble >= (double)low && item->valuedouble <= (double)high) == false ||
	    (double)(UINT)item->valuedouble != item->valuedouble) {
		snprintf(what, sizeof(what), "is not a whole number from %u to %u", low, high);
		return PolicyFail(ps, where, what);
	}

	*out = (UINT)item->valuedouble;
	return true;
}

// The value of item at where as a string
static bool PolicyString(POLICY_PARSER *ps, const cJSON *item, const char *where, const char **out) {
	if (cJSON_IsString(item) == false || item->valuestring == NULL)
		return PolicyFail(ps, where, "is not a string");

	*out = item->valuestring;
	return true;
}

// The value of item at where as one of the num choices: its index
static bool PolicyChoice(POLICY_PARSER *ps, const cJSON *item, const char *where, const char *const *choices, UINT num, UINT *out) {
	const char *s = NULL;

	if (PolicyString(ps, item, where, &s) == false)
		return false;
	for (UINT i = 0; i < num; i++) {
		if (strcmp(s, choices[i]) == 0) {
			*out = i;
			return true;
		}
	}

	return PolicyFail(ps, where, "is none of the values it may have");
}

// The name of the required string of key in object o at where; *name stays NULL when it is none
static bool PolicyRequiredName(POLICY_PARSER *ps, const cJSON *o, const char *where, const char *key, const char **name) {
	char at[POLICY_MAX_PATH];
	const cJSON *v = PolicyItem(o, key);

	*name = NULL;
	snprintf(at, sizeof(at), "%s.%s", where, key);
	if (v == NULL)
		return PolicyFail(ps, at, "is missing");
	if (PolicyString(ps, v, at, name) == false)
		return false;
	if (PolicyNameOk(*name, false) == false) {
		*name = NULL;
		return PolicyFail(ps, at, "is not a name: 1 to 63 letters, digits, '.', '-' and '_'");
	}

	return true;
}

// The names of the array item at where in the arena: of users, groups and tags (identity), or of Networks and address
// groups
static bool PolicyNames(POLICY_PARSER *ps, const cJSON *item, const char *where, bool identity, char ***out, UINT *num) {
	char at[POLICY_MAX_PATH];
	UINT n = 0;
	UINT i = 0;

	*out = NULL;
	*num = 0;
	if (PolicyArray(ps, item, where, POLICY_MAX_VALUES, &n) == false)
		return false;
	if (n == 0)
		return true;

	char **list = (char **)PolicyAlloc(&ps->Doc->Arena, sizeof(char *) * n);
	if (list == NULL)
		return PolicyFail(ps, where, "takes more memory than there is");

	for (const cJSON *c = item->child; c != NULL && i < n; c = c->next) {
		const char *s = NULL;

		snprintf(at, sizeof(at), "%s[%u]", where, i);
		if (PolicyString(ps, c, at, &s) == false)
			return false;
		if (PolicyNameOk(s, identity) == false)
			return PolicyFail(ps, at, identity ? "is not the name of a user, a group or a tag" : "is not a name");

		SIZE_T len = strlen(s);
		list[i] = (char *)PolicyAlloc(&ps->Doc->Arena, len + 1);
		if (list[i] == NULL)
			return PolicyFail(ps, at, "takes more memory than there is");
		CopyMemory(list[i], s, len);
		i++;
	}

	*out = list;
	*num = i;
	return true;
}

// The prefix of the text s: an IPv4 or IPv6 address, with /length for a prefix; its host bits are made 0
static bool PolicyPrefixOf(const char *s, POLICY_PREFIX *p) {
	char addr[64];
	const char *slash = strchr(s, '/');
	SIZE_T n = (slash != NULL ? (SIZE_T)(slash - s) : strlen(s));
	UINT len = 0;

	ZeroMemory(p, sizeof(POLICY_PREFIX));
	if (n == 0 || n >= sizeof(addr))
		return false;
	CopyMemory(addr, s, n);
	addr[n] = 0;

	if (inet_pton(AF_INET, addr, p->Addr) == 1) {
		p->Family = POLICY_IPV4;
		len = 32;
	} else if (inet_pton(AF_INET6, addr, p->Addr) == 1) {
		p->Family = POLICY_IPV6;
		len = 128;
	} else {
		return false;
	}

	// The length: 1 to 3 digits, no more than the bits of the address
	if (slash != NULL) {
		UINT v = 0;
		UINT digits = 0;

		while (slash[1 + digits] != 0) {
			UCHAR c = (UCHAR)slash[1 + digits];

			if (c < '0' || c > '9' || digits >= 3)
				return false;
			v = v * 10 + (UINT)(c - '0');
			digits++;
		}
		if (digits == 0 || v > len)
			return false;
		len = v;
	}

	p->Length = len;
	for (UINT i = 0; i < sizeof(p->Addr); i++) {
		UINT bits = (len > i * 8 ? len - i * 8 : 0);

		if (bits == 0)
			p->Addr[i] = 0;
		else if (bits < 8)
			p->Addr[i] &= (UCHAR)(0xFF << (8 - bits));
	}

	return true;
}

// The addresses of the array item at where, max at most, in the arena
static bool PolicyPrefixes(POLICY_PARSER *ps, const cJSON *item, const char *where, UINT max, POLICY_PREFIX **out, UINT *num) {
	char at[POLICY_MAX_PATH];
	UINT n = 0;
	UINT i = 0;

	*out = NULL;
	*num = 0;
	if (PolicyArray(ps, item, where, max, &n) == false)
		return false;
	if (n == 0)
		return true;

	POLICY_PREFIX *list = (POLICY_PREFIX *)PolicyAlloc(&ps->Doc->Arena, sizeof(POLICY_PREFIX) * n);
	if (list == NULL)
		return PolicyFail(ps, where, "takes more memory than there is");

	for (const cJSON *c = item->child; c != NULL && i < n; c = c->next) {
		const char *s = NULL;

		snprintf(at, sizeof(at), "%s[%u]", where, i);
		if (PolicyString(ps, c, at, &s) == false)
			return false;
		if (PolicyPrefixOf(s, &list[i]) == false)
			return PolicyFail(ps, at, "is not an IPv4 or IPv6 address, or one with /length");
		i++;
	}

	*out = list;
	*num = i;
	return true;
}

// The ports of the text s: "port" or "low-high"
static bool PolicyPortText(const char *s, POLICY_RANGE *r) {
	UINT v[2] = {0, 0};
	UINT k = 0;
	UINT digits = 0;

	for (UINT i = 0; s[i] != 0; i++) {
		UCHAR c = (UCHAR)s[i];

		if (c == '-' && k == 0 && digits != 0) {
			k = 1;
			digits = 0;
			continue;
		}
		if (c < '0' || c > '9' || digits >= 5)
			return false;
		v[k] = v[k] * 10 + (UINT)(c - '0');
		digits++;
	}

	if (digits == 0)
		return false;
	if (k == 0)
		v[1] = v[0];
	if (v[0] > 65535 || v[1] > 65535 || v[0] > v[1])
		return false;

	r->Low = v[0];
	r->High = v[1];
	return true;
}

// The ports of item: a port, or the text of one or of a range
static bool PolicyRangeOf(const cJSON *item, POLICY_RANGE *r) {
	if (cJSON_IsNumber(item)) {
		double v = item->valuedouble;

		if ((v >= 0 && v <= 65535) == false || (double)(UINT)v != v)
			return false;
		r->Low = (UINT)v;
		r->High = r->Low;
		return true;
	}

	if (cJSON_IsString(item) == false || item->valuestring == NULL)
		return false;

	return PolicyPortText(item->valuestring, r);
}

// The address group of the document of a name, NULL for none
static const POLICY_ADDR_GROUP *PolicyAddrGroupOf(const POLICY_DOC *d, const char *name) {
	for (UINT i = 0; i < d->NumAddrGroups; i++) {
		if (strcmp(d->AddrGroups[i].Name, name) == 0)
			return &d->AddrGroups[i];
	}

	return NULL;
}

// An end of a rule: the object item at where, NULL for any end
static bool PolicyParseSide(POLICY_PARSER *ps, const cJSON *item, const char *where, POLICY_SIDE *side) {
	static const char *const keys[] = {"users", "groups", "tags", "addresses", "addressGroups"};
	char at[POLICY_MAX_PATH];
	char **names = NULL;
	UINT n = 0;

	ZeroMemory(side, sizeof(POLICY_SIDE));
	if (item == NULL)
		return true;
	if (cJSON_IsObject(item) == false)
		return PolicyFail(ps, where, "is not an object");
	if (PolicyKeys(ps, item, where, keys, ARRAYSIZE(keys)) == false)
		return false;

	snprintf(at, sizeof(at), "%s.users", where);
	if (PolicyNames(ps, PolicyItem(item, "users"), at, true, &side->Users, &side->NumUsers) == false)
		return false;
	snprintf(at, sizeof(at), "%s.groups", where);
	if (PolicyNames(ps, PolicyItem(item, "groups"), at, true, &side->Groups, &side->NumGroups) == false)
		return false;
	snprintf(at, sizeof(at), "%s.tags", where);
	if (PolicyNames(ps, PolicyItem(item, "tags"), at, true, &side->Tags, &side->NumTags) == false)
		return false;
	snprintf(at, sizeof(at), "%s.addresses", where);
	if (PolicyPrefixes(ps, PolicyItem(item, "addresses"), at, POLICY_MAX_VALUES, &side->Prefixes, &side->NumPrefixes) == false)
		return false;

	// The address groups, by name
	snprintf(at, sizeof(at), "%s.addressGroups", where);
	if (PolicyNames(ps, PolicyItem(item, "addressGroups"), at, false, &names, &n) == false)
		return false;
	if (n == 0)
		return true;

	side->AddrGroups = (const POLICY_ADDR_GROUP **)PolicyAlloc(&ps->Doc->Arena, sizeof(POLICY_ADDR_GROUP *) * n);
	if (side->AddrGroups == NULL)
		return PolicyFail(ps, at, "takes more memory than there is");
	for (UINT i = 0; i < n; i++) {
		const POLICY_ADDR_GROUP *g = PolicyAddrGroupOf(ps->Doc, names[i]);

		if (g == NULL) {
			snprintf(at, sizeof(at), "%s.addressGroups[%u]", where, i);
			return PolicyFail(ps, at, "is not the name of an address group of the document");
		}
		side->AddrGroups[i] = g;
	}
	side->NumAddrGroups = n;

	return true;
}

// The protocol of a rule: a name, or an IP protocol number
static bool PolicyParseProtocol(POLICY_PARSER *ps, const cJSON *item, const char *where, UINT *protocol) {
	static const char *const names[] = {"any", "ip", "tcp", "udp", "icmp"};
	static const UINT values[] = {POLICY_PROTO_ANY, POLICY_PROTO_IP, 6, 17, POLICY_PROTO_ICMP};
	UINT i = 0;

	*protocol = POLICY_PROTO_ANY;
	if (item == NULL)
		return true;
	if (cJSON_IsNumber(item))
		return PolicyNumber(ps, item, where, 0, 255, protocol);
	if (PolicyChoice(ps, item, where, names, ARRAYSIZE(names), &i) == false)
		return false;

	*protocol = values[i];
	return true;
}

// The ports of a rule of protocol TCP or UDP
static bool PolicyParsePorts(POLICY_PARSER *ps, const cJSON *item, const char *where, POLICY_RULE *r) {
	char at[POLICY_MAX_PATH];
	UINT n = 0;
	UINT i = 0;

	if (PolicyArray(ps, item, where, POLICY_MAX_VALUES, &n) == false)
		return false;
	if (n == 0)
		return true;
	if (r->Protocol != 6 && r->Protocol != 17)
		return PolicyFail(ps, where, "are for a rule of the protocol tcp or udp only");
	if (ps->NumRanges + n > POLICY_MAX_RANGES)
		return PolicyFail(ps, where, "make more port ranges than a document may have");

	r->Ports = (POLICY_RANGE *)PolicyAlloc(&ps->Doc->Arena, sizeof(POLICY_RANGE) * n);
	if (r->Ports == NULL)
		return PolicyFail(ps, where, "take more memory than there is");

	for (const cJSON *c = item->child; c != NULL && i < n; c = c->next) {
		snprintf(at, sizeof(at), "%s[%u]", where, i);
		if (PolicyRangeOf(c, &r->Ports[i]) == false)
			return PolicyFail(ps, at, "is not a port from 0 to 65535, or a range of them as \"low-high\"");
		i++;
	}

	r->NumPorts = i;
	ps->NumRanges += i;
	return true;
}

// The VLANs of a rule
static bool PolicyParseVlans(POLICY_PARSER *ps, const cJSON *item, const char *where, POLICY_RULE *r) {
	char at[POLICY_MAX_PATH];
	UINT n = 0;
	UINT i = 0;

	if (PolicyArray(ps, item, where, POLICY_MAX_VALUES, &n) == false)
		return false;
	if (n == 0)
		return true;

	r->Vlans = (UINT *)PolicyAlloc(&ps->Doc->Arena, sizeof(UINT) * n);
	if (r->Vlans == NULL)
		return PolicyFail(ps, where, "take more memory than there is");

	for (const cJSON *c = item->child; c != NULL && i < n; c = c->next) {
		snprintf(at, sizeof(at), "%s[%u]", where, i);
		if (PolicyNumber(ps, c, at, 1, 4094, &r->Vlans[i]) == false)
			return false;
		i++;
	}

	r->NumVlans = i;
	return true;
}

// The Networks of a rule: each of the document
static bool PolicyParseRuleNets(POLICY_PARSER *ps, const cJSON *item, const char *where, POLICY_RULE *r) {
	char at[POLICY_MAX_PATH];

	if (PolicyNames(ps, item, where, false, &r->Nets, &r->NumNets) == false)
		return false;

	for (UINT i = 0; i < r->NumNets; i++) {
		bool found = false;

		for (UINT j = 0; j < ps->Doc->NumNets && found == false; j++)
			found = (strcmp(ps->Doc->Nets[j].Name, r->Nets[i]) == 0);
		if (found == false) {
			snprintf(at, sizeof(at), "%s[%u]", where, i);
			return PolicyFail(ps, at, "is not the name of a Network of the document");
		}
	}

	return true;
}

// Rule index of the document, the object item
static bool PolicyParseRule(POLICY_PARSER *ps, const cJSON *item, UINT index, POLICY_RULE *r) {
	static const char *const keys[] = {"name", "action", "priority", "networks", "vlans", "from", "to", "protocol", "ports", "direction"};
	char where[POLICY_MAX_PATH];
	char at[POLICY_MAX_PATH];
	const char *name = NULL;
	const cJSON *v = NULL;
	UINT both = 0;

	ZeroMemory(r, sizeof(POLICY_RULE));
	snprintf(where, sizeof(where), "rules[%u]", index);
	if (cJSON_IsObject(item) == false)
		return PolicyFail(ps, where, "is not an object");
	if (PolicyKeys(ps, item, where, keys, ARRAYSIZE(keys)) == false)
		return false;

	// Its name, which no rule before it has
	if (PolicyRequiredName(ps, item, where, "name", &name) == false)
		return false;
	for (UINT i = 0; i < index; i++) {
		if (strcmp(ps->Doc->Rules[i].Name, name) == 0) {
			snprintf(at, sizeof(at), "%s.name", where);
			return PolicyFail(ps, at, "is the name of a rule before it");
		}
	}
	PolicyCopyName(r->Name, name);
	r->Order = index;

	snprintf(at, sizeof(at), "%s.action", where);
	v = PolicyItem(item, "action");
	if (v == NULL)
		return PolicyFail(ps, at, "is missing");
	if (PolicyChoice(ps, v, at, policy_actions, ARRAYSIZE(policy_actions), &r->Action) == false)
		return false;

	snprintf(at, sizeof(at), "%s.priority", where);
	v = PolicyItem(item, "priority");
	if (v != NULL && PolicyNumber(ps, v, at, 0, POLICY_MAX_PRIORITY, &r->Priority) == false)
		return false;

	snprintf(at, sizeof(at), "%s.networks", where);
	if (PolicyParseRuleNets(ps, PolicyItem(item, "networks"), at, r) == false)
		return false;
	snprintf(at, sizeof(at), "%s.vlans", where);
	if (PolicyParseVlans(ps, PolicyItem(item, "vlans"), at, r) == false)
		return false;
	snprintf(at, sizeof(at), "%s.from", where);
	if (PolicyParseSide(ps, PolicyItem(item, "from"), at, &r->From) == false)
		return false;
	snprintf(at, sizeof(at), "%s.to", where);
	if (PolicyParseSide(ps, PolicyItem(item, "to"), at, &r->To) == false)
		return false;
	snprintf(at, sizeof(at), "%s.protocol", where);
	if (PolicyParseProtocol(ps, PolicyItem(item, "protocol"), at, &r->Protocol) == false)
		return false;
	snprintf(at, sizeof(at), "%s.ports", where);
	if (PolicyParsePorts(ps, PolicyItem(item, "ports"), at, r) == false)
		return false;

	snprintf(at, sizeof(at), "%s.direction", where);
	v = PolicyItem(item, "direction");
	if (v != NULL && PolicyChoice(ps, v, at, policy_directions, ARRAYSIZE(policy_directions), &both) == false)
		return false;
	r->Both = (both != 0);

	return true;
}

// The timeouts of a Network, the object item at where, in seconds; ms into timeouts
static bool PolicyParseTimeouts(POLICY_PARSER *ps, const cJSON *item, const char *where, UINT *timeouts) {
	static const char *const keys[] = {"tcpEstablished", "tcpTransitory", "udp", "icmp", "other"};
	char at[POLICY_MAX_PATH];

	if (item == NULL)
		return true;
	if (cJSON_IsObject(item) == false)
		return PolicyFail(ps, where, "is not an object");
	if (PolicyKeys(ps, item, where, keys, ARRAYSIZE(keys)) == false)
		return false;

	for (UINT i = 0; i < POLICY_NUM_TIMEOUTS; i++) {
		const cJSON *v = PolicyItem(item, keys[i]);
		UINT s = 0;

		if (v == NULL)
			continue;
		snprintf(at, sizeof(at), "%s.%s", where, keys[i]);
		if (PolicyNumber(ps, v, at, 1, POLICY_MAX_TIMEOUT, &s) == false)
			return false;
		timeouts[i] = s * 1000;
	}

	return true;
}

// Network index of the document, the object item
static bool PolicyParseNetwork(POLICY_PARSER *ps, const cJSON *item, UINT index, POLICY_NET_CONFIG *n) {
	static const char *const keys[] = {"name", "mode", "maxFlows", "timeouts"};
	char where[POLICY_MAX_PATH];
	char at[POLICY_MAX_PATH];
	const char *name = NULL;
	const cJSON *v = NULL;

	ZeroMemory(n, sizeof(POLICY_NET_CONFIG));
	n->Mode = POLICY_L3;
	n->DefaultAction = POLICY_DENY;
	n->MaxFlows = POLICY_DEFAULT_FLOWS;
	n->Timeouts[POLICY_TIMEOUT_TCP_ESTABLISHED] = POLICY_TCP_ESTABLISHED;
	n->Timeouts[POLICY_TIMEOUT_TCP_TRANSITORY] = POLICY_TCP_TRANSITORY;
	n->Timeouts[POLICY_TIMEOUT_UDP] = POLICY_UDP_TIMEOUT;
	n->Timeouts[POLICY_TIMEOUT_ICMP] = POLICY_ICMP_TIMEOUT;
	n->Timeouts[POLICY_TIMEOUT_OTHER] = POLICY_OTHER_TIMEOUT;

	snprintf(where, sizeof(where), "networks[%u]", index);
	if (cJSON_IsObject(item) == false)
		return PolicyFail(ps, where, "is not an object");
	if (PolicyKeys(ps, item, where, keys, ARRAYSIZE(keys)) == false)
		return false;

	// Its name, which no Network before it has
	if (PolicyRequiredName(ps, item, where, "name", &name) == false)
		return false;
	for (UINT i = 0; i < index; i++) {
		if (strcmp(ps->Doc->Nets[i].Name, name) == 0) {
			snprintf(at, sizeof(at), "%s.name", where);
			return PolicyFail(ps, at, "is the name of a Network before it");
		}
	}
	PolicyCopyName(n->Name, name);

	snprintf(at, sizeof(at), "%s.mode", where);
	v = PolicyItem(item, "mode");
	if (v != NULL && PolicyChoice(ps, v, at, policy_modes, ARRAYSIZE(policy_modes), &n->Mode) == false)
		return false;
	snprintf(at, sizeof(at), "%s.maxFlows", where);
	v = PolicyItem(item, "maxFlows");
	if (v != NULL && PolicyNumber(ps, v, at, 1, POLICY_MAX_FLOWS, &n->MaxFlows) == false)
		return false;
	snprintf(at, sizeof(at), "%s.timeouts", where);

	return PolicyParseTimeouts(ps, PolicyItem(item, "timeouts"), at, n->Timeouts);
}

// Address group index of the document, the object item
static bool PolicyParseAddrGroup(POLICY_PARSER *ps, const cJSON *item, UINT index, POLICY_ADDR_GROUP *g) {
	static const char *const keys[] = {"name", "addresses"};
	char where[POLICY_MAX_PATH];
	char at[POLICY_MAX_PATH];
	const char *name = NULL;

	ZeroMemory(g, sizeof(POLICY_ADDR_GROUP));
	snprintf(where, sizeof(where), "addressGroups[%u]", index);
	if (cJSON_IsObject(item) == false)
		return PolicyFail(ps, where, "is not an object");
	if (PolicyKeys(ps, item, where, keys, ARRAYSIZE(keys)) == false)
		return false;

	if (PolicyRequiredName(ps, item, where, "name", &name) == false)
		return false;
	if (PolicyAddrGroupOf(ps->Doc, name) != NULL) {
		snprintf(at, sizeof(at), "%s.name", where);
		return PolicyFail(ps, at, "is the name of an address group before it");
	}
	PolicyCopyName(g->Name, name);

	snprintf(at, sizeof(at), "%s.addresses", where);
	return PolicyPrefixes(ps, PolicyItem(item, "addresses"), at, POLICY_MAX_GROUP_SIZE, &g->Prefixes, &g->NumPrefixes);
}

// The parts of the document root: its Networks, its address groups, then its rules, which name both
static bool PolicyParseDoc(POLICY_PARSER *ps, const cJSON *root) {
	static const char *const keys[] = {"networks", "addressGroups", "rules"};
	POLICY_DOC *d = ps->Doc;
	const cJSON *nets = PolicyItem(root, "networks");
	const cJSON *groups = PolicyItem(root, "addressGroups");
	const cJSON *rules = PolicyItem(root, "rules");
	UINT n = 0;

	if (PolicyKeys(ps, root, "the document", keys, ARRAYSIZE(keys)) == false)
		return false;

	if (PolicyArray(ps, nets, "networks", POLICY_MAX_NETWORKS, &n) == false)
		return false;
	if (n != 0) {
		d->Nets = (POLICY_NET_CONFIG *)PolicyAlloc(&d->Arena, sizeof(POLICY_NET_CONFIG) * n);
		if (d->Nets == NULL)
			return PolicyFail(ps, "networks", "take more memory than there is");
		for (const cJSON *c = nets->child; c != NULL && d->NumNets < n; c = c->next) {
			if (PolicyParseNetwork(ps, c, d->NumNets, &d->Nets[d->NumNets]) == false)
				return false;
			d->NumNets++;
		}
	}

	if (PolicyArray(ps, groups, "addressGroups", POLICY_MAX_GROUPS, &n) == false)
		return false;
	if (n != 0) {
		d->AddrGroups = (POLICY_ADDR_GROUP *)PolicyAlloc(&d->Arena, sizeof(POLICY_ADDR_GROUP) * n);
		if (d->AddrGroups == NULL)
			return PolicyFail(ps, "addressGroups", "take more memory than there is");
		for (const cJSON *c = groups->child; c != NULL && d->NumAddrGroups < n; c = c->next) {
			if (PolicyParseAddrGroup(ps, c, d->NumAddrGroups, &d->AddrGroups[d->NumAddrGroups]) == false)
				return false;
			d->NumAddrGroups++;
		}
	}

	if (PolicyArray(ps, rules, "rules", POLICY_MAX_RULES, &n) == false)
		return false;
	if (n != 0) {
		d->Rules = (POLICY_RULE *)PolicyAlloc(&d->Arena, sizeof(POLICY_RULE) * n);
		if (d->Rules == NULL)
			return PolicyFail(ps, "rules", "take more memory than there is");
		for (const cJSON *c = rules->child; c != NULL && d->NumRules < n; c = c->next) {
			if (PolicyParseRule(ps, c, d->NumRules, &d->Rules[d->NumRules]) == false)
				return false;
			d->NumRules++;
		}
	}

	return true;
}

// The document of json, size bytes, NULL with the reason in error when it is none (Policy.h, the comment of this file)
POLICY_DOC *PolicyNewDoc(const char *json, UINT size, char *error, UINT error_size) {
	POLICY_PARSER ps;
	bool ok = false;

	ZeroMemory(&ps, sizeof(ps));
	ps.Error = error;
	ps.ErrorSize = error_size;
	if (error != NULL && error_size != 0)
		error[0] = 0;

	if (json == NULL || size == 0 || size > POLICY_MAX_DOCUMENT) {
		PolicyFail(&ps, "the document", "is empty, or longer than 1048576 bytes");
		return NULL;
	}

	ps.Doc = (POLICY_DOC *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_DOC));
	if (ps.Doc == NULL) {
		PolicyFail(&ps, "the document", "takes more memory than there is");
		return NULL;
	}

	cJSON *root = cJSON_ParseWithLength(json, size);
	if (root == NULL)
		PolicyFail(&ps, "the document", "is not JSON");
	else if (cJSON_IsObject(root) == false)
		PolicyFail(&ps, "the document", "is not a JSON object");
	else
		ok = PolicyParseDoc(&ps, root);
	cJSON_Delete(root);

	if (ok == false) {
		PolicyFreeDoc(ps.Doc);
		return NULL;
	}

	return ps.Doc;
}

// Free a document, with the tables in its arena
void PolicyFreeDoc(POLICY_DOC *d) {
	if (d == NULL)
		return;

	PolicyFreeArena(&d->Arena);
	HeapFree(GetProcessHeap(), 0, d);
}

//
// The tables
//

// The order of two rules of a table: by priority, then in the order of the document
static int PolicyCompareRules(const void *p1, const void *p2) {
	const POLICY_RULE *a = *(const POLICY_RULE *const *)p1;
	const POLICY_RULE *b = *(const POLICY_RULE *const *)p2;

	if (a->Priority != b->Priority)
		return (a->Priority < b->Priority ? -1 : 1);
	if (a->Order != b->Order)
		return (a->Order < b->Order ? -1 : 1);

	return 0;
}

// The order of two ports
static int PolicyComparePorts(const void *p1, const void *p2) {
	UINT a = *(const UINT *)p1;
	UINT b = *(const UINT *)p2;

	if (a == b)
		return 0;

	return (a < b ? -1 : 1);
}

// Whether a rule is of the table of the Network net
static bool PolicyRuleIn(const POLICY_RULE *r, const char *net) {
	if (r->NumNets == 0)
		return true;

	for (UINT i = 0; i < r->NumNets; i++) {
		if (strcmp(r->Nets[i], net) == 0)
			return true;
	}

	return false;
}

// Whether a rule may match the frames of the class c
static bool PolicyEligible(const POLICY_RULE *r, UINT c) {
	if (r->Protocol == POLICY_PROTO_ANY)
		return true;

	switch (c) {
	case POLICY_CLASS_TCP:
		return r->Protocol == POLICY_PROTO_IP || r->Protocol == 6;
	case POLICY_CLASS_UDP:
		return r->Protocol == POLICY_PROTO_IP || r->Protocol == 17;
	case POLICY_CLASS_ICMP:
		return r->Protocol == POLICY_PROTO_IP || r->Protocol == POLICY_PROTO_ICMP || r->Protocol == 1 || r->Protocol == 58;
	case POLICY_CLASS_OTHER:
		return r->Protocol == POLICY_PROTO_IP || (r->Protocol < POLICY_PROTO_ANY && r->Protocol != 6 && r->Protocol != 17);
	default:
		return false;
	}
}

// Whether the ports of a rule hold the port
static bool PolicyRuleHasPort(const POLICY_RULE *r, UINT port) {
	if (r->NumPorts == 0)
		return true;

	for (UINT i = 0; i < r->NumPorts; i++) {
		if (port >= r->Ports[i].Low && port <= r->Ports[i].High)
			return true;
	}

	return false;
}

// Whether entry e of a table holds the frames of class c of the interval of destination ports that starts at port (any
// port for a class without ports)
static bool PolicyHolds(const POLICY_ENTRY *e, UINT c, bool ports, UINT port) {
	return PolicyEligible(e->Rule, c) && (ports == false || PolicyRuleHasPort(e->Rule, port));
}

// The index of class c of table t: for TCP and UDP, the intervals of destination ports that the bounds of the port
// ranges of the rules make, each with the entries that hold its ports; for another class, one interval with every entry
// that it may match. *budget is what the indexes of the table may still take; false when they take more, or there is
// no memory.
static bool PolicyBuildIndex(POLICY_ARENA *a, POLICY_TABLE *t, UINT c, UINT *budget) {
	POLICY_INDEX *x = &t->Index[c];
	bool ports = (c == POLICY_CLASS_TCP || c == POLICY_CLASS_UDP);
	UINT max = 1;
	UINT num = 1;
	UINT total = 0;

	// The first port of each interval: 0, the first port of each range and the port after its last
	for (UINT i = 0; i < t->NumEntries && ports; i++) {
		if (PolicyEligible(t->Entries[i].Rule, c))
			max += t->Entries[i].Rule->NumPorts * 2;
	}
	x->Starts = (UINT *)PolicyAlloc(a, sizeof(UINT) * max);
	if (x->Starts == NULL)
		return false;
	for (UINT i = 0; i < t->NumEntries && ports; i++) {
		const POLICY_RULE *r = t->Entries[i].Rule;

		for (UINT j = 0; j < r->NumPorts && PolicyEligible(r, c); j++) {
			x->Starts[num] = r->Ports[j].Low;
			num++;
			if (r->Ports[j].High < 65535) {
				x->Starts[num] = r->Ports[j].High + 1;
				num++;
			}
		}
	}
	if (num > 1) {
		UINT u = 1;

		qsort(x->Starts, num, sizeof(UINT), PolicyComparePorts);
		for (UINT i = 1; i < num; i++) {
			if (x->Starts[i] != x->Starts[u - 1]) {
				x->Starts[u] = x->Starts[i];
				u++;
			}
		}
		num = u;
	}
	x->NumBounds = num;

	// The entries of each interval, counted, then put in
	x->Offsets = (UINT *)PolicyAlloc(a, sizeof(UINT) * (num + 1));
	if (x->Offsets == NULL)
		return false;
	for (UINT i = 0; i < num; i++) {
		x->Offsets[i] = total;
		for (UINT e = 0; e < t->NumEntries; e++) {
			if (PolicyHolds(&t->Entries[e], c, ports, x->Starts[i]) == false)
				continue;
			if (total >= *budget)
				return false;
			total++;
		}
	}
	x->Offsets[num] = total;
	*budget -= total;

	x->Cands = (UINT *)PolicyAlloc(a, sizeof(UINT) * total);
	if (x->Cands == NULL)
		return false;
	total = 0;
	for (UINT i = 0; i < num; i++) {
		for (UINT e = 0; e < t->NumEntries; e++) {
			if (PolicyHolds(&t->Entries[e], c, ports, x->Starts[i])) {
				x->Cands[total] = e;
				total++;
			}
		}
	}

	return true;
}

// The table of Network net of document d into t: its rules by priority, its entries, its indexes and its counters, in
// the arena of the document; false when its indexes take more than POLICY_MAX_CANDIDATES entries, or there is no memory
static bool PolicyBuildTable(POLICY_DOC *d, UINT net, POLICY_TABLE *t) {
	POLICY_ARENA *a = &d->Arena;
	UINT budget = POLICY_MAX_CANDIDATES;
	UINT num = 0;

	ZeroMemory(t, sizeof(POLICY_TABLE));
	t->Config = d->Nets[net];

	for (UINT i = 0; i < d->NumRules; i++) {
		if (PolicyRuleIn(&d->Rules[i], t->Config.Name))
			num++;
	}
	t->Rules = (const POLICY_RULE **)PolicyAlloc(a, sizeof(POLICY_RULE *) * num);
	t->Entries = (POLICY_ENTRY *)PolicyAlloc(a, sizeof(POLICY_ENTRY) * num * 2);
	if (t->Rules == NULL || t->Entries == NULL)
		return false;
	for (UINT i = 0; i < d->NumRules && t->NumRules < num; i++) {
		if (PolicyRuleIn(&d->Rules[i], t->Config.Name)) {
			t->Rules[t->NumRules] = &d->Rules[i];
			t->NumRules++;
		}
	}
	if (t->NumRules > 1)
		qsort((void *)t->Rules, t->NumRules, sizeof(POLICY_RULE *), PolicyCompareRules);

	// Each rule forward, and a rule of direction both also from its to end to its from end
	for (UINT i = 0; i < t->NumRules; i++) {
		const POLICY_RULE *r = t->Rules[i];
		POLICY_ENTRY *e = &t->Entries[t->NumEntries];

		e->Rule = r;
		e->Index = i;
		e->From = &r->From;
		e->To = &r->To;
		t->NumEntries++;
		if (r->Both) {
			e = &t->Entries[t->NumEntries];
			e->Rule = r;
			e->Index = i;
			e->From = &r->To;
			e->To = &r->From;
			t->NumEntries++;
		}
	}

	for (UINT c = 0; c < POLICY_NUM_CLASSES; c++) {
		if (PolicyBuildIndex(a, t, c, &budget) == false)
			return false;
	}

	// The counters of each slot of processors on whole cache lines, which start at one
	t->Stride = ((t->NumRules + 1) * POLICY_NUM_COUNTS + 7) & ~7u;
	UCHAR *block = (UCHAR *)PolicyAlloc(a, sizeof(LONG64) * POLICY_SLOTS * t->Stride + POLICY_CACHE_LINE);
	if (block == NULL)
		return false;
	t->Counters = (volatile LONG64 *)(block + POLICY_CACHE_LINE - ((UINT_PTR)block & (POLICY_CACHE_LINE - 1)));

	return true;
}

// The tables of the Networks of document d, in its order and in its arena; NULL with the reason in error when one takes
// more than the indexes of a table may take, or there is no memory
POLICY_TABLE *PolicyCompile(POLICY_DOC *d, char *error, UINT error_size) {
	POLICY_TABLE *tables = (POLICY_TABLE *)PolicyAlloc(&d->Arena, sizeof(POLICY_TABLE) * d->NumNets);

	if (error != NULL && error_size != 0)
		error[0] = 0;
	if (tables == NULL) {
		if (error != NULL && error_size != 0)
			snprintf(error, error_size, "the document: takes more memory than there is");
		return NULL;
	}

	for (UINT i = 0; i < d->NumNets; i++) {
		if (PolicyBuildTable(d, i, &tables[i]) == false) {
			if (error != NULL && error_size != 0)
				snprintf(error, error_size, "networks[%u]: its rules and ports take more than %u entries of the indexes of a table, or more memory than there is", i, POLICY_MAX_CANDIDATES);
			return NULL;
		}
	}

	return tables;
}

//
// The match
//

// Whether the list of names holds the name, without case
static bool PolicyListHas(char **list, UINT num, const char *name) {
	for (UINT i = 0; i < num; i++) {
		if (_stricmp(list[i], name) == 0)
			return true;
	}

	return false;
}

// Whether the list of names holds one of the names
static bool PolicyListMeets(char **list, UINT num, const char **names, UINT num_names) {
	for (UINT i = 0; i < num_names; i++) {
		if (PolicyListHas(list, num, names[i]))
			return true;
	}

	return false;
}

// Whether prefix p holds the address addr of the family family
static bool PolicyPrefixHas(const POLICY_PREFIX *p, UINT family, const UCHAR *addr) {
	UINT full = p->Length / 8;
	UINT rest = p->Length % 8;

	if (p->Family != family || memcmp(p->Addr, addr, full) != 0)
		return false;
	if (rest == 0)
		return true;

	return ((addr[full] ^ p->Addr[full]) & (UCHAR)(0xFF << (8 - rest))) == 0;
}

// Whether the addresses of an end, and those of its address groups, hold the address addr
static bool PolicySideHasAddr(const POLICY_SIDE *s, UINT family, const UCHAR *addr) {
	for (UINT i = 0; i < s->NumPrefixes; i++) {
		if (PolicyPrefixHas(&s->Prefixes[i], family, addr))
			return true;
	}

	for (UINT i = 0; i < s->NumAddrGroups; i++) {
		const POLICY_ADDR_GROUP *g = s->AddrGroups[i];

		for (UINT j = 0; j < g->NumPrefixes; j++) {
			if (PolicyPrefixHas(&g->Prefixes[j], family, addr))
				return true;
		}
	}

	return false;
}

// Whether an end of a rule holds the end of a flow: its member (NULL for an end outside the Network) and its address
// (family 0 for a frame that is not IP)
static bool PolicySideMatch(const POLICY_SIDE *s, const POLICY_IDENTITY *id, UINT family, const UCHAR *addr) {
	if (s->NumUsers != 0 && (id == NULL || id->User == NULL || PolicyListHas(s->Users, s->NumUsers, id->User) == false))
		return false;
	if (s->NumGroups != 0 && (id == NULL || PolicyListMeets(s->Groups, s->NumGroups, id->Groups, id->NumGroups) == false))
		return false;
	if (s->NumTags != 0 && (id == NULL || PolicyListMeets(s->Tags, s->NumTags, id->Tags, id->NumTags) == false))
		return false;
	if (s->NumPrefixes + s->NumAddrGroups != 0 && (family == 0 || addr == NULL || PolicySideHasAddr(s, family, addr) == false))
		return false;

	return true;
}

// Whether entry e matches flow or frame m, whose class and ports the index chose
static bool PolicyEntryMatch(const POLICY_ENTRY *e, const POLICY_MATCH *m) {
	const POLICY_RULE *r = e->Rule;

	if (r->Protocol < POLICY_PROTO_ANY && (m->Family == 0 || r->Protocol != m->Protocol))
		return false;

	if (r->NumVlans != 0) {
		bool found = false;

		for (UINT i = 0; i < r->NumVlans && found == false; i++)
			found = (r->Vlans[i] == m->Vlan);
		if (found == false)
			return false;
	}

	return PolicySideMatch(e->From, m->From, m->Family, m->Src) && PolicySideMatch(e->To, m->To, m->Family, m->Dst);
}

// The index of the first rule of table t, by priority, that matches flow or frame m; NumRules for none, which is the
// default action of the Network
UINT PolicyMatch(const POLICY_TABLE *t, const POLICY_MATCH *m) {
	if (m->Class >= POLICY_NUM_CLASSES)
		return t->NumRules;

	const POLICY_INDEX *x = &t->Index[m->Class];
	bool ports = (m->Class == POLICY_CLASS_TCP || m->Class == POLICY_CLASS_UDP);
	UINT b = 0;

	// A later fragment has no ports: the entries of the class that match any port
	if (ports && m->HasPort == false) {
		for (UINT i = 0; i < t->NumEntries; i++) {
			const POLICY_ENTRY *e = &t->Entries[i];

			if (PolicyEligible(e->Rule, m->Class) && e->Rule->NumPorts == 0 && PolicyEntryMatch(e, m))
				return e->Index;
		}
		return t->NumRules;
	}

	// The last interval whose first port is the destination port or below it
	if (ports) {
		UINT lo = 0;
		UINT hi = x->NumBounds;

		while (hi - lo > 1) {
			UINT mid = lo + (hi - lo) / 2;

			if (x->Starts[mid] <= m->DstPort)
				lo = mid;
			else
				hi = mid;
		}
		b = lo;
	}

	for (UINT k = x->Offsets[b]; k < x->Offsets[b + 1]; k++) {
		const POLICY_ENTRY *e = &t->Entries[x->Cands[k]];

		if (PolicyEntryMatch(e, m))
			return e->Index;
	}

	return t->NumRules;
}

//
// The checks of a document, and the counters for the admin API
//

// Whether json, size bytes, is a document of rules that compiles: what PolicySetRules takes, without taking it. The
// reason when it is not goes to error.
bool PolicyParseRules(const char *json, UINT size, char *error, UINT error_size) {
	POLICY_DOC *d = PolicyNewDoc(json, size, error, error_size);

	if (d == NULL)
		return false;

	bool ok = (PolicyCompile(d, error, error_size) != NULL);
	PolicyFreeDoc(d);

	return ok;
}

// A text on its way (PolicyCountersText)
typedef struct POLICY_TEXT {
	char *Buf;  // The text, from the heap of the process
	SIZE_T Len; // ... its length
	SIZE_T Max; // ... and its room
	UINT Width; // The width of the column of the rule names of the Network that it lists
} POLICY_TEXT;

// The counters of an engine (PolicyGetCounters) in a list from the heap of the process, *num of them; NULL when there is
// no memory. The list is that of one document: a document that replaced the one in force while it was taken makes it
// be taken again.
static POLICY_COUNTERS *PolicyCountersList(POLICY_ENGINE *p, UINT *num) {
	*num = 0;
	if (p == NULL)
		return NULL;

	for (UINT tries = 0; tries < 8; tries++) {
		UINT max = PolicyGetCounters(p, NULL, 0);
		POLICY_COUNTERS *list = (POLICY_COUNTERS *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLICY_COUNTERS) * (max + 1));

		if (list == NULL)
			return NULL;

		UINT total = PolicyGetCounters(p, list, max + 1);
		if (total <= max + 1) {
			*num = total;
			return list;
		}
		HeapFree(GetProcessHeap(), 0, list);
	}

	return NULL;
}

// A copy of a string from the heap of the process; NULL when there is no memory
static char *PolicyCopyString(const char *s) {
	SIZE_T len = strlen(s);
	char *copy = (char *)HeapAlloc(GetProcessHeap(), 0, len + 1);

	if (copy != NULL)
		CopyMemory(copy, s, len + 1);

	return copy;
}

// Add a number to a JSON object; false when there is no memory
static bool PolicyJsonNumber(cJSON *o, const char *key, UINT64 v) {
	return cJSON_AddNumberToObject(o, key, (double)v) != NULL;
}

// Add a string to a JSON object; false when there is no memory
static bool PolicyJsonString(cJSON *o, const char *key, const char *v) {
	return cJSON_AddStringToObject(o, key, v) != NULL;
}

// A Network of the counters of an engine as an object of the array nets: its kind, its default action, its conntrack
// table and the array of its rules; that array, NULL when there is no memory
static cJSON *PolicyJsonNetwork(POLICY_ENGINE *p, cJSON *nets, const char *name) {
	POLICY_NETWORK_STATS st;
	cJSON *o = cJSON_CreateObject();
	cJSON *rules = cJSON_CreateArray();
	bool ok = (o != NULL && rules != NULL);

	if (ok == false || PolicyGetNetworkStats(p, name, &st) == false) {
		cJSON_Delete(o);
		cJSON_Delete(rules);
		return NULL;
	}

	ok = PolicyJsonString(o, "name", name) && PolicyJsonString(o, "mode", st.Mode == POLICY_L2 ? "l2" : "l3") &&
	     PolicyJsonString(o, "defaultAction", st.DefaultAction == POLICY_ALLOW ? "allow" : "deny") &&
	     PolicyJsonNumber(o, "members", st.NumMembers) && PolicyJsonNumber(o, "flows", st.Flows) && PolicyJsonNumber(o, "maxFlows", st.MaxFlows) &&
	     PolicyJsonNumber(o, "tracked", st.Tracked) && PolicyJsonNumber(o, "evicted", st.Evicted) && PolicyJsonNumber(o, "expired", st.Expired);
	if (ok == false || cJSON_AddItemToObject(o, "rules", rules) == false) {
		cJSON_Delete(o);
		cJSON_Delete(rules);
		return NULL;
	}
	if (cJSON_AddItemToArray(nets, o) == false) {
		cJSON_Delete(o);
		return NULL;
	}

	return rules;
}

// The counters of a rule or of a default action as an object of the array rules; false when there is no memory
static bool PolicyJsonRule(cJSON *rules, const POLICY_COUNTERS *c) {
	cJSON *o = cJSON_CreateObject();
	bool ok = (o != NULL && PolicyJsonString(o, "name", c->Rule));

	if (ok && c->Default)
		ok = (cJSON_AddTrueToObject(o, "default") != NULL);
	else if (ok)
		ok = PolicyJsonNumber(o, "priority", c->Priority);
	ok = ok && PolicyJsonString(o, "action", c->Action == POLICY_ALLOW ? "allow" : "deny") && PolicyJsonNumber(o, "flows", c->Flows) &&
	     PolicyJsonNumber(o, "packets", c->Packets) && PolicyJsonNumber(o, "bytes", c->Bytes);
	if (ok == false || cJSON_AddItemToArray(rules, o) == false) {
		cJSON_Delete(o);
		return false;
	}

	return true;
}

// The counters of an engine as the JSON of the admin API (one line): the number of the document in force, and for each
// of its Networks, its kind, its default action, its members, its conntrack table and the counters of each of its rules,
// by priority, and of its default action:
//   {"generation": 3, "networks": [{"name": "lab", "mode": "l2", "defaultAction": "deny", "members": 4, "flows": 2,
//     "maxFlows": 4, "tracked": 5, "evicted": 1, "expired": 0, "rules": [{"name": "web", "priority": 100,
//     "action": "allow", "flows": 1, "packets": 5, "bytes": 300}, {"name": "default:deny", "default": true,
//     "action": "deny", "flows": 0, "packets": 2, "bytes": 120}]}]}
// NULL when there is no memory; PolicyFreeString frees it.
char *PolicyCountersJson(POLICY_ENGINE *p) {
	POLICY_STATS st;
	cJSON *array = NULL;
	cJSON *rules = NULL;
	char *json = NULL;
	UINT num = 0;
	POLICY_COUNTERS *list = PolicyCountersList(p, &num);
	cJSON *root = cJSON_CreateObject();
	cJSON *nets = cJSON_CreateArray();
	bool ok = (list != NULL && root != NULL && nets != NULL);

	if (ok) {
		PolicyGetStats(p, &st);
		ok = PolicyJsonNumber(root, "generation", st.Generation);
	}

	// The root owns the array of the Networks once it holds it
	if (ok && cJSON_AddItemToObject(root, "networks", nets)) {
		array = nets;
		nets = NULL;
	} else {
		ok = false;
	}

	for (UINT i = 0; i < num && ok; i++) {
		if (i == 0 || strcmp(list[i].Network, list[i - 1].Network) != 0)
			rules = PolicyJsonNetwork(p, array, list[i].Network);
		ok = (rules != NULL && PolicyJsonRule(rules, &list[i]));
	}

	if (ok) {
		char *s = cJSON_PrintUnformatted(root);

		// A copy from the heap of the process, which does not depend on the allocator that cJSON has when it is freed
		if (s != NULL) {
			json = PolicyCopyString(s);
			cJSON_free(s);
		}
	}

	cJSON_Delete(nets);
	cJSON_Delete(root);
	if (list != NULL)
		HeapFree(GetProcessHeap(), 0, list);

	return json;
}

// Add a line to a text; false when there is no memory, and the text stays as it was
static bool PolicyTextLine(POLICY_TEXT *t, const char *line) {
	SIZE_T len = strlen(line);

	if (t->Len + len + 2 > t->Max) {
		SIZE_T max = (t->Max == 0 ? 1024 : t->Max * 2);
		char *buf = NULL;

		while (max < t->Len + len + 2)
			max *= 2;
		buf = (char *)HeapAlloc(GetProcessHeap(), 0, max);
		if (buf == NULL)
			return false;
		if (t->Buf != NULL) {
			CopyMemory(buf, t->Buf, t->Len);
			HeapFree(GetProcessHeap(), 0, t->Buf);
		}
		t->Buf = buf;
		t->Max = max;
	}

	CopyMemory(t->Buf + t->Len, line, len);
	t->Len += len;
	t->Buf[t->Len] = '\n';
	t->Len++;
	t->Buf[t->Len] = 0;

	return true;
}

// The counters of an engine as the CLI shows them: for each Network of the document in force, a line with its kind, its
// default action, its members and its conntrack table, then a line for each of its rules, by priority, and one for its
// default action:
//   network lab: l2, default action deny, 4 members, 2 of 4 flows (tracked 5, evicted 1, expired 0)
//     priority  rule          action  flows  packets  bytes
//     100       web           allow   1      5        300
//     -         default:deny  deny    0      2        120
// "no document of rules" before the first one. NULL when there is no memory; PolicyFreeString frees it.
char *PolicyCountersText(POLICY_ENGINE *p) {
	POLICY_TEXT t;
	char line[POLICY_MAX_NAME * 2 + 160];
	UINT num = 0;
	POLICY_COUNTERS *list = PolicyCountersList(p, &num);
	bool ok = (list != NULL);

	ZeroMemory(&t, sizeof(t));
	if (ok && num == 0)
		ok = PolicyTextLine(&t, "no document of rules");

	for (UINT i = 0; i < num && ok; i++) {
		char priority[16];

		if (i == 0 || strcmp(list[i].Network, list[i - 1].Network) != 0) {
			POLICY_NETWORK_STATS st;
			UINT width = 4;

			// The width of the column of the rule names of the Network
			for (UINT k = i; k < num && strcmp(list[k].Network, list[i].Network) == 0; k++) {
				UINT len = (UINT)strlen(list[k].Rule);

				if (len > width)
					width = len;
			}

			ZeroMemory(&st, sizeof(st));
			PolicyGetNetworkStats(p, list[i].Network, &st);
			snprintf(line, sizeof(line), "network %s: %s, default action %s, %u members, %u of %u flows (tracked %llu, evicted %llu, expired %llu)",
			         list[i].Network, st.Mode == POLICY_L2 ? "l2" : "l3", st.DefaultAction == POLICY_ALLOW ? "allow" : "deny", st.NumMembers,
			         st.Flows, st.MaxFlows, (unsigned long long)st.Tracked, (unsigned long long)st.Evicted, (unsigned long long)st.Expired);
			ok = PolicyTextLine(&t, line);
			snprintf(line, sizeof(line), "  %-8s  %-*s  %-6s  %-8s  %-8s  %s", "priority", (int)width, "rule", "action", "flows", "packets", "bytes");
			ok = ok && PolicyTextLine(&t, line);
			t.Width = width;
		}

		if (list[i].Default)
			snprintf(priority, sizeof(priority), "-");
		else
			snprintf(priority, sizeof(priority), "%u", list[i].Priority);
		snprintf(line, sizeof(line), "  %-8s  %-*s  %-6s  %-8llu  %-8llu  %llu", priority, (int)t.Width, list[i].Rule,
		         list[i].Action == POLICY_ALLOW ? "allow" : "deny", (unsigned long long)list[i].Flows, (unsigned long long)list[i].Packets,
		         (unsigned long long)list[i].Bytes);
		ok = ok && PolicyTextLine(&t, line);
	}

	if (list != NULL)
		HeapFree(GetProcessHeap(), 0, list);
	if (ok == false && t.Buf != NULL) {
		HeapFree(GetProcessHeap(), 0, t.Buf);
		t.Buf = NULL;
	}

	return t.Buf;
}

// Free what PolicyCountersJson or PolicyCountersText returned
void PolicyFreeString(char *s) {
	if (s != NULL)
		HeapFree(GetProcessHeap(), 0, s);
}
