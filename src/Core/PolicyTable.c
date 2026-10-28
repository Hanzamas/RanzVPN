// PolicyTable.c
// The compiled rule tables of a document of rules as text (Policy.h): what PolicyCompile makes of each Network of the
// document, its rules in the order that the engine evaluates them, each with all that it matches, then the default action
// of the Network. The import of the fork's access list (Cedar/ConfigStoreImport.c; CORE-S4-3, #76) asserts the tables of
// the document that its store makes against a golden rule table, and the CLI can show what a document compiles to:
//   network lab: l2, default action deny, 2 rules
//     priority  rule          action  match
//     10        web           allow   protocol tcp; ports 80,8000-8080; from groups staff; to addresses 10.0.0.0/24
//     1000000   starter       allow   protocol any
//     -         default:deny  deny    every frame that no rule matches

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/PolicyInternal.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define POLICY_TABLE_FIRST 4096 // Bytes of the first room of a text
#define POLICY_TABLE_PIECE 512  // Bytes of one formatted piece of a text at most: names are POLICY_MAX_NAME bytes at most

// A text that grows as it is written
typedef struct POLICY_TABLE_TEXT {
	char *Buf;  // The text, from the heap of the process
	SIZE_T Len; // ... its length
	SIZE_T Max; // ... and its room
	bool Fail;  // There was no memory: the text is dropped
} POLICY_TABLE_TEXT;

// Append the string s to the text t
static void PolicyTablePut(POLICY_TABLE_TEXT *t, const char *s) {
	SIZE_T len = strlen(s);

	if (t->Fail)
		return;

	if (t->Len + len + 1 > t->Max) {
		SIZE_T max = (t->Max == 0 ? POLICY_TABLE_FIRST : t->Max);

		while (max < t->Len + len + 1)
			max *= 2;

		char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, max);
		if (buf == NULL) {
			t->Fail = true;
			return;
		}

		if (t->Buf != NULL) {
			CopyMemory(buf, t->Buf, t->Len);
			HeapFree(GetProcessHeap(), 0, t->Buf);
		}

		t->Buf = buf;
		t->Max = max;
	}

	CopyMemory(t->Buf + t->Len, s, len + 1);
	t->Len += len;
}

// Append the text that fmt formats to the text t
static void PolicyTablePrintf(POLICY_TABLE_TEXT *t, const char *fmt, ...) {
	char piece[POLICY_TABLE_PIECE];
	va_list args;

	va_start(args, fmt);
	int n = vsnprintf(piece, sizeof(piece), fmt, args);
	va_end(args);

	if (n < 0) {
		t->Fail = true;
		return;
	}

	PolicyTablePut(t, piece);
}

// The names of a list of an end of a rule, as "; from users alice,bob"
static void PolicyTableNames(POLICY_TABLE_TEXT *t, const char *end, const char *list, char *const *names, UINT num) {
	if (num == 0)
		return;

	PolicyTablePrintf(t, "; %s %s ", end, list);

	for (UINT i = 0; i < num; i++) {
		if (i != 0)
			PolicyTablePut(t, ",");

		PolicyTablePut(t, names[i]);
	}
}

// The prefixes of an end of a rule, or of an address group, as "; to addresses 10.0.0.0/24,2001:db8::/32"
static void PolicyTablePrefixes(POLICY_TABLE_TEXT *t, const char *end, const char *list, const POLICY_PREFIX *prefixes, UINT num) {
	char addr[INET6_ADDRSTRLEN];

	if (num == 0)
		return;

	PolicyTablePrintf(t, "; %s %s ", end, list);

	for (UINT i = 0; i < num; i++) {
		const POLICY_PREFIX *p = &prefixes[i];

		if (inet_ntop(p->Family == POLICY_IPV4 ? AF_INET : AF_INET6, p->Addr, addr, sizeof(addr)) == NULL)
			snprintf(addr, sizeof(addr), "?");

		PolicyTablePrintf(t, "%s%s/%u", i != 0 ? "," : "", addr, p->Length);
	}
}

// An end of a rule: its users, groups and tags, its addresses and its address groups, each with the prefixes it holds
static void PolicyTableSide(POLICY_TABLE_TEXT *t, const char *end, const POLICY_SIDE *s) {
	char list[POLICY_MAX_NAME + 32];

	PolicyTableNames(t, end, "users", s->Users, s->NumUsers);
	PolicyTableNames(t, end, "groups", s->Groups, s->NumGroups);
	PolicyTableNames(t, end, "tags", s->Tags, s->NumTags);
	PolicyTablePrefixes(t, end, "addresses", s->Prefixes, s->NumPrefixes);

	for (UINT i = 0; i < s->NumAddrGroups; i++) {
		const POLICY_ADDR_GROUP *g = s->AddrGroups[i];

		snprintf(list, sizeof(list), "address group %s", g->Name);
		if (g->NumPrefixes == 0)
			PolicyTablePrintf(t, "; %s %s, which holds no address", end, list);
		else
			PolicyTablePrefixes(t, end, list, g->Prefixes, g->NumPrefixes);
	}
}

// What rule r matches: its protocol, its destination ports, its VLANs, its two ends and its direction
static void PolicyTableMatch(POLICY_TABLE_TEXT *t, const POLICY_RULE *r) {
	switch (r->Protocol) {
	case POLICY_PROTO_ANY:
		PolicyTablePut(t, "protocol any");
		break;
	case POLICY_PROTO_IP:
		PolicyTablePut(t, "protocol ip");
		break;
	case POLICY_PROTO_ICMP:
		PolicyTablePut(t, "protocol icmp");
		break;
	case 6:
		PolicyTablePut(t, "protocol tcp");
		break;
	case 17:
		PolicyTablePut(t, "protocol udp");
		break;
	default:
		PolicyTablePrintf(t, "protocol %u", r->Protocol);
		break;
	}

	for (UINT i = 0; i < r->NumPorts; i++) {
		const POLICY_RANGE *p = &r->Ports[i];

		PolicyTablePut(t, i == 0 ? "; ports " : ",");
		if (p->Low == p->High)
			PolicyTablePrintf(t, "%u", p->Low);
		else
			PolicyTablePrintf(t, "%u-%u", p->Low, p->High);
	}

	for (UINT i = 0; i < r->NumVlans; i++)
		PolicyTablePrintf(t, "%s%u", i == 0 ? "; vlans " : ",", r->Vlans[i]);

	PolicyTableSide(t, "from", &r->From);
	PolicyTableSide(t, "to", &r->To);

	if (r->Both)
		PolicyTablePut(t, "; direction both");
}

// The compiled rule tables of the document json, size bytes, as text (the comment of this file): for each Network, in
// the order of the document, its kind, its default action and its rules in the order that the engine evaluates them,
// each with what it matches. NULL with the reason in error when the document is none that PolicySetRules takes, or there
// is no memory; PolicyFreeString frees it.
char *PolicyTableText(const char *json, UINT size, char *error, UINT error_size) {
	POLICY_TABLE_TEXT t;
	POLICY_DOC *d = PolicyNewDoc(json, size, error, error_size);

	if (d == NULL)
		return NULL;

	POLICY_TABLE *tables = PolicyCompile(d, error, error_size);
	if (tables == NULL) {
		PolicyFreeDoc(d);
		return NULL;
	}

	ZeroMemory(&t, sizeof(t));
	if (d->NumNets == 0)
		PolicyTablePut(&t, "no network\n");

	for (UINT i = 0; i < d->NumNets; i++) {
		const POLICY_TABLE *table = &tables[i];
		const char *deflt = (table->Config.DefaultAction == POLICY_ALLOW ? "default:allow" : "default:deny");
		int width = (int)strlen(deflt);

		// The width of the column of the rule names of the Network
		for (UINT k = 0; k < table->NumRules; k++) {
			int len = (int)strlen(table->Rules[k]->Name);

			if (len > width)
				width = len;
		}

		PolicyTablePrintf(&t, "network %s: %s, default action %s, %u rules\n", table->Config.Name, table->Config.Mode == POLICY_L2 ? "l2" : "l3",
		                  table->Config.DefaultAction == POLICY_ALLOW ? "allow" : "deny", table->NumRules);
		PolicyTablePrintf(&t, "  %-8s  %-*s  %-6s  %s\n", "priority", width, "rule", "action", "match");

		for (UINT k = 0; k < table->NumRules; k++) {
			const POLICY_RULE *r = table->Rules[k];

			PolicyTablePrintf(&t, "  %-8u  %-*s  %-6s  ", r->Priority, width, r->Name, r->Action == POLICY_ALLOW ? "allow" : "deny");
			PolicyTableMatch(&t, r);
			PolicyTablePut(&t, "\n");
		}

		PolicyTablePrintf(&t, "  %-8s  %-*s  %-6s  %s\n", "-", width, deflt, table->Config.DefaultAction == POLICY_ALLOW ? "allow" : "deny",
		                  "every frame that no rule matches");
	}

	PolicyFreeDoc(d);

	if (t.Fail || t.Buf == NULL) {
		if (t.Buf != NULL)
			HeapFree(GetProcessHeap(), 0, t.Buf);

		if (error != NULL && error_size != 0)
			snprintf(error, error_size, "the document: takes more memory than there is");

		return NULL;
	}

	return t.Buf;
}
