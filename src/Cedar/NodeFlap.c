// NodeFlap.c
// The detection of a session that two holders of one key replace again and again (AUD1-DT-11, #459; NS-12 and G-30 of
// docs/threat-model.md). A new handshake of a static key closes the session that the overlay holds for the peer of that key
// (NodeOverlayReplace), which is how a Node that roamed or woke from sleep takes its place again (CORE-S3-1). It also lets a
// thief of the key and the real Node keep each other off by taking turns: each dials again as soon as the other closed its
// session.
//
// The overlay tells this module each replacement, with the addresses that the closed session and the new one came from (the
// transport tells them, TransportRemote), and the module counts them for each peer in a window. Above the limit it reports
// the peer as an Event of the type session-flap to the Controller (CONTROL_EVENT_SESSION_FLAP, through the queue of events of
// the control stream) and writes a line of the node log. The subject is the name of the peer, and the message says how often
// its session was replaced and which addresses the sessions came from: two addresses show two holders. The addresses are the
// hosts, without the port, which changes with each connection. A peer that was reported is not reported again before another
// window has passed, so a flap that goes on makes one Event for each window.
//
// A Node that roams once replaces one session and reports nothing. The operator deletes the Node resource of the peer and
// makes a new key for it (ADR-0030, the amendment of AUD1-DT-11).

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#define NODE_FLAP_RING  64  // The replacements that are kept for one peer at most: the limit stays below it
#define NODE_FLAP_PEERS 256 // The peers that are counted at most: when there are more, the one replaced longest ago leaves
#define NODE_FLAP_HOST  48  // An address without its port, with its NUL: an IPv6 address is 45 characters at most
#define NODE_FLAP_NAMED 4   // The addresses that a report names at most

// One replacement: when it was, and the addresses of the closed session and of the one that closed it, "" for none
typedef struct NODE_FLAP_REPLACEMENT {
	UINT64 Time;
	char Closed[NODE_FLAP_HOST];
	char Opened[NODE_FLAP_HOST];
} NODE_FLAP_REPLACEMENT;

// The replacements of the session of one peer in the window, oldest first
typedef struct NODE_FLAP_PEER {
	char Name[PEER_NAME_SIZE];
	UINT64 Last;       // When its session was replaced last
	bool Reported;     // The overlay reported it ...
	UINT64 ReportedAt; // ... when it last did
	UINT Num;
	NODE_FLAP_REPLACEMENT List[NODE_FLAP_RING];
} NODE_FLAP_PEER;

struct NODE_FLAP {
	NODE *Node;
	struct CONTROL_EVENTS *Events; // The queue of the events for the Controller, which outlives the module
	UINT Limit;                    // The replacements in the window above which a peer is reported
	UINT64 Window;                 // ... and the window (ms)
	LOCK *Lock;                    // The peers and the counts
	LIST *Peers;                   // The peers that have replacements in the window (NODE_FLAP_PEER)
	UINT64 NumReplaced;            // The replacements that were told, ever
	UINT64 NumReported;            // The peers that were reported, ever
};

NODE_FLAP *NodeFlapStart(NODE *n, UINT limit, UINT window, struct CONTROL_EVENTS *events) {
	NODE_FLAP *f = ZeroMalloc(sizeof(NODE_FLAP));

	f->Node = n;
	f->Events = events;
	f->Limit = (limit != 0 ? MIN(limit, NODE_FLAP_RING - 1) : NODE_FLAP_LIMIT);
	f->Window = (window != 0 ? window : NODE_FLAP_WINDOW);
	f->Lock = NewLock();
	f->Peers = NewListFast(NULL);

	return f;
}

void NodeFlapFree(NODE_FLAP *f) {
	if (f == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(f->Peers); i++)
		Free(LIST_DATA(f->Peers, i));

	ReleaseList(f->Peers);
	DeleteLock(f->Lock);
	Free(f);
}

// The host of an address "host:port" (an IPv6 host in brackets) into host, which holds size bytes: the address without its
// port, "" for none
static void NodeFlapHost(const char *address, char *host, UINT size) {
	const char *start = address;
	UINT len = 0;

	host[0] = 0;
	if (address == NULL || address[0] == 0)
		return;

	len = StrLen(address);
	if (address[0] == '[') {
		// "[2001:db8::1]:443": what is between the brackets
		start = address + 1;
		len = 0;
		while (start[len] != 0 && start[len] != ']')
			len++;
	} else {
		// "198.51.100.7:443": up to the colon. An address with more colons has no port.
		UINT colons = 0, last = 0;

		for (UINT i = 0; address[i] != 0; i++) {
			if (address[i] == ':') {
				colons++;
				last = i;
			}
		}
		if (colons == 1)
			len = last;
	}

	if (len >= size)
		len = size - 1;
	Copy(host, start, len);
	host[len] = 0;
}

// The peer of name with its replacements. A peer that is not counted yet is made, and when the table is full the peer that
// was replaced longest ago leaves it. The caller holds the lock.
static NODE_FLAP_PEER *NodeFlapPeer(NODE_FLAP *f, const char *name) {
	NODE_FLAP_PEER *oldest = NULL;

	for (UINT i = 0; i < LIST_NUM(f->Peers); i++) {
		NODE_FLAP_PEER *p = LIST_DATA(f->Peers, i);

		if (StrCmp(p->Name, name) == 0)
			return p;
		if (oldest == NULL || p->Last < oldest->Last)
			oldest = p;
	}

	if (LIST_NUM(f->Peers) >= NODE_FLAP_PEERS && oldest != NULL) {
		Delete(f->Peers, oldest);
		Free(oldest);
	}

	NODE_FLAP_PEER *p = ZeroMalloc(sizeof(NODE_FLAP_PEER));

	StrCpy(p->Name, sizeof(p->Name), name);
	Add(f->Peers, p);

	return p;
}

// The report of p into message (size bytes): how often its session was replaced in the window, and the addresses of the
// sessions that did it, the first NODE_FLAP_NAMED of them, each once, in the order that they came
static void NodeFlapMessage(const NODE_FLAP_PEER *p, UINT64 window, char *message, UINT size) {
	char hosts[NODE_FLAP_NAMED][NODE_FLAP_HOST];
	char list[CONTROL_EVENT_MESSAGE_SIZE];
	char span[32];
	UINT num = 0;
	bool others = false;

	for (UINT i = 0; i < p->Num; i++) {
		const char *both[2] = {p->List[i].Closed, p->List[i].Opened};

		for (UINT j = 0; j < 2; j++) {
			bool seen = (both[j][0] == 0);

			for (UINT k = 0; k < num && seen == false; k++)
				seen = (StrCmp(hosts[k], both[j]) == 0);
			if (seen)
				continue;

			if (num < NODE_FLAP_NAMED)
				StrCpy(hosts[num++], sizeof(hosts[0]), both[j]);
			else
				others = true;
		}
	}

	if (window % 1000 == 0)
		Format(span, sizeof(span), "%u s", (UINT)(window / 1000));
	else
		Format(span, sizeof(span), "%u ms", (UINT)window);

	if (num == 0) {
		Format(message, size, "the session of peer %s was replaced %u times in %s", p->Name, p->Num, span);
		return;
	}

	// "a", "a and b", "a, b and c", and "a, b, c, d and others"
	list[0] = 0;
	for (UINT i = 0; i < num; i++) {
		if (i != 0)
			StrCat(list, sizeof(list), (i + 1 == num && others == false ? " and " : ", "));
		StrCat(list, sizeof(list), hosts[i]);
	}
	if (others)
		StrCat(list, sizeof(list), " and others");

	Format(message, size, "the session of peer %s was replaced %u times in %s, by sessions from %s", p->Name, p->Num, span, list);
}

void NodeFlapReplaced(NODE_FLAP *f, const char *peer, const char *old_source, const char *new_source) {
	char message[CONTROL_EVENT_MESSAGE_SIZE];
	char name[PEER_NAME_SIZE];
	bool report = false;

	if (f == NULL || peer == NULL)
		return;

	StrCpy(name, sizeof(name), peer);
	message[0] = 0;

	Lock(f->Lock);
	{
		UINT64 now = GetTickCount64();
		NODE_FLAP_PEER *p = NodeFlapPeer(f, name);
		UINT gone = 0;

		// The replacements older than the window do not count any more, and a full list drops its oldest
		while (gone < p->Num && now - p->List[gone].Time >= f->Window)
			gone++;
		if (gone == 0 && p->Num == NODE_FLAP_RING)
			gone = 1;
		if (gone != 0) {
			MoveMemory(p->List, p->List + gone, sizeof(NODE_FLAP_REPLACEMENT) * (p->Num - gone));
			p->Num -= gone;
		}

		NODE_FLAP_REPLACEMENT *r = &p->List[p->Num++];

		Zero(r, sizeof(NODE_FLAP_REPLACEMENT));
		r->Time = now;
		NodeFlapHost(old_source, r->Closed, sizeof(r->Closed));
		NodeFlapHost(new_source, r->Opened, sizeof(r->Opened));
		p->Last = now;
		f->NumReplaced++;

		// Above the limit in the window, and not reported in the last window
		if (p->Num > f->Limit && (p->Reported == false || now - p->ReportedAt >= f->Window)) {
			p->Reported = true;
			p->ReportedAt = now;
			f->NumReported++;
			NodeFlapMessage(p, f->Window, message, sizeof(message));
			report = true;
		}
	}
	Unlock(f->Lock);

	if (report == false)
		return;

	NodeLog(f->Node, "Overlay: session flap: %s", message);
	ControlRaiseEvent(f->Events, CONTROL_EVENT_SESSION_FLAP, name, message);
}

void NodeFlapGetStatus(NODE_FLAP *f, NODE_OVERLAY_STATUS *st) {
	if (f == NULL || st == NULL)
		return;

	Lock(f->Lock);
	{
		st->SessionsReplaced = f->NumReplaced;
		st->SessionFlaps = f->NumReported;
	}
	Unlock(f->Lock);
}
