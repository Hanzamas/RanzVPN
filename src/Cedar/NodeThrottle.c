// NodeThrottle.c
// The throttle of the Login of a node (AUD1-DT-5, #453; NS-15 and G-5 of docs/threat-model.md): the failed Logins of
// each user and each source in a window, and the Logins that it refuses without a check. NodeThrottle.h tells how.
//
// A user is counted by the hub and the name that its Login gives, without case as Sam compares them, and a source by
// its address: an IPv4 address, or the /64 prefix of an IPv6 address, which one host holds whole. Both are kept as the
// SHA-256 of that text, so the table is small and holds no name. A Login that the throttle passes counts as a failure
// before it is checked, so Logins that run at the same time cannot pass the limit together; one that passes takes it
// back. The table holds NODE_THROTTLE_MAX_ENTRIES at most: when it is full, the entries whose window ended go, then the
// oldest one that is not refused; when every entry is refused, a Login of a new user or source is refused too, so a
// flood of names cannot push a refused user or source out of the table.

#include "NodeThrottle.h"

#include "Node.h"
#include "Sam.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Noise.h"

#include "NodeInternal.h"

// One user or source that the throttle counts
typedef struct NODE_THROTTLE_ENTRY {
	UCHAR Key[SHA256_SIZE]; // The SHA-256 of the text of the user or the source
	bool Source;            // A source, else a user
	UINT Failures;          // The failures counted in the window, with the Logins that are being checked
	UINT64 Since;           // When the window began: the first failure that it counts (ms)
} NODE_THROTTLE_ENTRY;

struct NODE_THROTTLE {
	LOCK *Lock;                // Everything below
	LIST *List;                // The entries (NODE_THROTTLE_ENTRY), sorted by their key
	UINT UserFailures;         // The limits (NODE_THROTTLE_STATUS)
	UINT SourceFailures;
	UINT64 Window;
	UINT MaxEntries;
	UINT64 NumRefusedUser;     // The refusals by reason
	UINT64 NumRefusedSource;
	UINT64 NumRefusedFull;
};

static int NodeThrottleCompare(void *p1, void *p2) {
	NODE_THROTTLE_ENTRY *a = *(NODE_THROTTLE_ENTRY **)p1;
	NODE_THROTTLE_ENTRY *b = *(NODE_THROTTLE_ENTRY **)p2;

	return Cmp(a->Key, b->Key, sizeof(a->Key));
}

NODE_THROTTLE *NewNodeThrottle() {
	NODE_THROTTLE *t = ZeroMalloc(sizeof(NODE_THROTTLE));

	t->Lock = NewLock();
	t->List = NewList(NodeThrottleCompare);
	t->UserFailures = NODE_THROTTLE_USER_FAILURES;
	t->SourceFailures = NODE_THROTTLE_SOURCE_FAILURES;
	t->Window = NODE_THROTTLE_WINDOW;
	t->MaxEntries = NODE_THROTTLE_MAX_ENTRIES;

	return t;
}

void FreeNodeThrottle(NODE_THROTTLE *t) {
	if (t == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(t->List); i++)
		Free(LIST_DATA(t->List, i));

	ReleaseList(t->List);
	DeleteLock(t->Lock);
	Free(t);
}

void NodeThrottleSetLimits(NODE_THROTTLE *t, UINT user_failures, UINT source_failures, UINT64 window, UINT max_entries) {
	if (t == NULL)
		return;

	Lock(t->Lock);
	{
		if (user_failures != 0)
			t->UserFailures = user_failures;
		if (source_failures != 0)
			t->SourceFailures = source_failures;
		if (window != 0)
			t->Window = window;
		if (max_entries != 0)
			t->MaxEntries = max_entries;
	}
	Unlock(t->Lock);
}

// The key of the user name on hub, without case
static void NodeThrottleUserKey(UCHAR *key, char *hub, char *user) {
	char tmp[MAX_SIZE * 2];

	if (hub == NULL)
		hub = "";
	if (user == NULL)
		user = "";

	// The length of the hub name keeps "a b" + "c" apart from "a" + "b c"
	Format(tmp, sizeof(tmp), "user %u %s %s", StrLen(hub), hub, user);
	StrLower(tmp);
	Sha2_256(key, tmp, StrLen(tmp));
}

// The text of a source: an IPv4 address, or the /64 prefix of an IPv6 address
static void NodeThrottleSourceStr(char *str, UINT size, IP *source) {
	IP ip;

	if (source == NULL) {
		StrCpy(str, size, "an unknown source");
		return;
	}

	Copy(&ip, source, sizeof(IP));
	if (IsIP4(&ip) == false) {
		Zero(&ip.address[8], 8);
		ip.ipv6_scope_id = 0;
	}

	IPToStr(str, size, &ip);
	if (IsIP4(&ip) == false)
		StrCat(str, size, "/64");
}

// The key of a source; false for none
static bool NodeThrottleSourceKey(UCHAR *key, IP *source) {
	char str[MAX_SIZE];
	char tmp[MAX_SIZE];

	if (source == NULL)
		return false;

	NodeThrottleSourceStr(str, sizeof(str), source);
	Format(tmp, sizeof(tmp), "source %s", str);
	Sha2_256(key, tmp, StrLen(tmp));

	return true;
}

static UINT NodeThrottleLimit(NODE_THROTTLE *t, NODE_THROTTLE_ENTRY *e) {
	return (e->Source ? t->SourceFailures : t->UserFailures);
}

// Forget the failures of an entry whose window ended
static void NodeThrottleAge(NODE_THROTTLE *t, NODE_THROTTLE_ENTRY *e, UINT64 now) {
	if (e->Failures != 0 && now >= e->Since + t->Window)
		e->Failures = 0;
}

static NODE_THROTTLE_ENTRY *NodeThrottleFind(NODE_THROTTLE *t, UCHAR *key) {
	NODE_THROTTLE_ENTRY k;

	Zero(&k, sizeof(k));
	Copy(k.Key, key, sizeof(k.Key));

	return Search(t->List, &k);
}

// Whether the Logins of an entry are refused: it failed as often as its limit allows in a window that did not end
static bool NodeThrottleBlocked(NODE_THROTTLE *t, NODE_THROTTLE_ENTRY *e, UINT64 now) {
	if (e == NULL)
		return false;

	NodeThrottleAge(t, e, now);

	return (e->Failures >= NodeThrottleLimit(t, e));
}

// Room for one more entry, keeping the entry keep: the entries whose window ended go, then the oldest one that is not
// refused. False when every entry is refused.
static bool NodeThrottleMakeRoom(NODE_THROTTLE *t, UINT64 now, NODE_THROTTLE_ENTRY *keep) {
	if (LIST_NUM(t->List) < t->MaxEntries)
		return true;

	// A new list of the entries that still count failures: the order of the old one stays
	LIST *o = NewList(NodeThrottleCompare);
	for (UINT i = 0; i < LIST_NUM(t->List); i++) {
		NODE_THROTTLE_ENTRY *e = LIST_DATA(t->List, i);

		NodeThrottleAge(t, e, now);
		if (e->Failures != 0 || e == keep)
			Add(o, e);
		else
			Free(e);
	}
	ReleaseList(t->List);
	t->List = o;

	if (LIST_NUM(t->List) < t->MaxEntries)
		return true;

	NODE_THROTTLE_ENTRY *oldest = NULL;
	for (UINT i = 0; i < LIST_NUM(t->List); i++) {
		NODE_THROTTLE_ENTRY *e = LIST_DATA(t->List, i);

		if (e != keep && e->Failures < NodeThrottleLimit(t, e) && (oldest == NULL || e->Since < oldest->Since))
			oldest = e;
	}

	if (oldest == NULL)
		return false;

	Delete(t->List, oldest);
	Free(oldest);

	return true;
}

// The entry of key, added when there is none; NULL when the table has no room
static NODE_THROTTLE_ENTRY *NodeThrottleAdd(NODE_THROTTLE *t, UCHAR *key, bool source, UINT64 now, NODE_THROTTLE_ENTRY *keep) {
	NODE_THROTTLE_ENTRY *e = NodeThrottleFind(t, key);
	if (e != NULL)
		return e;

	if (NodeThrottleMakeRoom(t, now, keep) == false)
		return NULL;

	e = ZeroMalloc(sizeof(NODE_THROTTLE_ENTRY));
	Copy(e->Key, key, sizeof(e->Key));
	e->Source = source;
	e->Since = now;
	Insert(t->List, e);

	return e;
}

// Count a failure of an entry
static void NodeThrottleFail(NODE_THROTTLE *t, NODE_THROTTLE_ENTRY *e, UINT64 now) {
	NodeThrottleAge(t, e, now);
	if (e->Failures == 0)
		e->Since = now;
	e->Failures++;
}

UINT NodeThrottleBegin(NODE_THROTTLE *t, char *hub, char *user, IP *source, UINT64 now) {
	UCHAR user_key[SHA256_SIZE], source_key[SHA256_SIZE];
	UINT ret = NODE_THROTTLE_PASS;
	if (t == NULL)
		return NODE_THROTTLE_PASS;

	NodeThrottleUserKey(user_key, hub, user);
	bool has_source = NodeThrottleSourceKey(source_key, source);

	Lock(t->Lock);
	{
		if (NodeThrottleBlocked(t, NodeThrottleFind(t, user_key), now)) {
			ret = NODE_THROTTLE_USER;
			t->NumRefusedUser++;
		} else if (has_source && NodeThrottleBlocked(t, NodeThrottleFind(t, source_key), now)) {
			ret = NODE_THROTTLE_SOURCE;
			t->NumRefusedSource++;
		} else {
			NODE_THROTTLE_ENTRY *u = NodeThrottleAdd(t, user_key, false, now, NULL);
			NODE_THROTTLE_ENTRY *s = (has_source && u != NULL ? NodeThrottleAdd(t, source_key, true, now, u) : NULL);

			if (u == NULL || (has_source && s == NULL)) {
				ret = NODE_THROTTLE_FULL;
				t->NumRefusedFull++;
			} else {
				NodeThrottleFail(t, u, now);
				if (s != NULL)
					NodeThrottleFail(t, s, now);
			}
		}
	}
	Unlock(t->Lock);

	return ret;
}

void NodeThrottleEnd(NODE_THROTTLE *t, char *hub, char *user, IP *source, bool ok) {
	UCHAR user_key[SHA256_SIZE], source_key[SHA256_SIZE];
	if (t == NULL || ok == false)
		return;

	NodeThrottleUserKey(user_key, hub, user);
	bool has_source = NodeThrottleSourceKey(source_key, source);

	Lock(t->Lock);
	{
		NODE_THROTTLE_ENTRY *u = NodeThrottleFind(t, user_key);
		if (u != NULL) {
			Delete(t->List, u);
			Free(u);
		}

		NODE_THROTTLE_ENTRY *s = (has_source ? NodeThrottleFind(t, source_key) : NULL);
		if (s != NULL && s->Failures != 0)
			s->Failures--;
	}
	Unlock(t->Lock);
}

void NodeThrottleGetStatus(NODE_THROTTLE *t, NODE_THROTTLE_STATUS *s) {
	if (s == NULL)
		return;

	Zero(s, sizeof(NODE_THROTTLE_STATUS));
	if (t == NULL)
		return;

	Lock(t->Lock);
	{
		s->UserFailures = t->UserFailures;
		s->SourceFailures = t->SourceFailures;
		s->Window = t->Window;
		s->MaxEntries = t->MaxEntries;
		s->NumEntries = LIST_NUM(t->List);
		s->NumRefusedUser = t->NumRefusedUser;
		s->NumRefusedSource = t->NumRefusedSource;
		s->NumRefusedFull = t->NumRefusedFull;
		s->NumRefused = t->NumRefusedUser + t->NumRefusedSource + t->NumRefusedFull;
	}
	Unlock(t->Lock);
}

char *NodeThrottleReasonStr(UINT reason) {
	switch (reason) {
	case NODE_THROTTLE_PASS:
		return "passed";
	case NODE_THROTTLE_USER:
		return "the user failed too often in the window";
	case NODE_THROTTLE_SOURCE:
		return "the source failed too often in the window";
	case NODE_THROTTLE_FULL:
		return "the throttle is full";
	default:
		return "unknown";
	}
}

bool NodeLoginThrottleBegin(NODE *n, NOISE_LOGIN *login, IP *source, AUTH_RESULT *ret) {
	NODE_THROTTLE_STATUS st;
	char src[MAX_SIZE];

	if (ret == NULL)
		return false;

	Zero(ret, sizeof(AUTH_RESULT));
	ret->Error = ERR_AUTH_FAILED;
	if (n == NULL || login == NULL)
		return false;

	if (login->Method == NOISE_LOGIN_JOIN)
		return true;

	UINT why = NodeThrottleBegin(n->LoginThrottle, login->HubName, login->UserName, source, Tick64());
	if (why == NODE_THROTTLE_PASS)
		return true;

	// The answer of a wrong password, without a check; the log line names the user and the source, never the password
	NodeThrottleGetStatus(n->LoginThrottle, &st);
	NodeThrottleSourceStr(src, sizeof(src), source);
	NodeLog(n, "Login throttle: a Login of %s on %s from %s refused without a check: %s (refusal %I64u)", login->UserName, login->HubName, src,
	        NodeThrottleReasonStr(why), st.NumRefused);

	return false;
}

void NodeLoginThrottleEnd(NODE *n, NOISE_LOGIN *login, IP *source, bool ok) {
	if (n == NULL || login == NULL || login->Method == NOISE_LOGIN_JOIN)
		return;

	NodeThrottleEnd(n->LoginThrottle, login->HubName, login->UserName, source, ok);
}

bool NodeLoginThrottled(NODE *n, NOISE_LOGIN *login, UCHAR *challenge, UCHAR *static_key, IP *source, AUTH_RESULT *ret) {
	if (NodeLoginThrottleBegin(n, login, source, ret) == false)
		return false;

	bool ok = NodeLoginPinned(n, login, challenge, static_key, ret);
	NodeLoginThrottleEnd(n, login, source, ok);

	return ok;
}
