// SourceLimit.c
// The limits for a source of the new core's listeners (SourceLimit.h; AUD1-DT-3, #451). A table of sources, chained in
// buckets of a hash of the source, holds for each the connections that have not finished their handshake and two token
// buckets, one for the new connections and one for the handshake attempts. A bucket counts milli-tokens, so a refill of
// a rate of N tokens a second is N milli-tokens for each millisecond that passed, with no division. One lock guards the
// table: a call takes it for a lookup and a few additions, and the cost of a call does not depend on the number of
// sources beyond the length of one chain.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/SourceLimit.h"

#include <string.h>

#define SOURCE_BUCKETS 1024 // Chains of the table, a power of two
#define SOURCE_TOKEN   1000 // Milli-tokens in one token

// One source of the table
typedef struct SOURCE_ENTRY {
	struct SOURCE_ENTRY *Next; // The next source of the chain
	SOURCE_KEY Key;            // The source
	UINT Pending;              // Its connections that have not finished their handshake
	UINT64 ConnectTokens;      // The milli-tokens of its bucket of new connections, as of ConnectStamp ...
	UINT64 ConnectStamp;       // ... that moment (ms)
	UINT64 HandshakeTokens;    // The milli-tokens of its bucket of handshake attempts, as of HandshakeStamp ...
	UINT64 HandshakeStamp;     // ... that moment (ms)
} SOURCE_ENTRY;

struct SOURCE_LIMITS {
	SOURCE_LIMIT_CONFIG Cfg;               // The configuration, with the defaults filled in
	SRWLOCK Lock;                          // Everything below
	SOURCE_ENTRY *Buckets[SOURCE_BUCKETS]; // The table
	UINT Count;                            // The sources in it
	UINT Pending;                          // The connections that have not finished their handshake, in all
	UINT64 Admitted;                       // The counters of SOURCE_LIMIT_STATS
	UINT64 RefusedFull;
	UINT64 RefusedSource;
	UINT64 RefusedRate;
	UINT64 RefusedHandshake;
};

SOURCE_LIMITS *SourceLimitsNew(const SOURCE_LIMIT_CONFIG *cfg) {
	SOURCE_LIMITS *l = (SOURCE_LIMITS *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SOURCE_LIMITS));

	if (l == NULL)
		return NULL;

	if (cfg != NULL)
		l->Cfg = *cfg;
	if (l->Cfg.MaxPending == 0)
		l->Cfg.MaxPending = SOURCE_LIMIT_MAX_PENDING;
	if (l->Cfg.MaxPendingPerSource == 0)
		l->Cfg.MaxPendingPerSource = SOURCE_LIMIT_PER_SOURCE;
	if (l->Cfg.ConnectRate == 0)
		l->Cfg.ConnectRate = SOURCE_LIMIT_RATE;
	if (l->Cfg.ConnectBurst == 0)
		l->Cfg.ConnectBurst = SOURCE_LIMIT_BURST;
	if (l->Cfg.HandshakeRate == 0)
		l->Cfg.HandshakeRate = SOURCE_LIMIT_RATE;
	if (l->Cfg.HandshakeBurst == 0)
		l->Cfg.HandshakeBurst = SOURCE_LIMIT_BURST;
	InitializeSRWLock(&l->Lock);

	return l;
}

void SourceLimitsFree(SOURCE_LIMITS *l) {
	if (l == NULL)
		return;

	for (UINT i = 0; i < SOURCE_BUCKETS; i++) {
		SOURCE_ENTRY *e = l->Buckets[i];

		while (e != NULL) {
			SOURCE_ENTRY *next = e->Next;

			HeapFree(GetProcessHeap(), 0, e);
			e = next;
		}
	}

	HeapFree(GetProcessHeap(), 0, l);
}

void SourceLimitsGetConfig(SOURCE_LIMITS *l, SOURCE_LIMIT_CONFIG *cfg) {
	if (cfg == NULL)
		return;

	ZeroMemory(cfg, sizeof(SOURCE_LIMIT_CONFIG));
	if (l != NULL)
		*cfg = l->Cfg;
}

void SourceLimitsKey(const struct sockaddr *addr, SOURCE_KEY *key) {
	ZeroMemory(key, sizeof(SOURCE_KEY));
	if (addr == NULL)
		return;

	if (addr->sa_family == AF_INET) {
		key->Family = 4;
		memcpy(key->Bytes, &((const SOCKADDR_IN *)addr)->sin_addr, 4);
	} else if (addr->sa_family == AF_INET6) {
		const IN6_ADDR *a = &((const SOCKADDR_IN6 *)addr)->sin6_addr;

		if (IN6_IS_ADDR_V4MAPPED(a)) {
			key->Family = 4;
			memcpy(key->Bytes, a->u.Byte + 12, 4);
		} else {
			key->Family = 6;
			memcpy(key->Bytes, a->u.Byte, 8);
		}
	}
}

// The chain of a source: FNV-1a over its bytes
static UINT SourceHash(const SOURCE_KEY *key) {
	const UCHAR *p = (const UCHAR *)key;
	UINT h = 2166136261u;

	for (UINT i = 0; i < sizeof(SOURCE_KEY); i++) {
		h ^= p[i];
		h *= 16777619u;
	}

	return h & (SOURCE_BUCKETS - 1);
}

// The tokens of a bucket at now: what it held at stamp, and what its rate added since, up to its burst; stamp moves to now
static UINT64 SourceRefill(UINT64 tokens, UINT64 *stamp, UINT64 now, UINT rate, UINT burst) {
	UINT64 cap = (UINT64)burst * SOURCE_TOKEN;

	if (now > *stamp) {
		UINT64 elapsed = now - *stamp;

		// A long pause fills the bucket, and the product below cannot overflow
		tokens = (elapsed > cap / rate + 1 ? cap : tokens + elapsed * rate);
		*stamp = now;
	}

	return (tokens > cap ? cap : tokens);
}

// Forget the sources that hold nothing and whose buckets are full again: they are the same as a source never seen
static void SourceSweep(SOURCE_LIMITS *l, UINT64 now) {
	for (UINT i = 0; i < SOURCE_BUCKETS; i++) {
		SOURCE_ENTRY **link = &l->Buckets[i];

		while (*link != NULL) {
			SOURCE_ENTRY *e = *link;
			UINT64 connect = SourceRefill(e->ConnectTokens, &e->ConnectStamp, now, l->Cfg.ConnectRate, l->Cfg.ConnectBurst);
			UINT64 handshake = SourceRefill(e->HandshakeTokens, &e->HandshakeStamp, now, l->Cfg.HandshakeRate, l->Cfg.HandshakeBurst);

			e->ConnectTokens = connect;
			e->HandshakeTokens = handshake;
			if (e->Pending == 0 && connect == (UINT64)l->Cfg.ConnectBurst * SOURCE_TOKEN && handshake == (UINT64)l->Cfg.HandshakeBurst * SOURCE_TOKEN) {
				*link = e->Next;
				HeapFree(GetProcessHeap(), 0, e);
				l->Count--;
			} else {
				link = &e->Next;
			}
		}
	}
}

// The entry of a source, made when it has none, with full buckets; NULL when the table is full of sources that hold
// something. The caller holds the lock.
static SOURCE_ENTRY *SourceGet(SOURCE_LIMITS *l, const SOURCE_KEY *key, UINT64 now) {
	UINT h = SourceHash(key);

	for (SOURCE_ENTRY *e = l->Buckets[h]; e != NULL; e = e->Next)
		if (memcmp(&e->Key, key, sizeof(SOURCE_KEY)) == 0)
			return e;

	if (l->Count >= SOURCE_LIMIT_MAX_SOURCES)
		SourceSweep(l, now);
	if (l->Count >= SOURCE_LIMIT_MAX_SOURCES)
		return NULL;

	SOURCE_ENTRY *e = (SOURCE_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SOURCE_ENTRY));
	if (e == NULL)
		return NULL;

	e->Key = *key;
	e->ConnectTokens = (UINT64)l->Cfg.ConnectBurst * SOURCE_TOKEN;
	e->ConnectStamp = now;
	e->HandshakeTokens = (UINT64)l->Cfg.HandshakeBurst * SOURCE_TOKEN;
	e->HandshakeStamp = now;
	e->Next = l->Buckets[h];
	l->Buckets[h] = e;
	l->Count++;

	return e;
}

UINT SourceLimitsEnter(SOURCE_LIMITS *l, const SOURCE_KEY *key, UINT64 now) {
	UINT verdict = SOURCE_LIMIT_ADMIT;

	if (l == NULL || key == NULL)
		return SOURCE_LIMIT_ADMIT;

	AcquireSRWLockExclusive(&l->Lock);
	if (l->Pending >= l->Cfg.MaxPending) {
		verdict = SOURCE_LIMIT_FULL;
	} else {
		SOURCE_ENTRY *e = SourceGet(l, key, now);

		if (e == NULL) {
			verdict = SOURCE_LIMIT_FULL;
		} else if (e->Pending >= l->Cfg.MaxPendingPerSource) {
			verdict = SOURCE_LIMIT_SOURCE;
		} else {
			e->ConnectTokens = SourceRefill(e->ConnectTokens, &e->ConnectStamp, now, l->Cfg.ConnectRate, l->Cfg.ConnectBurst);
			if (e->ConnectTokens < SOURCE_TOKEN) {
				verdict = SOURCE_LIMIT_RATE_NEW;
			} else {
				e->ConnectTokens -= SOURCE_TOKEN;
				e->Pending++;
				l->Pending++;
			}
		}
	}

	switch (verdict) {
	case SOURCE_LIMIT_ADMIT:
		l->Admitted++;
		break;
	case SOURCE_LIMIT_FULL:
		l->RefusedFull++;
		break;
	case SOURCE_LIMIT_SOURCE:
		l->RefusedSource++;
		break;
	default:
		l->RefusedRate++;
		break;
	}
	ReleaseSRWLockExclusive(&l->Lock);

	return verdict;
}

UINT SourceLimitsHandshake(SOURCE_LIMITS *l, const SOURCE_KEY *key, UINT64 now) {
	UINT verdict = SOURCE_LIMIT_ADMIT;

	if (l == NULL || key == NULL)
		return SOURCE_LIMIT_ADMIT;

	AcquireSRWLockExclusive(&l->Lock);
	SOURCE_ENTRY *e = SourceGet(l, key, now);
	if (e == NULL) {
		verdict = SOURCE_LIMIT_RATE_HAND;
	} else {
		e->HandshakeTokens = SourceRefill(e->HandshakeTokens, &e->HandshakeStamp, now, l->Cfg.HandshakeRate, l->Cfg.HandshakeBurst);
		if (e->HandshakeTokens < SOURCE_TOKEN)
			verdict = SOURCE_LIMIT_RATE_HAND;
		else
			e->HandshakeTokens -= SOURCE_TOKEN;
	}
	if (verdict != SOURCE_LIMIT_ADMIT)
		l->RefusedHandshake++;
	ReleaseSRWLockExclusive(&l->Lock);

	return verdict;
}

void SourceLimitsLeave(SOURCE_LIMITS *l, const SOURCE_KEY *key) {
	if (l == NULL || key == NULL)
		return;

	AcquireSRWLockExclusive(&l->Lock);
	for (SOURCE_ENTRY *e = l->Buckets[SourceHash(key)]; e != NULL; e = e->Next) {
		if (memcmp(&e->Key, key, sizeof(SOURCE_KEY)) != 0)
			continue;

		if (e->Pending > 0) {
			e->Pending--;
			if (l->Pending > 0)
				l->Pending--;
		}
		break;
	}
	ReleaseSRWLockExclusive(&l->Lock);
}

void SourceLimitsGetStats(SOURCE_LIMITS *l, SOURCE_LIMIT_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(SOURCE_LIMIT_STATS));
	if (l == NULL)
		return;

	AcquireSRWLockExclusive(&l->Lock);
	st->Pending = l->Pending;
	st->Sources = l->Count;
	st->Admitted = l->Admitted;
	st->RefusedFull = l->RefusedFull;
	st->RefusedSource = l->RefusedSource;
	st->RefusedRate = l->RefusedRate;
	st->RefusedHandshake = l->RefusedHandshake;
	ReleaseSRWLockExclusive(&l->Lock);
}
