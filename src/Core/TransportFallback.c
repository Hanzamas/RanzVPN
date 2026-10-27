// TransportFallback.c
// The fallback after a handshake (CORE-H5-R, #443): a client whose race gave it a stream on which the Noise handshake then
// failed dials the next transport of its fallback list, and not the same one again. The race alone picks the first
// stream to connect, so a node of this build and a node of the build before CORE-H5, whose QUIC handshakes fail against
// each other while their TLS-443 handshakes work, would meet over QUIC forever in a rolling upgrade. A transport whose
// handshake failed stays out of the races of the list for TRANSPORT_FALLBACK_HOLD, then comes back.

#include "Core/Transport.h"

// Whether the transport t is taken out of the races
static bool TransportFallbackOut(const TRANSPORT_FALLBACK *f, const TRANSPORT *t) {
	for (UINT i = 0; i < f->NumRefused; i++) {
		if (f->Refused[i] == t)
			return true;
	}

	return false;
}

UINT TransportFallbackTargets(TRANSPORT_FALLBACK *f, const TRANSPORT_TARGET *targets, UINT num, UINT64 now, TRANSPORT_TARGET *out, UINT max) {
	UINT n = 0;

	if (f == NULL || targets == NULL || out == NULL)
		return 0;

	// A transport whose hold is over comes back
	for (UINT i = 0; i < f->NumRefused;) {
		if (now >= f->Until[i]) {
			f->NumRefused--;
			f->Refused[i] = f->Refused[f->NumRefused];
			f->Until[i] = f->Until[f->NumRefused];
		} else {
			i++;
		}
	}

	for (UINT i = 0; i < num && n < max; i++) {
		if (TransportFallbackOut(f, targets[i].Transport) == false)
			CopyMemory(&out[n++], &targets[i], sizeof(TRANSPORT_TARGET));
	}

	// Every transport of the list is out: the race dials them all, rather than none
	if (n == 0) {
		for (UINT i = 0; i < num && n < max; i++)
			CopyMemory(&out[n++], &targets[i], sizeof(TRANSPORT_TARGET));
	}

	return n;
}

void TransportFallbackWon(TRANSPORT_FALLBACK *f, TRANSPORT *t) {
	if (f != NULL)
		f->Last = t;
}

TRANSPORT *TransportFallbackRefused(TRANSPORT_FALLBACK *f, UINT64 now) {
	if (f == NULL || f->Last == NULL)
		return NULL;

	TRANSPORT *t = f->Last;
	UINT i = 0;

	f->Last = NULL;

	// The transport again, if it is out already: its hold starts over
	while (i < f->NumRefused && f->Refused[i] != t)
		i++;
	if (i == f->NumRefused) {
		if (f->NumRefused >= TRANSPORT_MAX_TARGETS)
			return NULL;
		f->NumRefused++;
	}

	f->Refused[i] = t;
	f->Until[i] = now + TRANSPORT_FALLBACK_HOLD;

	return t;
}
