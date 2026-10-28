// ControlSignal.c
// The Relays of a desired state and the Signals of the peers on the control stream (CORE-S5-5, #411; Core/Control.h). The
// Relay objects of a state are the relays that the node may use, in name order: the first is its home relay
// (ControlCopyRelays). A Signal is an envelope that the peer layer of a node seals to one peer (PeerSealSignal of
// Core/Peer.h): the node writes it on its stream with the name of that peer (ControlSendSignal, ControlWriteSignals), and
// the controller forwards it to the peer, with the name of the sender, when the two share a VRF. The client hands each
// Signal that the controller forwarded to its owner as it came (ControlTakeSignal): only the peer layer of the node opens
// it, so the controller can neither read nor alter one.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_SIGNAL_HEADER 4    // The size of a frame, big-endian, before its message (as Control.c writes them)
#define CONTROL_SIGNAL_FRAME  2048 // The frame of a Signal: more than its largest, a name and an envelope of the largest sizes

// One Signal that waits for the stream
typedef struct CONTROL_SIGNAL_ITEM {
	char Peer[CONTROL_NAME_SIZE];         // The node name of the peer
	UINT Size;                            // The size of the envelope
	UCHAR Envelope[CONTROL_MAX_ENVELOPE]; // ... and its bytes
} CONTROL_SIGNAL_ITEM;

// The Signals that a client sends
struct CONTROL_SIGNALS {
	SRWLOCK Lock;                                   // The queue
	UINT First;                                     // The oldest Signal of the ring below
	UINT Num;                                       // The Signals that wait
	CONTROL_SIGNAL_ITEM Items[CONTROL_MAX_SIGNALS]; // ... a ring of them
	ranz_control_v1_Signal *Message;                // The message that the thread of the client writes ...
	UCHAR *Frame;                                   // ... and its frame
};

static void *ControlSignalAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlSignalFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The Relays of a state
//

// The Relay objects among num objects into the state, CONTROL_MAX_RELAYS at most: the first of them by name, in name order,
// so that the first is the home relay of the node whatever the order of the objects. A Relay without a static key of
// NOISE_KEY_SIZE bytes, an IPv4 or IPv6 address and a port from 1 to 65535 is left out.
void ControlCopyRelays(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumRelays = 0;

	for (UINT i = 0; i < num; i++) {
		CONTROL_RELAY c;

		if (objects[i].which_kind != ranz_control_v1_Object_relay_tag)
			continue;

		const ranz_control_v1_Relay *r = &objects[i].kind.relay;
		if (r->public_key.size != NOISE_KEY_SIZE || (r->address.size != 4 && r->address.size != 16) || r->port == 0 || r->port > 65535)
			continue;

		ZeroMemory(&c, sizeof(c));
		strncpy_s(c.Name, sizeof(c.Name), r->name, _TRUNCATE);
		CopyMemory(c.Key, r->public_key.bytes, NOISE_KEY_SIZE);
		CopyMemory(c.Address, r->address.bytes, r->address.size);
		c.AddressSize = r->address.size;
		c.Port = r->port;

		// A full list takes the relay in place of its last one when its name comes before
		UINT n = st->NumRelays;
		if (n == CONTROL_MAX_RELAYS) {
			if (strcmp(c.Name, st->Relays[n - 1].Name) >= 0)
				continue;
			n--;
		}

		UINT k = n;
		while (k > 0 && strcmp(c.Name, st->Relays[k - 1].Name) < 0) {
			st->Relays[k] = st->Relays[k - 1];
			k--;
		}
		st->Relays[k] = c;
		st->NumRelays = n + 1;
	}
}

//
// The Signals that the controller forwarded
//

// Hand a Signal that the controller forwarded to the owner, as it came: the name of the peer that sent it and its
// envelope, which the owner's peer layer opens. A Signal without a name or an envelope is dropped.
void ControlTakeSignal(const CONTROL_CONFIG *cfg, const ranz_control_v1_Signal *sig) {
	if (cfg->SignalProc == NULL || sig->peer[0] == 0 || sig->envelope.size == 0)
		return;

	cfg->SignalProc(cfg->SignalParam, sig->peer, sig->envelope.bytes, sig->envelope.size);
}

//
// The Signals that the node sends
//

CONTROL_SIGNALS *ControlNewSignals() {
	CONTROL_SIGNALS *q = ControlSignalAlloc(sizeof(CONTROL_SIGNALS));

	if (q == NULL)
		return NULL;

	InitializeSRWLock(&q->Lock);
	q->Message = ControlSignalAlloc(sizeof(ranz_control_v1_Signal));
	q->Frame = ControlSignalAlloc(CONTROL_SIGNAL_FRAME);
	if (q->Message == NULL || q->Frame == NULL) {
		ControlFreeSignals(q);
		return NULL;
	}

	return q;
}

void ControlFreeSignals(CONTROL_SIGNALS *q) {
	if (q == NULL)
		return;

	ControlSignalFree(q->Message);
	ControlSignalFree(q->Frame);
	ControlSignalFree(q);
}

// Queue a Signal for the peer of the node name peer, with its envelope of size bytes: the client writes it on its stream.
// A full queue drops its oldest Signal: the node signals again a peer that did not answer. False for a name that is empty
// or too long, or an envelope of 0 or more than CONTROL_MAX_ENVELOPE bytes.
bool ControlSendSignal(CONTROL_SIGNALS *q, const char *peer, const UCHAR *envelope, UINT size) {
	if (q == NULL || peer == NULL || peer[0] == 0 || strnlen(peer, CONTROL_NAME_SIZE) >= CONTROL_NAME_SIZE || envelope == NULL || size == 0 || size > CONTROL_MAX_ENVELOPE)
		return false;

	AcquireSRWLockExclusive(&q->Lock);
	{
		if (q->Num == CONTROL_MAX_SIGNALS) {
			q->First = (q->First + 1) % CONTROL_MAX_SIGNALS;
			q->Num--;
		}

		CONTROL_SIGNAL_ITEM *it = &q->Items[(q->First + q->Num) % CONTROL_MAX_SIGNALS];
		strcpy_s(it->Peer, sizeof(it->Peer), peer);
		CopyMemory(it->Envelope, envelope, size);
		it->Size = size;
		q->Num++;
	}
	ReleaseSRWLockExclusive(&q->Lock);

	return true;
}

// Write the Message of q as the body Signal of a ControlMessage, in one frame
static bool ControlSignalWrite(CONTROL_SIGNALS *q, TRANSPORT_STREAM *s) {
	pb_ostream_t os = pb_ostream_from_buffer(q->Frame + CONTROL_SIGNAL_HEADER, CONTROL_SIGNAL_FRAME - CONTROL_SIGNAL_HEADER);

	if (pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_signal_tag) == false || pb_encode_submessage(&os, ranz_control_v1_Signal_fields, q->Message) == false)
		return false;

	UINT size = (UINT)os.bytes_written;
	q->Frame[0] = (UCHAR)(size >> 24);
	q->Frame[1] = (UCHAR)(size >> 16);
	q->Frame[2] = (UCHAR)(size >> 8);
	q->Frame[3] = (UCHAR)size;

	return TransportWrite(s, q->Frame, CONTROL_SIGNAL_HEADER + size);
}

// Write each Signal that waits, one frame each, on the thread of the client: false when a write failed, which ends the
// stream. The Signal of that write is lost, as one that a stream carries when it ends.
bool ControlWriteSignals(CONTROL_SIGNALS *q, TRANSPORT_STREAM *s) {
	if (q == NULL)
		return true;

	while (true) {
		bool found = false;

		AcquireSRWLockExclusive(&q->Lock);
		if (q->Num != 0) {
			const CONTROL_SIGNAL_ITEM *it = &q->Items[q->First];

			ZeroMemory(q->Message, sizeof(ranz_control_v1_Signal));
			strcpy_s(q->Message->peer, sizeof(q->Message->peer), it->Peer);
			q->Message->envelope.size = (pb_size_t)it->Size;
			CopyMemory(q->Message->envelope.bytes, it->Envelope, it->Size);
			q->First = (q->First + 1) % CONTROL_MAX_SIGNALS;
			q->Num--;
			found = true;
		}
		ReleaseSRWLockExclusive(&q->Lock);

		if (found == false)
			return true;
		if (ControlSignalWrite(q, s) == false)
			return false;
	}
}
