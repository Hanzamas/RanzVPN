// ControlMimic.c
// The mimic part of a node on the control stream (SDN-94, #423; CORE-P2-7, #424; ADR-0023; Core/Control.h). The NodeConfig of a
// state that carries a mimic part gives the state its mimic part (CONTROL_STATE.Mimic) while the owner takes the state
// (ControlCopyMimic): the settings of the mimic server of the node, which the node turns into the text that its sidecar reads,
// with a key of its own, and its links to the mimic servers among its peers. A string that does not fit its field is cut, a
// server that names no server name is none, and a link without an address or with a public key of another size than
// CONTROL_MIMIC_KEY_SIZE is left out: the sidecar checks the rest. The part goes with the state (ControlFreeMimic).
//
// The node reports the public key of its mimic server in a Pins message (CONTROL_KEYS): after each Hello while it has a key,
// so that a controller that the node reaches anew has it, and whenever the key changed, an empty Pins once the key went. A node
// that never had a key sends no Pins, so a controller of an older release, which answers the first one with
// REFUSE_REASON_PROTOCOL, sees none from it.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_KEYS_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The keys that a client reports
struct CONTROL_KEYS {
	SRWLOCK Lock;                           // Everything below
	bool HasKey;                            // The node has a mimic server, whose public key is ...
	UCHAR MimicKey[CONTROL_MIMIC_KEY_SIZE]; // ... this
	bool Changed;                           // The report changed since the client sent it last
};

static void *ControlMimicAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlMimicRelease(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The mimic part of a state
//

// The bytes of a field of the protocol, at most max of them, into dst, and their number into num: a field that is longer than
// its buffer is cut
static void ControlMimicBytes(UCHAR *dst, UINT *num, UINT max, const UCHAR *src, pb_size_t size) {
	*num = (size < max ? (UINT)size : max);
	CopyMemory(dst, src, *num);
}

// The settings of the mimic server of src into m: none for a server that names no server name, which no sidecar could run
static void ControlMimicServer(CONTROL_MIMIC *m, const ranz_control_v1_MimicServer *src) {
	CONTROL_MIMIC_SERVER *s = &m->Server;

	for (pb_size_t i = 0; i < src->server_names_count && s->NumServerNames < CONTROL_MIMIC_NAMES; i++) {
		if (src->server_names[i][0] == 0)
			continue;

		strncpy_s(s->ServerNames[s->NumServerNames], sizeof(s->ServerNames[s->NumServerNames]), src->server_names[i], _TRUNCATE);
		s->NumServerNames++;
	}

	if (s->NumServerNames == 0) {
		ZeroMemory(s, sizeof(CONTROL_MIMIC_SERVER));
		return;
	}

	strncpy_s(s->Listen, sizeof(s->Listen), src->listen, _TRUNCATE);
	s->MaxTimeDiffMs = src->max_time_diff_ms;
	ControlMimicBytes(s->ShortId, &s->ShortIdSize, CONTROL_MIMIC_SHORT_ID, src->short_id.bytes, src->short_id.size);

	// The decoy: the mode borrow takes its site, the mode own, the default, the source of its certificate
	const ranz_control_v1_MimicDecoy *d = &src->decoy;
	s->DecoyMode = (src->has_decoy && d->mode == ranz_control_v1_MimicDecoyMode_MIMIC_DECOY_MODE_BORROW ? CONTROL_MIMIC_DECOY_BORROW : CONTROL_MIMIC_DECOY_OWN);
	if (src->has_decoy) {
		strncpy_s(s->Dest, sizeof(s->Dest), d->dest, _TRUNCATE);
		strncpy_s(s->CertFile, sizeof(s->CertFile), d->cert_file, _TRUNCATE);
		strncpy_s(s->KeyFile, sizeof(s->KeyFile), d->key_file, _TRUNCATE);
		s->SelfSigned = d->self_signed;
		s->Acme = d->has_acme;
		if (s->Acme) {
			strncpy_s(s->AcmeDirectory, sizeof(s->AcmeDirectory), d->acme.directory, _TRUNCATE);
			strncpy_s(s->AcmeEmail, sizeof(s->AcmeEmail), d->acme.email, _TRUNCATE);
			strncpy_s(s->AcmeCacheDir, sizeof(s->AcmeCacheDir), d->acme.cache_dir, _TRUNCATE);
			strncpy_s(s->AcmeCaFile, sizeof(s->AcmeCaFile), d->acme.ca_file, _TRUNCATE);
		}
	}

	m->HasServer = true;
}

// A link of src into m, unless it has no address or no public key of CONTROL_MIMIC_KEY_SIZE bytes, which the sidecar could not
// dial or pin
static void ControlMimicLink(CONTROL_MIMIC *m, const ranz_control_v1_MimicLink *src) {
	if (src->address[0] == 0 || src->public_key.size != CONTROL_MIMIC_KEY_SIZE)
		return;

	CONTROL_MIMIC_LINK *l = &m->Links[m->NumLinks++];

	strncpy_s(l->Peer, sizeof(l->Peer), src->peer, _TRUNCATE);
	strncpy_s(l->Address, sizeof(l->Address), src->address, _TRUNCATE);
	strncpy_s(l->ServerName, sizeof(l->ServerName), src->server_name, _TRUNCATE);
	CopyMemory(l->PublicKey, src->public_key.bytes, CONTROL_MIMIC_KEY_SIZE);
	ControlMimicBytes(l->ShortId, &l->ShortIdSize, CONTROL_MIMIC_SHORT_ID, src->short_id.bytes, src->short_id.size);
}

// The mimic part of the NodeConfig among num objects into the state. A state whose NodeConfig has none has none, and so has
// one whose part holds neither a server nor a link; a part that cannot be allocated is left out.
void ControlCopyMimic(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->Mimic = NULL;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_node_tag || o->kind.node.has_mimic == false)
			continue;

		const ranz_control_v1_Mimic *src = &o->kind.node.mimic;
		CONTROL_MIMIC *m = ControlMimicAlloc(sizeof(CONTROL_MIMIC));
		if (m == NULL)
			return;

		if (src->has_server)
			ControlMimicServer(m, &src->server);
		for (pb_size_t j = 0; j < src->links_count && m->NumLinks < CONTROL_MIMIC_LINKS; j++)
			ControlMimicLink(m, &src->links[j]);

		if (m->HasServer == false && m->NumLinks == 0) {
			ControlMimicRelease(m);
			return;
		}

		st->Mimic = m;
		return;
	}
}

// Free the mimic part of a state, once its owner took it
void ControlFreeMimic(CONTROL_STATE *st) {
	ControlMimicRelease(st->Mimic);
	st->Mimic = NULL;
}

//
// The keys that the node reports
//

CONTROL_KEYS *ControlNewKeys() {
	CONTROL_KEYS *k = ControlMimicAlloc(sizeof(CONTROL_KEYS));

	if (k != NULL)
		InitializeSRWLock(&k->Lock);

	return k;
}

void ControlFreeKeys(CONTROL_KEYS *k) {
	ControlMimicRelease(k);
}

// Put the public key key in place of the one before, or none for NULL: the client sends the report when it changed
void ControlSetMimicKey(CONTROL_KEYS *k, const UCHAR *key) {
	if (k == NULL)
		return;

	AcquireSRWLockExclusive(&k->Lock);
	if (key == NULL) {
		if (k->HasKey) {
			k->HasKey = false;
			ZeroMemory(k->MimicKey, sizeof(k->MimicKey));
			k->Changed = true;
		}
	} else if (k->HasKey == false || memcmp(k->MimicKey, key, sizeof(k->MimicKey)) != 0) {
		k->HasKey = true;
		CopyMemory(k->MimicKey, key, sizeof(k->MimicKey));
		k->Changed = true;
	}
	ReleaseSRWLockExclusive(&k->Lock);
}

// The public key that the owner set last into key: false, with key zero, while there is none
bool ControlGetMimicKey(CONTROL_KEYS *k, UCHAR *key) {
	bool has = false;

	if (key == NULL)
		return false;

	ZeroMemory(key, CONTROL_MIMIC_KEY_SIZE);
	if (k == NULL)
		return false;

	AcquireSRWLockShared(&k->Lock);
	has = k->HasKey;
	if (has)
		CopyMemory(key, k->MimicKey, CONTROL_MIMIC_KEY_SIZE);
	ReleaseSRWLockShared(&k->Lock);

	return has;
}

// A new stream has none of the keys: the client sends the key after the Hello while the node has one, and a report that changed
// while no stream ran
void ControlKeysResend(CONTROL_KEYS *k) {
	if (k == NULL)
		return;

	AcquireSRWLockExclusive(&k->Lock);
	k->Changed = (k->Changed || k->HasKey);
	ReleaseSRWLockExclusive(&k->Lock);
}

// Write m as the body Pins of a ControlMessage, in one frame
static bool ControlKeysSend(const ranz_control_v1_Pins *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_pins_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Pins_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlMimicAlloc(CONTROL_KEYS_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_KEYS_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_pins_tag) && pb_encode_submessage(&os, ranz_control_v1_Pins_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_KEYS_HEADER + size);
	}

	ControlMimicRelease(frame);
	return ok;
}

// Write the keys as one Pins message, on the thread of the client, when the report changed since the client sent it: the key,
// or an empty Pins once it went. False when the write failed, which ends the stream; the report then goes on the next stream.
bool ControlWriteKeys(CONTROL_KEYS *k, TRANSPORT_STREAM *s) {
	ranz_control_v1_Pins m;
	bool due = false;

	if (k == NULL)
		return true;

	ZeroMemory(&m, sizeof(m));

	AcquireSRWLockExclusive(&k->Lock);
	due = k->Changed;
	if (due) {
		if (k->HasKey) {
			m.mimic_key.size = CONTROL_MIMIC_KEY_SIZE;
			CopyMemory(m.mimic_key.bytes, k->MimicKey, CONTROL_MIMIC_KEY_SIZE);
		}
		k->Changed = false;
	}
	ReleaseSRWLockExclusive(&k->Lock);

	if (due == false || ControlKeysSend(&m, s))
		return true;

	AcquireSRWLockExclusive(&k->Lock);
	k->Changed = true;
	ReleaseSRWLockExclusive(&k->Lock);

	return false;
}
