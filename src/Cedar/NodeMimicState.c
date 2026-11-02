// NodeMimicState.c
// The mimic part of the desired state of a node (CORE-P2-7, #424; SDN-94, #423; ADR-0023): the half of the mimic servers and
// their clients that runs on the node. An operator declares a mimic server in the mimic section of the Listener of its Node,
// and the Controller gives that node the settings of the server with a short id, and each node that has the server as a peer
// with a mimic endpoint a link to it (CONTROL_STATE.Mimic, Core/ControlMimic.c). Each state that the overlay applies
// (NodeMimicApplied):
// - writes the settings of the server role and the links into the Configuration store as the texts that the mimic transport
//   reads (the MimicServer and MimicClient settings, NodeMimic.c; CORE-P2-6, #406): JSON objects of the fields of the sidecar,
//   which the core does not parse beyond its own private key. The sidecar checks them, and refuses a field that it does not
//   know;
// - makes the X25519 key of the mimic server the first time that a state asks the node for one (CryptoX25519GenerateKey, on
//   CNG). The private key is part of the text of the server role and nowhere else: in the Configuration store, which only
//   SYSTEM, the Administrators and the account of the node open, and on the control pipe of the sidecar, never on a command
//   line. The node writes no text of the settings into its log, and the diagnostics bundle blanks the key by its name,
//   private_key. The node keeps the key while its states have a server role: a state without one removes the text and the key
//   with it, and the next state that asks for a server gets a new key. A key is never replaced by itself;
// - reports the public key on its control stream (Pins; CONTROL_KEYS of Core/Control.h) once the store holds the text, after
//   each Hello and whenever it changed, and an empty report once the key went. After a restart the node reports the key that
//   its store holds (NodeMimicStart);
// - listens on its mimic transport with the server role, which starts the sidecar as a server, and gives the overlay the
//   streams of the clients that proved the key (NodeMimicAcceptServed); and starts the sidecar of the client role for the links, so
//   that the data transport dials a link by its address;
// - starts, restarts or stops the sidecar of a role when its text changes: a change of the server settings or of the links
//   restarts the sidecar of that role, the streams over it end and the clients dial again through their fallback list, and the
//   other role and the other transports of the node are not touched. A state without the mimic part stops both sidecars and
//   takes the texts out.
// A node without ranz.exe beside it applies the state all the same, writes the texts and keeps its key, and says why the mimic
// transport is unavailable, as NodeMimicStart does at its start; nothing else of the node is affected.

#include "Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Crypto.h"

#include "ConfigStore.h"
#include "NodeInternal.h"
#include "NodeMimicInternal.h"

#include <string.h>

#include <cjson/cJSON.h>

// Write size bytes as lower-case hexadecimal digits into str, which holds size * 2 + 1 bytes
static void NodeMimicHex(char *str, const UCHAR *data, UINT size) {
	static const char digits[] = "0123456789abcdef";

	for (UINT i = 0; i < size; i++) {
		str[i * 2] = digits[data[i] >> 4];
		str[i * 2 + 1] = digits[data[i] & 0x0F];
	}

	str[size * 2] = 0;
}

// The value of the hexadecimal digit c, or -1
static int NodeMimicDigit(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

// The private key of the mimic server that a text of the server role holds, its private_key of 64 hexadecimal digits, into
// priv. False, with priv zero, for a text without one. The copy of the key that the parse made is wiped with it.
static bool NodeMimicKeyOf(const char *text, UCHAR *priv) {
	cJSON *o = (text != NULL && text[0] != 0 ? cJSON_Parse(text) : NULL);
	char *hex = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, "private_key"));
	bool ok = (hex != NULL && StrLen(hex) == CRYPTO_X25519_SIZE * 2);

	for (UINT i = 0; i < CRYPTO_X25519_SIZE; i++) {
		int hi = (ok ? NodeMimicDigit(hex[i * 2]) : -1);
		int lo = (ok ? NodeMimicDigit(hex[i * 2 + 1]) : -1);

		ok = (hi >= 0 && lo >= 0);
		priv[i] = (UCHAR)(ok ? hi * 16 + lo : 0);
	}

	if (hex != NULL)
		SecureZeroMemory(hex, StrLen(hex));
	cJSON_Delete(o);

	if (ok == false)
		SecureZeroMemory(priv, CRYPTO_X25519_SIZE);

	return ok;
}

// The text of a JSON object on one line, in memory of the node, with the object freed: secret, an item of it, is wiped first.
// NULL when it cannot be printed. The caller wipes and frees the text (NodeMimicDropText).
static char *NodeMimicPrint(cJSON *o, cJSON *secret) {
	char *s = cJSON_PrintUnformatted(o);
	char *ret = (s != NULL ? CopyStr(s) : NULL);

	if (s != NULL) {
		SecureZeroMemory(s, StrLen(s));
		cJSON_free(s);
	}
	if (secret != NULL && secret->valuestring != NULL)
		SecureZeroMemory(secret->valuestring, StrLen(secret->valuestring));
	cJSON_Delete(o);

	return ret;
}

// Wipe and free a text of a role, NULL for none
static void NodeMimicDropText(char *text) {
	if (text == NULL)
		return;

	SecureZeroMemory(text, StrLen(text));
	Free(text);
}

// The text of the server role that the settings s of a state give, with the private key priv: the JSON object of the
// MimicServer setting (ServerSettings of controller/internal/mimic), its fields in a fixed order, so that the same state and
// key give the same text. The caller wipes and frees it.
static char *NodeMimicServerText(const CONTROL_MIMIC_SERVER *s, const UCHAR *priv) {
	char hex[CRYPTO_X25519_SIZE * 2 + 1];
	char id[CONTROL_MIMIC_SHORT_ID * 2 + 1];
	cJSON *o = cJSON_CreateObject();

	if (s->Listen[0] != 0)
		cJSON_AddStringToObject(o, "listen", s->Listen);

	NodeMimicHex(hex, priv, CRYPTO_X25519_SIZE);
	cJSON *key = cJSON_AddStringToObject(o, "private_key", hex);
	SecureZeroMemory(hex, sizeof(hex));

	NodeMimicHex(id, s->ShortId, s->ShortIdSize);
	cJSON_AddItemToArray(cJSON_AddArrayToObject(o, "short_ids"), cJSON_CreateString(id));

	cJSON *names = cJSON_AddArrayToObject(o, "server_names");
	for (UINT i = 0; i < s->NumServerNames && i < CONTROL_MIMIC_NAMES; i++)
		cJSON_AddItemToArray(names, cJSON_CreateString(s->ServerNames[i]));

	if (s->MaxTimeDiffMs != 0)
		cJSON_AddNumberToObject(o, "max_time_diff_ms", (double)s->MaxTimeDiffMs);

	// The decoy: the site that a borrow decoy names, or the source of the certificate of an own decoy
	cJSON *d = cJSON_AddObjectToObject(o, "decoy");
	if (s->DecoyMode == CONTROL_MIMIC_DECOY_BORROW) {
		cJSON_AddStringToObject(d, "mode", "borrow");
		cJSON_AddStringToObject(d, "dest", s->Dest);
	} else {
		cJSON_AddStringToObject(d, "mode", "own");
		if (s->Acme) {
			cJSON *a = cJSON_AddObjectToObject(d, "acme");

			if (s->AcmeDirectory[0] != 0)
				cJSON_AddStringToObject(a, "directory", s->AcmeDirectory);
			if (s->AcmeEmail[0] != 0)
				cJSON_AddStringToObject(a, "email", s->AcmeEmail);
			cJSON_AddStringToObject(a, "cache_dir", s->AcmeCacheDir);
			if (s->AcmeCaFile[0] != 0)
				cJSON_AddStringToObject(a, "ca_file", s->AcmeCaFile);
		}
		if (s->CertFile[0] != 0)
			cJSON_AddStringToObject(d, "cert_file", s->CertFile);
		if (s->KeyFile[0] != 0)
			cJSON_AddStringToObject(d, "key_file", s->KeyFile);
		if (s->SelfSigned)
			cJSON_AddTrueToObject(d, "self_signed");
	}

	return NodeMimicPrint(o, key);
}

// The text of the client role that the links of a state give: the JSON object of the MimicClient setting (ClientSettings of
// controller/internal/mimic), in the order of the state. The sidecar names a link by its address, so an address that a link
// before has is left out. The caller frees it.
static char *NodeMimicClientText(const CONTROL_MIMIC *m) {
	char key[CONTROL_MIMIC_KEY_SIZE * 2 + 1];
	char id[CONTROL_MIMIC_SHORT_ID * 2 + 1];
	cJSON *o = cJSON_CreateObject();
	cJSON *links = cJSON_AddArrayToObject(o, "links");

	for (UINT i = 0; i < m->NumLinks && i < CONTROL_MIMIC_LINKS; i++) {
		const CONTROL_MIMIC_LINK *l = &m->Links[i];
		bool again = false;

		for (UINT j = 0; j < i && again == false; j++)
			again = (strcmp(m->Links[j].Address, l->Address) == 0);
		if (again)
			continue;

		cJSON *item = cJSON_CreateObject();
		cJSON_AddStringToObject(item, "address", l->Address);
		if (l->ServerName[0] != 0)
			cJSON_AddStringToObject(item, "server_name", l->ServerName);
		NodeMimicHex(key, l->PublicKey, CONTROL_MIMIC_KEY_SIZE);
		cJSON_AddStringToObject(item, "public_key", key);
		NodeMimicHex(id, l->ShortId, l->ShortIdSize);
		cJSON_AddStringToObject(item, "short_id", id);
		cJSON_AddItemToArray(links, item);
	}

	return NodeMimicPrint(o, NULL);
}

// The text of the setting name that the Configuration store holds, "" for none; the caller wipes and frees it
// (NodeMimicDropText)
static char *NodeMimicStored(NODE *n, char *name) {
	char *value = ZeroMalloc(NODE_MIMIC_MAX_SETTING + 2);

	CsGetSetting(n->Store, name, value, NODE_MIMIC_MAX_SETTING + 2);

	return value;
}

// Put text in place of the settings that the sidecar of a role runs with, NULL for none, under the node lock, under which
// NodeMimicTransport reads them; the sidecar of the role does not run. The status of the role takes whether it is configured,
// and why it is unavailable, "" for nothing.
static void NodeMimicSettings(NODE *n, NODE_MIMIC_SIDECAR *sc, const char *text, bool configured, const char *error) {
	char *old;

	Lock(n->Lock);
	{
		old = sc->Settings;
		sc->Settings = (text != NULL ? CopyStr(text) : NULL);
	}
	Unlock(n->Lock);

	Lock(sc->Lock);
	{
		sc->St.Configured = configured;
		StrCpy(sc->St.Error, sizeof(sc->St.Error), error);
	}
	Unlock(sc->Lock);

	NodeMimicDropText(old);
}

// Whether ranz.exe, which holds the sidecar, is missing beside the node: the role then says why it is unavailable, and so does
// the node log, as at the start of the node (NodeMimicStart)
static bool NodeMimicMissing(NODE *n, NODE_MIMIC_SIDECAR *sc, UINT64 gen) {
	char error[MAX_SIZE];

	if (IsFileExistsW(n->MimicSidecar))
		return false;

	Format(error, sizeof(error), "ranz.exe, which holds the sidecar, is not installed at %S", n->MimicSidecar);
	NodeMimicSettings(n, sc, NULL, true, error);
	NodeLog(n, "Mimic transport unavailable: %s (generation %I64u)", error, gen);

	return true;
}

// Write the text of a role to the Configuration store; false, with the role unavailable and the node log saying why, when the
// store does not take it
static bool NodeMimicStore(NODE *n, NODE_MIMIC *m, NODE_MIMIC_SIDECAR *sc, char *name, const char *text, UINT64 gen) {
	if (CsSetSetting(n->Store, name, (char *)text) == ERR_NO_ERROR)
		return true;

	NodeMimicSettings(n, sc, NULL, true, "the setting could not be written to the Configuration store");
	m->Unavailable[sc->Role] = true;
	NodeLog(n, "Mimic transport: the %s setting of generation %I64u could not be written to the Configuration store", name, gen);

	return false;
}

// The sidecars of the node: made for a state that has a mimic part (create), when the node has none yet; NULL when it has
// none, and when it does not run
static NODE_MIMIC *NodeMimicOf(NODE *n, bool create) {
	NODE_MIMIC *m;

	Lock(n->Lock);
	{
		m = n->Mimic;
		if (m == NULL && create && n->Running && n->Store != NULL) {
			m = NodeMimicNew(n);
			// The overlay takes the streams of the mimic server without the node lock (NodeMimicAcceptServed)
			InterlockedExchangePointer((PVOID volatile *)&n->Mimic, m);
		}
	}
	Unlock(n->Lock);

	return m;
}

// The text of the server role of the settings s of a state of Generation gen, with the key of the text in the store, or with
// a new one the first time that a state asks the node for a mimic server, and its public key into pub; NULL when no key can be
// made
static char *NodeMimicServer(NODE *n, const CONTROL_MIMIC_SERVER *s, UINT64 gen, UCHAR *pub) {
	UCHAR priv[CRYPTO_X25519_SIZE];
	char hex[CRYPTO_X25519_SIZE * 2 + 1];
	char *ret = NULL;

	char *stored = NodeMimicStored(n, NODE_SETTING_MIMIC_SERVER);
	bool kept = NodeMimicKeyOf(stored, priv);
	NodeMimicDropText(stored);

	if (kept ? CryptoX25519PublicKey(pub, priv) : CryptoX25519GenerateKey(priv, pub)) {
		ret = NodeMimicServerText(s, priv);
		if (kept == false) {
			NodeMimicHex(hex, pub, CRYPTO_X25519_SIZE);
			NodeLog(n, "Mimic server role: generation %I64u asks the node for a mimic server, so the node made the key of the server: it reports its public key %s", gen, hex);
		}
	} else {
		NodeLog(n, "Mimic server role: generation %I64u asks the node for a mimic server, and the node cannot make its key", gen);
	}

	SecureZeroMemory(priv, sizeof(priv));

	return ret;
}

void NodeMimicReportKey(NODE *n, const char *text) {
	UCHAR priv[CRYPTO_X25519_SIZE];
	UCHAR pub[CRYPTO_X25519_SIZE];

	if (n != NULL && NodeMimicKeyOf(text, priv) && CryptoX25519PublicKey(pub, priv))
		ControlSetMimicKey(n->MimicKeys, pub);

	SecureZeroMemory(priv, sizeof(priv));
}

void NodeMimicUnserve(NODE_MIMIC *m) {
	TRANSPORT_LISTENER *l;

	if (m == NULL)
		return;

	AcquireSRWLockExclusive(&m->ServeLock);
	l = m->Served;
	m->Served = NULL;
	ReleaseSRWLockExclusive(&m->ServeLock);

	// Closing the listener stops the sidecar of the server role: the streams over it end
	if (l != NULL)
		TransportCloseListener(l);
}

// The text of the server role of a state of Generation gen, NULL for none, whose server has the public key pub: the store holds
// it, the node reports the key, and the node listens on its mimic transport with it, which starts the sidecar as a server. A
// change of the text restarts the sidecar, and a state without the role stops it and takes the text, and the key with it, out.
static void NodeMimicServe(NODE *n, NODE_MIMIC *m, const char *text, const UCHAR *pub, UINT64 gen) {
	NODE_MIMIC_SIDECAR *sc = &m->Sidecars[NODE_MIMIC_ROLE_SERVER];
	char *stored = NodeMimicStored(n, NODE_SETTING_MIMIC_SERVER);
	bool had = (stored[0] != 0);
	bool changed = (strcmp(stored, (text != NULL ? text : "")) != 0);

	NodeMimicDropText(stored);

	if (text == NULL) {
		if (had == false && m->Served == NULL && sc->Settings == NULL)
			return;

		NodeMimicUnserve(m);
		NodeMimicSettings(n, sc, NULL, false, "");
		m->Unavailable[NODE_MIMIC_ROLE_SERVER] = false;
		CsSetSetting(n->Store, NODE_SETTING_MIMIC_SERVER, NULL);
		ControlSetMimicKey(n->MimicKeys, NULL);
		NodeLog(n, "Mimic server role: generation %I64u has none, so its sidecar stopped, and the %s setting and the key of the server are gone", gen, NODE_SETTING_MIMIC_SERVER);
		return;
	}

	if (changed) {
		NodeMimicUnserve(m);
		m->Unavailable[NODE_MIMIC_ROLE_SERVER] = false;
		if (NodeMimicStore(n, m, sc, NODE_SETTING_MIMIC_SERVER, text, gen) == false)
			return;
	}

	// The key in force goes to the Controller once the store holds it
	ControlSetMimicKey(n->MimicKeys, pub);

	// The server listens once for each text: a text that could not run waits for another
	if (m->Served != NULL || m->Unavailable[NODE_MIMIC_ROLE_SERVER])
		return;

	m->Unavailable[NODE_MIMIC_ROLE_SERVER] = true;
	if (NodeMimicMissing(n, sc, gen))
		return;

	NodeMimicSettings(n, sc, text, true, "");
	TRANSPORT_LISTENER *l = TransportListen(&m->Transport, "");
	if (l == NULL) {
		NodeLog(n, "Mimic server role: generation %I64u: the sidecar of the server is not ready, so the role stays unavailable until its setting changes", gen);
		return;
	}

	AcquireSRWLockExclusive(&m->ServeLock);
	m->Served = l;
	ReleaseSRWLockExclusive(&m->ServeLock);
	m->Unavailable[NODE_MIMIC_ROLE_SERVER] = false;

	NodeLog(n, "Mimic server role: generation %I64u: the sidecar of the server listens%s, and the node takes the streams of the clients that prove its key", gen,
	        changed ? " with the new setting" : "");
}

// The text of the client role of a state of Generation gen, NULL for none, from its num links: the store holds it, and the
// sidecar of the client role runs with it, which the data transport dials a link through by its address. A change of the text
// restarts the sidecar, and a state without links stops it and takes the text out.
static void NodeMimicLink(NODE *n, NODE_MIMIC *m, const char *text, UINT num, UINT64 gen) {
	NODE_MIMIC_SIDECAR *sc = &m->Sidecars[NODE_MIMIC_ROLE_CLIENT];
	char *stored = NodeMimicStored(n, NODE_SETTING_MIMIC_CLIENT);
	bool had = (stored[0] != 0);
	bool changed = (strcmp(stored, (text != NULL ? text : "")) != 0);

	NodeMimicDropText(stored);

	if (text == NULL) {
		if (had == false && sc->Supervisor == NULL && sc->Settings == NULL)
			return;

		NodeMimicStopSidecar(sc);
		NodeMimicSettings(n, sc, NULL, false, "");
		m->Unavailable[NODE_MIMIC_ROLE_CLIENT] = false;
		CsSetSetting(n->Store, NODE_SETTING_MIMIC_CLIENT, NULL);
		NodeLog(n, "Mimic client role: generation %I64u has no link, so its sidecar stopped and the %s setting is gone", gen, NODE_SETTING_MIMIC_CLIENT);
		return;
	}

	if (changed) {
		NodeMimicStopSidecar(sc);
		m->Unavailable[NODE_MIMIC_ROLE_CLIENT] = false;
		if (NodeMimicStore(n, m, sc, NODE_SETTING_MIMIC_CLIENT, text, gen) == false)
			return;
	}

	// The sidecar starts once for each text: a text that could not run waits for another
	if (sc->Supervisor != NULL || m->Unavailable[NODE_MIMIC_ROLE_CLIENT])
		return;

	m->Unavailable[NODE_MIMIC_ROLE_CLIENT] = true;
	if (NodeMimicMissing(n, sc, gen))
		return;

	NodeMimicSettings(n, sc, text, true, "");
	// The client role listens on a data pipe of its own, which the node names
	if (sc->DataPipe[0] == 0)
		NodeMimicPipeName(sc->DataPipe, sizeof(sc->DataPipe), L"client");

	bool ready = NodeMimicStartSidecar(sc);
	m->Unavailable[NODE_MIMIC_ROLE_CLIENT] = false;

	NodeLog(n, "Mimic client role: generation %I64u gives the node %u links: %s", gen, num,
	        ready ? "its sidecar runs, and the node dials a link by its address" : "its sidecar is not ready, so the role is unavailable until it is");
}

void NodeMimicApplied(NODE *n, const CONTROL_STATE *st) {
	UCHAR pub[CRYPTO_X25519_SIZE];
	char *server = NULL;
	char *client = NULL;

	if (n == NULL || st == NULL)
		return;

	const CONTROL_MIMIC *want = st->Mimic;
	NODE_MIMIC *m = NodeMimicOf(n, want != NULL);
	if (m == NULL)
		return;

	Zero(pub, sizeof(pub));
	if (want != NULL && want->HasServer)
		server = NodeMimicServer(n, &want->Server, st->Generation, pub);
	if (want != NULL && want->NumLinks != 0)
		client = NodeMimicClientText(want);

	// A server whose key could not be made stays as it was
	if (want == NULL || want->HasServer == false || server != NULL)
		NodeMimicServe(n, m, server, pub, st->Generation);
	NodeMimicLink(n, m, client, (want != NULL ? want->NumLinks : 0), st->Generation);

	NodeMimicDropText(server);
	NodeMimicDropText(client);
}

TRANSPORT_STREAM *NodeMimicAcceptServed(NODE *n) {
	TRANSPORT_STREAM *s = NULL;
	NODE_MIMIC *m = (n != NULL ? ReadPointerAcquire((PVOID const volatile *)&n->Mimic) : NULL);

	// It never waits: while the mimic part of a state changes the server, the overlay takes no stream of it
	if (m == NULL || TryAcquireSRWLockShared(&m->ServeLock) == FALSE)
		return NULL;

	if (m->Served != NULL)
		s = TransportAccept(m->Served, 0);
	ReleaseSRWLockShared(&m->ServeLock);

	return s;
}
