// NodeController.c
// The Controller of a Node (SDN-90, #395): the Node service joins the Controller of its Controller settings by itself.
// - The Controller settings are one JSON object in the Configuration store (NODE_SETTING_CONTROLLER): the address of the
//   Controller's TLS port, its static key and the TLS fingerprint of its certificate, the three values that ranz status
//   prints on the Controller. With them the overlay of the node has its control stream (Core/Control.h): TLS 1.3 on
//   Schannel (TransportTls.c) that offers the ALPN protocol of the control stream and gives its TLS exporter as the Channel
//   binding, the certificate of the Controller checked against the fingerprint in place of a thumbprint pin, and the
//   Noise_IK handshake with the static key. The overlay starts in the service for every set of Roles: the client role
//   starts it with its adapters and its dialler and takes the control stream from here (NodeControllerOverlay); without
//   the client role the node starts it here, with no adapter and a data transport that dials and listens nowhere, and the
//   Roles decide what else runs. A node without the settings runs as before, says once in its log that it has no
//   Controller and opens no stream.
// - A stream that ends, or does not open, opens again after a delay that grows while the attempts fail (ControlRetry.c),
//   whatever failed. A stream on a path that went dead without a reset ends by TCP keepalive, NODE_CONTROLLER_KEEPALIVE
//   seconds after its last segment and a few probes (TransportTlsKeepAlive.c). The log says what: no Controller answered, the TLS fingerprint check or the Noise handshake with the
//   static key of the Controller failed, both of which fail closed before any state comes, or the Controller refused the
//   node, as one whose static key no Node resource names yet. The node keeps dialling, so it joins without a restart once
//   an operator has written its Node resource.
// - The Controller can change the certificate that it serves (SDN-92, #397). A certificate with another key has another TLS
//   fingerprint, so the Controller sends the fingerprint of the next certificate with the one in use in the state of the node
//   (NodeConfig.controller_tls), waits until the node acknowledged the state, and only then serves the next certificate. The
//   node accepts every fingerprint that the Controller sent in place of the one of its settings, and writes them into the
//   setting (tlsFingerprints) before it acknowledges, so that it still reaches the Controller after the change and after a
//   restart of the service (NodeControllerPins). A node that was not connected when the certificate changed has the old
//   fingerprint only, and ranz node controller set gives it the new one.
// - The logged-in user enrols the node through the tray (ranz tray; SDN-55, #248): the sign-in of the user at a Controller
//   brings its keys, and the tray gives them to the client role on the pipe of the user (enrol), which a user without
//   administrator rights may open. So the node takes them only while it has no Controller settings, in its store or in
//   use: a user cannot move a node that an Administrator joined, and the same settings again change nothing. The node
//   writes them into the store and takes them at once: a thread of its own starts the client role again, whose overlay
//   then opens the control stream (NodeControllerEnrol).
// - The admin pipe (NODE_ADMIN_PIPE), which only SYSTEM, the Administrators and the service account may open, takes one
//   command line of an Administrator, as ranz node sends them, and answers it with one JSON object: key gives the public
//   half of the static key of the node, which it makes first when no role needed it yet; controller gives the settings
//   and the state of the control stream; controller set <address> <key> <fingerprint> and controller clear write and
//   remove the settings; state gives what the node does now, which NodeState.c answers (SDN-91, #396). The service is
//   the one writer of its Configuration store, and it takes the settings at its next start, which ranz node makes at
//   once. The private half of the key stays in the key storage provider: it is in no answer and no line of the log.
//   Only the node of the service, on the default data directory, has the pipe, unless a test names one in
//   NODE.AdminPipe before NodeStart.

#include "Node.h"

#include "ConfigStore.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Crypto.h"

#include "NodeInternal.h"

#include <aclapi.h>
#include <sddl.h>

#include <cjson/cJSON.h>

// The DACL of the admin pipe: full control for SYSTEM, the Administrators and the virtual account of the ranzvpnserver
// service (ADR-0039 decision 3), nothing for anyone else. The pipe has one instance, the first, so no one can serve under
// its name.
#define NODE_ADMIN_PIPE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" NODE_SERVICE_SID L")"

// The Controller of a node
struct NODE_CONTROLLER {
	NODE *Node;                                    // The node
	bool Set;                                      // The Controller settings are there, and valid
	char Address[TRANSPORT_ADDRESS_SIZE];          // The address of the Controller's TLS port ...
	UCHAR Key[PEER_KEY_SIZE];                      // ... its static key ...
	char Fingerprint[NODE_CONTROLLER_FINGERPRINT]; // ... and the TLS fingerprint of its certificate, in lower case
	TRANSPORT *Tls;                                // The TLS transport of the control stream, NULL until an overlay needs it
	TRANSPORT None;                                // The data transport of an overlay without the client role: nowhere
	PEER_KEY NodeKey;                              // The node's static key, for that overlay
	bool Overlay;                                  // The node started that overlay
	LOCK *SettingLock;                             // One change of the stored setting at a time: an Administrator's and the Controller's own (SDN-92)
	LOCK *Lock;                                    // The fields below
	bool Checked;                                  // The certificate of the attempt that ends next reached the fingerprint check
	bool Mismatch;                                 // The certificate of the last dial that reached the check failed it ...
	char Seen[NODE_CONTROLLER_FINGERPRINT];        // ... and had this fingerprint
	UINT NumPins;                                  // The TLS fingerprints that the Controller sent (SDN-92, #397), 0 before it did: Fingerprint alone passes the check ...
	NODE_FINGERPRINT Pins[NODE_CONTROLLER_PINS];   // ... in lower case, the certificate in use first
	UINT64 NumEnds;                                // Streams that ended or did not open
	UINT LastEnd;                                  // How the last one ended (CONTROL_END_*)
	UINT NextRetry;                                // ms before the next attempt after it
	char Why[MAX_SIZE * 2];                        // Why the last one ended, as the log says it (SDN-91, #396)
	wchar_t Pipe[MAX_PATH];                        // The admin pipe, empty for none
	HANDLE PipeHandle;                             // Its server end, INVALID_HANDLE_VALUE without
	HANDLE PipeStop;                               // Ends the thread of the pipe
	HANDLE PipeThread;                             // The thread of the pipe
	HANDLE Rejoin;                                 // The thread that has the node take the settings of an enrolment (SDN-55, #248), NULL for none (under Lock)
};

//
// The Controller settings
//

// Whether a string is n hex digits and nothing else
static bool NodeControllerHex(const char *s, UINT n) {
	UINT i;

	for (i = 0; s[i] != 0; i++)
		if (i >= n || ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F')) == false)
			return false;

	return (i == n);
}

// The address of a Controller: a host and a port from 1 to 65535 after the last colon, an IPv6 host in brackets
static bool NodeControllerAddressOk(const char *address) {
	UINT len = StrLen(address);
	UINT colon = INFINITE;
	UINT port = 0;

	for (UINT i = 0; i < len; i++) {
		if (address[i] == ':')
			colon = i;
		else if (address[i] == ' ' || address[i] == '\t')
			return false;
	}

	if (colon == INFINITE || colon == 0 || colon + 1 >= len || len >= TRANSPORT_ADDRESS_SIZE)
		return false;

	for (UINT i = colon + 1; i < len; i++) {
		if (address[i] < '0' || address[i] > '9' || port > 65535)
			return false;
		port = port * 10 + (UINT)(address[i] - '0');
	}

	// An IPv6 address has colons of its own: it is in brackets, and the port follows the closing one
	if (address[0] == '[' && address[colon - 1] != ']')
		return false;
	for (UINT i = 0; address[0] != '[' && i < colon; i++)
		if (address[i] == ':' || address[i] == ']')
			return false;

	return (port >= 1 && port <= 65535);
}

// Check the three values of the Controller settings, as an Administrator gives them and as the store keeps them, into c:
// false with the reason in error, which says which value is wrong
static bool NodeControllerCheck(NODE_CONTROLLER *c, const char *address, const char *key, const char *fingerprint, char *error, UINT error_size) {
	UINT key_size = 0;

	if (IsEmptyStr((char *)address) || NodeControllerAddressOk(address) == false) {
		Format(error, error_size, "the address of the Controller has no port, or no host: give host:port, the TLS port of ranz status on the Controller");
		return false;
	}

	UCHAR *bin = (IsEmptyStr((char *)key) ? NULL : Base64ToBin(&key_size, key, StrLen((char *)key)));
	if (bin == NULL || key_size != PEER_KEY_SIZE) {
		Format(error, error_size, "the static key of the Controller is %u bytes long, not %u: give publicKey of ranz status on the Controller", (bin == NULL ? 0 : key_size), (UINT)PEER_KEY_SIZE);
		Free(bin);
		return false;
	}

	if (IsEmptyStr((char *)fingerprint) || NodeControllerHex(fingerprint, NODE_CONTROLLER_FINGERPRINT - 1) == false) {
		Format(error, error_size, "the TLS fingerprint of the Controller is not 64 hex digits: give tlsFingerprint of ranz status on the Controller");
		Free(bin);
		return false;
	}

	StrCpy(c->Address, sizeof(c->Address), (char *)address);
	Copy(c->Key, bin, PEER_KEY_SIZE);
	StrCpy(c->Fingerprint, sizeof(c->Fingerprint), (char *)fingerprint);
	StrLower(c->Fingerprint);
	Free(bin);

	return true;
}

// The string member name of a JSON object, "" when it has none
static const char *NodeControllerJsonStr(cJSON *o, const char *name) {
	const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));

	return (s != NULL ? s : "");
}

// The TLS fingerprints that the Controller sent (SDN-92, #397), as the setting keeps them in the array tlsFingerprints, into
// c: the strings of it that are 64 hex digits, in lower case, at most NODE_CONTROLLER_PINS. A setting without the array has
// none, and the fingerprint of the setting alone passes the check.
static void NodeControllerLoadPins(NODE_CONTROLLER *c, cJSON *o) {
	cJSON *list = cJSON_GetObjectItemCaseSensitive(o, "tlsFingerprints");
	cJSON *item;

	c->NumPins = 0;
	if (cJSON_IsArray(list) == false)
		return;

	cJSON_ArrayForEach(item, list) {
		const char *s = cJSON_GetStringValue(item);

		if (s == NULL || c->NumPins >= NODE_CONTROLLER_PINS || NodeControllerHex(s, NODE_CONTROLLER_FINGERPRINT - 1) == false)
			continue;

		StrCpy(c->Pins[c->NumPins], sizeof(c->Pins[c->NumPins]), (char *)s);
		StrLower(c->Pins[c->NumPins]);
		c->NumPins++;
	}
}

// Read the Controller settings of the store into c; a setting that is no JSON object of three valid values counts as none,
// with the node log saying why
static void NodeControllerLoad(NODE_CONTROLLER *c) {
	char error[MAX_SIZE];
	char *setting = ZeroMalloc(NODE_CONTROLLER_MAX_SETTING);

	c->Set = false;
	if (c->Node->Store != NULL && CsGetSetting(c->Node->Store, NODE_SETTING_CONTROLLER, setting, NODE_CONTROLLER_MAX_SETTING) && IsEmptyStr(setting) == false) {
		cJSON *o = cJSON_Parse(setting);

		c->Set = (cJSON_IsObject(o) && NodeControllerCheck(c, NodeControllerJsonStr(o, "address"), NodeControllerJsonStr(o, "publicKey"), NodeControllerJsonStr(o, "tlsFingerprint"), error, sizeof(error)));
		if (c->Set)
			NodeControllerLoadPins(c, o);
		else
			NodeLog(c->Node, "Controller: the %s setting is not used: %s", NODE_SETTING_CONTROLLER, (cJSON_IsObject(o) ? error : "it is not a JSON object"));
		cJSON_Delete(o);
	}

	Free(setting);
}

// The TLS fingerprints of the settings into the JSON object o: tlsFingerprint, the one of the certificate in use, which is
// the first that the Controller sent once it sent any (the one that the store holds, NodeControllerSavePins), and the array
// tlsFingerprints with all that the Controller sent, none without them. The settings of an Administrator, which have a Lock
// of no one, have none of the Controller's.
static void NodeControllerJsonFingerprints(NODE_CONTROLLER *c, cJSON *o) {
	Lock(c->Lock);
	{
		cJSON_AddStringToObject(o, "tlsFingerprint", (c->NumPins == 0 ? c->Fingerprint : c->Pins[0]));
		cJSON *list = (c->NumPins != 0 ? cJSON_AddArrayToObject(o, "tlsFingerprints") : NULL);

		for (UINT i = 0; list != NULL && i < c->NumPins; i++)
			cJSON_AddItemToArray(list, cJSON_CreateString(c->Pins[i]));
	}
	Unlock(c->Lock);
}

// The settings of c as one JSON object, or JSON null without them
static cJSON *NodeControllerJson(NODE_CONTROLLER *c) {
	char *key;
	UINT key_size = 0;

	if (c->Set == false)
		return cJSON_CreateNull();

	cJSON *o = cJSON_CreateObject();
	key = Base64FromBin(&key_size, c->Key, PEER_KEY_SIZE);
	cJSON_AddStringToObject(o, "address", c->Address);
	cJSON_AddStringToObject(o, "publicKey", key != NULL ? key : "");
	NodeControllerJsonFingerprints(c, o);
	Free(key);

	return o;
}

//
// The control stream
//

// The TLS fingerprint of a certificate: the SHA-256 of its SubjectPublicKeyInfo in hex, in lower case, as the Controller
// prints it
static bool NodeControllerCertFingerprint(PCCERT_CONTEXT cert, char *fp, UINT size) {
	static const char digits[] = "0123456789abcdef";
	UCHAR hash[CRYPTO_SHA256_SIZE];
	BYTE *der = NULL;
	DWORD der_size = 0;

	StrCpy(fp, size, "");
	if (cert == NULL || size < NODE_CONTROLLER_FINGERPRINT ||
	    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &der, &der_size) == FALSE)
		return false;

	bool ok = CryptoSha256(hash, der, der_size);
	LocalFree(der);
	if (ok == false)
		return false;

	for (UINT i = 0; i < CRYPTO_SHA256_SIZE; i++) {
		fp[2 * i] = digits[hash[i] >> 4];
		fp[2 * i + 1] = digits[hash[i] & 0x0F];
	}
	fp[2 * CRYPTO_SHA256_SIZE] = 0;

	return true;
}

// The fingerprints that the node accepts as the log says them: the ones that the Controller sent, or the one of the settings,
// with " or " between them. c->Lock is held.
static void NodeControllerAcceptedText(NODE_CONTROLLER *c, char *text, UINT size) {
	StrCpy(text, size, (c->NumPins == 0 ? c->Fingerprint : c->Pins[0]));

	for (UINT i = 1; i < c->NumPins; i++) {
		StrCat(text, size, " or ");
		StrCat(text, size, c->Pins[i]);
	}
}

// The check of the certificate of the Controller, in place of a thumbprint pin (TRANSPORT_TLS_CONFIG.Verify): its
// fingerprint is the one of the settings, or one that the Controller sent (SDN-92, #397). The end of the stream tells the log
// whether it passed.
static bool NodeControllerVerify(void *param, const struct _CERT_CONTEXT *cert) {
	NODE_CONTROLLER *c = (NODE_CONTROLLER *)param;
	char seen[NODE_CONTROLLER_FINGERPRINT];
	bool ok = false;

	bool known = NodeControllerCertFingerprint(cert, seen, sizeof(seen));

	Lock(c->Lock);
	{
		// The one Fingerprint of the settings, until the Controller sent others, which take its place
		if (c->NumPins == 0)
			ok = (known && StrCmpi(seen, c->Fingerprint) == 0);
		for (UINT i = 0; i < c->NumPins && ok == false; i++)
			ok = (known && StrCmpi(seen, c->Pins[i]) == 0);
		c->Checked = true;
		c->Mismatch = (ok == false);
		StrCpy(c->Seen, sizeof(c->Seen), seen);
	}
	Unlock(c->Lock);

	return ok;
}

// A stream ended or did not open, on the thread of the control stream: the log says why and when the next attempt comes
static void NodeControllerEnd(void *param, const CONTROL_STATUS *st) {
	NODE_CONTROLLER *c = (NODE_CONTROLLER *)param;
	char why[MAX_SIZE * 2];
	char seen[NODE_CONTROLLER_FINGERPRINT];
	char accepted[NODE_CONTROLLER_PINS * NODE_CONTROLLER_FINGERPRINT + 16];
	bool checked, mismatch;

	Lock(c->Lock);
	{
		checked = c->Checked;
		mismatch = c->Mismatch;
		StrCpy(seen, sizeof(seen), c->Seen);
		NodeControllerAcceptedText(c, accepted, sizeof(accepted));
		c->Checked = false;
		c->NumEnds++;
		c->LastEnd = st->LastEnd;
		c->NextRetry = st->NextRetry;
	}
	Unlock(c->Lock);

	switch (st->LastEnd) {
	case CONTROL_END_DIAL:
		if (checked && mismatch)
			Format(why, sizeof(why), "the TLS fingerprint check failed: the certificate of the Controller has the TLS fingerprint %s, not %s of the Controller settings, so no state is taken",
			       IsEmptyStr(seen) ? "(none)" : seen, accepted);
		else if (checked)
			Format(why, sizeof(why), "the certificate passed the TLS fingerprint check, and then the TLS session failed: the server did not select the ALPN protocol %s of the control stream, or gave no TLS exporter, so no state is taken",
			       CONTROL_ALPN);
		else
			Format(why, sizeof(why), "no Controller answered there, or its TLS session failed");
		break;
	case CONTROL_END_HANDSHAKE:
		Format(why, sizeof(why), "the Noise handshake failed: the Controller does not hold the static key of the Controller settings, or the TLS session is not end to end, so no state is taken");
		break;
	case CONTROL_END_REFUSED:
		Format(why, sizeof(why), "the Controller refused the node (reason %u): %s. A node whose static key no Node resource holds joins once an operator writes one; ranz node key prints its key",
		       st->LastRefuse, st->LastMessage);
		break;
	default:
		Format(why, sizeof(why), "the control stream ended after it was open");
		break;
	}

	// The state of the node says it too (NodeState.c; SDN-91, #396)
	Lock(c->Lock);
	StrCpy(c->Why, sizeof(c->Why), why);
	Unlock(c->Lock);

	NodeLog(c->Node, "Controller %s: %s; the next attempt in %u ms", c->Address, why, st->NextRetry);
}

// The TLS transport of the control stream: TLS 1.3 with the ALPN protocol of the control stream, its TLS exporter as the
// Channel binding, the certificate checked against the fingerprint of the settings, and TCP keepalive
static TRANSPORT *NodeControllerTls(NODE_CONTROLLER *c) {
	TRANSPORT_TLS_CONFIG tc;

	if (c->Tls != NULL)
		return c->Tls;

	TransportTlsDefaultConfig(&tc, NULL, false);
	tc.Versions = TRANSPORT_TLS_13;
	tc.SetGroups = false;
	tc.Queue = TRANSPORT_QUEUE_NONE;
	StrCpy(tc.Alpn, sizeof(tc.Alpn), CONTROL_ALPN);
	StrCpy(tc.ExporterLabel, sizeof(tc.ExporterLabel), CONTROL_EXPORTER_LABEL);
	tc.Verify = NodeControllerVerify;
	tc.VerifyParam = c;
	// A stream that is quiet on a path that went dead without a reset ends, and the node dials again
	tc.KeepAlive = NODE_CONTROLLER_KEEPALIVE;

	c->Tls = TransportTlsClientNew(&tc);
	if (c->Tls == NULL)
		NodeLog(c->Node, "Controller: the TLS transport of the control stream cannot be made");

	return c->Tls;
}

// The data transport of an overlay without the client role: it dials no peer and listens nowhere, so the node takes its
// state and keeps no session; a Node that listens for other Nodes is the Listener (SDN-45, #238)
static bool NodeControllerNoDial(void *param, const char *address, HANDLE cancel, void **stream) {
	*stream = NULL;
	return false;
}

static bool NodeControllerNoListen(void *param, const char *address, void **listener) {
	*listener = NULL;
	return false;
}

static bool NodeControllerNoAccept(void *listener, UINT timeout, void **stream) {
	*stream = NULL;
	return false;
}

static void NodeControllerNoCloseListener(void *listener) {
	// No listener
	return;
}

static UINT NodeControllerNoRead(void *stream, void *buf, UINT size, UINT timeout) {
	return 0;
}

static bool NodeControllerNoWrite(void *stream, const void *buf, UINT size) {
	return false;
}

static void NodeControllerNoClose(void *stream) {
	// No stream
	return;
}

// The Controller of the node, made with its settings when it does not exist yet (the node lock is held)
static NODE_CONTROLLER *NodeControllerGet(NODE *n) {
	if (n->Controller != NULL)
		return n->Controller;

	NODE_CONTROLLER *c = ZeroMalloc(sizeof(NODE_CONTROLLER));
	c->Node = n;
	c->Lock = NewLock();
	c->SettingLock = NewLock();
	c->PipeHandle = INVALID_HANDLE_VALUE;

	StrCpy(c->None.Name, sizeof(c->None.Name), "none");
	c->None.Param = c;
	c->None.Dial = NodeControllerNoDial;
	c->None.Listen = NodeControllerNoListen;
	c->None.Accept = NodeControllerNoAccept;
	c->None.CloseListener = NodeControllerNoCloseListener;
	c->None.Read = NodeControllerNoRead;
	c->None.Write = NodeControllerNoWrite;
	c->None.Close = NodeControllerNoClose;

	NodeControllerLoad(c);
	n->Controller = c;

	return c;
}

// The control stream of the overlay of the node to the Controller of its settings, into cfg; nothing without the settings
// (the node lock is held). The client role calls it before it starts the overlay (NodeClient.c).
void NodeControllerOverlay(NODE *n, NODE_OVERLAY_CONFIG *cfg) {
	if (n == NULL || cfg == NULL)
		return;

	NODE_CONTROLLER *c = NodeControllerGet(n);
	if (c->Set == false || NodeControllerTls(c) == NULL)
		return;

	cfg->Control = c->Tls;
	StrCpy(cfg->Controller, sizeof(cfg->Controller), c->Address);
	Copy(cfg->ControllerKey, c->Key, PEER_KEY_SIZE);
	cfg->ControlEnd = NodeControllerEnd;
	cfg->ControlEndParam = c;
}

//
// The TLS fingerprints that the Controller sends (SDN-92, #397)
//

// Write the TLS fingerprints pins into the Controller setting of the store, in place of the ones it holds: tlsFingerprint
// becomes the first and tlsFingerprints all of them. The setting is changed only while it still names the Controller of c:
// an Administrator may have written another one, which the node takes at its next start, with a fingerprint of its own.
static void NodeControllerSavePins(NODE_CONTROLLER *c, char pins[][NODE_CONTROLLER_FINGERPRINT], UINT num) {
	NODE *n = c->Node;
	NODE_CONTROLLER *stored = ZeroMalloc(sizeof(NODE_CONTROLLER));
	char *setting = ZeroMalloc(NODE_CONTROLLER_MAX_SETTING);
	char error[MAX_SIZE];
	char *text = NULL;
	const char *skipped = NULL;
	UINT ret = ERR_NO_ERROR;

	Lock(c->SettingLock);
	{
		cJSON *o = NULL;
		bool found = (n->Store != NULL && CsGetSetting(n->Store, NODE_SETTING_CONTROLLER, setting, NODE_CONTROLLER_MAX_SETTING) && IsEmptyStr(setting) == false);

		if (found)
			o = cJSON_Parse(setting);

		if (cJSON_IsObject(o) == false)
			skipped = "the Configuration store holds no Controller setting";
		else if (NodeControllerCheck(stored, NodeControllerJsonStr(o, "address"), NodeControllerJsonStr(o, "publicKey"), NodeControllerJsonStr(o, "tlsFingerprint"), error, sizeof(error)) == false ||
		         StrCmp(stored->Address, c->Address) != 0 || Cmp(stored->Key, c->Key, PEER_KEY_SIZE) != 0)
			skipped = "the Controller setting of the store names another Controller now";

		if (skipped == NULL) {
			cJSON_DeleteItemFromObjectCaseSensitive(o, "tlsFingerprint");
			cJSON_DeleteItemFromObjectCaseSensitive(o, "tlsFingerprints");
			cJSON_AddStringToObject(o, "tlsFingerprint", pins[0]);
			cJSON *list = cJSON_AddArrayToObject(o, "tlsFingerprints");

			for (UINT i = 0; list != NULL && i < num; i++)
				cJSON_AddItemToArray(list, cJSON_CreateString(pins[i]));

			text = cJSON_PrintUnformatted(o);
			if (text == NULL || StrLen(text) >= NODE_CONTROLLER_MAX_SETTING - 1)
				skipped = "the setting would be too long";
			else
				ret = CsSetSetting(n->Store, NODE_SETTING_CONTROLLER, text);
		}

		cJSON_Delete(o);
	}
	Unlock(c->SettingLock);

	if (skipped != NULL)
		NodeLog(n, "Controller %s: the TLS fingerprints are not written into the Controller setting (%s), so the node takes them until its next start", c->Address, skipped);
	else if (ret != ERR_NO_ERROR)
		NodeLog(n, "Controller %s: the TLS fingerprints cannot be written into the Configuration store, so the node takes them until its next start", c->Address);

	if (text != NULL)
		cJSON_free(text);
	Free(setting);
	Free(stored);
}

// The TLS fingerprints of the certificate of the Controller that a state names: the node accepts them in place of the ones it
// had, and writes them into its Controller setting before the control stream acknowledges the state, so that a node that
// pinned the fingerprint of the certificate in use still reaches the Controller once it serves another, also after the service
// restarts. A state that names none leaves them as they are, and a node without Controller settings has none to change. It
// runs on the thread of the control stream, or on the caller's of NodeOverlayApply.
void NodeControllerPins(NODE *n, const CONTROL_STATE *st) {
	NODE_CONTROLLER *c = (n != NULL ? n->Controller : NULL);
	char pins[NODE_CONTROLLER_PINS][NODE_CONTROLLER_FINGERPRINT];
	char text[NODE_CONTROLLER_PINS * NODE_CONTROLLER_FINGERPRINT + 16];
	UINT num = 0;
	bool changed;

	if (c == NULL || st == NULL || c->Set == false)
		return;

	Zero(pins, sizeof(pins));
	for (UINT i = 0; i < st->NumTlsPins && i < NODE_CONTROLLER_PINS; i++) {
		if (NodeControllerHex(st->TlsPins[i], NODE_CONTROLLER_FINGERPRINT - 1) == false)
			continue;

		StrCpy(pins[num], sizeof(pins[num]), (char *)st->TlsPins[i]);
		StrLower(pins[num]);
		num++;
	}

	if (num == 0)
		return;

	Lock(c->Lock);
	{
		changed = (c->NumPins != num || Cmp(c->Pins, pins, sizeof(pins)) != 0);
		if (changed) {
			c->NumPins = num;
			Copy(c->Pins, pins, sizeof(pins));
		}
		NodeControllerAcceptedText(c, text, sizeof(text));
	}
	Unlock(c->Lock);

	if (changed == false)
		return;

	NodeLog(n, "Controller %s: the TLS fingerprints of its certificate that the node accepts are now %s", c->Address, text);
	NodeControllerSavePins(c, pins, num);
}

//
// The enrolment through the tray (SDN-55, #248)
//

// The Controller settings and the state of the control stream for the status of the client role on the pipe of the logged-in
// user (NodeClient.c), into o as the object controller: whether the node has settings, their address, static key and TLS
// fingerprint in use, whether the stream is open, the Generation of the state, and why the last stream ended or why there is
// none. The thread of the pipe takes no node lock: the Controller of the node is there before the pipe starts and goes only
// once the pipe stopped (NodeControllerStop stops the overlay, which stops the pipe first), and its settings are read under its
// own lock, under which an enrolment changes them.
void NodeControllerClientJson(NODE *n, cJSON *o) {
	NODE_CONTROLLER *c = (n != NULL ? n->Controller : NULL);
	NODE_OVERLAY_STATUS os;
	cJSON *j = cJSON_CreateObject();
	char *key = NULL;
	UINT key_size = 0;
	bool set = false;

	NodeOverlayGetStatus(n, &os);

	if (c != NULL) {
		Lock(c->Lock);
		{
			set = c->Set;
			if (set) {
				key = Base64FromBin(&key_size, c->Key, PEER_KEY_SIZE);
				cJSON_AddStringToObject(j, "address", c->Address);
				cJSON_AddStringToObject(j, "publicKey", key != NULL ? key : "");
				cJSON_AddStringToObject(j, "tlsFingerprint", c->NumPins == 0 ? c->Fingerprint : c->Pins[0]);
				cJSON_AddStringToObject(j, "why", os.Connected ? "" : c->Why);
			}
		}
		Unlock(c->Lock);
	}

	cJSON_AddBoolToObject(j, "set", set);
	if (set == false)
		cJSON_AddStringToObject(j, "why", "the node has no Controller settings: a sign-in or ranz node controller set gives it some");
	cJSON_AddBoolToObject(j, "connected", os.Connected);
	cJSON_AddNumberToObject(j, "generation", (double)os.Generation);
	cJSON_AddItemToObject(o, "controller", j);

	Free(key);
}

// Whether the Controller settings b name the Controller of the settings a: the same address and static key, and a TLS
// fingerprint that a accepts
static bool NodeControllerSame(const NODE_CONTROLLER *a, const NODE_CONTROLLER *b) {
	bool fingerprint = (StrCmp(a->Fingerprint, b->Fingerprint) == 0);

	for (UINT i = 0; i < a->NumPins && fingerprint == false; i++)
		fingerprint = (StrCmp(a->Pins[i], b->Fingerprint) == 0);

	return (StrCmp(a->Address, b->Address) == 0 && Cmp(a->Key, b->Key, PEER_KEY_SIZE) == 0 && fingerprint);
}

// The thread of an enrolment: the node takes the Controller settings that it wrote, and its client role starts again, so that
// its overlay opens the control stream to that Controller. The role that it stops is the one whose pipe took the enrolment,
// whose overlay has no control stream, so it stops under the node lock (NodeSetRoles). NodeControllerStop joins the thread.
static DWORD WINAPI NodeControllerRejoin(LPVOID param) {
	NODE_CONTROLLER *c = (NODE_CONTROLLER *)param;
	NODE *n = c->Node;
	bool set, running;
	UINT roles;

	Lock(n->Lock);
	{
		Lock(c->Lock);
		NodeControllerLoad(c);
		set = c->Set;
		Unlock(c->Lock);
		running = n->Running;
		roles = n->Roles;
	}
	Unlock(n->Lock);

	if (set == false || running == false || (roles & NODE_ROLE_CLIENT) == 0) {
		NodeLog(n, "Controller: the settings of the enrolment wait for the next start of the node (%s)",
		        set == false ? "they are not valid" : (running ? "the client role does not run" : "the node stops"));
		return 0;
	}

	NodeLog(n, "Controller %s: the logged-in user enrolled the node, so its client role starts again to join it", c->Address);
	NodeSetRoles(n, roles & ~NODE_ROLE_CLIENT);
	NodeSetRoles(n, roles);

	return 0;
}

// Wait for the thread of an enrolment to end (the node lock is not held)
static void NodeControllerRejoinWait(NODE_CONTROLLER *c) {
	HANDLE h;

	Lock(c->Lock);
	h = c->Rejoin;
	c->Rejoin = NULL;
	Unlock(c->Lock);

	if (h != NULL) {
		WaitForSingleObject(h, INFINITE);
		CloseHandle(h);
	}
}

// Have the node take the Controller settings of an enrolment at once, on a thread of its own (NodeControllerRejoin). The pipe
// of the client role calls it once the user who enrolled closed it, so that the restart of the role does not cut the answer
// short.
void NodeControllerRejoinStart(NODE *n) {
	NODE_CONTROLLER *c = (n != NULL ? n->Controller : NULL);
	bool started;

	if (c == NULL)
		return;

	Lock(c->Lock);
	{
		// A thread of an earlier enrolment that ended makes way
		if (c->Rejoin != NULL && WaitForSingleObject(c->Rejoin, 0) == WAIT_OBJECT_0) {
			CloseHandle(c->Rejoin);
			c->Rejoin = NULL;
		}
		if (c->Rejoin == NULL)
			c->Rejoin = CreateThread(NULL, 0, NodeControllerRejoin, c, 0, NULL);
		started = (c->Rejoin != NULL);
	}
	Unlock(c->Lock);

	if (started == false)
		NodeLog(n, "Controller: the thread that takes the settings of the enrolment cannot start (error %u), so the node takes them at its next start", (UINT)GetLastError());
}

// The Controller settings that the sign-in of the logged-in user brought: enrol <address> <key> <fingerprint> on the pipe of
// the client role, as ranz tray sends it (SDN-55, #248). The node takes them only while it has none, in its store or in use;
// settings of the same Controller change nothing, and settings of another are refused. The answer, into o: the settings and
// whether they changed, or an error. Settings that the node takes go into the store; true when the node should take them at
// once (NodeControllerRejoinStart), as it should the same settings that an Administrator wrote into the store and that the
// node does not use yet. It runs on the thread of the pipe, which takes no node lock (NodeControllerClientJson says why the
// Controller is there).
bool NodeControllerEnrol(NODE *n, const char *address, const char *key, const char *fingerprint, cJSON *o) {
	if (n == NULL || o == NULL)
		return false;

	NODE_CONTROLLER *c = n->Controller;
	NODE_CONTROLLER *check = ZeroMalloc(sizeof(NODE_CONTROLLER));
	NODE_CONTROLLER *stored = ZeroMalloc(sizeof(NODE_CONTROLLER));
	char *setting = ZeroMalloc(NODE_CONTROLLER_MAX_SETTING);
	char error[MAX_SIZE];
	bool has = false;
	bool same = false;
	bool changed = false;
	bool rejoin = false;

	StrCpy(error, sizeof(error), "");

	if (c == NULL)
		StrCpy(error, sizeof(error), "the node runs no Controller module");
	else if (NodeControllerCheck(check, address, key, fingerprint, error, sizeof(error)))
		check->Set = true;

	if (c != NULL && check->Set) {
		Lock(c->SettingLock);
		{
			// The settings of the store, which the node takes at its next start ...
			if (n->Store != NULL && CsGetSetting(n->Store, NODE_SETTING_CONTROLLER, setting, NODE_CONTROLLER_MAX_SETTING) && IsEmptyStr(setting) == false) {
				cJSON *s = cJSON_Parse(setting);
				char ignored[MAX_SIZE];

				if (cJSON_IsObject(s) && NodeControllerCheck(stored, NodeControllerJsonStr(s, "address"), NodeControllerJsonStr(s, "publicKey"), NodeControllerJsonStr(s, "tlsFingerprint"), ignored, sizeof(ignored))) {
					NodeControllerLoadPins(stored, s);
					has = true;
					same = NodeControllerSame(stored, check);
				}
				cJSON_Delete(s);
			}

			// ... and those in use
			Lock(c->Lock);
			{
				bool used = c->Set;

				if (has == false && used) {
					has = true;
					same = NodeControllerSame(c, check);
				}
				// The same settings in the store that the node does not use yet: it takes them now
				rejoin = (has && same && used == false);
			}
			Unlock(c->Lock);

			if (has == false) {
				cJSON *json = NodeControllerJson(check);
				char *text = cJSON_PrintUnformatted(json);

				cJSON_Delete(json);
				changed = (text != NULL && n->Store != NULL && CsSetSetting(n->Store, NODE_SETTING_CONTROLLER, text) == ERR_NO_ERROR);
				if (changed == false)
					StrCpy(error, sizeof(error), "the Configuration store of the node cannot be written");
				if (text != NULL)
					cJSON_free(text);
			} else if (same == false) {
				StrCpy(error, sizeof(error), "the node has Controller settings of another Controller already: an Administrator changes them with ranz node controller set");
			}
		}
		Unlock(c->SettingLock);
	}

	if (IsEmptyStr(error) == false) {
		cJSON_AddStringToObject(o, "error", error);
	} else {
		cJSON_AddItemToObject(o, "controller", NodeControllerJson(check));
		cJSON_AddBoolToObject(o, "changed", changed);
	}

	if (changed || rejoin)
		NodeLog(n, "Client pipe: the logged-in user enrolled the node at the Controller %s, which it joins once the user closed the pipe", check->Address);

	Free(setting);
	Free(stored);
	Free(check);

	return (changed || rejoin);
}

//
// The admin pipe
//

// The answer to key: the public half of the static key of the node, made first when it does not exist yet. The private
// half stays in the key storage provider.
static void NodeAdminKey(NODE *n, cJSON *o) {
	wchar_t name[MAX_SIZE];
	PEER_KEY key;
	UINT size = 0;

	StrToUni(name, sizeof(name), n->IdentityKey);
	if (PeerKeyOpen(&key, name) == false) {
		cJSON_AddStringToObject(o, "error", "the static key of the node cannot be opened or made in the key storage provider");
		return;
	}

	char *pub = Base64FromBin(&size, key.Public, PEER_KEY_SIZE);
	cJSON_AddStringToObject(o, "publicKey", pub != NULL ? pub : "");
	NodeLog(n, "Admin pipe: the static key \"%s\" of the node, made first if no role had needed it, has the public half %s", n->IdentityKey, pub != NULL ? pub : "");
	Free(pub);
	PeerKeyClose(&key);
}

// The answer to controller: the settings and the state of the control stream
static void NodeAdminController(NODE *n, NODE_CONTROLLER *c, cJSON *o) {
	NODE_OVERLAY_STATUS os;

	NodeOverlayGetStatus(n, &os);
	cJSON_AddItemToObject(o, "controller", NodeControllerJson(c));
	cJSON_AddBoolToObject(o, "connected", os.Connected);
	cJSON_AddNumberToObject(o, "generation", (double)os.Generation);
}

// Write the settings of the command into the store (set), or take them out (clear); the service takes them at its next
// start. The settings that the node runs with stay until then.
static void NodeAdminSet(NODE *n, NODE_CONTROLLER *c, TOKEN_LIST *t, cJSON *o) {
	NODE_CONTROLLER *check = ZeroMalloc(sizeof(NODE_CONTROLLER));
	char error[MAX_SIZE];
	char *setting = NULL;
	UINT ret;

	if (t->NumTokens == 5 && StrCmpi(t->Token[1], "set") == 0) {
		if (NodeControllerCheck(check, t->Token[2], t->Token[3], t->Token[4], error, sizeof(error)) == false) {
			cJSON_AddStringToObject(o, "error", error);
			Free(check);
			return;
		}
		check->Set = true;
		cJSON *json = NodeControllerJson(check);
		setting = cJSON_PrintUnformatted(json);
		cJSON_Delete(json);
	}

	// Beside the fingerprints that the Controller sends (NodeControllerPins), which change the stored setting too
	Lock(c->SettingLock);
	ret = (n->Store == NULL ? ERR_INTERNAL_ERROR : CsSetSetting(n->Store, NODE_SETTING_CONTROLLER, setting));
	Unlock(c->SettingLock);
	if (ret != ERR_NO_ERROR) {
		cJSON_AddStringToObject(o, "error", "the Configuration store of the node cannot be written");
	} else {
		cJSON_AddItemToObject(o, "controller", NodeControllerJson(check));
		cJSON_AddBoolToObject(o, "connected", false);
		cJSON_AddNumberToObject(o, "generation", 0);
		if (setting != NULL)
			NodeLog(n, "Admin pipe: the Controller settings now name the Controller %s; the node takes them at its next start", check->Address);
		else
			NodeLog(n, "Admin pipe: the Controller settings are cleared; the node takes that at its next start");
	}

	if (setting != NULL)
		cJSON_free(setting);
	Free(check);
}

// One command line of an Administrator, as ranz node sends it: key, controller, controller set <address> <key>
// <fingerprint> or controller clear. The answer is one JSON object; a line that is no command gets an error.
void NodeAdminCommand(NODE *n, char *line, char *reply, UINT size) {
	if (n == NULL || line == NULL || reply == NULL || size == 0)
		return;

	cJSON *o = cJSON_CreateObject();
	TOKEN_LIST *t = ParseToken(line, " \t\r\n");

	Lock(n->Lock);
	{
		NODE_CONTROLLER *c = NodeControllerGet(n);

		if (t->NumTokens == 1 && StrCmpi(t->Token[0], "key") == 0)
			NodeAdminKey(n, o);
		else if (t->NumTokens == 1 && StrCmpi(t->Token[0], "controller") == 0)
			NodeAdminController(n, c, o);
		else if (t->NumTokens >= 2 && StrCmpi(t->Token[0], "controller") == 0 &&
		         ((t->NumTokens == 2 && StrCmpi(t->Token[1], "clear") == 0) || (t->NumTokens == 5 && StrCmpi(t->Token[1], "set") == 0)))
			NodeAdminSet(n, c, t, o);
		else if (t->NumTokens == 1 && StrCmpi(t->Token[0], "state") == 0)
			NodeAdminState(n, o);
		else
			cJSON_AddStringToObject(o, "error", "unknown command: key, controller, controller set <address> <key> <fingerprint>, controller clear or state");
	}
	Unlock(n->Lock);

	char *text = cJSON_PrintUnformatted(o);
	StrCpy(reply, size, text != NULL ? text : "{}");
	if (text != NULL)
		cJSON_free(text);
	cJSON_Delete(o);
	FreeToken(t);
}

// One read or write of the pipe, overlapped, until it completes, the pipe stops or the Administrator stays idle too
// long: false for the last two and for a failure, with the operation cancelled
static bool NodeAdminPipeIo(NODE_CONTROLLER *c, HANDLE event, bool write, void *buf, UINT size, UINT *done) {
	OVERLAPPED ov;
	HANDLE waits[2];
	DWORD n = 0;

	*done = 0;
	Zero(&ov, sizeof(ov));
	ov.hEvent = event;
	ResetEvent(event);

	BOOL ok = (write ? WriteFile(c->PipeHandle, buf, size, NULL, &ov) : ReadFile(c->PipeHandle, buf, size, NULL, &ov));
	if (ok == FALSE && GetLastError() != ERROR_IO_PENDING)
		return false;

	waits[0] = c->PipeStop;
	waits[1] = event;
	if (WaitForMultipleObjects(2, waits, FALSE, NODE_ADMIN_IDLE) != WAIT_OBJECT_0 + 1) {
		CancelIoEx(c->PipeHandle, &ov);
		GetOverlappedResult(c->PipeHandle, &ov, &n, TRUE);
		return false;
	}

	if (GetOverlappedResult(c->PipeHandle, &ov, &n, FALSE) == FALSE)
		return false;

	*done = (UINT)n;
	return true;
}

// The commands of one connected Administrator, one a line, each answered with one line, until the Administrator closes
// the pipe. A line longer than NODE_ADMIN_LINE ends the connection.
static void NodeAdminSession(NODE_CONTROLLER *c, HANDLE event) {
	char *line = ZeroMalloc(NODE_ADMIN_LINE);
	char *buf = ZeroMalloc(NODE_ADMIN_LINE);
	char *reply = ZeroMalloc(NODE_ADMIN_REPLY);
	UINT used = 0;
	UINT got = 0;
	bool alive = true;

	while (alive && NodeAdminPipeIo(c, event, false, buf, NODE_ADMIN_LINE, &got) && got != 0) {
		for (UINT i = 0; alive && i < got; i++) {
			UINT written = 0;

			if (buf[i] != '\n') {
				alive = (used < NODE_ADMIN_LINE - 1);
				if (alive)
					line[used++] = buf[i];
				continue;
			}

			line[used] = 0;
			used = 0;
			NodeAdminCommand(c->Node, line, reply, NODE_ADMIN_REPLY - 1);
			StrCat(reply, NODE_ADMIN_REPLY, "\n");
			alive = NodeAdminPipeIo(c, event, true, reply, StrLen(reply), &written);
		}
	}

	Free(reply);
	Free(buf);
	Free(line);
}

// The thread of the admin pipe: one Administrator at a time, until the node stops
static DWORD WINAPI NodeAdminThread(LPVOID param) {
	NODE_CONTROLLER *c = (NODE_CONTROLLER *)param;
	HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE waits[2];

	while (event != NULL && WaitForSingleObject(c->PipeStop, 0) == WAIT_TIMEOUT) {
		OVERLAPPED ov;
		DWORD n = 0;

		Zero(&ov, sizeof(ov));
		ov.hEvent = event;
		ResetEvent(event);

		BOOL connected = ConnectNamedPipe(c->PipeHandle, &ov);
		DWORD err = GetLastError();
		if (connected == FALSE && err == ERROR_IO_PENDING) {
			waits[0] = c->PipeStop;
			waits[1] = event;
			if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
				CancelIoEx(c->PipeHandle, &ov);
				GetOverlappedResult(c->PipeHandle, &ov, &n, TRUE);
				break;
			}
			connected = GetOverlappedResult(c->PipeHandle, &ov, &n, FALSE);
		} else if (connected == FALSE && err == ERROR_PIPE_CONNECTED) {
			connected = TRUE;
		}

		if (connected)
			NodeAdminSession(c, event);
		else
			Sleep(NODE_CLIENT_SLICE);

		DisconnectNamedPipe(c->PipeHandle);
	}

	if (event != NULL)
		CloseHandle(event);

	return 0;
}

// Stop the thread of the admin pipe and close the pipe; nothing when it does not run
static void NodeAdminStop(NODE_CONTROLLER *c) {
	if (c->PipeThread != NULL) {
		SetEvent(c->PipeStop);
		WaitForSingleObject(c->PipeThread, INFINITE);
		CloseHandle(c->PipeThread);
		c->PipeThread = NULL;
	}

	if (c->PipeHandle != INVALID_HANDLE_VALUE && c->PipeHandle != NULL) {
		CloseHandle(c->PipeHandle);
		c->PipeHandle = INVALID_HANDLE_VALUE;
	}

	if (c->PipeStop != NULL) {
		CloseHandle(c->PipeStop);
		c->PipeStop = NULL;
	}
}

// The admin pipe and its thread: the node of the service, on the default data directory, or the pipe that a test named.
// Without it the node runs, and ranz node cannot reach it.
static void NodeAdminStart(NODE_CONTROLLER *c) {
	NODE *n = c->Node;
	wchar_t def[MAX_PATH];
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_ATTRIBUTES sa;

	NodeDefaultDataDir(def, sizeof(def));
	if (UniIsEmptyStr(n->AdminPipe) == false)
		UniFormat(c->Pipe, sizeof(c->Pipe), L"\\\\.\\pipe\\%s", n->AdminPipe);
	else if (UniStrCmpi(n->DataDir, def) == 0)
		UniFormat(c->Pipe, sizeof(c->Pipe), L"\\\\.\\pipe\\%S", NODE_ADMIN_PIPE);
	else
		return;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_ADMIN_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE) {
		NodeLog(n, "Admin pipe: its DACL is not valid (error %u)", (UINT)GetLastError());
		return;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	// The first and only instance, for local callers only: no one can serve under its name
	c->PipeHandle = CreateNamedPipeW(c->Pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
	                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, NODE_ADMIN_REPLY, NODE_ADMIN_LINE, 0, &sa);
	DWORD err = GetLastError();
	LocalFree(sd);

	if (c->PipeHandle == INVALID_HANDLE_VALUE) {
		NodeLog(n, "Admin pipe: %S cannot be created (error %u), so ranz node cannot reach this node", c->Pipe, (UINT)err);
		return;
	}

	c->PipeStop = CreateEventW(NULL, TRUE, FALSE, NULL);
	c->PipeThread = (c->PipeStop != NULL ? CreateThread(NULL, 0, NodeAdminThread, c, 0, NULL) : NULL);
	if (c->PipeThread == NULL) {
		NodeLog(n, "Admin pipe: its thread cannot start (error %u)", (UINT)GetLastError());
		NodeAdminStop(c);
		return;
	}

	NodeLog(n, "Admin pipe: %S, for SYSTEM and the Administrators only (ranz node)", c->Pipe);
}

//
// The Controller
//

// Start the Controller of the node (the node lock is held), after its roles: the admin pipe, and the overlay with the
// control stream of the settings when the client role did not start it. Without the settings the node opens no stream,
// and says so once.
void NodeControllerStart(NODE *n) {
	wchar_t name[MAX_SIZE];
	NODE_OVERLAY_CONFIG cfg;

	if (n == NULL)
		return;

	NODE_CONTROLLER *c = NodeControllerGet(n);
	NodeAdminStart(c);

	if (c->Set == false) {
		NodeLog(n, "Controller: none, so the node opens no control stream and dials no Controller; ranz node controller set joins it to one");
		return;
	}

	if (n->Overlay != NULL) {
		NodeLog(n, "Controller %s: the overlay of the client role has the control stream", c->Address);
		return;
	}

	// The overlay without the client role: no adapter, and a data transport that dials and listens nowhere
	StrToUni(name, sizeof(name), n->IdentityKey);
	if (NodeControllerTls(c) == NULL || PeerKeyOpen(&c->NodeKey, name) == false) {
		NodeLog(n, "Controller %s: no control stream: %s", c->Address, c->Tls == NULL ? "no TLS transport" : "the static key of the node cannot be opened or made");
		return;
	}

	Zero(&cfg, sizeof(cfg));
	cfg.Data = &c->None;
	cfg.Key = &c->NodeKey;
	NodeControllerOverlay(n, &cfg);
	c->Overlay = NodeOverlayStart(n, &cfg);

	NodeLog(n, c->Overlay ? "Controller %s: the overlay of the node runs with its control stream" : "Controller %s: the overlay of the node could not start", c->Address);
}

// Stop the Controller of the node (the node lock is not held): the admin pipe first, which reads the overlay, then the
// overlay, which closes the control stream, then its transport and the key
void NodeControllerStop(NODE *n) {
	NODE_CONTROLLER *c;

	if (n == NULL)
		return;

	Lock(n->Lock);
	c = n->Controller;
	Unlock(n->Lock);

	if (c == NULL)
		return;

	NodeAdminStop(c);
	// The thread of an enrolment ends before the overlay that it starts (SDN-55, #248)
	NodeControllerRejoinWait(c);
	NodeOverlayStop(n);

	Lock(n->Lock);
	n->Controller = NULL;
	Unlock(n->Lock);

	TransportTlsFree(c->Tls);
	PeerKeyClose(&c->NodeKey);
	DeleteLock(c->SettingLock);
	DeleteLock(c->Lock);
	Free(c);
}

// The state of the Controller of the node; Set is false without the settings or while the node does not run
void NodeControllerGetStatus(NODE *n, NODE_CONTROLLER_STATUS *st) {
	NODE_OVERLAY_STATUS os;
	PACL dacl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	LPWSTR sddl = NULL;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_CONTROLLER_STATUS));
	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		NODE_CONTROLLER *c = n->Controller;

		if (c != NULL) {
			NodeOverlayGetStatus(n, &os);
			st->Set = c->Set;
			StrCpy(st->Address, sizeof(st->Address), c->Address);
			Copy(st->Key, c->Key, PEER_KEY_SIZE);
			StrCpy(st->Fingerprint, sizeof(st->Fingerprint), c->Fingerprint);
			st->Overlay = c->Overlay;
			st->Connected = os.Connected;
			st->Generation = os.Generation;

			Lock(c->Lock);
			{
				st->NumEnds = c->NumEnds;
				st->LastEnd = c->LastEnd;
				st->NextRetry = c->NextRetry;
				st->Mismatch = c->Mismatch;
				StrCpy(st->Seen, sizeof(st->Seen), c->Seen);
				StrCpy(st->Why, sizeof(st->Why), c->Why);
				st->NumPins = c->NumPins;
				Copy(st->Pins, c->Pins, sizeof(st->Pins));
			}
			Unlock(c->Lock);

			if (c->PipeHandle != INVALID_HANDLE_VALUE && c->PipeHandle != NULL &&
			    GetSecurityInfo(c->PipeHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
			    ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL)) {
				UniToStr(st->PipeAcl, sizeof(st->PipeAcl), sddl);
			}
		}
	}
	Unlock(n->Lock);

	if (sddl != NULL)
		LocalFree(sddl);
	if (sd != NULL)
		LocalFree(sd);
}
