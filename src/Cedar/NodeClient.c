// NodeClient.c
// The client role of a node (CORE-S3-1, #71; ADR-0011, ADR-0022 Roles): the node dials the servers of its
// configuration over QUIC or TLS-443, joins their L3 network through the overlay of the node (NodeOverlay.c) and brings
// it up on one Wintun adapter per VRF (NodeVrfAdapter.c; SDN-5, #181). It replaces Cascade for new peers. Here are the
// pieces that a server does not need (ADR-0011): the adapters with their routes and DNS servers, sleep and roaming, and
// the control by the logged-in user.
// - The Client setting of the configuration store (NODE_SETTING_CLIENT), one JSON object, names the adapters, the DNS
//   servers and suffix of the network, the pipe of the logged-in user, and each server: its node name, the thumbprint
//   of its certificate, which both transports pin, and its fallback list ("quic:vpn.example:443, tls:vpn.example:443").
//   A server that names no fallback list is dialled at the endpoints of its Peer object, which the Controller sends
//   (NodeEndpoints.c; SDN-93, #410), and only while that Peer object lists some. With "forwarding": true the node is a
//   gateway or an exit, and each of its adapters forwards between it and the other interfaces of the host. Without the
//   setting the role holds nothing.
// - The role runs the overlay of the node. Its data transport is the dialler of the role: a peer is dialled by its
//   name, which is the race of the fallback list of the server of that name (TransportRace), so QUIC wins where UDP
//   passes and TLS-443 where it does not. A transport whose Noise handshake then fails, as QUIC between a node of the
//   build before CORE-H5 and one of this build, stays out of the races of that server for TRANSPORT_FALLBACK_HOLD, so
//   the next dial goes to the next transport of the list (TransportFallback.c; CORE-H5-R, #443). A client dials every
//   server whatever the order of the keys, and listens
//   nowhere. The data records of its Noise sessions wait in the ingress queue of the session layer, which CoDel runs,
//   over QUIC as over TLS-443: the overlay carries them on a reliable stream of either.
// - Each state that the overlay applies reconciles the adapters, one per VRF of the state, each with a fixed GUID of the
//   node and its VRF (NodeVrfAdapter.c): the node's addresses in the VRF as host addresses, and a route through the
//   adapter to the prefix of each address of the node and of its peers in that VRF. The packets of the host's own stack
//   go from the ring of the adapter of a VRF into the overlay in that VRF (NodeOverlayInput) on the I/O thread of its
//   adapter queue; the packets of the peers in a VRF go into the adapter of that VRF. The adapters stay while the
//   streams close and the servers are dialled again.
// - Sleep: the node takes the suspend and resume events of Windows (PowerRegisterSuspendResumeNotification). On
//   suspend it closes its streams and dials nothing; on resume it dials again, and the server replaces the session
//   that the sleep left behind with the new one (NodeOverlay.c).
// - Roaming: a unicast address that comes, changes or goes on another interface (NotifyUnicastIpAddressChange) closes
//   the streams once the changes settled, so the servers are dialled again on the new path.
// - The logged-in user drives the role through a named pipe that the interactive users may open and no one remote:
//   one command a line, status, up or down, each answered with the status of the role as one JSON object.
//
// The role takes its states from the control stream of the Controller settings of the node (NodeController.c; SDN-90,
// #395), or without them from NodeOverlayApply, as the vpntest harness gives them. In the ranzvpnserver service the role
// needs what ONE-3 (#312) installs: the Wintun driver and wintun.dll next to ranz-node, which the service account may
// load and use.

#include "Node.h"

#include "ConfigStore.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#include <iphlpapi.h>
#include <powrprof.h>
#include <sddl.h>

#include <cjson/cJSON.h>

// The DACL of the pipe of the logged-in user: full control for SYSTEM, the Administrators and the virtual account of the
// ranzvpnserver service (ADR-0039 decision 3), read and write for the interactive users, nothing for anyone else. The
// pipe has one instance, the first, so no user can serve under its name.
#define NODE_CLIENT_PIPE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" NODE_SERVICE_SID L")(A;;GRGW;;;IU)"

// A server of the Client setting: the transports that dial it, each pinning the certificate of the server, and its
// fallback list
typedef struct NODE_CLIENT_SERVER {
	char Name[PEER_NAME_SIZE];                       // Its node name: the address of its peer on the dialler
	TRANSPORT *Quic;                                 // The QUIC transport, NULL when the list names none or msquic.dll is missing
	TRANSPORT *Tls;                                  // The TLS transport, NULL when the list names none
	UINT NumTargets;                                 // The entries of the fallback list that a transport here can dial
	TRANSPORT_TARGET Targets[TRANSPORT_MAX_TARGETS]; // ... in the order of the list
	TRANSPORT_FALLBACK Fallback;                     // The transports whose handshake failed, out of its races for a while (under the lock)
} NODE_CLIENT_SERVER;

// A stream of the dialler: the stream of the transport that won the race, which the role closes on suspend, resume,
// roaming and down
typedef struct NODE_CLIENT_STREAM {
	NODE_CLIENT *Client;      // The role
	TRANSPORT_STREAM *Stream; // The stream of QUIC or TLS-443
	volatile LONG Broken;     // Closed by the role: its reads end and its writes fail until the overlay closes it
} NODE_CLIENT_STREAM;

// The client role of a node
struct NODE_CLIENT {
	NODE *Node;                                     // The node
	LOCK *Lock;                                     // The streams, the flags and the counters below
	wchar_t Adapter[MAX_SIZE];                      // The name of the Wintun adapter
	char Dns[MAX_SIZE];                             // The DNS servers of the network, comma-separated, empty for none
	char Suffix[MAX_SIZE];                          // ... and its DNS suffix, empty for none
	wchar_t Pipe[MAX_PATH];                         // The pipe of the logged-in user
	UINT NumServers;                                // The servers
	NODE_CLIENT_SERVER *Servers;                    // ... NODE_CLIENT_MAX_SERVERS of them allocated
	TRANSPORT Dialler;                              // The data transport of the overlay: it dials a server by its name
	PEER_KEY Key;                                   // The node's static key
	bool Forwarding;                                // The node is a gateway or an exit: its adapters forward
	NODE_VRF_ADAPTERS *Adapters;                    // The adapters, one per VRF of the state (NodeVrfAdapter.c)
	volatile LONG VrfId;                            // The VRF of the node's first address, whose adapter the status names
	bool Overlay;                                   // The role started the overlay of the node
	LIST *Streams;                                  // The streams of the dialler that the overlay holds (NODE_CLIENT_STREAM)
	UINT64 Epoch;                                   // One more at each close of the streams
	bool Down;                                      // The logged-in user took the role down: no server is dialled
	bool Asleep;                                    // Between a suspend and a resume: no server is dialled
	bool Failing;                                   // The last race failed: the next failure is not logged again
	char Transport[TRANSPORT_NAME_SIZE];            // The transport of the stream that connected last
	UINT64 NumDials;                                // Streams that connected
	UINT64 NumResets;                               // Times the role closed its streams
	UINT64 NumRoams;                                // Settled address changes on other interfaces
	DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS PowerParams; // The callback of the suspend and resume events
	HPOWERNOTIFY Power;                             // ... and its registration
	HANDLE Addresses;                               // The registration of the address changes
	PTP_TIMER Settle;                               // Fires once the address changes settled
	HANDLE PipeHandle;                              // The server end of the pipe, INVALID_HANDLE_VALUE without
	HANDLE PipeStop;                                // Ends the thread of the pipe
	HANDLE PipeThread;                              // The thread of the pipe
};

static void NodeClientPipeStop(NODE_CLIENT *c);

//
// The Client setting
//

// The string member name of a JSON object; def when it has none
static const char *NodeClientJsonStr(cJSON *o, const char *name, const char *def) {
	const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));

	return (s != NULL ? s : def);
}

// The thumbprint of a server's certificate as the transports take it: its 40 hex digits, without the spaces and colons
// of the setting; false for anything else
static bool NodeClientThumbprint(char *dst, UINT size, const char *src) {
	UINT n = 0;

	if (size < 2 * CRYPTO_THUMBPRINT_SIZE + 1)
		return false;

	for (UINT i = 0; src[i] != 0; i++) {
		char ch = src[i];

		if (ch == ' ' || ch == ':')
			continue;
		if (((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) == false || n >= 2 * CRYPTO_THUMBPRINT_SIZE)
			return false;

		dst[n++] = ch;
	}

	dst[n] = 0;

	return (n == 2 * CRYPTO_THUMBPRINT_SIZE);
}

// A server of the setting: its name, the transports that its fallback list names, each pinning its certificate, and the
// entries of the list that they can dial. An entry of a transport that cannot run here (QUIC without msquic.dll) is
// left out, so the others still dial. False when no entry is left. A server without a fallback list has both transports,
// and the entries come from the endpoints of its Peer object when it is dialled (SDN-93, #410); it is left out when no
// transport can run.
static bool NodeClientAddServer(NODE_CLIENT *c, NODE_CLIENT_SERVER *s, const char *name, const char *thumbprint, const char *dial) {
	char pin[2 * CRYPTO_THUMBPRINT_SIZE + 1];
	TRANSPORT *known[2];
	UINT num_known = 0;

	Zero(s, sizeof(NODE_CLIENT_SERVER));

	if (IsEmptyStr(name) || StrLen(name) >= PEER_NAME_SIZE || NodeClientThumbprint(pin, sizeof(pin), thumbprint) == false) {
		NodeLog(c->Node, "Role client: a server of the %s setting has no name or no thumbprint of 40 hex digits", NODE_SETTING_CLIENT);
		return false;
	}

	StrCpy(s->Name, sizeof(s->Name), name);
	bool endpoints = IsEmptyStr(dial);

	if (endpoints || InStr(dial, "quic:")) {
		TRANSPORT_QUIC_CONFIG qc;

		TransportQuicDefaultConfig(&qc, pin, false);
		s->Quic = TransportQuicClientNew(&qc);
		if (s->Quic != NULL)
			known[num_known++] = s->Quic;
		else
			NodeLog(c->Node, "Role client: server %s: no QUIC here (msquic.dll is missing), so its fallback list goes on without", name);
	}

	if (endpoints || InStr(dial, "tls:")) {
		TRANSPORT_TLS_CONFIG tc;

		TransportTlsDefaultConfig(&tc, pin, false);
		s->Tls = TransportTlsClientNew(&tc);
		if (s->Tls != NULL)
			known[num_known++] = s->Tls;
	}

	// Each entry on its own, so that an entry of a transport that cannot run here leaves the others
	TOKEN_LIST *t = ParseToken(dial, ",");
	for (UINT i = 0; i < t->NumTokens && s->NumTargets < TRANSPORT_MAX_TARGETS; i++) {
		if (TransportParseList(t->Token[i], known, num_known, &s->Targets[s->NumTargets], 1) == 1)
			s->NumTargets++;
		else
			NodeLog(c->Node, "Role client: server %s: the entry \"%s\" of its fallback list names no transport that runs here", name, t->Token[i]);
	}
	FreeToken(t);

	if ((endpoints == false && s->NumTargets == 0) || (endpoints && s->Quic == NULL && s->Tls == NULL)) {
		TransportQuicFree(s->Quic);
		TransportTlsFree(s->Tls);
		Zero(s, sizeof(NODE_CLIENT_SERVER));
		return false;
	}

	if (endpoints)
		NodeLog(c->Node, "Role client: server %s, dialled at the endpoints of its Peer object, which the Controller sends", name);
	else
		NodeLog(c->Node, "Role client: server %s, dialled over %u entries of its fallback list \"%s\"", name, s->NumTargets, dial);
	return true;
}

// Read the Client setting: the adapter, the DNS servers and suffix, the pipe, and each server. False, with the node log
// saying why, for a setting that is not a JSON object or names no server that a transport here can dial.
static bool NodeClientLoad(NODE_CLIENT *c, const char *setting) {
	cJSON *cfg = cJSON_Parse(setting);
	cJSON *servers = cJSON_GetObjectItemCaseSensitive(cfg, "servers");
	cJSON *dns = cJSON_GetObjectItemCaseSensitive(cfg, "dns");
	cJSON *item = NULL;

	if (cJSON_IsObject(cfg) == false || cJSON_IsArray(servers) == false) {
		NodeLog(c->Node, "Role client: the %s setting is not a JSON object with an array of servers", NODE_SETTING_CLIENT);
		cJSON_Delete(cfg);
		return false;
	}

	StrToUni(c->Adapter, sizeof(c->Adapter), NodeClientJsonStr(cfg, "adapter", NODE_CLIENT_ADAPTER));
	UniFormat(c->Pipe, sizeof(c->Pipe), L"\\\\.\\pipe\\%S", NodeClientJsonStr(cfg, "pipe", NODE_CLIENT_PIPE));
	StrCpy(c->Suffix, sizeof(c->Suffix), NodeClientJsonStr(cfg, "suffix", ""));
	c->Forwarding = (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cfg, "forwarding")) != 0);

	cJSON_ArrayForEach(item, dns) {
		if (cJSON_IsString(item) == false)
			continue;
		if (IsEmptyStr(c->Dns) == false)
			StrCat(c->Dns, sizeof(c->Dns), ",");
		StrCat(c->Dns, sizeof(c->Dns), cJSON_GetStringValue(item));
	}

	c->Servers = ZeroMalloc(sizeof(NODE_CLIENT_SERVER) * NODE_CLIENT_MAX_SERVERS);
	cJSON_ArrayForEach(item, servers) {
		if (c->NumServers >= NODE_CLIENT_MAX_SERVERS)
			break;
		if (NodeClientAddServer(c, &c->Servers[c->NumServers], NodeClientJsonStr(item, "name", ""), NodeClientJsonStr(item, "thumbprint", ""), NodeClientJsonStr(item, "dial", "")))
			c->NumServers++;
	}

	cJSON_Delete(cfg);

	if (c->NumServers == 0) {
		NodeLog(c->Node, "Role client: the %s setting names no server that a transport here can dial", NODE_SETTING_CLIENT);
		return false;
	}

	return true;
}

//
// The dialler: the data transport of the overlay of a client node
//

// Close every stream of the dialler, also one that a race delivers after it: the overlay closes their sessions and
// dials the servers again, unless the role is down or asleep
static void NodeClientReset(NODE_CLIENT *c, const char *why) {
	UINT num = 0;

	Lock(c->Lock);
	{
		c->Epoch++;
		c->NumResets++;

		for (UINT i = 0; i < LIST_NUM(c->Streams); i++) {
			NODE_CLIENT_STREAM *s = LIST_DATA(c->Streams, i);

			if (InterlockedExchange(&s->Broken, 1) == 0)
				num++;
		}
	}
	Unlock(c->Lock);

	NodeLog(c->Node, "Client: %s (%u streams closed)", why, num);
}

// Dial the server named address: the race of its fallback list, or of the endpoints of its Peer object when it has none
// (SDN-93, #410). While the role is down or asleep it dials nothing.
static bool NodeClientDial(void *param, const char *address, HANDLE cancel, void **stream) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;
	NODE_CLIENT_SERVER *s = NULL;
	TRANSPORT_RACE race;
	UINT64 epoch;
	bool idle;

	*stream = NULL;

	Lock(c->Lock);
	{
		epoch = c->Epoch;
		idle = (c->Down || c->Asleep);
	}
	Unlock(c->Lock);

	for (UINT i = 0; i < c->NumServers && s == NULL; i++)
		if (StrCmp(c->Servers[i].Name, address) == 0)
			s = &c->Servers[i];

	if (idle || s == NULL)
		return false;

	// The entries of the race: those of the fallback list of the server, or without a list the endpoints of its Peer object
	// that a transport here can dial (NodeEndpoints.c; SDN-93, #410)
	TRANSPORT_TARGET listed[TRANSPORT_MAX_TARGETS];
	const TRANSPORT_TARGET *targets = s->Targets;
	UINT num = s->NumTargets;

	if (num == 0) {
		CONTROL_ENDPOINT endpoints[CONTROL_MAX_ENDPOINTS];
		TRANSPORT *known[2] = {s->Quic, s->Tls};
		UINT num_endpoints = NodeOverlayEndpoints(c->Node, address, endpoints, CONTROL_MAX_ENDPOINTS);

		num = NodeEndpointsTargets(endpoints, num_endpoints, known, 2, listed, TRANSPORT_MAX_TARGETS);
		targets = listed;
		if (num == 0)
			return false;
	}

	// Without the transports whose handshake failed, so that the dial after a failed handshake goes to the next transport
	// of the list (TransportFallback.c; CORE-H5-R, #443)
	TRANSPORT_TARGET raced[TRANSPORT_MAX_TARGETS];
	Lock(c->Lock);
	num = TransportFallbackTargets(&s->Fallback, targets, num, GetTickCount64(), raced, TRANSPORT_MAX_TARGETS);
	Unlock(c->Lock);
	targets = raced;

	TRANSPORT_STREAM *t = TransportRace(targets, num, TRANSPORT_RACE_DELAY, NODE_CLIENT_DIAL, &race);
	if (t == NULL) {
		bool logged;

		Lock(c->Lock);
		logged = c->Failing;
		c->Failing = true;
		Unlock(c->Lock);

		if (logged == false)
			NodeLog(c->Node, "Client: server %s not reached: %u of its %u entries failed within %u ms", address, race.NumFailed, num, (UINT)NODE_CLIENT_DIAL);
		return false;
	}

	char *winner = targets[race.Winner].Transport->Name;
	NODE_CLIENT_STREAM *cs = ZeroMalloc(sizeof(NODE_CLIENT_STREAM));
	cs->Client = c;
	cs->Stream = t;

	Lock(c->Lock);
	{
		// A close of the streams while the race ran closes this one too: it may run on the path that went
		cs->Broken = ((c->Down || c->Asleep || c->Epoch != epoch) ? 1 : 0);
		Add(c->Streams, cs);
		c->NumDials++;
		c->Failing = false;
		StrCpy(c->Transport, sizeof(c->Transport), winner);
		TransportFallbackWon(&s->Fallback, targets[race.Winner].Transport);
	}
	Unlock(c->Lock);

	NodeLog(c->Node, "Client: server %s reached over %s in %I64u ms", address, winner, race.Elapsed);

	*stream = cs;
	return true;
}

// Whether the dialler dials the peer name, whose Peer object lists the num endpoints: a server of the Client setting that has
// a fallback list, or none and an endpoint that a transport here can dial (SDN-93, #410). A peer that is no server, or that has
// no such endpoint, is not dialled: the overlay does not start a dial for it, so the role does not retry for it in a loop. The
// servers do not change while the role runs, so this takes no lock: the overlay asks under its own.
static bool NodeClientDialable(NODE *n, void *param, const char *name, const CONTROL_ENDPOINT *endpoints, UINT num) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;

	for (UINT i = 0; i < c->NumServers; i++) {
		NODE_CLIENT_SERVER *s = &c->Servers[i];
		TRANSPORT *known[2] = {s->Quic, s->Tls};

		if (StrCmp(s->Name, name) == 0)
			return (s->NumTargets != 0 || NodeEndpointsTargets(endpoints, num, known, 2, NULL, 0) != 0);
	}

	return false;
}

// The handshake failed on the stream that the last race for the server name gave (CORE-H5-R, #443): its transport stays
// out of the races of the server for TRANSPORT_FALLBACK_HOLD, so the overlay's next dial goes to the next transport of
// its list, as from a QUIC that a node of the build before CORE-H5 refuses to its TLS-443
static void NodeClientRefused(NODE *n, void *param, const char *name) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;
	TRANSPORT *t = NULL;

	for (UINT i = 0; i < c->NumServers; i++) {
		NODE_CLIENT_SERVER *s = &c->Servers[i];

		if (StrCmp(s->Name, name) == 0) {
			Lock(c->Lock);
			t = TransportFallbackRefused(&s->Fallback, GetTickCount64());
			Unlock(c->Lock);
			break;
		}
	}

	if (t != NULL)
		NodeLog(n, "Client: server %s: the handshake over %s failed, so its next dials race the rest of its list for %u s", name, t->Name,
		        (UINT)(TRANSPORT_FALLBACK_HOLD / 1000));
}

// A client listens nowhere: no peer dials it
static bool NodeClientListen(void *param, const char *address, void **listener) {
	*listener = NULL;
	return false;
}

static bool NodeClientAccept(void *listener, UINT timeout, void **stream) {
	*stream = NULL;
	return false;
}

static void NodeClientCloseListener(void *listener) {
	// No listener
	return;
}

// Read the stream of the transport, in slices of NODE_CLIENT_SLICE, so that a stream that the role closed ends soon
static UINT NodeClientRead(void *stream, void *buf, UINT size, UINT timeout) {
	NODE_CLIENT_STREAM *s = (NODE_CLIENT_STREAM *)stream;
	UINT64 end = (timeout == INFINITE ? 0 : GetTickCount64() + timeout);

	while (true) {
		UINT wait = NODE_CLIENT_SLICE;

		if (ReadAcquire(&s->Broken) != 0)
			return 0;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			wait = (now >= end ? 0 : (UINT)MIN(end - now, (UINT64)NODE_CLIENT_SLICE));
		}

		UINT got = TransportRead(s->Stream, buf, size, wait);
		if (got != TRANSPORT_LATER || (timeout != INFINITE && GetTickCount64() >= end))
			return got;
	}
}

static bool NodeClientWrite(void *stream, const void *buf, UINT size) {
	NODE_CLIENT_STREAM *s = (NODE_CLIENT_STREAM *)stream;

	if (ReadAcquire(&s->Broken) != 0)
		return false;

	return TransportWrite(s->Stream, buf, size);
}

static void NodeClientClose(void *stream) {
	NODE_CLIENT_STREAM *s = (NODE_CLIENT_STREAM *)stream;
	NODE_CLIENT *c = s->Client;

	Lock(c->Lock);
	Delete(c->Streams, s);
	Unlock(c->Lock);

	TransportClose(s->Stream);
	Free(s);
}

// The binding of the outer TLS or QUIC session, which the Noise session takes
static UINT NodeClientBinding(void *stream, UCHAR *binding, UINT max, UINT *size) {
	return TransportBinding(((NODE_CLIENT_STREAM *)stream)->Stream, binding, max, size);
}

static bool NodeClientRekey(void *stream) {
	return TransportRekey(((NODE_CLIENT_STREAM *)stream)->Stream);
}

//
// The adapter
//

// A packet of a peer for the host, on the thread of the overlay: into the ring of the adapter of its VRF (SDN-5, #181)
static void NodeClientToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;

	NodeVrfAdaptersSend(c->Adapters, vrf_id, packet, size);
}

// A state that the overlay applied, once its forwarding tables are in: the adapters of its VRFs take the node's
// addresses and the routes of each VRF (NodeVrfAdapter.c), and the status names the VRF of the node's first address
static void NodeClientState(NODE *n, void *param, const CONTROL_STATE *st) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;
	UINT vrf = (st->NumAddresses != 0 ? st->Addresses[0].VrfId : 0);

	InterlockedExchange(&c->VrfId, (LONG)vrf);
	bool ok = NodeVrfAdaptersApply(c->Adapters, st);

	NodeLog(n, "Client: generation %I64u on the adapters %S <VRF>: the first address in VRF %u, %u addresses, %u VRFs%s", st->Generation, c->Adapter, vrf,
	        st->NumAddresses, st->NumVrfs, ok ? "" : " (not all of them set, see the lines before)");
}

// The adapter of the VRF of the node's first address into first, the name of the setting before the first state, and
// the packets of the host taken from all the adapters of the role and put into them: the number of adapters
static UINT NodeClientAdapters(NODE_CLIENT *c, NODE_VRF_ADAPTER_STATUS *first, UINT64 *from_host, UINT64 *to_host) {
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	UINT num = NodeVrfAdaptersGetStatus(c->Adapters, list, NODE_VRF_MAX_ADAPTERS);
	UINT vrf = (UINT)ReadAcquire(&c->VrfId);

	Zero(first, sizeof(NODE_VRF_ADAPTER_STATUS));
	UniStrCpy(first->Name, sizeof(first->Name), c->Adapter);
	*from_host = 0;
	*to_host = 0;

	for (UINT i = 0; i < num; i++) {
		if (list[i].VrfId == vrf)
			Copy(first, &list[i], sizeof(NODE_VRF_ADAPTER_STATUS));
		*from_host += list[i].FromHost;
		*to_host += list[i].ToHost;
	}

	Free(list);

	return num;
}

// Stop what of the role calls into the overlay: the pipe of the logged-in user, which reads the status of the overlay,
// and the adapter queues, which feed it the packets of the host. NodeOverlayStop calls it first thing.
static void NodeClientHalt(NODE *n, void *param) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;

	NodeClientPipeStop(c);
	NodeVrfAdaptersHalt(c->Adapters);
}

//
// Sleep and roaming
//

// What a power event does to the role: on suspend it closes its streams and dials nothing until a resume; on resume it
// closes what the sleep left and dials again. A resume without the suspend before it, as after a hibernation that the
// process did not see begin, closes the streams too.
static void NodeClientPowerOf(NODE_CLIENT *c, UINT event) {
	const char *why = NULL;

	Lock(c->Lock);
	{
		if (event == PBT_APMSUSPEND && c->Asleep == false) {
			c->Asleep = true;
			why = "suspend: the streams close, and no server is dialled until the resume";
		} else if (event == PBT_APMRESUMEAUTOMATIC || (event == PBT_APMRESUMESUSPEND && c->Asleep)) {
			c->Asleep = false;
			why = "resume: what the sleep left closes, and the servers are dialled again";
		}
	}
	Unlock(c->Lock);

	if (why != NULL)
		NodeClientReset(c, why);
}

// The suspend and resume events of Windows, on a thread of the system
static ULONG CALLBACK NodeClientPowerEvent(PVOID context, ULONG type, PVOID setting) {
	NodeClientPowerOf((NODE_CLIENT *)context, (UINT)type);

	return ERROR_SUCCESS;
}

// A power event for the client role of a node (PBT_APMSUSPEND, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND), as
// Windows gives it to the role; the vpntest harness drives it this way, since its runner cannot sleep
void NodeClientPower(NODE *n, UINT event) {
	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		if (n->Client != NULL)
			NodeClientPowerOf(n->Client, event);
	}
	Unlock(n->Lock);
}

// An address of an interface came, changed or went: unless it is one of the node's own adapters or the loopback
// interface, the timer moves on, so that it fires once the changes settled
static VOID WINAPI NodeClientAddressChanged(PVOID context, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE type) {
	NODE_CLIENT *c = (NODE_CLIENT *)context;
	ULARGE_INTEGER due;
	FILETIME ft;

	if (row == NULL || type == MibInitialNotification || row->InterfaceLuid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK || NodeVrfAdaptersHas(c->Adapters, row->InterfaceLuid.Value))
		return;

	due.QuadPart = (ULONGLONG)(-(LONGLONG)NODE_CLIENT_SETTLE * 10000);
	ft.dwLowDateTime = due.LowPart;
	ft.dwHighDateTime = due.HighPart;
	SetThreadpoolTimer(c->Settle, &ft, 0, 0);
}

// The address changes settled: the node roamed, so the streams on the old path close
static VOID CALLBACK NodeClientSettled(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_TIMER timer) {
	NODE_CLIENT *c = (NODE_CLIENT *)context;

	Lock(c->Lock);
	c->NumRoams++;
	Unlock(c->Lock);

	NodeClientReset(c, "roaming: an address of another interface changed, so the servers are dialled again on the new path");
}

// Take the suspend and resume events of Windows and the address changes of the other interfaces
static void NodeClientWatch(NODE_CLIENT *c) {
	c->PowerParams.Callback = NodeClientPowerEvent;
	c->PowerParams.Context = c;
	DWORD err = PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, (HANDLE)&c->PowerParams, &c->Power);
	if (err != ERROR_SUCCESS) {
		c->Power = NULL;
		NodeLog(c->Node, "Role client: the suspend and resume events cannot be taken (error %u)", (UINT)err);
	}

	c->Settle = CreateThreadpoolTimer(NodeClientSettled, c, NULL);
	err = (c->Settle != NULL ? NotifyUnicastIpAddressChange(AF_UNSPEC, NodeClientAddressChanged, c, FALSE, &c->Addresses) : ERROR_NOT_ENOUGH_MEMORY);
	if (err != NO_ERROR) {
		c->Addresses = NULL;
		NodeLog(c->Node, "Role client: the address changes cannot be taken (error %u)", (UINT)err);
	}
}

// Stop the events: no callback runs once it returns
static void NodeClientUnwatch(NODE_CLIENT *c) {
	if (c->Power != NULL) {
		PowerUnregisterSuspendResumeNotification(c->Power);
		c->Power = NULL;
	}

	if (c->Addresses != NULL) {
		CancelMibChangeNotify2(c->Addresses);
		c->Addresses = NULL;
	}

	if (c->Settle != NULL) {
		SetThreadpoolTimer(c->Settle, NULL, 0, 0);
		WaitForThreadpoolTimerCallbacks(c->Settle, TRUE);
		CloseThreadpoolTimer(c->Settle);
		c->Settle = NULL;
	}
}

//
// The logged-in user
//

// Take the role down (no server is dialled, its streams close) or up again
static void NodeClientSetDown(NODE_CLIENT *c, bool down) {
	bool changed;

	Lock(c->Lock);
	changed = (c->Down != down);
	c->Down = down;
	Unlock(c->Lock);

	if (changed == false)
		return;

	if (down)
		NodeClientReset(c, "down by the logged-in user: the streams close, and no server is dialled");
	else
		NodeLog(c->Node, "Client: up by the logged-in user: the servers are dialled again");
}

// The status of the role as one JSON object: its state (connected, connecting, down or asleep), the adapter and its
// interface, the transport of the last stream, the peers of the overlay and their sessions, the node's addresses and
// the counters
static void NodeClientStatusJson(NODE_CLIENT *c, char *reply, UINT size) {
	NODE_OVERLAY_STATUS os;
	NODE_VRF_ADAPTER_STATUS first;
	UINT64 from_host = 0;
	UINT64 to_host = 0;
	char adapter[MAX_SIZE];
	char addr[64];
	const char *state;

	NodeOverlayGetStatus(c->Node, &os);
	UINT num_adapters = NodeClientAdapters(c, &first, &from_host, &to_host);
	UniToStr(adapter, sizeof(adapter), first.Name);

	cJSON *o = cJSON_CreateObject();
	cJSON *addresses = cJSON_CreateArray();

	Lock(c->Lock);
	{
		if (c->Down)
			state = "down";
		else if (c->Asleep)
			state = "asleep";
		else if (os.NumPeers != 0 && os.NumLinks == os.NumPeers)
			state = "connected";
		else
			state = "connecting";

		cJSON_AddStringToObject(o, "state", state);
		cJSON_AddStringToObject(o, "adapter", adapter);
		cJSON_AddNumberToObject(o, "interface", first.InterfaceIndex);
		cJSON_AddNumberToObject(o, "adapters", num_adapters);
		cJSON_AddStringToObject(o, "transport", c->Transport);
		cJSON_AddNumberToObject(o, "servers", c->NumServers);
		cJSON_AddNumberToObject(o, "peers", os.NumPeers);
		cJSON_AddNumberToObject(o, "sessions", os.NumLinks);
		cJSON_AddNumberToObject(o, "dials", (double)c->NumDials);
		cJSON_AddNumberToObject(o, "resets", (double)c->NumResets);
		cJSON_AddNumberToObject(o, "roams", (double)c->NumRoams);
	}
	Unlock(c->Lock);

	for (UINT i = 0; i < os.NumAddresses; i++) {
		IPToStr32(addr, sizeof(addr), os.Addresses[i]);
		cJSON_AddItemToArray(addresses, cJSON_CreateString(addr));
	}
	cJSON_AddItemToObject(o, "addresses", addresses);
	cJSON_AddNumberToObject(o, "fromHost", (double)from_host);
	cJSON_AddNumberToObject(o, "toHost", (double)to_host);

	char *text = cJSON_PrintUnformatted(o);
	StrCpy(reply, size, text != NULL ? text : "{}");
	if (text != NULL)
		cJSON_free(text);
	cJSON_Delete(o);
}

// One command line of the logged-in user: status, up or down, without case. up and down take the role up and down,
// and each is answered with the status of the role; another line with an error. The line is compared with the three
// words and nothing else of it is read.
static void NodeClientCommand(NODE_CLIENT *c, char *line, char *reply, UINT size) {
	Trim(line);

	if (StrCmpi(line, "up") == 0) {
		NodeClientSetDown(c, false);
	} else if (StrCmpi(line, "down") == 0) {
		NodeClientSetDown(c, true);
	} else if (StrCmpi(line, "status") != 0) {
		StrCpy(reply, size, "{\"error\":\"unknown command: status, up or down\"}");
		return;
	}

	NodeClientStatusJson(c, reply, size);
}

// One read or write of the pipe, overlapped, until it completes, the role stops or the user stays idle too long; false
// for the last two and for a failure (the user closed the pipe), with the operation cancelled
static bool NodeClientPipeIo(NODE_CLIENT *c, HANDLE event, bool write, void *buf, UINT size, UINT *done) {
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
	if (WaitForMultipleObjects(2, waits, FALSE, NODE_CLIENT_PIPE_IDLE) != WAIT_OBJECT_0 + 1) {
		CancelIoEx(c->PipeHandle, &ov);
		GetOverlappedResult(c->PipeHandle, &ov, &n, TRUE);
		return false;
	}

	if (GetOverlappedResult(c->PipeHandle, &ov, &n, FALSE) == FALSE)
		return false;

	*done = (UINT)n;
	return true;
}

// The commands of one connected user, one a line, each answered with one line, until the user closes the pipe. A
// line longer than NODE_CLIENT_LINE ends the connection.
static void NodeClientPipeSession(NODE_CLIENT *c, HANDLE event) {
	char line[NODE_CLIENT_LINE];
	char buf[NODE_CLIENT_LINE];
	char reply[NODE_CLIENT_REPLY];
	UINT used = 0;
	UINT got = 0;

	while (NodeClientPipeIo(c, event, false, buf, sizeof(buf), &got) && got != 0) {
		for (UINT i = 0; i < got; i++) {
			UINT written = 0;

			if (buf[i] != '\n') {
				if (used >= sizeof(line) - 1)
					return;
				line[used++] = buf[i];
				continue;
			}

			line[used] = 0;
			used = 0;
			NodeClientCommand(c, line, reply, sizeof(reply) - 1);
			StrCat(reply, sizeof(reply), "\n");
			if (NodeClientPipeIo(c, event, true, reply, StrLen(reply), &written) == false)
				return;
		}
	}
}

// The thread of the pipe: one user at a time, until the role stops
static DWORD WINAPI NodeClientPipeThread(LPVOID param) {
	NODE_CLIENT *c = (NODE_CLIENT *)param;
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
			NodeClientPipeSession(c, event);
		else
			Sleep(NODE_CLIENT_SLICE);

		DisconnectNamedPipe(c->PipeHandle);
	}

	if (event != NULL)
		CloseHandle(event);

	return 0;
}

// The pipe of the logged-in user and its thread. Without it the role still runs, with no user to drive it.
static void NodeClientPipeStart(NODE_CLIENT *c) {
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_ATTRIBUTES sa;
	DWORD thread_id = 0;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_CLIENT_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE) {
		NodeLog(c->Node, "Role client: the DACL of the pipe of the logged-in user is not valid (error %u)", (UINT)GetLastError());
		return;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	// The first and only instance, for local users only: no one can serve under its name
	c->PipeHandle = CreateNamedPipeW(c->Pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
	                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, NODE_CLIENT_REPLY, NODE_CLIENT_LINE, 0, &sa);
	DWORD err = GetLastError();
	LocalFree(sd);

	if (c->PipeHandle == INVALID_HANDLE_VALUE) {
		NodeLog(c->Node, "Role client: the pipe %S of the logged-in user cannot be created (error %u)", c->Pipe, (UINT)err);
		return;
	}

	c->PipeStop = CreateEventW(NULL, TRUE, FALSE, NULL);
	c->PipeThread = (c->PipeStop != NULL ? CreateThread(NULL, 0, NodeClientPipeThread, c, 0, &thread_id) : NULL);
	if (c->PipeThread == NULL) {
		NodeLog(c->Node, "Role client: the thread of the pipe of the logged-in user cannot start (error %u)", (UINT)GetLastError());
		NodeClientPipeStop(c);
		return;
	}

	NodeLog(c->Node, "Role client: the logged-in user drives the role through the pipe %S", c->Pipe);
}

// Stop the thread of the pipe and close the pipe; nothing when it does not run
static void NodeClientPipeStop(NODE_CLIENT *c) {
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

//
// The role
//

// The state of the client role of a node; Running is false while the role holds nothing
void NodeClientGetStatus(NODE *n, NODE_CLIENT_STATUS *st) {
	NODE_VRF_ADAPTER_STATUS first;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_CLIENT_STATUS));
	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		NODE_CLIENT *c = n->Client;

		if (c != NULL) {
			st->Running = true;
			NodeClientAdapters(c, &first, &st->FromHost, &st->ToHost);
			UniStrCpy(st->Adapter, sizeof(st->Adapter), first.Name);
			st->InterfaceIndex = first.InterfaceIndex;
			st->InterfaceLuid = first.InterfaceLuid;
			UniStrCpy(st->Pipe, sizeof(st->Pipe), c->Pipe);
			Copy(st->Key, c->Key.Public, PEER_KEY_SIZE);
			st->VrfId = (UINT)ReadAcquire(&c->VrfId);
			st->NumServers = c->NumServers;

			Lock(c->Lock);
			{
				st->Down = c->Down;
				st->Asleep = c->Asleep;
				StrCpy(st->Transport, sizeof(st->Transport), c->Transport);
				st->NumDials = c->NumDials;
				st->NumResets = c->NumResets;
				st->NumRoams = c->NumRoams;
			}
			Unlock(c->Lock);
		}
	}
	Unlock(n->Lock);
}

// The Wintun adapters of the client role of a node, one per VRF of its state, at most max of them into list in the order
// of their VRF ids: their number, 0 while the role holds nothing
UINT NodeClientGetAdapters(NODE *n, NODE_VRF_ADAPTER_STATUS *list, UINT max) {
	UINT num = 0;

	if (n == NULL || list == NULL)
		return 0;

	Lock(n->Lock);
	{
		if (n->Client != NULL)
			num = NodeVrfAdaptersGetStatus(n->Client->Adapters, list, max);
	}
	Unlock(n->Lock);

	return num;
}

// The overlay of the node with the adapters and the dialler of the role, and the control stream of the Controller settings
// when the node has them (NodeController.c); without them its states come from NodeOverlayApply, as the vpntest harness
// gives them
static bool NodeClientOverlayStart(NODE_CLIENT *c) {
	NODE_OVERLAY_CONFIG cfg;

	if (c->Node->Overlay != NULL) {
		NodeLog(c->Node, "Role client: the overlay of the node runs already, without the adapters of the role");
		return false;
	}

	Zero(&cfg, sizeof(cfg));
	cfg.Data = &c->Dialler;
	cfg.Key = &c->Key;
	cfg.Adapter = NodeClientToHost;
	cfg.AdapterParam = c;
	cfg.AdapterStop = NodeClientHalt;
	cfg.State = NodeClientState;
	cfg.Dialler = true;
	// Only a server that it can dial is dialled, through the endpoints of its Peer object where its setting names no list
	cfg.Dialable = NodeClientDialable;
	// A failed handshake sends the next dial of its server to the next transport of the list (CORE-H5-R, #443)
	cfg.Refused = NodeClientRefused;
	// The control stream to the Controller of the Controller settings, when the node has them (NodeController.c; SDN-90, #395)
	NodeControllerOverlay(c->Node, &cfg);

	c->Overlay = NodeOverlayStart(c->Node, &cfg);

	return c->Overlay;
}

// Release what the role holds, in the order that keeps each part valid for the ones that call into it: the pipe and the
// adapter queues, the events, the overlay, which closes every stream of the dialler, then the adapters, the key and
// the transports. The overlay stops under the node lock here (NodeSetRoles): it has no control stream that would take
// it.
static void NodeClientFree(NODE_CLIENT *c) {
	NODE *n = c->Node;

	NodeClientHalt(n, c);
	NodeClientUnwatch(c);

	if (c->Overlay && n->Overlay != NULL)
		NodeOverlayStop(n);

	NodeVrfAdaptersFree(c->Adapters);
	PeerKeyClose(&c->Key);

	for (UINT i = 0; i < c->NumServers; i++) {
		TransportQuicFree(c->Servers[i].Quic);
		TransportTlsFree(c->Servers[i].Tls);
	}

	Free(c->Servers);
	ReleaseList(c->Streams);
	DeleteLock(c->Lock);
	Free(c);
}

// Start the client role (the node lock is held): with the Client setting, its servers and their transports, the identity
// key, the Wintun adapters of its VRFs, which come with the states, the overlay, the events of Windows and the pipe of the
// logged-in user. Without the setting the role holds nothing. False when the setting cannot be used, wintun.dll is
// missing or the overlay cannot come up.
bool NodeClientStart(NODE *n) {
	wchar_t key_name[MAX_SIZE];

	char *setting = ZeroMalloc(NODE_CLIENT_MAX_SETTING);
	if (n->Store == NULL || CsGetSetting(n->Store, NODE_SETTING_CLIENT, setting, NODE_CLIENT_MAX_SETTING) == false || IsEmptyStr(setting)) {
		Free(setting);
		NodeLog(n, "Role client: no %s setting, so the role holds no adapter and dials no server", NODE_SETTING_CLIENT);
		return true;
	}

	NODE_CLIENT *c = ZeroMalloc(sizeof(NODE_CLIENT));
	c->Node = n;
	c->Lock = NewLock();
	c->Streams = NewListFast(NULL);
	c->PipeHandle = INVALID_HANDLE_VALUE;

	StrCpy(c->Dialler.Name, sizeof(c->Dialler.Name), "client");
	c->Dialler.Param = c;
	c->Dialler.Dial = NodeClientDial;
	c->Dialler.Listen = NodeClientListen;
	c->Dialler.Accept = NodeClientAccept;
	c->Dialler.CloseListener = NodeClientCloseListener;
	c->Dialler.Read = NodeClientRead;
	c->Dialler.Write = NodeClientWrite;
	c->Dialler.Close = NodeClientClose;
	c->Dialler.Binding = NodeClientBinding;
	c->Dialler.Rekey = NodeClientRekey;
	c->Dialler.Queue = TRANSPORT_QUEUE_CODEL;

	bool ok = NodeClientLoad(c, setting);
	Free(setting);

	if (ok) {
		StrToUni(key_name, sizeof(key_name), n->IdentityKey);
		ok = PeerKeyOpen(&c->Key, key_name);
		if (ok == false)
			NodeLog(n, "Role client: the identity key \"%s\" cannot be opened or created", n->IdentityKey);
	}

	if (ok) {
		c->Adapters = NodeVrfAdaptersNew(n, c->Adapter, c->Key.Public, c->Forwarding);
		ok = (c->Adapters != NULL);
	}

	if (ok) {
		NodeVrfAdaptersSetDns(c->Adapters, c->Dns, c->Suffix);
		ok = NodeClientOverlayStart(c);
	}

	if (ok == false) {
		NodeClientFree(c);
		return false;
	}

	n->Client = c;
	NodeClientWatch(c);
	NodeClientPipeStart(c);

	NodeLog(n, "Role client: adapters %S <VRF>, %u servers, the overlay of the node%s", c->Adapter, c->NumServers,
	        c->Forwarding ? ", forwarding as a gateway or an exit" : "");

	return true;
}

// Stop the client role (the node lock is held) and release all it holds; its adapters go with it
void NodeClientStop(NODE *n) {
	NODE_CLIENT *c = n->Client;

	if (c == NULL)
		return;

	n->Client = NULL;
	NodeClientFree(c);

	NodeLog(n, "Role client: its adapters, its streams and its pipe are gone");
}
