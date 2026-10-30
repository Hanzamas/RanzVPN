// NodeState.c
// The state of a Node on its own PC (SDN-91, #396): the answer of the admin pipe (NodeController.c) to the command state,
// which ranz node state prints. It says what the Node service does now: its Roles, its control stream (the Controller,
// since when it is connected and the Generation that the overlay runs, or why it is not), its Wintun adapters with their
// VRFs and the addresses of the node in each VRF, the Noise sessions of its peers with their transport and their age, how it
// reaches each peer, on its stream session or through a Relay, with the datagrams that went each way there (CORE-S5-5, #411),
// its datagram path with the Upgrades and the Fallbacks of its Paths and its port mapping (CORE-S5-6, #412), and its
// listeners (the data transport of the overlay, the front door and QUIC of its Listener, the UDP port of the relay role). The
// pipe is the local channel: only SYSTEM, the Administrators and the service account may open it.

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeAgent.h"
#include "NodeInternal.h"

#include <cjson/cJSON.h>

// The seconds from the GetTickCount64 since to now, 0 for a time that has not come
static double NodeStateAge(UINT64 since, UINT64 now) {
	return (since == 0 || since > now ? 0.0 : (double)((now - since) / 1000));
}

// The control stream: the Controller of the settings, and since when it is connected at which Generation, or why not
static void NodeStateController(NODE *n, const NODE_OVERLAY_STATUS *os, UINT64 now, cJSON *o) {
	NODE_CONTROLLER_STATUS *cs = ZeroMalloc(sizeof(NODE_CONTROLLER_STATUS));
	cJSON *c = cJSON_AddObjectToObject(o, "controlStream");

	NodeControllerGetStatus(n, cs);
	cJSON_AddBoolToObject(c, "set", cs->Set);
	cJSON_AddStringToObject(c, "controller", cs->Address);
	cJSON_AddBoolToObject(c, "connected", os->Connected);
	cJSON_AddNumberToObject(c, "connectedSeconds", os->Connected ? NodeStateAge(os->Since, now) : 0.0);
	cJSON_AddNumberToObject(c, "generation", (double)os->Generation);
	if (os->Connected)
		cJSON_AddStringToObject(c, "why", "");
	else if (cs->Set == false)
		cJSON_AddStringToObject(c, "why", "the node has no Controller settings");
	else if (cs->Why[0] == 0)
		cJSON_AddStringToObject(c, "why", "the first attempt has not ended yet");
	else
		cJSON_AddStringToObject(c, "why", cs->Why);
	cJSON_AddNumberToObject(c, "nextRetryMs", os->Connected ? 0.0 : (double)cs->NextRetry);

	Free(cs);
}

// The Wintun adapters of the node, each with its VRF and the addresses of the node in that VRF
static void NodeStateAdapters(NODE *n, const NODE_OVERLAY_STATUS *os, cJSON *o) {
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	UINT num = MIN(NodeClientGetAdapters(n, list, NODE_VRF_MAX_ADAPTERS), NODE_VRF_MAX_ADAPTERS);
	cJSON *a = cJSON_AddArrayToObject(o, "adapters");

	for (UINT i = 0; i < num; i++) {
		cJSON *e = cJSON_CreateObject();
		char name[NODE_VRF_ADAPTER_NAME * 3];

		UniToUtf8(name, sizeof(name), list[i].Name);
		cJSON_AddNumberToObject(e, "vrf", list[i].VrfId);
		cJSON_AddStringToObject(e, "name", name);
		cJSON_AddNumberToObject(e, "interfaceIndex", list[i].InterfaceIndex);
		cJSON *addresses = cJSON_AddArrayToObject(e, "addresses");
		for (UINT j = 0; j < os->NumAddresses && j < NODE_OVERLAY_MAX_ADDRESSES; j++) {
			char addr[64];

			if (os->VrfIds[j] != list[i].VrfId)
				continue;
			IPToStr32(addr, sizeof(addr), os->Addresses[j]);
			cJSON_AddItemToArray(addresses, cJSON_CreateString(addr));
		}
		cJSON_AddItemToArray(a, e);
	}

	Free(list);
}

// The peers of the overlay and their Noise sessions, and the data transport that the overlay listens on into listener
static void NodeStateSessions(NODE *n, UINT64 now, cJSON *o, char *listener, UINT listener_size) {
	NODE_OVERLAY_SESSION *list = ZeroMalloc(sizeof(NODE_OVERLAY_SESSION) * NODE_STATE_MAX_SESSIONS);
	UINT total = NodeOverlayGetSessions(n, list, NODE_STATE_MAX_SESSIONS, listener, listener_size);
	cJSON *a = cJSON_AddArrayToObject(o, "sessions");

	for (UINT i = 0; i < total && i < NODE_STATE_MAX_SESSIONS; i++) {
		cJSON *e = cJSON_CreateObject();

		cJSON_AddStringToObject(e, "peer", list[i].Name);
		cJSON_AddBoolToObject(e, "up", list[i].Up);
		cJSON_AddStringToObject(e, "transport", list[i].Transport);
		cJSON_AddNumberToObject(e, "ageSeconds", list[i].Up ? NodeStateAge(list[i].Since, now) : 0.0);
		// How the overlay reaches the peer, and the records that went each way on its datagram path (NodeAgent.c; CORE-S5-5, #411)
		cJSON_AddStringToObject(e, "path", NodeAgentPathName(list[i].Path));
		cJSON_AddNumberToObject(e, "datagramsOut", (double)list[i].DatagramsOut);
		cJSON_AddNumberToObject(e, "datagramsIn", (double)list[i].DatagramsIn);
		cJSON_AddItemToArray(a, e);
	}
	cJSON_AddNumberToObject(o, "numPeers", total);

	Free(list);
}

// The name of a NAT of PEER_NAT_*, as the state of the node says it
static const char *NodeStateNatName(UINT nat) {
	switch (nat) {
	case PEER_NAT_CONE:
		return "cone";
	case PEER_NAT_SEQUENTIAL:
		return "sequential";
	case PEER_NAT_RANDOM:
		return "random";
	default:
		return "unknown";
	}
}

// The peer agent of the overlay (NodeAgent.c; CORE-S5-5 #411, CORE-S5-6 #412): whether its peer layer runs, with ICE or
// without, and on which UDP port; the Relays of the state; the Upgrades of its Paths to a direct path and their Fallbacks to
// the Relay since the node started; the port mapping of the home gateway, with the public address that it granted; and the
// punches of the node (CORE-S5-7, #413): its NAT as the answers of its binds show it, and its attempts, the ones that met
// and the ones whose prediction failed
static void NodeStateAgent(NODE *n, cJSON *o) {
	NODE_AGENT_STATUS *st = ZeroMalloc(sizeof(NODE_AGENT_STATUS));
	cJSON *a = cJSON_AddObjectToObject(o, "datagramPath");
	char mapped[64];

	NodeAgentGetStatus(n, st);
	mapped[0] = 0;
	if (st->Peer.PortMap == PEER_PORTMAP_MAPPED)
		PeerAddrToStr(mapped, sizeof(mapped), &st->Peer.Mapped);

	cJSON_AddBoolToObject(a, "running", st->Running);
	cJSON_AddBoolToObject(a, "ice", st->Ice);
	cJSON_AddNumberToObject(a, "udpPort", st->Port);
	cJSON_AddNumberToObject(a, "relays", st->NumRelays);
	cJSON_AddNumberToObject(a, "upgrades", (double)st->Peer.Upgrades);
	cJSON_AddNumberToObject(a, "fallbacks", (double)st->Peer.Fallbacks);
	cJSON_AddStringToObject(a, "portMapping", NodeAgentPortMapName(st->Peer.PortMap));
	cJSON_AddStringToObject(a, "mappedAddress", mapped);
	cJSON_AddStringToObject(a, "nat", NodeStateNatName(st->Peer.Nat));
	cJSON_AddNumberToObject(a, "punchAttempts", (double)st->Peer.PunchAttempts);
	cJSON_AddNumberToObject(a, "punchSuccesses", (double)st->Peer.PunchSuccesses);
	cJSON_AddNumberToObject(a, "punchFailures", (double)st->Peer.PunchFailures);

	Free(st);
}

// What the limits for a source of one listener hold and refused (AUD1-DT-3, #451): the connections that wait for their
// handshake now, and the refusals by reason since the node started
static void NodeStateLimits(cJSON *o, const SOURCE_LIMIT_STATS *st) {
	cJSON_AddNumberToObject(o, "pending", st->Pending);
	cJSON_AddNumberToObject(o, "sources", st->Sources);
	cJSON_AddNumberToObject(o, "admitted", (double)st->Admitted);
	cJSON_AddNumberToObject(o, "refusedFull", (double)st->RefusedFull);
	cJSON_AddNumberToObject(o, "refusedSource", (double)st->RefusedSource);
	cJSON_AddNumberToObject(o, "refusedRate", (double)st->RefusedRate);
	cJSON_AddNumberToObject(o, "refusedHandshake", (double)st->RefusedHandshake);
}

// The refusals of the front door and of QUIC, and the retry of msquic, into the front door object f
static void NodeStateRefused(cJSON *f, const NODE_LISTENER_STATUS *ls) {
	cJSON *r = cJSON_AddObjectToObject(f, "refused");

	NodeStateLimits(cJSON_AddObjectToObject(r, "tcp"), &ls->FrontDoorLimits);
	cJSON *q = cJSON_AddObjectToObject(r, "quic");
	NodeStateLimits(q, &ls->QuicLimits);
	cJSON_AddBoolToObject(q, "available", ls->HasQuic);
	cJSON_AddNumberToObject(q, "retryMemoryLimit", ls->QuicRetryMemoryLimit);
	cJSON_AddBoolToObject(q, "retrying", ls->QuicRetrying);
	cJSON_AddNumberToObject(q, "retries", (double)ls->QuicRetries);
}

// The listeners: the data transport of the overlay, the front door and QUIC of the Listener, the UDP port of the relay role
static void NodeStateListeners(NODE *n, const NODE_STATUS *ns, const char *overlay, cJSON *o) {
	NODE_LISTENER_STATUS *ls = ZeroMalloc(sizeof(NODE_LISTENER_STATUS));
	cJSON *l = cJSON_AddObjectToObject(o, "listeners");

	NodeListenerGetStatus(n, ls);
	cJSON_AddStringToObject(l, "overlay", overlay);
	cJSON *f = cJSON_AddObjectToObject(l, "frontDoor");
	cJSON_AddStringToObject(f, "listener", ls->Name);
	cJSON_AddBoolToObject(f, "running", ls->Running);
	cJSON_AddNumberToObject(f, "tcpPort", ls->Running ? ls->Port : 0);
	cJSON_AddNumberToObject(f, "quicPort", ls->Running ? ls->QuicPort : 0);
	cJSON_AddBoolToObject(f, "fallback", ls->Fallback);
	cJSON_AddStringToObject(f, "decoy", ls->Decoy);
	cJSON_AddStringToObject(f, "error", ls->Error);
	NodeStateRefused(f, ls);
	cJSON_AddNumberToObject(l, "relayUdpPort", ns->RelayPort);

	Free(ls);
}

// The answer to state: what the node does now
void NodeAdminState(NODE *n, cJSON *o) {
	NODE_STATUS ns;
	NODE_OVERLAY_STATUS *os = ZeroMalloc(sizeof(NODE_OVERLAY_STATUS));
	char roles[MAX_SIZE];
	char listener[TRANSPORT_NAME_SIZE];
	UINT64 now = GetTickCount64();

	if (n == NULL || o == NULL) {
		Free(os);
		return;
	}

	NodeGetStatus(n, &ns);
	NodeOverlayGetStatus(n, os);
	NodeRolesToStr(roles, sizeof(roles), ns.Roles);

	cJSON_AddBoolToObject(o, "running", ns.Running);
	cJSON_AddStringToObject(o, "roles", roles);
	cJSON_AddStringToObject(o, "name", os->Name);
	NodeStateController(n, os, now, o);
	NodeStateAdapters(n, os, o);
	NodeStateSessions(n, now, o, listener, sizeof(listener));
	NodeStateAgent(n, o);
	NodeStateListeners(n, &ns, listener, o);

	Free(os);
}
