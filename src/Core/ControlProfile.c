// ControlProfile.c
// The session profiles of a node and of its peers on the control stream (SDN-40, #233; Core/Control.h). The NodeConfig of a
// state carries the profile that the node runs under as a device of a User (CONTROL_STATE.Profile), and each Peer object the
// one of the peer, which the node enforces on its session with it (CONTROL_PEER.Profile). They go with the state, as the
// owner takes it (ControlCopyProfiles).

#include "Core/ControlInternal.h"

#include <string.h>

// The session profile src into dst
static void ControlCopyProfile(CONTROL_PROFILE *dst, const ranz_control_v1_SessionProfile *src) {
	ZeroMemory(dst, sizeof(CONTROL_PROFILE));
	dst->Set = true;
	strncpy_s(dst->Name, sizeof(dst->Name), src->name, _TRUNCATE);
	strncpy_s(dst->User, sizeof(dst->User), src->user, _TRUNCATE);
	dst->UploadLimit = src->upload_limit;
	dst->DownloadLimit = src->download_limit;
	dst->MaxSessions = src->max_sessions;
	dst->MaxMacs = src->max_macs;
	dst->MaxIpv4 = src->max_ipv4;
	dst->MaxIpv6 = src->max_ipv6;
	dst->IdleTimeout = src->idle_timeout;
	dst->AutoDisconnect = src->auto_disconnect;
	dst->NoBridge = src->no_bridge;
	dst->NoRouting = src->no_routing;
	dst->NoServer = src->no_server;
	dst->PrivacyFilter = src->privacy_filter;
}

// The session profiles of the NodeConfig and of each Peer object among num objects into the state, which holds the peers
// that the client took from them already: the profile of the node into the state, the one of a Peer object into the peer of
// its name. A node or a peer without one runs under none.
void ControlCopyProfiles(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	ZeroMemory(&st->Profile, sizeof(st->Profile));

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_node_tag && o->kind.node.has_profile) {
			ControlCopyProfile(&st->Profile, &o->kind.node.profile);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag && o->kind.peer.has_profile) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (strcmp(p->Name, o->kind.peer.name) == 0)
					ControlCopyProfile(&p->Profile, &o->kind.peer.profile);
			}
		}
	}
}
