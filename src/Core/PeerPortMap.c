// PeerPortMap.c
// The port mapping of a node behind a home gateway (ADR-0015 decision 5; CORE-S5-3, #79; CORE-S5-6, #412) on libplum:
// PCP, then NAT-PMP, then UPnP IGD, as the portmapper of Tailscale does, ask the gateway for a public port of the
// socket of the peer layer, the ICE socket (PeerIce.c). The node's signals then offer that port as their first
// candidate (PEER_CANDIDATE_MAPPED), and a peer reaches the node there without hole punching. libplum keeps the
// mapping alive and removes it at the end.
//
// It is opt-in for each node (Config.PortMap), off by default: a port that a gateway opens is attack surface, and many
// offices switch the protocols off. Without it libplum never starts, so no request of it leaves the node. With it the
// mapping starts once the host candidates of the layer name the port of its socket (PeerSetHostCandidates).
//
// libplum has one client per process, on a thread of its own: it starts with the first mapping and ends after the
// last one, with the timeouts of the node that started it.

#include "Core/PeerInternal.h"

#include <plum/plum.h>

// The client of libplum, and the nodes that have a mapping on it
static SRWLOCK PeerPlumLock = SRWLOCK_INIT;
static UINT PeerPlumUsers = 0;

// Ask the home gateway for a public port of the socket of the layer, whose port is port: the same number where the
// gateway allows it. The answer comes later (PeerPortMapGet). A node asks once.
void PeerPortMapStart(PEER_AGENT *a, USHORT port) {
	plum_config_t pc;
	plum_mapping_t m;

	if (port == 0)
		return;

	AcquireSRWLockExclusive(&PeerPlumLock);
	{
		bool started = (PeerPlumUsers != 0);

		if (a->Ice.Port == 0 && started == false) {
			ZeroMemory(&pc, sizeof(pc));
			pc.log_level = PLUM_LOG_LEVEL_WARN;
			pc.discover_timeout = (int)a->Config.PortMapTimeout;
			pc.mapping_timeout = (int)a->Config.PortMapTimeout;
			started = (plum_init(&pc) == PLUM_ERR_SUCCESS);
		}

		if (a->Ice.Port == 0 && started) {
			ZeroMemory(&m, sizeof(m));
			m.protocol = PLUM_IP_PROTOCOL_UDP;
			m.internal_port = port;
			m.external_port = port;

			int id = plum_create_mapping(&m, NULL);
			a->Ice.PortMap = (id >= 0 ? id : -1);
			a->Ice.Port = port;

			if (id >= 0)
				PeerPlumUsers++;
			else if (PeerPlumUsers == 0)
				plum_cleanup();
		}
	}
	ReleaseSRWLockExclusive(&PeerPlumLock);
}

// Remove the mapping from the gateway; the client of libplum ends after the last one
void PeerPortMapStop(PEER_AGENT *a) {
	if (a->Ice.PortMap < 0)
		return;

	AcquireSRWLockExclusive(&PeerPlumLock);
	{
		plum_destroy_mapping(a->Ice.PortMap);
		a->Ice.PortMap = -1;

		if (--PeerPlumUsers == 0)
			plum_cleanup();
	}
	ReleaseSRWLockExclusive(&PeerPlumLock);
}

// The public address and port that the home gateway granted; false while it has granted none
bool PeerPortMapGet(PEER_AGENT *a, PEER_ADDR *addr) {
	plum_state_t state;
	plum_mapping_t m;

	if (a->Ice.PortMap < 0 || plum_query_mapping(a->Ice.PortMap, &state, &m) != PLUM_ERR_SUCCESS || state != PLUM_STATE_SUCCESS)
		return false;

	m.external_host[PLUM_MAX_HOST_LEN - 1] = 0;

	return m.external_port != 0 && PeerAddrFromHost(addr, m.external_host, m.external_port);
}

// Where the port mapping is (PEER_PORTMAP_*): off without Config.PortMap, asking while libplum has no answer yet, then
// mapped or failed
UINT PeerPortMapState(PEER_AGENT *a) {
	plum_state_t state;
	plum_mapping_t m;
	PEER_ADDR addr;

	if (a->Config.PortMap == false)
		return PEER_PORTMAP_OFF;

	if (PeerPortMapGet(a, &addr))
		return PEER_PORTMAP_MAPPED;

	// The socket has no port yet, or libplum still asks
	if (a->Ice.Port == 0 || (a->Ice.PortMap >= 0 && plum_query_mapping(a->Ice.PortMap, &state, &m) == PLUM_ERR_SUCCESS && state == PLUM_STATE_PENDING))
		return PEER_PORTMAP_PENDING;

	return PEER_PORTMAP_FAILED;
}
