// PeerPortMap.c
// The port mapping of a node behind a home gateway (ADR-0015 decision 5; CORE-S5-3, #79) on libplum: PCP, then
// NAT-PMP, then UPnP IGD, as the portmapper of Tailscale does, ask the gateway for a public port of the node's ICE
// socket (PeerIce.c). The node's signals then offer that port as a candidate (PEER_CANDIDATE_MAPPED), and a peer
// reaches the node there without hole punching. libplum keeps the mapping alive and removes it at the end.
//
// libplum has one client per process, on a thread of its own: it starts with the first mapping and ends after the
// last one, with the timeouts of the node that started it.

#include "Core/PeerInternal.h"

#include <plum/plum.h>

// The client of libplum, and the nodes that have a mapping on it
static SRWLOCK PeerPlumLock = SRWLOCK_INIT;
static UINT PeerPlumUsers = 0;

// Ask the home gateway for a public port of the ICE socket: the same number as the socket's port where the gateway
// allows it. The answer comes later (PeerPortMapGet).
void PeerPortMapStart(PEER_AGENT *a) {
	plum_config_t pc;
	plum_mapping_t m;

	AcquireSRWLockExclusive(&PeerPlumLock);
	{
		bool started = (PeerPlumUsers != 0);

		if (started == false) {
			ZeroMemory(&pc, sizeof(pc));
			pc.log_level = PLUM_LOG_LEVEL_WARN;
			pc.discover_timeout = (int)a->Config.PortMapTimeout;
			pc.mapping_timeout = (int)a->Config.PortMapTimeout;
			started = (plum_init(&pc) == PLUM_ERR_SUCCESS);
		}

		if (started) {
			ZeroMemory(&m, sizeof(m));
			m.protocol = PLUM_IP_PROTOCOL_UDP;
			m.internal_port = a->Ice.Port;
			m.external_port = a->Ice.Port;

			int id = plum_create_mapping(&m, NULL);
			a->Ice.PortMap = (id >= 0 ? id : -1);

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
