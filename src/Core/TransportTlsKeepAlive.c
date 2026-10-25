// TransportTlsKeepAlive.c
// The TCP keepalive of a client of the TLS transport (SDN-90, #395). The control stream of a Node is quiet while its
// desired state does not change: the controller sends nothing, and the node writes only its Acks and its leases. A path
// that goes dead without a reset, a cable or a Wi-Fi that drops, a NAT that forgets the mapping, would leave the node on a
// stream that no read and no write ever ends, so it would never dial again. With KeepAlive in its configuration the client
// turns on the keepalive of Windows on the socket of each connection: after KeepAlive seconds without a segment, the
// probes of TRANSPORT_TLS_KEEPALIVE_PROBES and TRANSPORT_TLS_KEEPALIVE_INTERVAL, and the socket fails once none of them is
// answered, which ends the stream.

#include "Core/TransportInternal.h"

bool TransportTlsKeepAlive(const TRANSPORT_TLS_CONFIG *cfg, UINT_PTR socket) {
	SOCKET s = (SOCKET)socket;
	BOOL on = TRUE;
	DWORD idle = (cfg != NULL ? cfg->KeepAlive : 0);
	DWORD interval = TRANSPORT_TLS_KEEPALIVE_INTERVAL;
	DWORD probes = TRANSPORT_TLS_KEEPALIVE_PROBES;

	if (idle == 0)
		return true;

	// The options of Windows 10 1709 and later, which the new core needs anyway; SIO_KEEPALIVE_VALS sets no count
	return (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on)) == 0 &&
	        setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (const char *)&idle, sizeof(idle)) == 0 &&
	        setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, (const char *)&interval, sizeof(interval)) == 0 &&
	        setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, (const char *)&probes, sizeof(probes)) == 0);
}
