// TransportQuicGroup.c
// The key exchange group of a QUIC connection (CORE-P2-5, #382; Core/TransportInternal.h): the TlsGroup of the handshake
// information that msquic gives for a connection (QUIC_PARAM_TLS_HANDSHAKE_INFO), the field that msquic 2.5 added, which
// its Schannel build fills with the dwKeyType of the cipher information of its context, as the TLS-443 path reads its own
// (TransportTls.c). The QUIC transport takes it in the CONNECTED event, as it takes the exporter (TransportQuicExporter.c),
// while msquic still holds the TLS state, which a server lets go of once the client acknowledged its handshake. The field
// is in the stable part of msquic.h, so this file needs no preview features.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/TransportInternal.h"

#include <msquic.h>

UINT TransportQuicGroup(const void *api, void *connection) {
	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;
	QUIC_HANDSHAKE_INFO info;
	uint32_t size = sizeof(info);

	if (quic == NULL || connection == NULL)
		return 0;

	// An msquic before 2.5 fills the information up to the cipher suite only, and leaves the group as it found it: 0
	ZeroMemory(&info, sizeof(info));
	if (QUIC_FAILED(quic->GetParam((HQUIC)connection, QUIC_PARAM_TLS_HANDSHAKE_INFO, &size, &info)))
		return 0;

	return (UINT)info.TlsGroup;
}
