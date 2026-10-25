// TransportTlsAlpn.c
// The ALPN protocol of a client of the TLS transport (SDN-90, #395). The controller's port tells the control stream of a
// Node from the HTTP of its API by the ALPN protocol of the TLS session (CONTROL_ALPN), so the client of the control
// stream offers that protocol in its ClientHello and takes a session only when the server selected it. Schannel takes the
// list of the ClientHello in a SECBUFFER_APPLICATION_PROTOCOLS buffer of the first InitializeSecurityContext of the client
// and tells the protocol that the server selected through SECPKG_ATTR_APPLICATION_PROTOCOL.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/Transport.h"
#include "Core/TransportInternal.h"

#define SECURITY_WIN32
#include <security.h>

#include <string.h>

SecBufferDesc *TransportTlsAlpnOffer(const TRANSPORT_TLS_CONFIG *cfg, SecBufferDesc *desc, SecBuffer *buf, ULONG *list, UINT size) {
	SEC_APPLICATION_PROTOCOLS *p = (SEC_APPLICATION_PROTOCOLS *)list;
	size_t name = (cfg != NULL ? strnlen(cfg->Alpn, sizeof(cfg->Alpn)) : 0);
	UINT entry = (UINT)(FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) + 1 + name);
	UINT need = (UINT)FIELD_OFFSET(SEC_APPLICATION_PROTOCOLS, ProtocolLists) + entry;

	// A protocol id is 1 to 255 bytes after its length (RFC 7301 section 3.1)
	if (name == 0 || name >= sizeof(cfg->Alpn) || desc == NULL || buf == NULL || list == NULL || need > size)
		return NULL;

	ZeroMemory(list, size);
	p->ProtocolListsSize = entry;
	p->ProtocolLists[0].ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
	p->ProtocolLists[0].ProtocolListSize = (unsigned short)(1 + name);
	// The one protocol id after its length, past the ANYSIZE_ARRAY of the header
	UCHAR *ids = (UCHAR *)list + FIELD_OFFSET(SEC_APPLICATION_PROTOCOLS, ProtocolLists) + FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList);
	ids[0] = (UCHAR)name;
	CopyMemory(ids + 1, cfg->Alpn, name);

	buf->BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
	buf->cbBuffer = need;
	buf->pvBuffer = list;
	desc->ulVersion = SECBUFFER_VERSION;
	desc->cBuffers = 1;
	desc->pBuffers = buf;

	return desc;
}

bool TransportTlsAlpnSelected(const TRANSPORT_TLS_CONFIG *cfg, CtxtHandle *ctx) {
	SecPkgContext_ApplicationProtocol selected;
	size_t name = (cfg != NULL ? strnlen(cfg->Alpn, sizeof(cfg->Alpn)) : 0);

	if (name == 0)
		return true;

	ZeroMemory(&selected, sizeof(selected));
	if (ctx == NULL || QueryContextAttributesW(ctx, SECPKG_ATTR_APPLICATION_PROTOCOL, &selected) != SEC_E_OK)
		return false;

	return (selected.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success && selected.ProtoNegoExt == SecApplicationProtocolNegotiationExt_ALPN &&
	        selected.ProtocolIdSize == name && memcmp(selected.ProtocolId, cfg->Alpn, name) == 0);
}
