// TransportQuicExporter.c
// The channel binding of a QUIC connection (CORE-H5, #408): the TLS exporter of the connection (RFC 8446 section 7.5,
// RFC 9001 section 4.1) with NOISE_EXPORTER_LABEL, no context and NOISE_EXPORTER_SIZE bytes, the binding of the TLS-443
// path (TlsExporter). msquic gives it from 2.6 on through ConnectionExportKeyingMaterial, which its Schannel build
// answers with SECPKG_ATTR_KEYING_MATERIAL; the API table has that entry in the preview part of the header only, so this
// file, and no other, includes msquic.h with the preview features. The exporter is of one connection: a middlebox that
// holds the key of the certificate and terminates the QUIC session of a client has one exporter with the client and
// another with the server, so the Noise handshake that it relays fails (finding F1 of docs/formal-model.md).

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/TransportInternal.h"

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include <msquic.h>

#define QUIC_EXPORTER_MAJOR 2 // The msquic whose API table has ConnectionExportKeyingMaterial: 2.6 and later 2.x
#define QUIC_EXPORTER_MINOR 6

// Whether the msquic that api is the table of has the exporter: its version is 2.6 or a later 2.x, since the table of
// an older one ends before the entry
static bool QuicExporterAvailable(const QUIC_API_TABLE *api) {
	uint32_t version[4];
	uint32_t size = sizeof(version);

	ZeroMemory(version, sizeof(version));
	if (QUIC_FAILED(api->GetParam(NULL, QUIC_PARAM_GLOBAL_LIBRARY_VERSION, &size, version)) || size != sizeof(version))
		return false;

	return (version[0] == QUIC_EXPORTER_MAJOR && version[1] >= QUIC_EXPORTER_MINOR && api->ConnectionExportKeyingMaterial != NULL);
}

bool TransportQuicExporter(const void *api, void *connection, UCHAR *exporter) {
	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;
	QUIC_KEYING_MATERIAL_CONFIG cfg;

	if (quic == NULL || connection == NULL || exporter == NULL || QuicExporterAvailable(quic) == false)
		return false;

	ZeroMemory(&cfg, sizeof(cfg));
	cfg.Label = NOISE_EXPORTER_LABEL;
	cfg.OutputLength = NOISE_EXPORTER_SIZE;
	if (QUIC_FAILED(quic->ConnectionExportKeyingMaterial((HQUIC)connection, &cfg, exporter))) {
		SecureZeroMemory(exporter, NOISE_EXPORTER_SIZE);
		return false;
	}

	return true;
}
