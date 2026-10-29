// TransportQuicExporter.c
// The channel binding of a QUIC connection (CORE-H5, #408): the TLS exporter of the connection (RFC 8446 section 7.5,
// RFC 9001 section 4.1) with NOISE_EXPORTER_LABEL, no context and NOISE_EXPORTER_SIZE bytes, the binding of the TLS-443
// path (TlsExporter). msquic gives it from 2.6 on through ConnectionExportKeyingMaterial, which its Schannel build
// answers with SECPKG_ATTR_KEYING_MATERIAL; the API table has that entry in the preview part of the header only, so this
// file includes msquic.h with the preview features (as TransportQuicXdp.c does for the settings of the XDP datapath, and no
// other file of the module). The exporter is of one connection: a middlebox that
// holds the key of the certificate and terminates the QUIC session of a client has one exporter with the client and
// another with the server, so the Noise handshake that it relays fails (finding F1 of docs/formal-model.md).
//
// The preview part of the table may move or change with a minor version, so the entry is read only from the minor that
// the build was made against (TRANSPORT_QUIC_EXPORTER_MAJOR.MINOR, CORE-H5-R #443); a side without an exporter, whatever
// the reason, says so in the transport log (TransportLog.c), once per side and reason, since its sessions with a bound
// peer fail.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/TransportInternal.h"

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include <msquic.h>

// Why a side has no exporter, each logged once per side
#define QUIC_EXPORTER_NO_VERSION 0 // msquic does not tell its version
#define QUIC_EXPORTER_UNPINNED   1 // Its version is not the pinned minor
#define QUIC_EXPORTER_NO_ENTRY   2 // Its API table has no exporter
#define QUIC_EXPORTER_FAILED     3 // The connection gave none
#define QUIC_EXPORTER_REASONS    4

static volatile LONG g_quic_exporter_logged[2][QUIC_EXPORTER_REASONS]; // [server][reason]: the line went out

// The name of a side in the log
static const char *QuicExporterSide(bool server) {
	return (server ? "server" : "client");
}

// Whether the line of reason on the side is still to go out: true once per side and reason
static bool QuicExporterFirst(bool server, UINT reason) {
	return (InterlockedExchange(&g_quic_exporter_logged[server ? 1 : 0][reason], 1) == 0);
}

bool TransportQuicExporterVersion(const UINT *version, bool server) {
	if (version == NULL)
		return false;

	if (version[0] == TRANSPORT_QUIC_EXPORTER_MAJOR && version[1] == TRANSPORT_QUIC_EXPORTER_MINOR)
		return true;

	if (QuicExporterFirst(server, QUIC_EXPORTER_UNPINNED))
		TransportLog("QUIC: the %s side has no exporter: msquic %u.%u.%u is not the pinned %u.%u, whose API table this build reads "
		             "the exporter from, so its streams stay unbound and its sessions with a bound peer fail",
		             QuicExporterSide(server), version[0], version[1], version[2], (UINT)TRANSPORT_QUIC_EXPORTER_MAJOR,
		             (UINT)TRANSPORT_QUIC_EXPORTER_MINOR);
	return false;
}

// Whether the msquic that api is the table of has the exporter: its version is the pinned minor and its table has the
// entry. The side's line of the log says why not.
static bool QuicExporterAvailable(const QUIC_API_TABLE *api, bool server) {
	uint32_t version[4];
	uint32_t size = sizeof(version);

	ZeroMemory(version, sizeof(version));
	if (QUIC_FAILED(api->GetParam(NULL, QUIC_PARAM_GLOBAL_LIBRARY_VERSION, &size, version)) || size != sizeof(version)) {
		if (QuicExporterFirst(server, QUIC_EXPORTER_NO_VERSION))
			TransportLog("QUIC: the %s side has no exporter: msquic does not tell its version, so its streams stay unbound and its "
			             "sessions with a bound peer fail",
			             QuicExporterSide(server));
		return false;
	}

	if (TransportQuicExporterVersion((const UINT *)version, server) == false)
		return false;

	if (api->ConnectionExportKeyingMaterial == NULL) {
		if (QuicExporterFirst(server, QUIC_EXPORTER_NO_ENTRY))
			TransportLog("QUIC: the %s side has no exporter: the API table of msquic %u.%u.%u has no ConnectionExportKeyingMaterial, "
			             "so its streams stay unbound and its sessions with a bound peer fail",
			             QuicExporterSide(server), version[0], version[1], version[2]);
		return false;
	}

	return true;
}

bool TransportQuicExporter(const void *api, void *connection, bool server, UCHAR *exporter) {
	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;
	QUIC_KEYING_MATERIAL_CONFIG cfg;

	if (quic == NULL || connection == NULL || exporter == NULL || QuicExporterAvailable(quic, server) == false)
		return false;

	ZeroMemory(&cfg, sizeof(cfg));
	cfg.Label = NOISE_EXPORTER_LABEL;
	cfg.OutputLength = NOISE_EXPORTER_SIZE;
	QUIC_STATUS status = quic->ConnectionExportKeyingMaterial((HQUIC)connection, &cfg, exporter);
	if (QUIC_FAILED(status)) {
		SecureZeroMemory(exporter, NOISE_EXPORTER_SIZE);
		if (QuicExporterFirst(server, QUIC_EXPORTER_FAILED))
			TransportLog("QUIC: the %s side of a connection got no exporter from msquic (status 0x%08X), so its streams stay unbound "
			             "and its sessions with a bound peer fail",
			             QuicExporterSide(server), (UINT)status);
		return false;
	}

	return true;
}
