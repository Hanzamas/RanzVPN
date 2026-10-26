// quicexporter.c
// The msquic of the exporter of a QUIC connection (CORE-H5-R, #443; src/Core/TransportQuicExporter.c). The exporter,
// ConnectionExportKeyingMaterial, sits in the preview part of the msquic API table, so it is read only from the pinned
// minor version (TRANSPORT_QUIC_EXPORTER_MAJOR.MINOR, any patch); another minor is refused with a line of the transport
// log, and so is a side whose msquic gives no exporter for another reason, once per side and reason. The test runs the
// check of the version on its own and the exporter on an API table of its own, which stands for msquic: it answers the
// version and the export as the test sets them, so no msquic.dll is needed.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "coretest.h"

#include "Core/Transport.h"

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include <msquic.h>

#include <string.h>

#define QUICEXPORTER_PATTERN 0x5A // The bytes of the exporter that the table of the test gives

// What the transport log of the test took: the lines and the last one
typedef struct QUICEXPORTER_LOG {
	UINT NumLines;
	char Last[TRANSPORT_LOG_SIZE];
} QUICEXPORTER_LOG;

// What the API table of the test answers
static uint32_t quicexporter_version[4];     // The version it tells ...
static bool quicexporter_no_version = false; // ... or none
static QUIC_STATUS quicexporter_status = 0;  // What the export gives
static UINT quicexporter_length = 0;         // The OutputLength it was asked for
static bool quicexporter_label = false;      // ... and whether its label was NOISE_EXPORTER_LABEL, without a context

static void quicexporter_log(void *param, const char *line) {
	QUICEXPORTER_LOG *seen =(QUICEXPORTER_LOG *)param;

	seen->NumLines++;
	strncpy_s(seen->Last, sizeof(seen->Last), line, _TRUNCATE);
	coretest_info("transport log: %s", line);
}

static QUIC_STATUS QUIC_API quicexporter_get_param(HQUIC handle, uint32_t param, uint32_t *length, void *buffer) {
	if (handle != NULL || param != QUIC_PARAM_GLOBAL_LIBRARY_VERSION || quicexporter_no_version || *length < sizeof(quicexporter_version))
		return QUIC_STATUS_NOT_SUPPORTED;

	memcpy(buffer, quicexporter_version, sizeof(quicexporter_version));
	*length = sizeof(quicexporter_version);
	return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API quicexporter_export(HQUIC connection, const QUIC_KEYING_MATERIAL_CONFIG *cfg, uint8_t *output) {
	UNREFERENCED_PARAMETER(connection);

	quicexporter_length = cfg->OutputLength;
	quicexporter_label = (cfg->Label != NULL && strcmp(cfg->Label, NOISE_EXPORTER_LABEL) == 0 && cfg->ContextLength == 0);
	if (QUIC_FAILED(quicexporter_status))
		return quicexporter_status;

	memset(output, QUICEXPORTER_PATTERN, cfg->OutputLength);
	return QUIC_STATUS_SUCCESS;
}

// Set the version that the table of the test tells
static void quicexporter_set_version(uint32_t major, uint32_t minor, uint32_t patch) {
	quicexporter_version[0] = major;
	quicexporter_version[1] = minor;
	quicexporter_version[2] = patch;
	quicexporter_version[3] = 0;
	quicexporter_no_version = false;
}

// Whether the size bytes of p are all b
static bool quicexporter_all(const UCHAR *p, UINT size, UCHAR b) {
	for (UINT i = 0; i < size; i++) {
		if (p[i] != b)
			return false;
	}

	return true;
}

// The check of the version on its own: the pinned minor with any patch passes, another minor or major is refused with one
// line of the log for each side, which names the side and the version
static void quicexporter_versions(QUICEXPORTER_LOG *seen) {
	UINT pinned[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR, 2, 0};
	UINT patch[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR, 0, 0};
	UINT next[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR + 1, 0, 0};
	UINT next_patch[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR + 1, 1, 0};
	UINT major[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR + 1, TRANSPORT_QUIC_EXPORTER_MINOR, 0, 0};
	UINT before[4] = {TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR - 1, 1, 0};
	char want[64];

	coretest_check(TransportQuicExporterVersion(pinned, true) && TransportQuicExporterVersion(patch, false) && seen->NumLines == 0,
	               "the pinned msquic minor passes, with any patch, on both sides, and logs nothing");

	snprintf(want, sizeof(want), "msquic %u.%u.0 is not the pinned %u.%u", next[0], next[1], pinned[0], pinned[1]);
	coretest_check(TransportQuicExporterVersion(next, true) == false && seen->NumLines == 1 && strstr(seen->Last, "the server side has no exporter") != NULL &&
	                   strstr(seen->Last, want) != NULL,
	               "the next minor is refused on the server side, with a line of the log that names the side and the version");
	coretest_check(TransportQuicExporterVersion(next_patch, true) == false && seen->NumLines == 1,
	               "... refused again without a second line for that side");

	snprintf(want, sizeof(want), "msquic %u.%u.0 is not the pinned %u.%u", major[0], major[1], pinned[0], pinned[1]);
	coretest_check(TransportQuicExporterVersion(major, false) == false && seen->NumLines == 2 && strstr(seen->Last, "the client side has no exporter") != NULL &&
	                   strstr(seen->Last, want) != NULL,
	               "the next major with the pinned minor is refused on the client side, with its own line");
	coretest_check(TransportQuicExporterVersion(before, false) == false && seen->NumLines == 2,
	               "the minor before the pinned one is refused too, the client side's line already out");
	coretest_check(TransportQuicExporterVersion(NULL, true) == false && seen->NumLines == 2, "no version is refused");
}

// The exporter on the table of the test: the pinned minor gives the exporter with NOISE_EXPORTER_LABEL; a table without
// the entry, a connection that gives none and an msquic that does not tell its version each leave the side without an
// exporter, wiped, and log one line
static void quicexporter_exporter(QUICEXPORTER_LOG *seen) {
	QUIC_API_TABLE api;
	UCHAR exporter[NOISE_EXPORTER_SIZE];
	UCHAR connection = 0;
	UINT lines = seen->NumLines;

	ZeroMemory(&api, sizeof(api));
	api.GetParam = quicexporter_get_param;
	api.ConnectionExportKeyingMaterial = quicexporter_export;

	quicexporter_set_version(TRANSPORT_QUIC_EXPORTER_MAJOR, TRANSPORT_QUIC_EXPORTER_MINOR, 2);
	quicexporter_status = QUIC_STATUS_SUCCESS;
	ZeroMemory(exporter, sizeof(exporter));
	coretest_check(TransportQuicExporter(&api, &connection, true, exporter) && quicexporter_all(exporter, sizeof(exporter), QUICEXPORTER_PATTERN) &&
	                   quicexporter_length == NOISE_EXPORTER_SIZE && quicexporter_label && seen->NumLines == lines,
	               "the pinned msquic gives the exporter of NOISE_EXPORTER_SIZE bytes with NOISE_EXPORTER_LABEL and no context, and logs nothing");

	quicexporter_status = QUIC_STATUS_INVALID_STATE;
	FillMemory(exporter, sizeof(exporter), 0x11);
	coretest_check(TransportQuicExporter(&api, &connection, false, exporter) == false && quicexporter_all(exporter, sizeof(exporter), 0) &&
	                   seen->NumLines == lines + 1 && strstr(seen->Last, "the client side of a connection got no exporter from msquic") != NULL,
	               "a connection that gives no exporter: the client side has none, the output is wiped, and a line of the log says so");
	coretest_check(TransportQuicExporter(&api, &connection, false, exporter) == false && seen->NumLines == lines + 1,
	               "... again on the client side without a second line");

	api.ConnectionExportKeyingMaterial = NULL;
	coretest_check(TransportQuicExporter(&api, &connection, true, exporter) == false && seen->NumLines == lines + 2 &&
	                   strstr(seen->Last, "the server side has no exporter") != NULL && strstr(seen->Last, "no ConnectionExportKeyingMaterial") != NULL,
	               "a table without the entry: the server side has no exporter, and a line of the log says so");

	api.ConnectionExportKeyingMaterial = quicexporter_export;
	quicexporter_no_version = true;
	coretest_check(TransportQuicExporter(&api, &connection, true, exporter) == false && seen->NumLines == lines + 3 &&
	                   strstr(seen->Last, "msquic does not tell its version") != NULL,
	               "an msquic that does not tell its version: the server side has no exporter, and a line of the log says so");

	coretest_check(TransportQuicExporter(NULL, &connection, true, exporter) == false && TransportQuicExporter(&api, NULL, true, exporter) == false &&
	                   TransportQuicExporter(&api, &connection, true, NULL) == false,
	               "no table, no connection or no output is refused");

	// Without the procedure of the log, a line goes to the debugger and not to the procedure before
	TransportSetLog(NULL, NULL);
	coretest_check(TransportQuicExporter(&api, &connection, false, exporter) == false && seen->NumLines == lines + 3,
	               "with the log set back to the debugger, the client side's line goes there and not to the procedure of the test");
}

void quicexporter_test() {
	QUICEXPORTER_LOG seen;

	ZeroMemory(&seen, sizeof(seen));
	TransportSetLog(quicexporter_log, &seen);

	quicexporter_versions(&seen);
	quicexporter_exporter(&seen);

	TransportSetLog(NULL, NULL);
}
