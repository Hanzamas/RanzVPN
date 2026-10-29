// TransportQuicXdp.c
// The XDP datapath of msquic and QTIP for the QUIC transport (CORE-S7-2, #83; ADR-0018 decisions 2 and 5, ADR-0022;
// Core/Transport.h). msquic takes both as settings of QUIC_SETTINGS, XdpEnabled and QTIPEnabled, in the preview part of
// its header, so this file includes msquic.h with the preview features, as TransportQuicExporter.c does for the exporter,
// and TransportQuic.c, which includes it without them, calls this file for what needs them:
// - the datapath of a transport (TransportQuicXdpChoose): what its configuration asks, where the host and msquic let it
//   run;
// - the settings of its configuration (TransportQuicXdpSettings), which name both, so that msquic takes neither from its
//   global settings;
// - the start of its listeners (TransportQuicXdpListen): msquic takes the datapath of a listener from its global settings
//   when the listener starts, so a listener starts with them set for its own transport, and they are put back at once,
//   under a lock that every start of a listener of the module takes.
// The code follows docs/XDP.md and docs/QTIP.md of microsoft/msquic and its settings.c, listener.c and connection.c at the
// pinned release, which read the settings so (ADR-0002 amendment of 2026-10-21: the reference where CI cannot reach).

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/TransportInternal.h"

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include <msquic.h>

// Every start of a listener of the module, so that the global settings that one sets for its datapath reach no other
static SRWLOCK g_quic_xdp_lock = SRWLOCK_INIT;

bool TransportQuicXdpAllowed(bool server, UINT machine) {
	return (server && machine == PROCESSOR_ARCHITECTURE_AMD64);
}

// Whether this host runs a server edition of Windows: its product type is not the one of a workstation, as IsWindowsServer
// of VersionHelpers.h asks it, where a question that fails is no answer
static bool QuicXdpServerEdition() {
	OSVERSIONINFOEXW os;

	ZeroMemory(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	os.wProductType = VER_NT_WORKSTATION;

	if (VerifyVersionInfoW(&os, VER_PRODUCT_TYPE, VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL)))
		return false;

	return (GetLastError() == ERROR_OLD_WIN_VERSION);
}

bool TransportQuicXdpHost() {
	SYSTEM_INFO info;

	// The native architecture, as the Capabilities of a node take it: the same whichever architecture the program was built
	// for
	ZeroMemory(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	return TransportQuicXdpAllowed(QuicXdpServerEdition(), info.wProcessorArchitecture);
}

bool TransportQuicXdpRelease(const UINT *version) {
	if (version == NULL || version[0] != TRANSPORT_QUIC_QTIP_MAJOR)
		return false;

	return (version[1] >= TRANSPORT_QUIC_QTIP_MINOR && version[1] <= TRANSPORT_QUIC_EXPORTER_MINOR);
}

// The version of the msquic of api into version, its four numbers; false, with version zero, when it tells none
static bool QuicXdpVersion(const QUIC_API_TABLE *api, UINT *version) {
	uint32_t v[4];
	uint32_t size = sizeof(v);

	ZeroMemory(version, 4 * sizeof(UINT));
	ZeroMemory(v, sizeof(v));
	if (QUIC_FAILED(api->GetParam(NULL, QUIC_PARAM_GLOBAL_LIBRARY_VERSION, &size, v)) || size != sizeof(v))
		return false;

	for (UINT i = 0; i < 4; i++)
		version[i] = v[i];

	return true;
}

// Whether the msquic of api takes XdpEnabled and QTIPEnabled where this build sets them
static bool QuicXdpKnown(const QUIC_API_TABLE *api) {
	UINT version[4];

	return (QuicXdpVersion(api, version) && TransportQuicXdpRelease(version));
}

// The global settings of msquic now into settings; false when it tells none
static bool QuicXdpGetGlobal(const QUIC_API_TABLE *api, QUIC_SETTINGS *settings) {
	uint32_t size = sizeof(QUIC_SETTINGS);

	ZeroMemory(settings, sizeof(QUIC_SETTINGS));

	return QUIC_SUCCEEDED(api->GetParam(NULL, QUIC_PARAM_GLOBAL_SETTINGS, &size, settings));
}

// Set XdpEnabled and QTIPEnabled of the global settings of msquic, which a listener takes when it starts, and nothing else
static bool QuicXdpSetGlobal(const QUIC_API_TABLE *api, bool xdp, bool qtip) {
	QUIC_SETTINGS s;

	ZeroMemory(&s, sizeof(s));
	s.IsSet.XdpEnabled = 1;
	s.XdpEnabled = (xdp ? 1 : 0);
	s.IsSet.QTIPEnabled = 1;
	s.QTIPEnabled = (qtip ? 1 : 0);

	return QUIC_SUCCEEDED(api->SetParam(NULL, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(s), &s));
}

bool TransportQuicXdpChoose(const void *api, const TRANSPORT_QUIC_CONFIG *cfg, bool server, UINT *datapath) {
	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;
	const char *side = (server ? "server" : "client");
	const char *mode = (cfg->Qtip ? "QTIP" : "the XDP datapath of msquic");
	const char *then = (cfg->Qtip ? "it is not made, since QTIP has no normal datapath" : "it keeps the normal datapath");
	UINT version[4];

	*datapath = TRANSPORT_QUIC_DATAPATH_NORMAL;
	if (cfg->Xdp == false && cfg->Qtip == false)
		return true;

	if (TransportQuicXdpHost() == false) {
		TransportLog("QUIC: the %s transport %s asks for %s, which runs on Windows Server x64 only: %s", side, cfg->Name, mode, then);
		return (cfg->Qtip == false);
	}

	if (QuicXdpVersion(quic, version) == false || TransportQuicXdpRelease(version) == false) {
		TransportLog("QUIC: the %s transport %s asks for %s, which this build sets on msquic %u.%u to %u.%u, not on msquic %u.%u.%u: %s",
		             side, cfg->Name, mode, (UINT)TRANSPORT_QUIC_QTIP_MAJOR, (UINT)TRANSPORT_QUIC_QTIP_MINOR,
		             (UINT)TRANSPORT_QUIC_EXPORTER_MAJOR, (UINT)TRANSPORT_QUIC_EXPORTER_MINOR, version[0], version[1], version[2], then);
		return (cfg->Qtip == false);
	}

	*datapath = (cfg->Qtip ? TRANSPORT_QUIC_DATAPATH_QTIP : TRANSPORT_QUIC_DATAPATH_XDP);

	return true;
}

void TransportQuicXdpSettings(const void *api, void *settings, UINT datapath) {
	QUIC_SETTINGS *s = (QUIC_SETTINGS *)settings;

	// A transport of the normal datapath names both off where msquic takes them, so that no global setting reaches it, and
	// leaves the settings for another msquic as they were; one of another datapath was made on such an msquic only
	if (datapath == TRANSPORT_QUIC_DATAPATH_NORMAL && QuicXdpKnown((const QUIC_API_TABLE *)api) == false)
		return;

	s->IsSet.XdpEnabled = 1;
	s->XdpEnabled = (datapath != TRANSPORT_QUIC_DATAPATH_NORMAL ? 1 : 0);
	s->IsSet.QTIPEnabled = 1;
	s->QTIPEnabled = (datapath == TRANSPORT_QUIC_DATAPATH_QTIP ? 1 : 0);
}

bool TransportQuicXdpListen(const void *api, void *listener, const void *alpn, const void *address, UINT datapath) {
	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;
	bool xdp = (datapath != TRANSPORT_QUIC_DATAPATH_NORMAL);
	bool qtip = (datapath == TRANSPORT_QUIC_DATAPATH_QTIP);
	QUIC_SETTINGS before;
	bool set = false;
	bool ok = true;

	ZeroMemory(&before, sizeof(before));

	AcquireSRWLockExclusive(&g_quic_xdp_lock);

	// The global settings as the datapath of the listener wants them, where they differ: off for a listener of the normal
	// datapath too, so that a registry setting of msquic does not put it on XDP. An msquic without them starts the listener
	// as before.
	bool have = (QuicXdpKnown(quic) && QuicXdpGetGlobal(quic, &before));
	bool differ = (have && ((before.XdpEnabled != 0) != xdp || (before.QTIPEnabled != 0) != qtip));

	if (differ)
		set = QuicXdpSetGlobal(quic, xdp, qtip);

	// A listener of the XDP datapath starts only with the global settings for it; one of the normal datapath starts anyway
	if (xdp)
		ok = (have && (differ == false || set));

	if (ok)
		ok = QUIC_SUCCEEDED(quic->ListenerStart((HQUIC)listener, (const QUIC_BUFFER *)alpn, 1, (const QUIC_ADDR *)address));

	// ... and back as they were, for the next start
	if (set)
		(void)QuicXdpSetGlobal(quic, before.XdpEnabled != 0, before.QTIPEnabled != 0);

	ReleaseSRWLockExclusive(&g_quic_xdp_lock);

	return ok;
}

bool TransportQuicGetXdpStatus(TRANSPORT *t, TRANSPORT_QUIC_XDP_STATUS *st) {
	const void *api = NULL;
	void *configuration = NULL;
	UINT datapath = TRANSPORT_QUIC_DATAPATH_NORMAL;
	QUIC_SETTINGS s;
	uint32_t size = sizeof(s);

	if (st == NULL)
		return false;

	ZeroMemory(st, sizeof(TRANSPORT_QUIC_XDP_STATUS));
	if (TransportQuicXdpOf(t, &api, &configuration, &datapath) == false || api == NULL || configuration == NULL)
		return false;

	const QUIC_API_TABLE *quic = (const QUIC_API_TABLE *)api;

	st->Datapath = datapath;
	if (QuicXdpVersion(quic, st->Version) == false)
		return false;

	// The preview part of the settings is read only from an msquic that has it where this build looks
	st->Release = TransportQuicXdpRelease(st->Version);
	if (st->Release == false)
		return true;

	ZeroMemory(&s, sizeof(s));
	if (QUIC_FAILED(quic->GetParam((HQUIC)configuration, QUIC_PARAM_CONFIGURATION_SETTINGS, &size, &s)))
		return false;

	st->Named = (s.IsSet.XdpEnabled != 0 && s.IsSet.QTIPEnabled != 0);
	st->Xdp = (s.XdpEnabled != 0);
	st->Qtip = (s.QTIPEnabled != 0);

	// The global settings between two starts of a listener of the module, not the ones that a start sets for a moment
	AcquireSRWLockShared(&g_quic_xdp_lock);
	bool global = QuicXdpGetGlobal(quic, &s);
	ReleaseSRWLockShared(&g_quic_xdp_lock);
	if (global == false)
		return false;

	st->GlobalXdp = (s.XdpEnabled != 0);
	st->GlobalQtip = (s.QTIPEnabled != 0);

	return true;
}
