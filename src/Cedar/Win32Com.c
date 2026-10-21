// Win32Com.c
// Win32 COM module call


// COBJMACROS: the INetCfg_* call macros of the SDK headers (the COM interfaces are C structs here)
#define COBJMACROS

#include "Win32Com.h"

#include "SeLowUser.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <devguid.h>
#include <netcfgn.h>
#include <SetupAPI.h>

// Report a failed INetCfg or setup step of InstallNdisProtocolDriver and its HRESULT to the debug log
static void NetCfgDebugHr(char *step, HRESULT hr) {
	Debug("InstallNdisProtocolDriver: %s failed, HRESULT 0x%X\n", step, (UINT)hr);
}

// Install the SeLow NDIS protocol driver (SL_PROTOCOL_NAME) from the package whose INF is inf_path
bool InstallNdisProtocolDriver(wchar_t *inf_path) {
	bool ret = false;
	bool com_initialized = false;
	INetCfg *pNetCfg;
	if (inf_path == NULL)
		return false;

	// COM for this call only: S_OK and S_FALSE both take a reference that CoUninitialize returns.
	// RPC_E_CHANGED_MODE means the thread already runs in another apartment, which stays as it is.
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(hr)) {
		com_initialized = true;
	} else if (hr != RPC_E_CHANGED_MODE) {
		NetCfgDebugHr("CoInitializeEx", hr);
		return false;
	}

	hr = CoCreateInstance(&CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, &IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr)) {
		INetCfgLock *pLock;

		hr = INetCfg_QueryInterface(pNetCfg, &IID_INetCfgLock, (PVOID *)&pLock);

		if (SUCCEEDED(hr)) {
			LPWSTR locked_by = NULL;

			hr = INetCfgLock_AcquireWriteLock(pLock, SL_USER_INSTALL_LOCK_TIMEOUT, L"Ranz VPN", &locked_by);

			// S_FALSE: another client (locked_by) holds the write lock, so nothing may be installed
			if (locked_by != NULL)
				CoTaskMemFree(locked_by);

			if (hr == S_OK) {
				hr = INetCfg_Initialize(pNetCfg, NULL);

				if (SUCCEEDED(hr)) {
					wchar_t inf_dir[MAX_PATH];

					GetDirNameFromFilePathW(inf_dir, sizeof(inf_dir), inf_path);

					if (SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, NULL)) {
						INetCfgClassSetup *pSetup;

						hr = INetCfg_QueryNetCfgClass(pNetCfg, &GUID_DEVCLASS_NETTRANS, &IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr)) {
							OBO_TOKEN token;
							INetCfgComponent *pComponent = NULL;

							Zero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = INetCfgClassSetup_Install(pSetup, L"" SL_PROTOCOL_NAME, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr)) {
								if (pComponent != NULL)
									INetCfgComponent_Release(pComponent);

								hr = INetCfg_Apply(pNetCfg);

								if (SUCCEEDED(hr))
									ret = true;
								else
									NetCfgDebugHr("INetCfg::Apply", hr);
							} else {
								NetCfgDebugHr("INetCfgClassSetup::Install", hr);
							}

							INetCfgClassSetup_Release(pSetup);
						} else {
							NetCfgDebugHr("INetCfg::QueryNetCfgClass", hr);
						}

						if (ret == false) {
							wchar_t dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
							                     dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
							    GetLastError() == ERROR_FILE_EXISTS)
								SetupUninstallOEMInfW(dst_inf_name, 0, NULL);
						}
					} else {
						NetCfgDebugHr("SetupCopyOEMInfW", HRESULT_FROM_WIN32(GetLastError()));
					}

					hr = INetCfg_Uninitialize(pNetCfg);

					if (FAILED(hr))
						NetCfgDebugHr("INetCfg::Uninitialize", hr);
				} else {
					NetCfgDebugHr("INetCfg::Initialize", hr);
				}

				INetCfgLock_ReleaseWriteLock(pLock);
			} else {
				NetCfgDebugHr("INetCfgLock::AcquireWriteLock", hr);
			}

			INetCfgLock_Release(pLock);
		} else {
			NetCfgDebugHr("QueryInterface(INetCfgLock)", hr);
		}

		INetCfg_Release(pNetCfg);
	} else {
		NetCfgDebugHr("CoCreateInstance(CNetCfg)", hr);
	}

	if (com_initialized)
		CoUninitialize();

	return ret;
}

