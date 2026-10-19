// Win32Com.c
// Win32 COM module call


#include "Win32Com.h"

extern "C"
{
#include "SeLowUser.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
}

#include <devguid.h>
#include <netcfgn.h>
#include <SetupAPI.h>

// Report a failed INetCfg or setup step of InstallNdisProtocolDriver and its HRESULT to the debug log
static void NetCfgDebugHr(const char *step, HRESULT hr)
{
	char fmt[] = "InstallNdisProtocolDriver: %s failed, HRESULT 0x%X\n";

	Debug(fmt, step, (UINT)hr);
}

// Install the SeLow NDIS protocol driver (SL_PROTOCOL_NAME) from the package whose INF is inf_path
bool InstallNdisProtocolDriver(wchar_t *inf_path)
{
	bool ret = false;
	bool com_initialized = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	HINSTANCE hSetupApiDll = NULL;
	BOOL (WINAPI *_SetupCopyOEMInfW)(PCWSTR, PCWSTR, DWORD, DWORD, PWSTR, DWORD, PDWORD, PWSTR *) = NULL;
	BOOL (WINAPI *_SetupUninstallOEMInfW)(PCWSTR, DWORD, PVOID) = NULL;
	if (inf_path == NULL)
	{
		return false;
	}

	hSetupApiDll = LoadLibraryA("setupapi.dll");
	if (hSetupApiDll == NULL)
	{
		WHERE;
		goto LABEL_CLEANUP;
	}

	_SetupCopyOEMInfW =
		(BOOL (__stdcall *)(PCWSTR,PCWSTR,DWORD,DWORD,PWSTR,DWORD,PDWORD,PWSTR *))
		GetProcAddress(hSetupApiDll, "SetupCopyOEMInfW");

	_SetupUninstallOEMInfW =
		(BOOL (__stdcall *)(PCWSTR,DWORD,PVOID))
		GetProcAddress(hSetupApiDll, "SetupUninstallOEMInfW");

	if (_SetupCopyOEMInfW == NULL || _SetupUninstallOEMInfW == NULL)
	{
		WHERE;
		goto LABEL_CLEANUP;
	}

	// COM for this call only: S_OK and S_FALSE both take a reference that CoUninitialize returns.
	// RPC_E_CHANGED_MODE means the thread already runs in another apartment, which stays as it is.
	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(hr))
	{
		com_initialized = true;
	}
	else if (hr != RPC_E_CHANGED_MODE)
	{
		NetCfgDebugHr("CoInitializeEx", hr);
		goto LABEL_CLEANUP;
	}

	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by = NULL;

			hr = pLock->AcquireWriteLock(SL_USER_INSTALL_LOCK_TIMEOUT, L"Ranz VPN", &locked_by);

			// S_FALSE: another client (locked_by) holds the write lock, so nothing may be installed
			if (locked_by != NULL)
			{
				CoTaskMemFree(locked_by);
			}

			if (hr == S_OK)
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					wchar_t inf_dir[MAX_PATH];

					GetDirNameFromFilePathW(inf_dir, sizeof(inf_dir), inf_path);

					if (_SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, 0))
					{
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETTRANS, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;
							INetCfgComponent *pComponent = NULL;

							Zero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->Install(L"" SL_PROTOCOL_NAME, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								if (pComponent != NULL)
								{
									pComponent->Release();
								}

								hr = pNetCfg->Apply();

								if (SUCCEEDED(hr))
								{
									ret = true;
								}
								else
								{
									NetCfgDebugHr("INetCfg::Apply", hr);
								}
							}
							else
							{
								NetCfgDebugHr("INetCfgClassSetup::Install", hr);
							}

							pSetup->Release();
						}
						else
						{
							NetCfgDebugHr("INetCfg::QueryNetCfgClass", hr);
						}

						if (ret == false)
						{
							wchar_t dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (_SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
								dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
								GetLastError() == ERROR_FILE_EXISTS)
							{
								_SetupUninstallOEMInfW(dst_inf_name, 0, NULL);
							}
						}
					}
					else
					{
						NetCfgDebugHr("SetupCopyOEMInfW", HRESULT_FROM_WIN32(GetLastError()));
					}

					hr = pNetCfg->Uninitialize();

					if (FAILED(hr))
					{
						NetCfgDebugHr("INetCfg::Uninitialize", hr);
					}
				}
				else
				{
					NetCfgDebugHr("INetCfg::Initialize", hr);
				}

				pLock->ReleaseWriteLock();
			}
			else
			{
				NetCfgDebugHr("INetCfgLock::AcquireWriteLock", hr);
			}

			pLock->Release();
		}
		else
		{
			NetCfgDebugHr("QueryInterface(INetCfgLock)", hr);
		}

		pNetCfg->Release();
	}
	else
	{
		NetCfgDebugHr("CoCreateInstance(CNetCfg)", hr);
	}

	if (com_initialized)
	{
		CoUninitialize();
	}

LABEL_CLEANUP:

	if (hSetupApiDll != NULL)
	{
		FreeLibrary(hSetupApiDll);
	}

	return ret;
}

