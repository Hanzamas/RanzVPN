// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Win32Com.c
// Win32 COM module call


#include "Win32Com.h"

extern "C"
{
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
}

#include <devguid.h>
#include <netcfgn.h>
#include <SetupAPI.h>

// Install the NDIS protocol driver
bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	HINSTANCE hSetupApiDll = NULL;
	BOOL (WINAPI *_SetupCopyOEMInfW)(PCWSTR, PCWSTR, DWORD, DWORD, PWSTR, DWORD, PDWORD, PWSTR *) = NULL;
	BOOL (WINAPI *_SetupUninstallOEMInfW)(PCWSTR, DWORD, PVOID) = NULL;
	// Validate arguments
	if (inf_path == NULL || id == NULL)
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

	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"Ranz VPN", &locked_by);

			if (SUCCEEDED(hr))
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
							INetCfgComponent *pComponent;

							Zero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->Install(id, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								pNetCfg->Apply();

								ret = true;
							}
							else
							{
								WHERE;
								Debug("0x%x\n", hr);
							}

							pSetup->Release();
						}
						else
						{
							WHERE;
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
						WHERE;
					}
				}
				else
				{
					WHERE;
				}

				pLock->ReleaseWriteLock();
			}
			else
			{
				WHERE;
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}
	else
	{
		WHERE;
	}

LABEL_CLEANUP:

	if (hSetupApiDll != NULL)
	{
		FreeLibrary(hSetupApiDll);
	}

	return ret;
}

