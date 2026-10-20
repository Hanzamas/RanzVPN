// Win32Com.c
// Win32 COM module call


// COBJMACROS: the INetCfg_* call macros of the SDK headers (the COM interfaces are C structs here)
#define	COBJMACROS

#include "Win32Com.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <devguid.h>
#include <netcfgn.h>
#include <SetupAPI.h>

bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	if (inf_path == NULL || id == NULL)
	{
		return false;
	}

	hr = CoCreateInstance(&CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, &IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = INetCfg_QueryInterface(pNetCfg, &IID_INetCfgLock, (PVOID *)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = INetCfgLock_AcquireWriteLock(pLock, lock_timeout, L"Ranz VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = INetCfg_Initialize(pNetCfg, NULL);

				if (SUCCEEDED(hr))
				{
					wchar_t inf_dir[MAX_PATH];

					GetDirNameFromFilePathW(inf_dir, sizeof(inf_dir), inf_path);

					if (SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, NULL))
					{
						INetCfgClassSetup *pSetup;

						hr = INetCfg_QueryNetCfgClass(pNetCfg, &GUID_DEVCLASS_NETTRANS, &IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;
							INetCfgComponent *pComponent;

							Zero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = INetCfgClassSetup_Install(pSetup, id, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								INetCfg_Apply(pNetCfg);

								ret = true;
							}
							else
							{
								WHERE;
							}

							INetCfgClassSetup_Release(pSetup);
						}
						else
						{
							WHERE;
						}

						if (ret == false)
						{
							wchar_t dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
								dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
								GetLastError() == ERROR_FILE_EXISTS)
							{
								SetupUninstallOEMInfW(dst_inf_name, 0, NULL);
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

				INetCfgLock_ReleaseWriteLock(pLock);
			}
			else
			{
				WHERE;
			}

			INetCfgLock_Release(pLock);
		}

		INetCfg_Release(pNetCfg);
	}
	else
	{
		WHERE;
	}

	return ret;
}

