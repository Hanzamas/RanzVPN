// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AdminCrl.c
// Admin RPC area: certificate revocation list of a Virtual Hub

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

// Set CRL (Certificate Revocation List) entry
UINT StSetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						CRL *new_crl = CopyCrl(t->Crl);
						if (ReplaceListPointer(h->HubDb->CrlList, crl, new_crl))
						{
							ALog(a, h, "LA_ADD_CRL");
							FreeCrl(crl);

							IncrementServerConfigRevision(s);
						}
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Get CRL (Certificate Revocation List) entry
UINT StGetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcCrl(t);
	Zero(t, sizeof(RPC_CRL));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	t->Key = key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

				if (crl == NULL)
				{
					ret = ERR_OBJECT_NOT_FOUND;
				}
				else
				{
					t->Crl = CopyCrl(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

// Delete CRL (Certificate Revocation List) entry
UINT StDelCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						ALog(a, h, "LA_DEL_CRL");
						FreeCrl(crl);
						Delete(h->HubDb->CrlList, crl);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Add new CRL (Certificate Revocation List) entry
UINT StAddCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					if (LIST_NUM(h->HubDb->CrlList) < MAX_HUB_CRLS)
					{
						CRL *crl = CopyCrl(t->Crl);

						Insert(h->HubDb->CrlList, crl);

						ALog(a, h, "LA_SET_CRL");

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

// Get CRL (Certificate Revocation List) index
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumCrl(t);
	Zero(t, sizeof(RPC_ENUM_CRL));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				UINT i;

				t->NumItem = LIST_NUM(h->HubDb->CrlList);
				t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);

				for (i = 0;i < LIST_NUM(h->HubDb->CrlList);i++)
				{
					CRL *crl = LIST_DATA(h->HubDb->CrlList, i);
					wchar_t *info = GenerateCrlStr(crl);

					UniStrCpy(t->Items[i].CrlInfo, sizeof(t->Items[i].CrlInfo), info);
					Free(info);

					t->Items[i].Key = POINTER_TO_KEY(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}
