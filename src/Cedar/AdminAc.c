// AdminAc.c
// Admin RPC area: IP access control list of a Virtual Hub

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

UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcAcList(t);
	Zero(t, sizeof(RPC_AC_LIST));
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
			HUBDB *db = h->HubDb;

			LockList(db->AcList);
			{
				t->o = NewList(CmpAc);

				SetAcList(t->o, db->AcList);
			}
			UnlockList(db->AcList);
		}
		ReleaseHub(h);
	}

	return ret;
}

UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t)
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

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0 && LIST_NUM(t->o) >= 1)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
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
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_control_list") != 0)
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
				HUBDB *db = h->HubDb;

				LockList(db->AcList);
				{
					SetAcList(db->AcList, t->o);

					{
						ALog(a, h, "LA_SET_AC_LIST", LIST_NUM(t->o));

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(db->AcList);
			}
		}
		ReleaseHub(h);
	}

	return ret;
}
