// AdminAccess.c
// Admin RPC area: access lists

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

UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumAccessList(t);
	Zero(t, sizeof(RPC_ENUM_ACCESS_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->AccessList);
	{
		t->NumAccess = LIST_NUM(h->AccessList);
		t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);

		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = &t->Accesses[i];
			Copy(a, LIST_DATA(h->AccessList, i), sizeof(ACCESS));
			a->UniqueId = HashPtrToUINT(LIST_DATA(h->AccessList, i));
		}
	}
	UnlockList(h->AccessList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool exists;


	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	exists = false;

	LockList(h->AccessList);
	{
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);

			if ((t->Id < MAX_ACCESSLISTS && access->Id == t->Id) ||
				(t->Id >= MAX_ACCESSLISTS && HashPtrToUINT(access) == t->Id))
			{
				Free(access);
				Delete(h->AccessList, access);
				exists = true;

				break;
			}
		}
	}
	UnlockList(h->AccessList);

	if (exists == false)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_ACCESS");

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool no_jitter = false;
	bool no_include = false;

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (t->NumAccess > GetServerCapsInt(a->Server, "i_max_access_lists"))
	{
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "max_accesslists") != 0 &&
		t->NumAccess > GetHubAdminOption(h, "max_accesslists"))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockList(h->AccessList);
	{
		for (i = 0; i < LIST_NUM(h->AccessList); ++i)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);
			Free(access);
		}

		DeleteAll(h->AccessList);

		ALog(a, h, "LA_SET_ACCESS_LIST", t->NumAccess);

		for (i = 0; i < t->NumAccess; ++i)
		{
			ACCESS *a = &t->Accesses[i];

			if (no_jitter)
			{
				a->Jitter = a->Loss = a->Delay = 0;
			}

			if (no_include)
			{
				if (StartWith(a->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->SrcUsername, sizeof(a->SrcUsername));
				}

				if (StartWith(a->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->DestUsername, sizeof(a->DestUsername));
				}
			}

			if (i == (t->NumAccess - 1))
			{
				Sort(h->AccessList);
			}

			AddAccessListEx(h, a, ((i != (t->NumAccess - 1)) ? true : false), ((i != (t->NumAccess - 1)) ? true : false));
		}

		UnlockList(h->AccessList);

		IncrementServerConfigRevision(s);

	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	bool no_jitter = false;
	bool no_include = false;


	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if ((LIST_NUM(h->AccessList) >= GetServerCapsInt(a->Server, "i_max_access_lists") ||
		(GetHubAdminOption(h, "max_accesslists") != 0) && (LIST_NUM(h->AccessList) >= GetHubAdminOption(h, "max_accesslists"))))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	ALog(a, h, "LA_ADD_ACCESS");

	if (no_jitter)
	{
		t->Access.Jitter = t->Access.Delay = t->Access.Loss = 0;
	}

	if (no_include)
	{
		if (StartWith(t->Access.SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.SrcUsername, sizeof(t->Access.SrcUsername));
		}

		if (StartWith(t->Access.DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.DestUsername, sizeof(t->Access.DestUsername));
		}
	}

	AddAccessListEx(h, &t->Access, false, false);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}
