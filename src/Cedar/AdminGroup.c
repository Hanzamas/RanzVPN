// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AdminGroup.c
// Admin RPC area: groups

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

// Enumerate groups
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

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

	AcLock(h);
	{
		UINT i, j;

		FreeRpcEnumGroup(t);
		Zero(t, sizeof(RPC_ENUM_GROUP));
		StrCpy(t->HubName, sizeof(t->HubName), hubname);

		t->NumGroup = LIST_NUM(h->HubDb->GroupList);
		t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

		for (i = 0;i < t->NumGroup;i++)
		{
			RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];
			USERGROUP *g = LIST_DATA(h->HubDb->GroupList, i);

			Lock(g->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), g->Name);
				UniStrCpy(e->Realname, sizeof(e->Realname), g->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), g->Note);
				if (g->Policy != NULL)
				{
					if (g->Policy->Access == false)
					{
						e->DenyAccess = true;
					}
				}
			}
			Unlock(g->lock);

			e->NumUsers = 0;


			LockList(h->HubDb->UserList);
			{
				for (j = 0;j < LIST_NUM(h->HubDb->UserList);j++)
				{
					USER *u = LIST_DATA(h->HubDb->UserList, j);

					Lock(u->lock);
					{
						if (u->Group == g)
						{
							e->NumUsers++;
						}
					}
					Unlock(u->lock);
				}
			}
			UnlockList(h->HubDb->UserList);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Delete a group
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcDeleteGroup(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_GROUP", t->Name);
	}

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Get group information
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);

		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			FreeRpcSetGroup(t);
			Zero(t, sizeof(RPC_SET_GROUP));

			StrCpy(t->HubName, sizeof(t->HubName), hubname);

			Lock(g->lock);
			{
				StrCpy(t->Name, sizeof(t->Name), g->Name);
				UniStrCpy(t->Realname, sizeof(t->Realname), g->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), g->Note);
				Copy(&t->Traffic, g->Traffic, sizeof(TRAFFIC));
			}
			Unlock(g->lock);

			t->Policy = GetGroupPolicy(g);

			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

// Set group setting
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);
		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(g->lock);
			{
				Free(g->RealName);
				Free(g->Note);
				g->RealName = UniCopyStr(t->Realname);
				g->Note = UniCopyStr(t->Note);
			}
			Unlock(g->lock);

			SetGroupPolicy(g, t->Policy);

			ReleaseGroup(g);

			ALog(a, h, "LA_SET_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

// Create a group
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcIsGroup(h, t->Name))
		{
			ret = ERR_GROUP_ALREADY_EXISTS;
		}
		else
		{
			USERGROUP *g = NewGroup(t->Name, t->Realname, t->Note);
			SetGroupPolicy(g, t->Policy);

			if ((LIST_NUM(h->HubDb->GroupList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
				((GetHubAdminOption(h, "max_groups") != 0) && (LIST_NUM(h->HubDb->GroupList) >= GetHubAdminOption(h, "max_groups"))))
			{
				ret = ERR_TOO_MANY_GROUP;
			}
			else
			{
				AcAddGroup(h, g);
			}

			ReleaseGroup(g);

			ALog(a, h, "LA_CREATE_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}
