// AdminUser.c
// Admin RPC area: users

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

UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i, num;

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

	FreeRpcEnumUser(t);

	StrCpy(hubname, sizeof(hubname), t->HubName);

	Zero(t, sizeof(RPC_ENUM_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->HubDb->UserList);
	{
		num = LIST_NUM(h->HubDb->UserList);

		t->NumUser = num;
		t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * num);

		for (i = 0;i < num;i++)
		{
			USER *u = LIST_DATA(h->HubDb->UserList, i);

			Lock(u->lock);
			{
				RPC_ENUM_USER_ITEM *e = &t->Users[i];

				StrCpy(e->Name, sizeof(e->Name), u->Name);
				StrCpy(e->GroupName, sizeof(e->GroupName), u->GroupName);
				UniStrCpy(e->Realname, sizeof(e->Realname), u->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), u->Note);
				e->AuthType = u->AuthType;
				e->LastLoginTime = u->LastLoginTime;
				e->NumLogin = u->NumLogin;

				if (u->Policy != NULL)
				{
					e->DenyAccess = u->Policy->Access ? false : true;
				}

				Copy(&e->Traffic, u->Traffic, sizeof(TRAFFIC));
				e->IsTrafficFilled = true;

				e->Expires = u->ExpireTime;
				e->IsExpiresFilled = true;
			}
			Unlock(u->lock);
		}
	}
	UnlockList(h->HubDb->UserList);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DELETE_USER", t->Name);

	AcLock(h);
	{
		if (AcDeleteUser(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

UINT StGetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;
	char name[MAX_USERNAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	StrCpy(name, sizeof(name), t->Name);
	StrCpy(hubname, sizeof(hubname), t->HubName);

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	FreeRpcSetUser(t);
	Zero(t, sizeof(RPC_SET_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		u = AcGetUser(h, name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				StrCpy(t->GroupName, sizeof(t->GroupName), u->GroupName);
				UniStrCpy(t->Realname, sizeof(t->Realname), u->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), u->Note);
				t->CreatedTime = u->CreatedTime;
				t->UpdatedTime = u->UpdatedTime;
				t->ExpireTime = u->ExpireTime;

				t->AuthType = u->AuthType;
				t->AuthData = CopyAuthData(u->AuthData, t->AuthType);
				t->NumLogin = u->NumLogin;
				Copy(&t->Traffic, u->Traffic, sizeof(TRAFFIC));
				if (u->Policy != NULL)
				{
					t->Policy = ClonePolicy(u->Policy);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

UINT StSetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		u = AcGetUser(h, t->Name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				if (StrLen(t->GroupName) != 0)
				{
					g = AcGetGroup(h, t->GroupName);

					if (g != NULL)
					{
						JoinUserToGroup(u, g);
						ReleaseGroup(g);
					}
					else
					{
						ret = ERR_GROUP_NOT_FOUND;
					}
				}
				else
				{
					JoinUserToGroup(u, NULL);
				}

				if (ret != ERR_GROUP_NOT_FOUND)
				{
					Free(u->RealName);
					Free(u->Note);
					u->RealName = UniCopyStr(t->Realname);
					u->Note = UniCopyStr(t->Note);
					SetUserAuthData(u, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
					u->ExpireTime = t->ExpireTime;
					u->UpdatedTime = SystemTime64();

					SetUserPolicy(u, t->Policy);
				}
			}
			Unlock(u->lock);

			IncrementServerConfigRevision(s);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_USER", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

UINT StCreateUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	u = NewUser(t->Name, t->Realname, t->Note, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
	if (u == NULL)
	{
		ReleaseHub(h);
		return ERR_INTERNAL_ERROR;
	}

	u->ExpireTime = t->ExpireTime;

	SetUserPolicy(u, t->Policy);

	AcLock(h);
	{
		if ((LIST_NUM(h->HubDb->UserList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
			((GetHubAdminOption(h, "max_users") != 0) && (LIST_NUM(h->HubDb->UserList) >= GetHubAdminOption(h, "max_users"))))
		{
			ret = ERR_TOO_MANY_USER;
		}
		else if (SiTooManyUserObjectsInServer(s, false))
		{
			ret = ERR_TOO_MANY_USERS_CREATED;
			ALog(a, h, "ERR_128");
		}
		else if (AcIsUser(h, t->Name))
		{
			ret = ERR_USER_ALREADY_EXISTS;
		}
		else
		{
			if (StrLen(t->GroupName) != 0)
			{
				g = AcGetGroup(h, t->GroupName);
				if (g == NULL)
				{
					ret = ERR_GROUP_NOT_FOUND;
				}
			}

			if (ret != ERR_GROUP_NOT_FOUND)
			{
				if (g != NULL)
				{
					JoinUserToGroup(u, g);
					ReleaseGroup(g);
				}

				AcAddUser(h, u);
				ALog(a, h, "LA_CREATE_USER", t->Name);

				IncrementServerConfigRevision(s);
			}
		}
	}
	AcUnlock(h);

	ReleaseUser(u);

	ReleaseHub(h);

	return ret;
}
