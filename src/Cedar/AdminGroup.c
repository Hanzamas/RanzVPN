// AdminGroup.c
// Admin RPC area: groups

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "AdminInternal.h"

typedef struct ENUM_GROUP_COUNT {
	USERGROUP *Group;
	RPC_ENUM_GROUP_ITEM *Item;
} ENUM_GROUP_COUNT;

static int CompareEnumGroupCount(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	ENUM_GROUP_COUNT *c1 = *(ENUM_GROUP_COUNT **)p1;
	ENUM_GROUP_COUNT *c2 = *(ENUM_GROUP_COUNT **)p2;
	if (c1 == NULL || c2 == NULL) {
		return 0;
	}

	return COMPARE_RET(c1->Group, c2->Group);
}

UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t) {
	HUB *h = NULL;
	UINT err;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	AcLock(h);
	{
		FreeRpcEnumGroup(t);
		Zero(t, sizeof(RPC_ENUM_GROUP));
		StrCpy(t->HubName, sizeof(t->HubName), hubname);

		t->NumGroup = LIST_NUM(h->HubDb->GroupList);
		t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

		// Group pointer to its item, so the members are counted in one pass over the users
		ENUM_GROUP_COUNT *counts = ZeroMalloc(sizeof(ENUM_GROUP_COUNT) * t->NumGroup);
		LIST *index = NewListFast(CompareEnumGroupCount);

		for (UINT i = 0; i < t->NumGroup; i++) {
			RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];
			USERGROUP *g = LIST_DATA(h->HubDb->GroupList, i);

			Lock(g->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), g->Name);
				UniStrCpy(e->Realname, sizeof(e->Realname), g->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), g->Note);
				if (g->Policy != NULL) {
					if (g->Policy->Access == false) {
						e->DenyAccess = true;
					}
				}
			}
			Unlock(g->lock);

			e->NumUsers = 0;

			counts[i].Group = g;
			counts[i].Item = e;
			Add(index, &counts[i]);
		}

		for (UINT j = 0; j < LIST_NUM(h->HubDb->UserList); j++) {
			USER *u = LIST_DATA(h->HubDb->UserList, j);
			USERGROUP *ug;

			Lock(u->lock);
			{
				ug = u->Group;
			}
			Unlock(u->lock);

			if (ug != NULL) {
				ENUM_GROUP_COUNT key;

				key.Group = ug;
				key.Item = NULL;

				ENUM_GROUP_COUNT *found = Search(index, &key);
				if (found != NULL) {
					found->Item->NumUsers++;
				}
			}
		}

		ReleaseList(index);
		Free(counts);
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t) {
	SERVER *s = a->Server;
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false) {
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	h = AdminGetHub(a, t->HubName, "no_change_groups", &err);
	if (h == NULL) {
		return err;
	}

	AcLock(h);
	{
		if (AcDeleteGroup(h, t->Name) == false) {
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR) {
		ALog(a, h, "LA_DELETE_GROUP", t->Name);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ret;
}

UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t) {
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false) {
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = AdminGetHub(a, t->HubName, NULL, &ret);
	if (h == NULL) {
		return ret;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);

		if (g == NULL) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
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

UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t) {
	SERVER *s = a->Server;
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false) {
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	h = AdminGetHub(a, t->HubName, "no_change_groups", &err);
	if (h == NULL) {
		return err;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);
		if (g == NULL) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			Lock(g->lock);
			{
				Free(g->RealName);
				Free(g->Note);
				g->RealName = CopyUniStr(t->Realname);
				g->Note = CopyUniStr(t->Note);
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

UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t) {
	SERVER *s = a->Server;
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false) {
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	h = AdminGetHub(a, t->HubName, "no_change_groups", &err);
	if (h == NULL) {
		return err;
	}

	AcLock(h);
	{
		if (AcIsGroup(h, t->Name)) {
			ret = ERR_GROUP_ALREADY_EXISTS;
		} else {
			USERGROUP *g = NewGroup(t->Name, t->Realname, t->Note);
			SetGroupPolicy(g, t->Policy);

			if ((LIST_NUM(h->HubDb->GroupList) >= MAX_USERS) ||
			    ((GetHubAdminOption(h, "max_groups") != 0) && (LIST_NUM(h->HubDb->GroupList) >= GetHubAdminOption(h, "max_groups")))) {
				ret = ERR_TOO_MANY_GROUP;
			} else {
				AcAddGroup(h, g);

				ALog(a, h, "LA_CREATE_GROUP", t->Name);
			}

			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	if (ret == ERR_NO_ERROR) {
		IncrementServerConfigRevision(s);
	}

	return ret;
}
