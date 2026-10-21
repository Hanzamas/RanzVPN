// AdminAc.c
// Admin RPC area: IP access control list of a Virtual Hub

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "AdminInternal.h"

UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	UINT err;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcAcList(t);
	Zero(t, sizeof(RPC_AC_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	HUB *h = AdminGetHub(a, hubname, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	HUBDB *db = h->HubDb;

	LockList(db->AcList);
	{
		t->o = NewList(CmpAc);

		SetAcList(t->o, db->AcList);
	}
	UnlockList(db->AcList);
	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT err;

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_access_control_list", &err);
	if (h == NULL)
	{
		return err;
	}

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
	ReleaseHub(h);

	return ERR_NO_ERROR;
}
