// AdminAccess.c
// Admin RPC area: access lists

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "AdminInternal.h"

UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t) {
	UINT err;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumAccessList(t);
	Zero(t, sizeof(RPC_ENUM_ACCESS_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->AccessList);
	{
		t->NumAccess = LIST_NUM(h->AccessList);
		t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);

		for (UINT i = 0; i < LIST_NUM(h->AccessList); i++) {
			ACCESS *a = &t->Accesses[i];
			Copy(a, LIST_DATA(h->AccessList, i), sizeof(ACCESS));
			a->UniqueId = HashPtrToUINT(LIST_DATA(h->AccessList, i));
		}
	}
	UnlockList(h->AccessList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t) {
	SERVER *s = a->Server;
	UINT err;


	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_access_list", &err);
	if (h == NULL) {
		return err;
	}

	bool exists = false;

	LockList(h->AccessList);
	{
		for (UINT i = 0; i < LIST_NUM(h->AccessList); i++) {
			ACCESS *access = LIST_DATA(h->AccessList, i);

			if ((t->Id < MAX_ACCESSLISTS && access->Id == t->Id) ||
			    (t->Id >= MAX_ACCESSLISTS && HashPtrToUINT(access) == t->Id)) {
				Free(access);
				Delete(h->AccessList, access);
				exists = true;

				break;
			}
		}
	}
	UnlockList(h->AccessList);

	if (exists == false) {
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_ACCESS");

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Apply the hub admin options on an access list entry sent by a hub administrator:
// no delay, jitter and packet loss; no user name taken from an include or exclude file
static void AdminSanitizeAccess(ACCESS *access, bool no_jitter, bool no_include) {
	if (no_jitter) {
		access->Jitter = access->Loss = access->Delay = 0;
	}

	if (no_include) {
		if (StartWith(access->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
		    StartWith(access->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX)) {
			ClearStr(access->SrcUsername, sizeof(access->SrcUsername));
		}

		if (StartWith(access->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
		    StartWith(access->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX)) {
			ClearStr(access->DestUsername, sizeof(access->DestUsername));
		}
	}
}

UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t) {
	SERVER *s = a->Server;
	UINT err;
	bool no_jitter = false;
	bool no_include = false;

	CHECK_RIGHT;

	if (t->NumAccess > MAX_ACCESSLISTS) {
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	HUB *h = AdminGetHub(a, t->HubName, "no_change_access_list", &err);
	if (h == NULL) {
		return err;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "max_accesslists") != 0 &&
	    t->NumAccess > GetHubAdminOption(h, "max_accesslists")) {
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockList(h->AccessList);
	{
		for (UINT i = 0; i < LIST_NUM(h->AccessList); ++i) {
			ACCESS *access = LIST_DATA(h->AccessList, i);
			Free(access);
		}

		DeleteAll(h->AccessList);

		ALog(a, h, "LA_SET_ACCESS_LIST", t->NumAccess);

		for (UINT i = 0; i < t->NumAccess; ++i) {
			ACCESS *access = &t->Accesses[i];

			AdminSanitizeAccess(access, no_jitter, no_include);

			if (i == (t->NumAccess - 1)) {
				Sort(h->AccessList);
			}

			AddAccessListEx(h, access, ((i != (t->NumAccess - 1)) ? true : false), ((i != (t->NumAccess - 1)) ? true : false));
		}

		UnlockList(h->AccessList);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t) {
	SERVER *s = a->Server;
	UINT err;
	bool no_jitter = false;
	bool no_include = false;


	HUB *h = AdminGetHub(a, t->HubName, "no_change_access_list", &err);
	if (h == NULL) {
		return err;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if ((LIST_NUM(h->AccessList) >= MAX_ACCESSLISTS ||
	     (GetHubAdminOption(h, "max_accesslists") != 0) && (LIST_NUM(h->AccessList) >= GetHubAdminOption(h, "max_accesslists")))) {
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	ALog(a, h, "LA_ADD_ACCESS");

	AdminSanitizeAccess(&t->Access, no_jitter, no_include);

	AddAccessListEx(h, &t->Access, false, false);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}
