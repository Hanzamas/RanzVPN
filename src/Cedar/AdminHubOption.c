// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AdminHubOption.c
// Admin RPC area: Virtual Hub options and the server configuration file

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

// Set hub extended options
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;

	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}


	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
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

	if (GetHubAdminOption(h, "deny_hub_admin_change_ext_option") && not_server_admin)
	{
		// Insufficient permission
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	// Update setting
	Lock(h->lock);
	{
		DataToHubOptionStruct(h->Option, t);
	}
	Unlock(h->lock);

	ALog(a, NULL, "LA_SET_HUB_EXT_OPTION", h->Name);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub extended options
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

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

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	// Get options
	Lock(h->lock);
	{
		HubOptionStructToData(t, h->Option, h->Name);
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Set hub administration options
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;


	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
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

	if (GetHubAdminOption(h, "allow_hub_admin_change_option") == false
		&& not_server_admin)
	{
		// Insufficient permission
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->AdminOptionList);
	{
		DeleteAllHubAdminOption(h, false);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *e = &t->Items[i];
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}

		AddHubAdminOptionsDefaults(h, false);
	}
	UnlockList(h->AdminOptionList);

	ALog(a, NULL, "LA_SET_HUB_ADMIN_OPTION", h->Name);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub administration options
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

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

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	LockList(h->AdminOptionList);
	{
		t->NumItem = LIST_NUM(h->AdminOptionList);
		t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);
			ADMIN_OPTION *e = &t->Items[i];

			StrCpy(e->Name, sizeof(e->Name), a->Name);
			e->Value = a->Value;
			UniStrCpy(e->Descrption, sizeof(e->Descrption), GetHubAdminOptionHelpString(e->Name));
		}
	}
	UnlockList(h->AdminOptionList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get default hub administration options
UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;

	NO_SUPPORT_FOR_BRIDGE;
	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	t->NumItem = num_admin_options;
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *a = &t->Items[i];

		StrCpy(a->Name, sizeof(a->Name), admin_options[i].Name);
		a->Value = admin_options[i].Value;
		UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));
	}

	return ERR_NO_ERROR;
}

// Get configuration file stream
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;

	SERVER_ADMIN_ONLY;

	FreeRpcConfig(t);
	Zero(t, sizeof(RPC_CONFIG));

	s = a->Server;

	ALog(a, NULL, "LA_GET_CONFIG");

	if (s->CfgRw != NULL)
	{
		FOLDER *f = SiWriteConfigurationToCfg(s);
		BUF *b = CfgFolderToBuf(f, true);

		StrCpy(t->FileName, sizeof(t->FileName), s->CfgRw->FileName + (s->CfgRw->FileName[0] == '@' ? 1 : 0));

		t->FileData = ZeroMalloc(b->Size + 1);
		Copy(t->FileData, b->Buf, b->Size);

		CfgDeleteFolder(f);
		FreeBuf(b);

		return ERR_NO_ERROR;
	}
	else
	{
		return ERR_INTERNAL_ERROR;
	}
}

// Overwrite configuration file by specified data
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;
	IO *o;
	char filename[MAX_PATH];

	SERVER_ADMIN_ONLY;

	s = a->Server;
	if (s->CfgRw == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	// Write new configuration file
	Format(filename, sizeof(filename), "%s.new", s->CfgRw->FileName);

	o = FileCreate(filename);

	FileWrite(o, t->FileData, StrLen(t->FileData));

	FileClose(o);

	IncrementServerConfigRevision(s);

	ALog(a, NULL, "LA_SET_CONFIG");

	// Reboot server itself
	SiRebootServer(s->Cedar->Bridge);

	return ERR_NO_ERROR;
}

// Get capabilities
UINT StGetCaps(ADMIN *a, CAPSLIST *t)
{
	FreeRpcCapsList(t);
	Zero(t, sizeof(CAPSLIST));

	GetServerCapsMain(a->Server, t);

	return ERR_NO_ERROR;
}
