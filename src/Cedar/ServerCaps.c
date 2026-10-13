// ServerCaps.c
// VPN Server capabilities: the caps list, the server caps cache and the global server flags

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Sam.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Win32.h"
#include "ServerInternal.h"

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

UINT GetServerCapsInt(SERVER *s, char *name)
{
	CAPSLIST t;
	UINT ret;
	if (s == NULL || name == NULL)
	{
		return 0;
	}


	Lock(s->CapsCacheLock);
	{
		Zero(&t, sizeof(t));
		GetServerCaps(s, &t);

		ret = GetCapsInt(&t, name);
	}
	Unlock(s->CapsCacheLock);

	return ret;
}

bool GetServerCapsBool(SERVER *s, char *name)
{
	return (GetServerCapsInt(s, name) == 0) ? false : true;
}

void InitServerCapsCache(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->CapsCacheLock = NewLock();
	s->CapsListCache = NULL;
}

void FreeServerCapsCache(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->CapsListCache != NULL)
	{
		FreeCapsList(s->CapsListCache);
		s->CapsListCache = NULL;
	}
	DeleteLock(s->CapsCacheLock);
}

void DestroyServerCapsCache(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		if (s->CapsListCache != NULL)
		{
			FreeCapsList(s->CapsListCache);
			s->CapsListCache = NULL;
		}
	}
	Unlock(s->CapsCacheLock);
}

void FlushServerCaps(SERVER *s)
{
	CAPSLIST t;
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		DestroyServerCapsCache(s);

		Zero(&t, sizeof(t));
		GetServerCaps(s, &t);
	}
	Unlock(s->CapsCacheLock);
}

void GetServerCaps(SERVER *s, CAPSLIST *t)
{
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{

		if (s->CapsListCache == NULL)
		{
			s->CapsListCache = ZeroMalloc(sizeof(CAPSLIST));
			GetServerCapsMain(s, s->CapsListCache);
		}

		Copy(t, s->CapsListCache, sizeof(CAPSLIST));
	}
	Unlock(s->CapsCacheLock);
}

void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t)
{
	bool is_restricted = false;
	if (s == NULL || t == NULL)
	{
		return;
	}

	is_restricted = SiIsEnterpriseFunctionsRestrictedOnOpenSource(s->Cedar);

	SetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_CERT_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_DEEP_LOGGING, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_AC, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_SYSLOG, is_restricted);
}

void SetGlobalServerFlag(UINT index, UINT value)
{
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return;
	}

	global_server_flags[index] = value;
}

UINT GetGlobalServerFlag(UINT index)
{
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return 0;
	}

	return global_server_flags[index];
}

void GetServerCapsMain(SERVER *s, CAPSLIST *t)
{
	if (s == NULL || t == NULL)
	{
		return;
	}

	InitCapsList(t);

	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	if (s->Cedar->Bridge == false)
	{
		UINT max_sessions, max_clients, max_bridges, max_user_creations;

		max_clients = INFINITE;
		max_bridges = INFINITE;
		max_sessions = SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION;
		max_user_creations = INFINITE;

		AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION);

		AddCapsInt(t, "i_max_sessions", max_sessions);

		AddCapsInt(t, "i_max_user_creation", max_user_creations);

		AddCapsInt(t, "i_max_clients", max_clients);

		AddCapsInt(t, "i_max_bridges", max_bridges);

		AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

		AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

		AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);

		AddCapsBool(t, "b_support_limit_multilogin", true);

		AddCapsBool(t, "b_support_qos", true);

		AddCapsBool(t, "b_support_syslog", true);
	}
	else
	{
		AddCapsInt(t, "i_max_hubs", 0);

		AddCapsInt(t, "i_max_sessions", 0);

		AddCapsInt(t, "i_max_clients", 0);

		AddCapsInt(t, "i_max_bridges", 0);

		AddCapsInt(t, "i_max_users_per_hub", 0);

		AddCapsInt(t, "i_max_groups_per_hub", 0);

		AddCapsInt(t, "i_max_access_lists", 0);

		AddCapsBool(t, "b_support_qos", true);

		AddCapsBool(t, "b_support_syslog", true);
	}

	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	AddCapsBool(t, "b_support_cascade", true);

	if (s->Cedar->Bridge)
	{
		AddCapsBool(t, "b_bridge", true);
	}
	else
	{
		AddCapsBool(t, "b_standalone", true);
	}

	AddCapsBool(t, "b_support_config_hub", s->Cedar->Bridge == false);

	AddCapsBool(t, "b_vpn_client_connect", s->Cedar->Bridge == false ? true : false);

	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (IsBridgeSupported())
	{
		const UINT OsType = GetOsInfo()->OsType;
		AddCapsBool(t, "b_tap_supported", OsType == OSTYPE_LINUX || OsType == OSTYPE_BSD);
	}

	AddCapsBool(t, "b_support_cascade", true);

	AddCapsBool(t, "b_support_cascade_cert", true);

	AddCapsBool(t, "b_support_config_log", true);

	AddCapsBool(t, "b_support_autodelete", true);

	AddCapsBool(t, "b_support_config_rw", true);

	AddCapsBool(t, "b_support_hub_admin_option", true);

	AddCapsBool(t, "b_support_cascade_client_cert", true);

	AddCapsBool(t, "b_support_hide_hub", true);

	AddCapsBool(t, "b_is_softether", true);

	if (s->Cedar->Bridge == false)
	{
		AddCapsBool(t, "b_support_crl", true);

		AddCapsBool(t, "b_support_ac", true);
	}

	AddCapsBool(t, "b_support_read_log", true);

	AddCapsBool(t, "b_support_rename_cascade", true);


	if (s->Cedar->Beta)
	{
		AddCapsBool(t, "b_beta_version", true);
	}

	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	if (IsBridgeSupported())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}

	AddCapsBool(t, "b_support_check_mac", true);

	AddCapsBool(t, "b_support_check_tcp_state", true);

	AddCapsBool(t, "b_support_vlan", true);

	if (s->Cedar->Bridge == false)
	{
		AddCapsBool(t, "b_support_hub_ext_options", true);
	}
	else
	{
		AddCapsBool(t, "b_support_hub_ext_options", false);
	}

	AddCapsBool(t, "b_support_policy_ver_3", true);

	AddCapsBool(t, "b_support_ipv6_acl", true);

	AddCapsBool(t, "b_support_ex_acl", true);

	AddCapsBool(t, "b_support_redirect_url_acl", true);

	AddCapsBool(t, "b_support_acl_group", true);

	AddCapsBool(t, "b_support_ipv6_ac", true);

	AddCapsBool(t, "b_support_eth_vlan", true);

	AddCapsBool(t, "b_support_msg", true);

	AddCapsBool(t, "b_support_udp_acceleration", true);

	AddCapsBool(t, "b_support_aes_ni", IsAesNiSupported());

	AddCapsBool(t, "b_using_selow_driver", Win32IsUsingSeLow());

	AddCapsBool(t, "b_vpn3", true);

	AddCapsBool(t, "b_vpn4", true);


	UpdateGlobalServerFlags(s, t);
}

void InitCapsList(CAPSLIST *t)
{
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(NULL);
}

void InRpcCapsList(CAPSLIST *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(CompareCaps);

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (StartWith(e->name, "caps_") && e->type == VALUE_INT && e->num_value == 1)
		{
			CAPS *c = NewCaps(e->name + 5, e->values[0]->IntValue);
			Insert(t->CapsList, c);
		}
	}
}

void OutRpcCapsList(PACK *p, CAPSLIST *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		char tmp[MAX_SIZE];
		char ct_key[MAX_PATH];
		wchar_t ct_description[MAX_PATH];
		wchar_t *w;
		CAPS *c = LIST_DATA(t->CapsList, i);

		Format(tmp, sizeof(tmp), "caps_%s", c->Name);

		Format(ct_key, sizeof(ct_key), "CT_%s", c->Name);

		Zero(ct_description, sizeof(ct_description));
		w = _UU(ct_key);
		if (UniIsEmptyStr(w) == false)
		{
			UniStrCpy(ct_description, sizeof(ct_description), w);
		}
		else
		{
			StrToUni(ct_description, sizeof(ct_description), c->Name);
		}

		PackAddInt(p, tmp, c->Value);

		PackAddStrEx(p, "CapsName", c->Name, i, LIST_NUM(t->CapsList));
		PackAddIntEx(p, "CapsValue", c->Value, i, LIST_NUM(t->CapsList));
		PackAddUniStrEx(p, "CapsDescrption", ct_description, i, LIST_NUM(t->CapsList));
	}
}

void FreeRpcCapsList(CAPSLIST *t)
{
	UINT i;
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(t->CapsList);
}

void AddCapsBool(CAPSLIST *caps, char *name, bool b)
{
	CAPS *c;
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

void AddCapsInt(CAPSLIST *caps, char *name, UINT i)
{
	CAPS *c;
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, i);
	AddCaps(caps, c);
}

UINT GetCapsInt(CAPSLIST *caps, char *name)
{
	CAPS *c;
	if (caps == NULL || name == NULL)
	{
		return 0;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return 0;
	}

	return c->Value;
}

bool GetCapsBool(CAPSLIST *caps, char *name)
{
	CAPS *c;
	if (caps == NULL || name == NULL)
	{
		return false;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return false;
	}

	return c->Value == 0 ? false : true;
}

void FreeCapsList(CAPSLIST *caps)
{
	UINT i;
	if (caps == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(caps->CapsList);
	Free(caps);
}

CAPS *GetCaps(CAPSLIST *caps, char *name)
{
	UINT i;
	if (caps == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		if (StrCmpi(c->Name, name) == 0)
		{
			return c;
		}
	}

	return NULL;
}

void AddCaps(CAPSLIST *caps, CAPS *c)
{
	if (caps == NULL || c == NULL)
	{
		return;
	}

	Insert(caps->CapsList, c);
}

int CompareCaps(void *p1, void *p2)
{
	CAPS *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CAPS **)p1;
	c2 = *(CAPS **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

CAPSLIST *NewCapsList()
{
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

void FreeCaps(CAPS *c)
{
	if (c == NULL)
	{
		return;
	}

	Free(c->Name);
	Free(c);
}

CAPS *NewCaps(char *name, UINT value)
{
	CAPS *c;
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}
