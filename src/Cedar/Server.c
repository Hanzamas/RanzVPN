// Server.c
// VPN Server module

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "RpcField.h"
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

#include <stdlib.h>

static SERVER *server = NULL;
static LOCK *server_lock = NULL;
char *SERVER_CONFIG_FILE_NAME = "$ranz_server.config";
static char *SERVER_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";

static bool server_reset_setting = false;

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

UINT vpn_global_parameters[NUM_GLOBAL_PARAMS] = {0};

void SiDebugLog(SERVER *s, char *msg)
{
	if (s == NULL || msg == NULL)
	{
		return;
	}

	if (s->DebugLog != NULL)
	{
		WriteTinyLog(s->DebugLog, msg);
	}
}

static void SiCheckDeadLockMain(SERVER *s, UINT timeout)
{
	CEDAR *cedar;
	if (s == NULL)
	{
		return;
	}



	cedar = s->Cedar;

	if (s->ServerListenerList != NULL)
	{
		CheckDeadLock(s->ServerListenerList->lock, timeout, "s->ServerListenerList->lock");
	}

	CheckDeadLock(s->lock, timeout, "s->lock");

	if (s->HubCreateHistoryList != NULL)
	{
		CheckDeadLock(s->HubCreateHistoryList->lock, timeout, "s->HubCreateHistoryList->lock");
	}

	if (cedar != NULL)
	{
		if (cedar->HubList != NULL)
		{
			CheckDeadLock(cedar->HubList->lock, timeout, "cedar->HubList->lock");
		}

		if (cedar->ListenerList != NULL)
		{
			UINT i;
			LIST *o = NewListFast(NULL);

			CheckDeadLock(cedar->ListenerList->lock, timeout, "cedar->ListenerList->lock");

			LockList(cedar->ListenerList);
			{
				for (i = 0;i < LIST_NUM(cedar->ListenerList);i++)
				{
					LISTENER *r = LIST_DATA(cedar->ListenerList, i);

					AddRef(r->ref);

					Add(o, r);
				}
			}
			UnlockList(cedar->ListenerList);

			for (i = 0;i < LIST_NUM(o);i++)
			{
				LISTENER *r = LIST_DATA(o, i);


				ReleaseListener(r);
			}

			ReleaseList(o);
		}

		if (cedar->ConnectionList != NULL)
		{
			CheckDeadLock(cedar->ConnectionList->lock, timeout, "cedar->ConnectionList->lock");
		}

		if (cedar->CaList != NULL)
		{
			CheckDeadLock(cedar->CaList->lock, timeout, "cedar->CaList->lock");
		}

		if (cedar->TrafficLock != NULL)
		{
			CheckDeadLock(cedar->TrafficLock, timeout, "cedar->TrafficLock");
		}

		if (cedar->LocalBridgeList != NULL)
		{
			CheckDeadLock(cedar->LocalBridgeList->lock, timeout, "cedar->LocalBridgeList->lock");
		}
	}

}

static void SiDeadLockCheckThread(THREAD *t, void *param)
{
	SERVER *s = (SERVER *)param;
	if (s == NULL || t == NULL)
	{
		return;
	}

	while (true)
	{
		Wait(s->DeadLockWaitEvent, SERVER_DEADLOCK_CHECK_SPAN);

		if (s->HaltDeadLockThread)
		{
			break;
		}

		SiCheckDeadLockMain(s, SERVER_DEADLOCK_CHECK_TIMEOUT);
	}
}

static void SiInitDeadLockCheck(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}
	if (s->DisableDeadLockCheck)
	{
		return;
	}

	s->HaltDeadLockThread = false;
	s->DeadLockWaitEvent = NewEvent();
	s->DeadLockCheckThread = NewThread(SiDeadLockCheckThread, s);
}

static void SiFreeDeadLockCheck(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->DeadLockCheckThread == NULL)
	{
		return;
	}

	s->HaltDeadLockThread = true;
	Set(s->DeadLockWaitEvent);

	WaitThread(s->DeadLockCheckThread, INFINITE);

	ReleaseThread(s->DeadLockCheckThread);
	s->DeadLockCheckThread = NULL;

	ReleaseEvent(s->DeadLockWaitEvent);
	s->DeadLockWaitEvent = NULL;

	s->HaltDeadLockThread = false;
}

static void SiInitHubCreateHistory(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->HubCreateHistoryList = NewList(NULL);
}

static void SiFreeHubCreateHistory(SERVER *s)
{
	UINT i;
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
	{
		SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

		Free(h);
	}

	ReleaseList(s->HubCreateHistoryList);

	s->HubCreateHistoryList = NULL;
}

UINT SiGetSysLogSaveStatus(SERVER *s)
{
	SYSLOG_SETTING set;
	if (s == NULL)
	{
		return SYSLOG_NONE;
	}

	SiGetSysLogSetting(s, &set);

	return set.SaveType;
}

void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message)
{
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	if (s == NULL || typestr == NULL || message == NULL)
	{
		return;
	}

	GetMachineName(machinename, sizeof(machinename));

	LocalTime(&st);
	if(s->StrictSyslogDatetimeFormat){
		GetDateTimeStrRFC3339(datetime, sizeof(datetime), &st, GetCurrentTimezone());
	}else{
		GetDateTimeStrMilli(datetime, sizeof(datetime), &st);
	}

	if (IsEmptyStr(hubname) == false)
	{
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN/%S] (%S) <%S>: %s",
			machinename, hubname, datetime, typestr, message);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN] (%S) <%S>: %s",
			machinename, datetime, typestr, message);
	}

	SendSysLog(s->Syslog, tmp);
}

void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	SYSLOG_SETTING set;
	if (s == NULL || setting == NULL)
	{
		return;
	}

	Zero(&set, sizeof(set));
	Copy(&set, setting, sizeof(SYSLOG_SETTING));

	if (IsEmptyStr(set.Hostname) || set.Port == 0)
	{
		set.SaveType = SYSLOG_NONE;
	}

	Lock(s->SyslogLock);
	{
		Copy(&s->SyslogSetting, &set, sizeof(SYSLOG_SETTING));

		SetSysLog(s->Syslog, set.Hostname, set.Port);
	}
	Unlock(s->SyslogLock);
}

void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	if (s == NULL || setting == NULL)
	{
		return;
	}

	{
		Copy(setting, &s->SyslogSetting, sizeof(SYSLOG_SETTING));
	}
}


void GetServerProductName(SERVER *s, char *name, UINT size)
{
	if (s == NULL || name == NULL)
	{
		return;
	}

	StrCpy(name, size, CEDAR_SERVER_STR " (64 bit)");
}

bool CheckLogFileNameFromEnumList(LIST *o, char *name)
{
	LOG_FILE t;
	if (o == NULL || name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Path, sizeof(t.Path), name);

	if (Search(o, &t) == NULL)
	{
		return false;
	}

	return true;
}

void FreeEnumLogFile(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

LIST *EnumLogFile(char *hubname)
{
	char exe_dir[MAX_PATH];
	char tmp[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);
	DIRLIST *dir;

	if (StrLen(hubname) == 0)
	{
		hubname = NULL;
	}

	GetExeDir(exe_dir, sizeof(exe_dir));

	if (hubname == NULL)
	{
		EnumLogFileDir(o, SERVER_LOG_DIR);
	}

	Format(tmp, sizeof(tmp), "%s/"HUB_PACKET_LOG_DIR, exe_dir);

	if (hubname == NULL)
	{
		dir = EnumDir(tmp);
		if (dir != NULL)
		{
			UINT i;
			for (i = 0;i < dir->NumFiles;i++)
			{
				DIRENT *e = dir->File[i];

				if (e->Folder)
				{
					char dir_name[MAX_PATH];
					Format(dir_name, sizeof(dir_name), HUB_PACKET_LOG_DIR"/%s", e->FileName);
					EnumLogFileDir(o, dir_name);
				}
			}

			FreeDir(dir);
		}
	}
	else
	{
		char dir_name[MAX_PATH];

		Format(dir_name, sizeof(dir_name), HUB_PACKET_LOG_DIR"/%s", hubname);

		EnumLogFileDir(o, dir_name);
	}

	Format(tmp, sizeof(tmp), "%s/"HUB_SECURITY_LOG_DIR, exe_dir);

	if (hubname == NULL)
	{
		dir = EnumDir(tmp);
		if (dir != NULL)
		{
			UINT i;
			for (i = 0;i < dir->NumFiles;i++)
			{
				DIRENT *e = dir->File[i];

				if (e->Folder)
				{
					char dir_name[MAX_PATH];

					Format(dir_name, sizeof(dir_name), HUB_SECURITY_LOG_DIR"/%s", e->FileName);

					EnumLogFileDir(o, dir_name);
				}
			}

			FreeDir(dir);
		}
	}
	else
	{
		char dir_name[MAX_PATH];

		Format(dir_name, sizeof(dir_name), HUB_SECURITY_LOG_DIR"/%s", hubname);

		EnumLogFileDir(o, dir_name);
	}

	return o;
}

void EnumLogFileDir(LIST *o, char *dirname)
{
	UINT i;
	char exe_dir[MAX_PATH];
	char dir_full_path[MAX_PATH];
	DIRLIST *dir;
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(dir_full_path, sizeof(dir_full_path), "%s/%s", exe_dir, dirname);

	dir = EnumDir(dir_full_path);
	if (dir == NULL)
	{
		return;
	}

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];

		if (e->Folder == false && e->FileSize > 0)
		{
			char full_path[MAX_PATH];
			char file_path[MAX_PATH];

			Format(file_path, sizeof(file_path), "%s/%s", dirname, e->FileName);
			Format(full_path, sizeof(full_path), "%s/%s", exe_dir, file_path);

			if (EndWith(file_path, ".log"))
			{
				LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

				StrCpy(f->Path, sizeof(f->Path), file_path);
				f->FileSize = (UINT)(MIN(e->FileSize, 0xffffffffUL));
				f->UpdatedTime = e->UpdateDate;

				Insert(o, f);
			}
		}
	}

	FreeDir(dir);
}

int CmpLogFile(void *p1, void *p2)
{
	LOG_FILE *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(LOG_FILE **)p1;
	f2 = *(LOG_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}

	return StrCmpi(f1->Path, f2->Path);
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

	AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS);

	AddCapsInt(t, "i_max_sessions", SERVER_MAX_SESSIONS);

	AddCapsInt(t, "i_max_user_creation", INFINITE);

	AddCapsInt(t, "i_max_clients", INFINITE);

	AddCapsInt(t, "i_max_bridges", INFINITE);

	AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

	AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

	AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);

	AddCapsBool(t, "b_support_limit_multilogin", true);

	AddCapsBool(t, "b_support_qos", true);

	AddCapsBool(t, "b_support_syslog", true);

	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	AddCapsBool(t, "b_support_cascade", true);

	AddCapsBool(t, "b_standalone", true);

	AddCapsBool(t, "b_support_config_hub", true);

	AddCapsBool(t, "b_vpn_client_connect", true);

	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (IsBridgeSupported())
	{
		// No TAP device on Windows; the cap stays for admin clients that read it
		AddCapsBool(t, "b_tap_supported", false);
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

	AddCapsBool(t, "b_support_crl", true);

	AddCapsBool(t, "b_support_ac", true);

	AddCapsBool(t, "b_support_read_log", true);

	AddCapsBool(t, "b_support_rename_cascade", true);

	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	if (IsBridgeSupported())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}

	AddCapsBool(t, "b_support_check_mac", true);

	AddCapsBool(t, "b_support_check_tcp_state", true);

	AddCapsBool(t, "b_support_vlan", true);

	AddCapsBool(t, "b_support_hub_ext_options", true);

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
}

static const RPC_FIELD rpc_syslog_setting_fields[] =
{
	RPC_ROW_INT(SYSLOG_SETTING, SaveType, "SaveType"),
	RPC_ROW_INT(SYSLOG_SETTING, Port, "Port"),
	RPC_ROW_STR(SYSLOG_SETTING, Hostname, "Hostname"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_syslog_setting_table, SYSLOG_SETTING, rpc_syslog_setting_fields);

void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p)
{
	RpcFieldIn(&rpc_syslog_setting_table, t, p);
}
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t)
{
	RpcFieldOut(&rpc_syslog_setting_table, p, t);
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

// Validity of the default server certificate in days: until 2038-01-01, or from 2030 on until
// 2049-12-30. Certificate times themselves have no 2050 limit (UINT64ToAsn1Time writes GeneralizedTime);
// the default certificate keeps its existing end date
static UINT SiGetDefaultCertDays()
{
	UINT64 now = SystemTime64();
	UINT64 target;
	SYSTEMTIME st;

	Zero(&st, sizeof(st));
	SystemTime(&st);
	if (st.wYear >= 2030)
	{
		Zero(&st, sizeof(st));
		st.wYear = 2049;
		st.wMonth = 12;
		st.wDay = 30;
	}
	else
	{
		Zero(&st, sizeof(st));
		st.wYear = 2038;
		st.wMonth = 1;
		st.wDay = 1;
	}

	target = SystemToUINT64(&st);
	if (now >= target)
	{
		return 0;
	}

	return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
}

void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name)
{
	X *x;
	K *private_key, *public_key;
	NAME *name;
	char tmp[MAX_SIZE];
	wchar_t cn[MAX_SIZE];
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	RsaGen(&private_key, &public_key, 2048);

	if (IsEmptyStr(common_name))
	{
		StrCpy(tmp, sizeof(tmp), "server.softether.vpn");
		GetMachineName(tmp, sizeof(tmp));
		StrToUni(cn, sizeof(cn), tmp);
	}
	else
	{
		StrToUni(cn, sizeof(cn), common_name);
	}

	name = NewName(cn, cn, cn,
		L"US", NULL, NULL);
	x = NewRootX(public_key, private_key, name, SiGetDefaultCertDays(), NULL);

	*server_x = x;
	*server_k = private_key;

	FreeName(name);

	FreeK(public_key);
}

static void SiInitDefaultServerCert(SERVER *s)
{
	X *x = NULL;
	K *k = NULL;
	if (s == NULL)
	{
		return;
	}

	SiGenerateDefaultCertEx(&x, &k, NULL);

	SetCedarCertAndChain(s->Cedar, x, k, NULL);

	FreeX(x);
	FreeK(k);
}

static void SiInitCipherName(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
}

static void SiInitListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		{
			// Default listeners: 443 and 5555
			SiAddListenerEx(s, SERVER_DEF_PORTS_1, true, false);
			SiAddListenerEx(s, SERVER_DEF_PORTS_4, true, false);
		}
	}
	SiUnlockListenerList(s);
}

bool SiDeleteListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	SiDisableListener(s, port);

	if (e->Listener != NULL)
	{
		ReleaseListener(e->Listener);
	}

	Delete(s->ServerListenerList, e);
	Free(e);

	return true;
}

static int CompareServerListener(void *p1, void *p2)
{
	SERVER_LISTENER *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SERVER_LISTENER **)p1;
	s2 = *(SERVER_LISTENER **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1->Port > s2->Port)
	{
		return 1;
	}
	else if (s1->Port < s2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

bool SiDisableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled == false || e->Listener == NULL)
	{
		return true;
	}

	StopListener(e->Listener);

	ReleaseListener(e->Listener);
	e->Listener = NULL;

	e->Enabled = false;

	return true;
}

bool SiEnableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled)
	{
		return true;
	}

	e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	if (e->Listener == NULL)
	{
		return false;
	}

	e->Listener->DisableDos = e->DisableDos;

	e->Enabled = true;

	return true;
}

SERVER_LISTENER *SiGetListener(SERVER *s, UINT port)
{
	UINT i;
	if (s == NULL || port == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return e;
		}
	}

	return NULL;
}

bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos)
{
	SERVER_LISTENER *e;
	UINT i;
	if (s == NULL || port == 0)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return false;
		}
	}

	e = ZeroMalloc(sizeof(SERVER_LISTENER));
	e->Enabled = enabled;
	e->Port = port;
	e->DisableDos = disable_dos;

	if (e->Enabled)
	{
		e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
		if (e->Listener != NULL)
		{
			e->Listener->DisableDos = e->DisableDos;
		}
	}

	Insert(s->ServerListenerList, e);

	return true;
}

void SiLockListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
}

void SiUnlockListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	UnlockList(s->ServerListenerList);
}

void SiSetDefaultHubOption(HUB_OPTION *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < num_hub_option_fields;i++)
	{
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->Default != 0)
		{
			SetHubOptionField(o, f, f->Default);
		}
	}

	// A zero default is not applied (the caller may have set NoEnum), except MaxSession which is always reset
	o->MaxSession = 0;
}

static void SiInitDefaultHubList(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));

	SiSetDefaultHubOption(&o);

	h = NewHub(s->Cedar, SERVER_DEFAULT_HUB_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	h->Offline = true;
	SetHubOnline(h);

	ReleaseHub(h);
}

static void SiLoadInitialConfiguration(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	SiLoadGlobalParamsCfg(NULL);

	{
		Sha0(s->HashedPassword, "", 0);
	}

	SiInitCipherName(s);

	SiInitDefaultServerCert(s);

	// A fresh config does no reverse DNS or NetBIOS probe on the accept path
	s->DisableGetHostNameWhenAcceptTcp = true;
	DisableGetHostNameWhenAcceptInit();

	{
		SiInitDefaultHubList(s);
	}

	SiInitListenerList(s);

	s->Eraser = NewEraser(s->Logger, 0);
}

static bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root)
{
	if (s == NULL || root == NULL)
	{
		return false;
	}

	return SiLoadConfigurationCfg(s, root);
}

// Log what happened to a configuration file that could not be read: renamed to .bad, or still in place
static void SiLogBadConfigurationFile(SERVER *s)
{
	CFG_RW *rw = s->CfgRw;

	if (rw->BadFileRenamed)
	{
		SLog(s->Cedar, "LS_CONFIG_SET_ASIDE", rw->FileNameW, rw->FileNameW);
	}
	else if (rw->BadFilePending)
	{
		SLog(s->Cedar, "LS_CONFIG_SET_ASIDE_FAILED", rw->FileNameW, rw->FileNameW);
	}
}

static bool SiLoadConfigurationFile(SERVER *s)
{
	bool ret = false;
	FOLDER *root;
	if (s == NULL)
	{
		return false;
	}


	s->CfgRw = NewCfgRwEx2A(&root, SERVER_CONFIG_FILE_NAME, false, SERVER_CONFIG_TEMPLATE_NAME);

	SiLogBadConfigurationFile(s);

	if (server_reset_setting)
	{
		CfgDeleteFolder(root);
		root = NULL;
		server_reset_setting = false;
	}

	if (root == NULL)
	{
		return false;
	}

	ret = SiLoadConfigurationFileMain(s, root);

	CfgDeleteFolder(root);

	if (ret == false && s->CfgRw->BadFileRenamed == false)
	{
		// A parsed file without a server configuration: keep it as .bad, the server starts with the initial
		// settings
		CfgRwSetAsideBadFile(s->CfgRw);
		SiLogBadConfigurationFile(s);
	}

	return ret;
}

static void SiInitConfiguration(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	SLog(s->Cedar, "LS_LOAD_CONFIG_1");
	if (SiLoadConfigurationFile(s) == false)
	{
		InitEth();

		SLog(s->Cedar, "LS_LOAD_CONFIG_3");
		SiLoadInitialConfiguration(s);

		SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);

		server_reset_setting = false;
	}
	else
	{
		SLog(s->Cedar, "LS_LOAD_CONFIG_2");
	}

	s->CfgRw->DontBackup = s->DontBackupConfig;

	if (s->DisableDosProtection)
	{
		DisableDosProtect();
	}
	else
	{
		EnableDosProtect();
	}

	s->AutoSaveConfigSpanSaved = s->AutoSaveConfigSpan;

	// User mode: save more often
	if (MsIsUserMode())
	{
		s->AutoSaveConfigSpan = MIN(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_USERMODE);
	}

	SLog(s->Cedar, "LS_INIT_SAVE_THREAD", s->AutoSaveConfigSpan / 1000);
	s->SaveHaltEvent = NewEvent();
	s->SaveThread = NewThread(SiSaverThread, s);
}

bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root)
{
	FOLDER *f1, *f2, *f3, *f4;
	if (s == NULL || root == NULL)
	{
		return false;
	}

	f1 = CfgFindFolder(root, "ServerConfiguration");
	f2 = CfgFindFolder(root, "VirtualHUB");
	f3 = CfgFindFolder(root, "ListenerList");
	f4 = CfgFindFolder(root, "LocalBridgeList");

	if (f1 == NULL)
	{
		SLog(s->Cedar, "LS_BAD_CONFIG");
		return false;
	}

	if (f4 != NULL)
	{
		bool b = true;

		if (CfgIsItem(f4, "EnableSoftEtherKernelModeDriver"))
		{
			b = CfgGetBool(f4, "EnableSoftEtherKernelModeDriver");
		}

		Win32SetEnableSeLow(b);
	}

	InitEth();

	s->ConfigRevision = CfgGetInt(root, "ConfigRevision");

	SiLoadServerCfg(s, f1);

	SiLoadHubs(s, f2);

	SiLoadListeners(s, f3);

	if (f4 != NULL)
	{
		SiLoadLocalBridges(s, f4);
	}

	return true;
}

static void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r)
{
	if (f == NULL || r == NULL)
	{
		return;
	}

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
	CfgAddBool(f, "DisableDos", r->DisableDos);
}

static void SiLoadListenerCfg(SERVER *s, FOLDER *f)
{
	bool enable;
	UINT port;
	bool disable_dos;
	if (s == NULL || f == NULL)
	{
		return;
	}

	enable = CfgGetBool(f, "Enabled");
	port = CfgGetInt(f, "Port");
	disable_dos = CfgGetBool(f, "DisableDos");

	if (port == 0)
	{
		return;
	}

	SiAddListenerEx(s, port, enable, disable_dos);
}

void SiLoadListeners(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	if (s == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgFindFolder(f, t->Token[i]);
		if (ff != NULL)
		{
			SiLoadListenerCfg(s, ff);
		}
	}
	FreeToken(t);
}

static void SiWriteListeners(FOLDER *f, SERVER *s)
{
	if (f == NULL || s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *r = LIST_DATA(s->ServerListenerList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Listener%u", i);
			SiWriteListenerCfg(CfgCreateFolder(f, name), r);
		}
	}
	UnlockList(s->ServerListenerList);
}

static void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br)
{
	if (f == NULL || br == NULL)
	{
		return;
	}

	CfgAddStr(f, "DeviceName", br->DeviceName);
	CfgAddStr(f, "HubName", br->HubName);
	CfgAddBool(f, "NoPromiscuousMode", br->Local);
	CfgAddBool(f, "MonitorMode", br->Monitor);
	CfgAddBool(f, "LimitBroadcast", br->LimitBroadcast);
}

static void SiWriteLocalBridges(FOLDER *f, SERVER *s)
{
	if (s == NULL || f == NULL)
	{
		return;
	}

	CfgAddBool(f, "ShowAllInterfaces", Win32EthGetShowAllIf());

	CfgAddBool(f, "EnableSoftEtherKernelModeDriver", Win32GetEnableSeLow());

	LockList(s->Cedar->LocalBridgeList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->Cedar->LocalBridgeList);i++)
		{
			LOCALBRIDGE *br = LIST_DATA(s->Cedar->LocalBridgeList, i);
			char name[MAX_SIZE];

			Format(name, sizeof(name), "LocalBridge%u", i);
			SiWriteLocalBridgeCfg(CfgCreateFolder(f, name), br);
		}
	}
	UnlockList(s->Cedar->LocalBridgeList);
}

static void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f)
{
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	if (s == NULL || f == NULL)
	{
		return;
	}

	Zero(hub, sizeof(hub));
	Zero(nic, sizeof(nic));

	CfgGetStr(f, "HubName", hub, sizeof(hub));
	CfgGetStr(f, "DeviceName", nic, sizeof(nic));

	if (IsEmptyStr(hub) || IsEmptyStr(nic)
		)
	{
		return;
	}

	AddLocalBridge(s->Cedar, hub, nic, CfgGetBool(f, "NoPromiscuousMode"), CfgGetBool(f, "MonitorMode"),
		CfgGetBool(f, "LimitBroadcast"));
}

void SiLoadLocalBridges(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	if (s == NULL || f == NULL)
	{
		return;
	}

	Win32EthSetShowAllIf(CfgGetBool(f, "ShowAllInterfaces"));

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];

		SiLoadLocalBridgeCfg(s, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

void IncrementServerConfigRevision(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->ConfigRevision++;
}

// Stages an uploaded configuration that the next start loads in place of the live file. An upload
// that does not parse, is truncated or holds no ServerConfiguration folder gives ERR_INVALID_PARAMETER
// and a failed write ERR_INTERNAL_ERROR; either way the live configuration stays.
UINT SiStageConfiguration(SERVER *s, char *data, UINT size)
{
	BUF *b;
	FOLDER *root;
	bool valid;
	if (s == NULL || s->CfgRw == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (data == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	b = NewBufFromMemory(data, size);
	root = CfgBufToFolder(b, true);
	FreeBuf(b);

	valid = (root != NULL && CfgFindFolder(root, "ServerConfiguration") != NULL);
	CfgDeleteFolder(root);
	if (valid == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CfgStageNewFile(s->CfgRw, data, size) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

FOLDER *SiWriteConfigurationToCfg(SERVER *s)
{
	FOLDER *root;
	if (s == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddInt(root, "ConfigRevision", s->ConfigRevision);

	SiWriteListeners(CfgCreateFolder(root, "ListenerList"), s);

	SiWriteLocalBridges(CfgCreateFolder(root, "LocalBridgeList"), s);

	SiWriteServerCfg(CfgCreateFolder(root, "ServerConfiguration"), s);

	SiWriteHubs(CfgCreateFolder(root, "VirtualHUB"), s);

	if (s->Led)
	{
		CfgAddBool(root, "Led", true);
		CfgAddBool(root, "LedSpecial", s->LedSpecial);
	}


	return root;
}

static void SiLoadPolicyCfg(POLICY *p, FOLDER *f)
{
	if (f == NULL || p == NULL)
	{
		return;
	}

	Zero(p, sizeof(POLICY));

	p->Access = CfgGetBool(f, "Access");
	p->DHCPFilter = CfgGetBool(f, "DHCPFilter");
	p->DHCPNoServer = CfgGetBool(f, "DHCPNoServer");
	p->DHCPForce = CfgGetBool(f, "DHCPForce");
	p->NoBridge = CfgGetBool(f, "NoBridge");
	p->NoRouting = CfgGetBool(f, "NoRouting");
	p->CheckMac = CfgGetBool(f, "CheckMac");
	p->CheckIP = CfgGetBool(f, "CheckIP");
	p->ArpDhcpOnly = CfgGetBool(f, "ArpDhcpOnly");
	p->PrivacyFilter = CfgGetBool(f, "PrivacyFilter");
	p->NoServer = CfgGetBool(f, "NoServer");
	p->NoBroadcastLimiter = CfgGetBool(f, "NoBroadcastLimiter");
	p->MonitorPort = CfgGetBool(f, "MonitorPort");
	p->MaxConnection = CfgGetInt(f, "MaxConnection");
	p->TimeOut = CfgGetInt(f, "TimeOut");
	p->MaxMac = CfgGetInt(f, "MaxMac");
	p->MaxIP = CfgGetInt(f, "MaxIP");
	p->MaxUpload = CfgGetInt(f, "MaxUpload");
	p->MaxDownload = CfgGetInt(f, "MaxDownload");
	p->FixPassword = CfgGetBool(f, "FixPassword");
	p->MultiLogins = CfgGetInt(f, "MultiLogins");
	p->NoQoS = CfgGetBool(f, "NoQoS");

	p->RSandRAFilter = CfgGetBool(f, "RSandRAFilter");
	p->RAFilter = CfgGetBool(f, "RAFilter");
	p->DHCPv6Filter = CfgGetBool(f, "DHCPv6Filter");
	p->DHCPv6NoServer = CfgGetBool(f, "DHCPv6NoServer");
	p->NoRoutingV6 = CfgGetBool(f, "NoRoutingV6");
	p->CheckIPv6 = CfgGetBool(f, "CheckIPv6");
	p->NoServerV6 = CfgGetBool(f, "NoServerV6");
	p->MaxIPv6 = CfgGetInt(f, "MaxIPv6");
	p->NoSavePassword = CfgGetBool(f, "NoSavePassword");
	p->AutoDisconnect = CfgGetInt(f, "AutoDisconnect");
	p->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	p->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	p->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	p->NoIPv6DefaultRouterInRA = CfgGetBool(f, "NoIPv6DefaultRouterInRA");
	p->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	p->VLanId = CfgGetInt(f, "VLanId");
}

static void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode)
{
	if (f == NULL || p == NULL)
	{
		return;
	}

	if (cascade_mode == false)
	{
		CfgAddBool(f, "Access", p->Access);
	}

	CfgAddBool(f, "DHCPFilter", p->DHCPFilter);
	CfgAddBool(f, "DHCPNoServer", p->DHCPNoServer);
	CfgAddBool(f, "DHCPForce", p->DHCPForce);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoBridge", p->NoBridge);
		CfgAddBool(f, "NoRouting", p->NoRouting);
	}

	CfgAddBool(f, "CheckMac", p->CheckMac);
	CfgAddBool(f, "CheckIP", p->CheckIP);
	CfgAddBool(f, "ArpDhcpOnly", p->ArpDhcpOnly);
	CfgAddBool(f, "PrivacyFilter", p->PrivacyFilter);
	CfgAddBool(f, "NoServer", p->NoServer);
	CfgAddBool(f, "NoBroadcastLimiter", p->NoBroadcastLimiter);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "MonitorPort", p->MonitorPort);
		CfgAddInt(f, "MaxConnection", p->MaxConnection);
		CfgAddInt(f, "TimeOut", p->TimeOut);
	}

	CfgAddInt(f, "MaxMac", p->MaxMac);
	CfgAddInt(f, "MaxIP", p->MaxIP);
	CfgAddInt(f, "MaxUpload", p->MaxUpload);
	CfgAddInt(f, "MaxDownload", p->MaxDownload);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "FixPassword", p->FixPassword);
		CfgAddInt(f, "MultiLogins", p->MultiLogins);
		CfgAddBool(f, "NoQoS", p->NoQoS);
	}

	CfgAddBool(f, "RSandRAFilter", p->RSandRAFilter);
	CfgAddBool(f, "RAFilter", p->RAFilter);
	CfgAddBool(f, "DHCPv6Filter", p->DHCPv6Filter);
	CfgAddBool(f, "DHCPv6NoServer", p->DHCPv6NoServer);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoRoutingV6", p->NoRoutingV6);
	}

	CfgAddBool(f, "CheckIPv6", p->CheckIPv6);
	CfgAddBool(f, "NoServerV6", p->NoServerV6);
	CfgAddInt(f, "MaxIPv6", p->MaxIPv6);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoSavePassword", p->NoSavePassword);
		CfgAddInt(f, "AutoDisconnect", p->AutoDisconnect);
	}

	CfgAddBool(f, "FilterIPv4", p->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", p->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", p->FilterNonIP);
	CfgAddBool(f, "NoIPv6DefaultRouterInRA", p->NoIPv6DefaultRouterInRA);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", p->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddInt(f, "VLanId", p->VLanId);
}

static void SiWriteHubLinkCfg(FOLDER *f, LINK *k)
{
	if (f == NULL || k == NULL)
	{
		return;
	}

	Lock(k->lock);
	{
		CfgAddBool(f, "Online", k->Offline ? false : true);

		CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), k->Option);

		CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), k->Auth);

		if (k->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), k->Policy, true);
		}

		CfgAddBool(f, "CheckServerCert", k->CheckServerCert);
		CfgAddBool(f, "AddDefaultCA", k->AddDefaultCA);

		if (k->ServerCert != NULL)
		{
			BUF *b = XToBuf(k->ServerCert, false);
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}
	Unlock(k->lock);
}

static void SiLoadHubLinkCfg(FOLDER *f, HUB *h)
{
	bool online;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	FOLDER *pf;
	POLICY p;
	LINK *k;
	if (f == NULL || h == NULL)
	{
		return;
	}

	pf = CfgFindFolder(f, "Policy");
	if (pf == NULL)
	{
		return;
	}

	SiLoadPolicyCfg(&p, pf);

	online = CfgGetBool(f, "Online");

	o = CiLoadClientOption(CfgFindFolder(f, "ClientOption"));
	a = CiLoadClientAuth(CfgFindFolder(f, "ClientAuth"));
	if (o == NULL || a == NULL)
	{
		Free(o);
		ClientAuthFree(a);
		return;
	}

	k = NewLink(h->Cedar, h, o, a, &p);
	if (k != NULL)
	{
		BUF *b;
		k->CheckServerCert = CfgGetBool(f, "CheckServerCert");
		k->AddDefaultCA = CfgGetBool(f, "AddDefaultCA");
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			k->ServerCert = BufToX(b, false);
			FreeBuf(b);
		}

		k->Offline = !online;

		ReleaseLink(k);
	}

	Free(o);
	ClientAuthFree(a);
}

static void SiLoadHubAdminOptions(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumItemToTokenList(f);
	if (t != NULL)
	{
		UINT i;

		LockList(h->AdminOptionList);
		{
			DeleteAllHubAdminOption(h, false);

			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				ADMIN_OPTION *a;
				UINT value = CfgGetInt(f, name);;

				Trim(name);

				a = ZeroMalloc(sizeof(ADMIN_OPTION));
				StrCpy(a->Name, sizeof(a->Name), name);
				a->Value = value;

				Insert(h->AdminOptionList, a);
			}

			AddHubAdminOptionsDefaults(h, false);
		}
		UnlockList(h->AdminOptionList);

		FreeToken(t);
	}
}

static void SiWriteHubAdminOptions(FOLDER *f, HUB *h)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AdminOptionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);

			CfgAddInt(f, a->Name, a->Value);
		}
	}
	UnlockList(h->AdminOptionList);
}

static void SiWriteHubLinks(FOLDER *f, HUB *h)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Cascade%u", i);
			SiWriteHubLinkCfg(CfgCreateFolder(f, name), k);
		}
	}
	UnlockList(h->LinkList);
}

static void SiLoadHubLinks(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubLinkCfg(CfgFindFolder(f, name), h);
	}

	FreeToken(t);
}

static void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a)
{
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddUniStr(f, "Note", a->Note);
	CfgAddBool(f, "Active", a->Active);
	CfgAddInt(f, "Priority", a->Priority);
	CfgAddBool(f, "Discard", a->Discard);
	CfgAddBool(f, "IsIPv6", a->IsIPv6);

	if (a->IsIPv6 == false)
	{
		CfgAddIp32(f, "SrcIpAddress", a->SrcIpAddress);
		CfgAddIp32(f, "SrcSubnetMask", a->SrcSubnetMask);
		CfgAddIp32(f, "DestIpAddress", a->DestIpAddress);
		CfgAddIp32(f, "DestSubnetMask", a->DestSubnetMask);
	}
	else
	{
		CfgAddIp6Addr(f, "SrcIpAddress6", &a->SrcIpAddress6);
		CfgAddIp6Addr(f, "SrcSubnetMask6", &a->SrcSubnetMask6);
		CfgAddIp6Addr(f, "DestIpAddress6", &a->DestIpAddress6);
		CfgAddIp6Addr(f, "DestSubnetMask6", &a->DestSubnetMask6);
	}

	CfgAddInt(f, "Protocol", a->Protocol);
	CfgAddInt(f, "SrcPortStart", a->SrcPortStart);
	CfgAddInt(f, "SrcPortEnd", a->SrcPortEnd);
	CfgAddInt(f, "DestPortStart", a->DestPortStart);
	CfgAddInt(f, "DestPortEnd", a->DestPortEnd);
	CfgAddStr(f, "SrcUsername", a->SrcUsername);
	CfgAddStr(f, "DestUsername", a->DestUsername);
	CfgAddBool(f, "CheckSrcMac", a->CheckSrcMac);

	if (a->CheckSrcMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->SrcMacAddress);
		CfgAddStr(f, "SrcMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->SrcMacMask);
		CfgAddStr(f, "SrcMacMask", tmp);
	}

	CfgAddBool(f, "CheckDstMac", a->CheckDstMac);

	if (a->CheckDstMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->DstMacAddress);
		CfgAddStr(f, "DstMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->DstMacMask);
		CfgAddStr(f, "DstMacMask", tmp);
	}

	CfgAddBool(f, "CheckTcpState", a->CheckTcpState);
	CfgAddBool(f, "Established", a->Established);

	CfgAddStr(f, "RedirectUrl", a->RedirectUrl);

	CfgAddInt(f, "Delay", a->Delay);
	CfgAddInt(f, "Jitter", a->Jitter);
	CfgAddInt(f, "Loss", a->Loss);
}

static void SiLoadHubAccessCfg(HUB *h, FOLDER *f)
{
	ACCESS a;
	char tmp[MAX_PATH];
	if (h == NULL || f == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));

	CfgGetUniStr(f, "Note", a.Note, sizeof(a.Note));
	a.Active = CfgGetBool(f, "Active");
	a.Priority = CfgGetInt(f, "Priority");
	a.Discard = CfgGetBool(f, "Discard");
	a.IsIPv6 = CfgGetBool(f, "IsIPv6");

	if (a.IsIPv6 == false)
	{
		a.SrcIpAddress = CfgGetIp32(f, "SrcIpAddress");
		a.SrcSubnetMask = CfgGetIp32(f, "SrcSubnetMask");
		a.DestIpAddress = CfgGetIp32(f, "DestIpAddress");
		a.DestSubnetMask = CfgGetIp32(f, "DestSubnetMask");
	}
	else
	{
		CfgGetIp6Addr(f, "SrcIpAddress6", &a.SrcIpAddress6);
		CfgGetIp6Addr(f, "SrcSubnetMask6", &a.SrcSubnetMask6);
		CfgGetIp6Addr(f, "DestIpAddress6", &a.DestIpAddress6);
		CfgGetIp6Addr(f, "DestSubnetMask6", &a.DestSubnetMask6);
	}

	a.Protocol = CfgGetInt(f, "Protocol");
	a.SrcPortStart = CfgGetInt(f, "SrcPortStart");
	a.SrcPortEnd = CfgGetInt(f, "SrcPortEnd");
	a.DestPortStart = CfgGetInt(f, "DestPortStart");
	a.DestPortEnd = CfgGetInt(f, "DestPortEnd");
	CfgGetStr(f, "SrcUsername", a.SrcUsername, sizeof(a.SrcUsername));
	CfgGetStr(f, "DestUsername", a.DestUsername, sizeof(a.DestUsername));
	a.CheckSrcMac = CfgGetBool(f, "CheckSrcMac");

	if (CfgGetByte(f, "SrcMacAddress", a.SrcMacAddress, sizeof(a.SrcMacAddress)) == 0)
	{
		CfgGetStr(f, "SrcMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacAddress, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	if (CfgGetByte(f, "SrcMacMask", a.SrcMacMask, sizeof(a.SrcMacMask)) == 0)
	{
		CfgGetStr(f, "SrcMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacMask, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	a.CheckDstMac = CfgGetBool(f, "CheckDstMac");

	if (CfgGetByte(f, "DstMacAddress", a.DstMacAddress, sizeof(a.DstMacAddress)) == 0)
	{
		CfgGetStr(f, "DstMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacAddress, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	if (CfgGetByte(f, "DstMacMask", a.DstMacMask, sizeof(a.DstMacMask)) == 0)
	{
		CfgGetStr(f, "DstMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacMask, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	a.CheckTcpState = CfgGetBool(f, "CheckTcpState");
	a.Established = CfgGetBool(f, "Established");
	a.Delay = MAKESURE(CfgGetInt(f, "Delay"), 0, HUB_ACCESSLIST_DELAY_MAX);
	a.Jitter = MAKESURE(CfgGetInt(f, "Jitter"), 0, HUB_ACCESSLIST_JITTER_MAX);
	a.Loss = MAKESURE(CfgGetInt(f, "Loss"), 0, HUB_ACCESSLIST_LOSS_MAX);

	CfgGetStr(f, "RedirectUrl", a.RedirectUrl, sizeof(a.RedirectUrl));

	AddAccessListEx(h, &a, false, false);
}

static void SiWriteHubAccessLists(FOLDER *f, HUB *h)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AccessList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(h->AccessList, i);
			char name[MAX_SIZE];
			ToStr(name, a->Id);
			SiWriteHubAccessCfg(CfgCreateFolder(f, name), a);
		}
	}
	UnlockList(h->AccessList);
}

static void SiLoadHubAccessLists(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubAccessCfg(h, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

static void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	UINT i;
	if (f == NULL || o == NULL)
	{
		return;
	}

	// An item the file does not have keeps its default
	Zero(o, sizeof(HUB_OPTION));
	SiSetDefaultHubOption(o);

	for (i = 0;i < num_hub_option_fields;i++)
	{
		HUB_OPTION_FIELD *t = &hub_option_fields[i];
		UINT value = GetHubOptionField(o, t);
		char tmp[MAX_SIZE];

		if (CfgIsItem(f, t->CfgName) == false)
		{
			continue;
		}

		switch (t->Type)
		{
		case HUB_OPTION_BOOL:
			value = CfgGetBool(f, t->CfgName);
			break;

		case HUB_OPTION_UINT:
			value = CfgGetInt(f, t->CfgName);
			break;

		case HUB_OPTION_HEX:
			if (CfgGetStr(f, t->CfgName, tmp, sizeof(tmp)))
			{
				value = HexToInt(tmp);
			}
			break;
		}

		if ((t->Flags & HUB_OPTION_ZERO_IS_DEFAULT) != 0 && value == 0)
		{
			value = t->Default;
		}

		SetHubOptionField(o, t, value);
	}
}

static void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	UINT i;
	if (f == NULL || o == NULL)
	{
		return;
	}

	for (i = 0;i < num_hub_option_fields;i++)
	{
		HUB_OPTION_FIELD *t = &hub_option_fields[i];
		UINT value = GetHubOptionField(o, t);
		char tmp[MAX_SIZE];

		if ((t->Flags & HUB_OPTION_WRITE_IF_TRUE) != 0 && value == 0)
		{
			continue;
		}

		switch (t->Type)
		{
		case HUB_OPTION_BOOL:
			CfgAddBool(f, t->CfgName, value != 0);
			break;

		case HUB_OPTION_UINT:
			CfgAddInt(f, t->CfgName, value);
			break;

		case HUB_OPTION_HEX:
			Format(tmp, sizeof(tmp), "0x%x", value);
			CfgAddStr(f, t->CfgName, tmp);
			break;
		}
	}
}

static void SiWriteUserCfg(FOLDER *f, USER *u)
{
	BUF *b;
	AUTHPASSWORD *password;
	AUTHNT *nt;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	if (f == NULL || u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		CfgAddUniStr(f, "RealName", u->RealName);
		CfgAddUniStr(f, "Note", u->Note);
		if (u->Group != NULL)
		{
			CfgAddStr(f, "GroupName", u->GroupName);
		}
		CfgAddInt64(f, "CreatedTime", u->CreatedTime);
		CfgAddInt64(f, "UpdatedTime", u->UpdatedTime);
		CfgAddInt64(f, "ExpireTime", u->ExpireTime);
		CfgAddInt64(f, "LastLoginTime", u->LastLoginTime);
		CfgAddInt(f, "NumLogin", u->NumLogin);
		if (u->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), u->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", u->Traffic);

		CfgAddInt(f, "AuthType", u->AuthType);
		if (u->AuthData != NULL)
		{
			switch (u->AuthType)
			{
			case AUTHTYPE_ANONYMOUS:
				break;

			case AUTHTYPE_PASSWORD:
				password = (AUTHPASSWORD *)u->AuthData;
				CfgAddByte(f, "AuthPassword", password->HashedKey, sizeof(password->HashedKey));

				if (IsZero(password->NtLmSecureHash, sizeof(password->NtLmSecureHash)) == false)
				{
					CfgAddByte(f, "AuthNtLmSecureHash", password->NtLmSecureHash, sizeof(password->NtLmSecureHash));
				}
				break;

			case AUTHTYPE_NT:
				nt = (AUTHNT *)u->AuthData;
				CfgAddUniStr(f, "AuthNtUserName", nt->NtUsername);
				break;

			case AUTHTYPE_USERCERT:
				usercert = (AUTHUSERCERT *)u->AuthData;
				b = XToBuf(usercert->UserX, false);
				if (b != NULL)
				{
					CfgAddBuf(f, "AuthUserCert", b);
					FreeBuf(b);
				}
				break;

			case AUTHTYPE_ROOTCERT:
				rootcert = (AUTHROOTCERT *)u->AuthData;
				if (rootcert->Serial != NULL && rootcert->Serial->size >= 1)
				{
					CfgAddByte(f, "AuthSerial", rootcert->Serial->data, rootcert->Serial->size);
				}
				if (rootcert->CommonName != NULL && UniIsEmptyStr(rootcert->CommonName) == false)
				{
					CfgAddUniStr(f, "AuthCommonName", rootcert->CommonName);
				}
				break;
			}
		}
	}
	Unlock(u->lock);
}

static void SiLoadUserCfg(HUB *h, FOLDER *f)
{
	char *username;
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char groupname[MAX_SIZE];
	FOLDER *pf;
	UINT64 created_time;
	UINT64 updated_time;
	UINT64 expire_time;
	UINT64 last_login_time;
	UINT num_login;
	POLICY p;
	TRAFFIC t;
	BUF *b;
	UINT authtype;
	void *authdata;
	X_SERIAL *serial = NULL;
	wchar_t common_name[MAX_SIZE];
	UCHAR hashed_password[SHA1_SIZE];
	UCHAR md4_password[MD5_SIZE];
	wchar_t tmp[MAX_SIZE];
	USER *u;
	USERGROUP *g;
	if (h == NULL || f == NULL)
	{
		return;
	}

	username = f->Name;
	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));
	CfgGetStr(f, "GroupName", groupname, sizeof(groupname));

	created_time = CfgGetInt64(f, "CreatedTime");
	updated_time = CfgGetInt64(f, "UpdatedTime");
	expire_time = CfgGetInt64(f, "ExpireTime");
	last_login_time = CfgGetInt64(f, "LastLoginTime");
	num_login = CfgGetInt(f, "NumLogin");
	pf = CfgFindFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}
	SiLoadTraffic(f, "Traffic", &t);

	authtype = CfgGetInt(f, "AuthType");
	authdata = NULL;

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		Zero(hashed_password, sizeof(hashed_password));
		Zero(md4_password, sizeof(md4_password));
		CfgGetByte(f, "AuthPassword", hashed_password, sizeof(hashed_password));
		CfgGetByte(f, "AuthNtLmSecureHash", md4_password, sizeof(md4_password));
		authdata = NewPasswordAuthDataRaw(hashed_password, md4_password);
		break;

	case AUTHTYPE_NT:
		if (CfgGetUniStr(f, "AuthNtUserName", tmp, sizeof(tmp)))
		{
			authdata = NewNTAuthData(tmp);
		}
		else
		{
			authdata = NewNTAuthData(NULL);
		}
		break;

	case AUTHTYPE_USERCERT:
		b = CfgGetBuf(f, "AuthUserCert");
		if (b != NULL)
		{
			X *x = BufToX(b, false);
			if (x != NULL)
			{
				authdata = NewUserCertAuthData(x);
				FreeX(x);
			}
			FreeBuf(b);
		}
		break;

	case AUTHTYPE_ROOTCERT:
		b = CfgGetBuf(f, "AuthSerial");
		if (b != NULL)
		{
			serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		CfgGetUniStr(f, "AuthCommonName", common_name, sizeof(common_name));
		authdata = NewRootCertAuthData(serial, common_name);
		break;
	}

	AcLock(h);
	{
		if (StrLen(groupname) > 0)
		{
			g = AcGetGroup(h, groupname);
		}
		else
		{
			g = NULL;
		}

		u = NewUser(username, realname, note, authtype, authdata);
		if (u != NULL)
		{
			if (g != NULL)
			{
				JoinUserToGroup(u, g);
			}

			SetUserTraffic(u, &t);

			if (pf != NULL)
			{
				SetUserPolicy(u, &p);
			}

			Lock(u->lock);
			{
				u->CreatedTime = created_time;
				u->UpdatedTime = updated_time;
				u->ExpireTime = expire_time;
				u->LastLoginTime = last_login_time;
				u->NumLogin = num_login;
			}
			Unlock(u->lock);

			AcAddUser(h, u);

			ReleaseUser(u);
		}

		if (g != NULL)
		{
			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	if (serial != NULL)
	{
		FreeXSerial(serial);
	}
}

static void SiWriteUserList(FOLDER *f, LIST *o)
{
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USER *u = LIST_DATA(o, i);
			SiWriteUserCfg(CfgCreateFolder(f, u->Name), u);
		}
	}
	UnlockList(o);
}

static void SiLoadUserList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff;
		name = t->Token[i];
		ff = CfgFindFolder(f, name);
		SiLoadUserCfg(h, ff);
	}

	FreeToken(t);
}

static void SiWriteGroupCfg(FOLDER *f, USERGROUP *g)
{
	if (f == NULL || g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		CfgAddUniStr(f, "RealName", g->RealName);
		CfgAddUniStr(f, "Note", g->Note);
		if (g->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), g->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", g->Traffic);
	}
	Unlock(g->lock);
}

static void SiLoadGroupCfg(HUB *h, FOLDER *f)
{
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char *name;
	FOLDER *pf;
	POLICY p;
	TRAFFIC t;
	USERGROUP *g;
	if (h == NULL || f == NULL)
	{
		return;
	}

	name = f->Name;

	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));

	pf = CfgFindFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}

	SiLoadTraffic(f, "Traffic", &t);

	g = NewGroup(name, realname, note);
	if (g == NULL)
	{
		return;
	}

	if (pf != NULL)
	{
		SetGroupPolicy(g, &p);
	}

	SetGroupTraffic(g, &t);

	AcLock(h);
	{
		AcAddGroup(h, g);
	}
	AcUnlock(h);

	ReleaseGroup(g);
}

static void SiWriteGroupList(FOLDER *f, LIST *o)
{
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERGROUP *g = LIST_DATA(o, i);
			SiWriteGroupCfg(CfgCreateFolder(f, g->Name), g);
		}
	}
	UnlockList(o);
}

static void SiLoadGroupList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		name = t->Token[i];
		SiLoadGroupCfg(h, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

static void SiWriteAcList(FOLDER *f, LIST *o)
{
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			AC *ac = LIST_DATA(o, i);
			FOLDER *ff;

			Format(name, sizeof(name), "Acl%u", i + 1);

			ff = CfgCreateFolder(f, name);

			CfgAddBool(ff, "Deny", ac->Deny);
			CfgAddInt(ff, "Priority", ac->Priority);
			CfgAddIp(ff, "IpAddress", &ac->IpAddress);

			if (ac->Masked)
			{
				CfgAddIp(ff, "NetMask", &ac->SubnetMask);
			}
		}
	}
	UnlockList(o);
}

static void SiLoadAcList(LIST *o, FOLDER *f)
{
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

		if (t != NULL)
		{
			UINT i;

			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgFindFolder(f, t->Token[i]);

				if (ff != NULL)
				{
					AC ac;

					Zero(&ac, sizeof(ac));
					ac.Deny = CfgGetBool(ff, "Deny");
					ac.Priority = CfgGetInt(ff, "Priority");
					CfgGetIp(ff, "IpAddress", &ac.IpAddress);

					if (CfgGetIp(ff, "NetMask", &ac.SubnetMask))
					{
						ac.Masked = true;
					}

					AddAc(o, &ac);
				}
			}

			FreeToken(t);
		}
	}
	UnlockList(o);
}

static void SiWriteCrlList(FOLDER *f, LIST *o)
{
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			CRL *crl = LIST_DATA(o, i);
			FOLDER *ff;
			NAME *n;

			Format(name, sizeof(name), "Crl%u", i);

			ff = CfgCreateFolder(f, name);
			n = crl->Name;

			if (UniIsEmptyStr(n->CommonName) == false)
			{
				CfgAddUniStr(ff, "CommonName", n->CommonName);
			}

			if (UniIsEmptyStr(n->Organization) == false)
			{
				CfgAddUniStr(ff, "Organization", n->Organization);
			}

			if (UniIsEmptyStr(n->Unit) == false)
			{
				CfgAddUniStr(ff, "Unit", n->Unit);
			}

			if (UniIsEmptyStr(n->Country) == false)
			{
				CfgAddUniStr(ff, "Country", n->Country);
			}

			if (UniIsEmptyStr(n->State) == false)
			{
				CfgAddUniStr(ff, "State", n->State);
			}

			if (UniIsEmptyStr(n->Local) == false)
			{
				CfgAddUniStr(ff, "Local", n->Local);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestMD5, MD5_SIZE);
				CfgAddStr(ff, "DigestMD5", tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestSHA1, SHA1_SIZE);
				CfgAddStr(ff, "DigestSHA1", tmp);
			}

			if (crl->Serial != NULL)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->Serial->data, crl->Serial->size);
				CfgAddStr(ff, "Serial", tmp);
			}
		}
	}
	UnlockList(o);
}

static void SiLoadCrlList(LIST *o, FOLDER *f)
{
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			CRL *crl;
			FOLDER *ff = CfgFindFolder(f, t->Token[i]);
			wchar_t cn[MAX_SIZE], org[MAX_SIZE], u[MAX_SIZE], c[MAX_SIZE],
				st[MAX_SIZE], l[MAX_SIZE];
			char tmp[MAX_SIZE];

			if (ff != NULL)
			{
				BUF *b;

				crl = ZeroMalloc(sizeof(CRL));

				CfgGetUniStr(ff, "CommonName", cn, sizeof(cn));
				CfgGetUniStr(ff, "Organization", org, sizeof(org));
				CfgGetUniStr(ff, "Unit", u, sizeof(u));
				CfgGetUniStr(ff, "Country", c, sizeof(c));
				CfgGetUniStr(ff, "State", st, sizeof(st));
				CfgGetUniStr(ff, "Local", l, sizeof(l));

				crl->Name = NewName(cn, org, u, c, st, l);

				if (CfgGetStr(ff, "Serial", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size >= 1)
						{
							crl->Serial = NewXSerial(b->Buf, b->Size);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestMD5", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == MD5_SIZE)
						{
							Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestSHA1", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == SHA1_SIZE)
						{
							Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
						}

						FreeBuf(b);
					}
				}

				Insert(o, crl);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

static void SiWriteCertList(FOLDER *f, LIST *o)
{
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		X *x;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			BUF *b;
			x = LIST_DATA(o, i);
			Format(name, sizeof(name), "Cert%u", i);
			b = XToBuf(x, false);
			if (b != NULL)
			{
				CfgAddBuf(CfgCreateFolder(f, name), "X509", b);
				FreeBuf(b);
			}
		}
	}
	UnlockList(o);
}

static void SiLoadCertList(LIST *o, FOLDER *f)
{
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *ff = CfgFindFolder(f, t->Token[i]);
			BUF *b;

			b = CfgGetBuf(ff, "X509");
			if (b != NULL)
			{
				X *x = BufToX(b, false);
				if (x != NULL)
				{
					Insert(o, x);
				}
				FreeBuf(b);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

static void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list)
{
	if (f == NULL || db == NULL)
	{
		return;
	}

	SiWriteUserList(CfgCreateFolder(f, "UserList"), db->UserList);
	SiWriteGroupList(CfgCreateFolder(f, "GroupList"), db->GroupList);
	SiWriteCertList(CfgCreateFolder(f, "CertList"), db->RootCertList);
	SiWriteCrlList(CfgCreateFolder(f, "CrlList"), db->CrlList);

	if (no_save_ac_list == false)
	{
		SiWriteAcList(CfgCreateFolder(f, "IPAccessControlList"), db->AcList);
	}
}

static void SiLoadHubDb(HUB *h, FOLDER *f)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	SiLoadGroupList(h, CfgFindFolder(f, "GroupList"));
	SiLoadUserList(h, CfgFindFolder(f, "UserList"));

	if (h->HubDb != NULL)
	{
		SiLoadCertList(h->HubDb->RootCertList, CfgFindFolder(f, "CertList"));
		SiLoadCrlList(h->HubDb->CrlList, CfgFindFolder(f, "CrlList"));
		SiLoadAcList(h->HubDb->AcList, CfgFindFolder(f, "IPAccessControlList"));
	}
}

static void SiWriteHubCfg(FOLDER *f, HUB *h)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);

	SiWriteTraffic(f, "Traffic", h->Traffic);

	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (UniIsEmptyStr(h->Msg) == false)
		{
			CfgAddUniStr(folder, "MessageText", h->Msg);
		}
	}

	SiWriteHubLogCfgEx(CfgCreateFolder(f, "LogSetting"), &h->LogSetting, false);

	SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);

	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb,
		false
		);

	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

static void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f)
{
	if (f == NULL || g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = CfgGetBool(f, "SaveSecurityLog");
	g->SecurityLogSwitchType = CfgGetInt(f, "SecurityLogSwitchType");
	g->SavePacketLog = CfgGetBool(f, "SavePacketLog");
	g->PacketLogSwitchType = CfgGetInt(f, "PacketLogSwitchType");

	g->PacketLogConfig[PACKET_LOG_TCP_CONN] = CfgGetInt(f, "PACKET_LOG_TCP_CONN");
	g->PacketLogConfig[PACKET_LOG_TCP] = CfgGetInt(f, "PACKET_LOG_TCP");
	g->PacketLogConfig[PACKET_LOG_DHCP] = CfgGetInt(f, "PACKET_LOG_DHCP");
	g->PacketLogConfig[PACKET_LOG_UDP] = CfgGetInt(f, "PACKET_LOG_UDP");
	g->PacketLogConfig[PACKET_LOG_ICMP] = CfgGetInt(f, "PACKET_LOG_ICMP");
	g->PacketLogConfig[PACKET_LOG_IP] = CfgGetInt(f, "PACKET_LOG_IP");
	g->PacketLogConfig[PACKET_LOG_ARP] = CfgGetInt(f, "PACKET_LOG_ARP");
	g->PacketLogConfig[PACKET_LOG_ETHERNET] = CfgGetInt(f, "PACKET_LOG_ETHERNET");
}

void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode)
{
	if (f == NULL || g == NULL)
	{
		return;
	}

	if (el_mode == false)
	{
		CfgAddBool(f, "SaveSecurityLog", g->SaveSecurityLog);
		CfgAddInt(f, "SecurityLogSwitchType", g->SecurityLogSwitchType);
		CfgAddBool(f, "SavePacketLog", g->SavePacketLog);
	}

	CfgAddInt(f, "PacketLogSwitchType", g->PacketLogSwitchType);

	CfgAddInt(f, "PACKET_LOG_TCP_CONN", g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
	CfgAddInt(f, "PACKET_LOG_TCP", g->PacketLogConfig[PACKET_LOG_TCP]);
	CfgAddInt(f, "PACKET_LOG_DHCP", g->PacketLogConfig[PACKET_LOG_DHCP]);
	CfgAddInt(f, "PACKET_LOG_UDP", g->PacketLogConfig[PACKET_LOG_UDP]);
	CfgAddInt(f, "PACKET_LOG_ICMP", g->PacketLogConfig[PACKET_LOG_ICMP]);
	CfgAddInt(f, "PACKET_LOG_IP", g->PacketLogConfig[PACKET_LOG_IP]);
	CfgAddInt(f, "PACKET_LOG_ARP", g->PacketLogConfig[PACKET_LOG_ARP]);
	CfgAddInt(f, "PACKET_LOG_ETHERNET", g->PacketLogConfig[PACKET_LOG_ETHERNET]);
}

static void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name)
{
	HUB *h;
	CEDAR *c;
	HUB_OPTION o;
	bool online;
	if (s == NULL || f == NULL || name == NULL)
	{
		return;
	}

	c = s->Cedar;

	Zero(&o, sizeof(o));
	SiLoadHubOptionCfg(CfgFindFolder(f, "Option"), &o);

	h = NewHub(c, name, &o);
	if (h != NULL)
	{
		HUB_LOG g;
		if (CfgGetByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword)) != sizeof(h->HashedPassword))
		{
			Sha0(h->HashedPassword, "", 0);
		}
		if (CfgGetByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword)) != sizeof(h->SecurePassword))
		{
			HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
		}

		Zero(&g, sizeof(g));
		SiLoadHubLogCfg(&g, CfgFindFolder(f, "LogSetting"));
		SetHubLogSettingEx(h, &g, false);

		online = CfgGetBool(f, "Online");

		SiLoadTraffic(f, "Traffic", h->Traffic);

		SiLoadHubAccessLists(h, CfgFindFolder(f, "AccessList"));

		{
			FOLDER *folder = CfgFindFolder(f, "Message");
			if (folder != NULL)
			{
				wchar_t *tmp = Malloc(sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1));
				if (CfgGetUniStr(folder, "MessageText", tmp, sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1)))
				{
					SetHubMsg(h, tmp);
				}
				Free(tmp);
			}
		}

		SiLoadHubLinks(h, CfgFindFolder(f, "CascadeList"));

		SiLoadHubAdminOptions(h, CfgFindFolder(f, "AdminOption"));

		SiLoadHubDb(h, CfgFindFolder(f, "SecurityAccountDatabase"));

		h->LastCommTime = CfgGetInt64(f, "LastCommTime");
		if (h->LastCommTime == 0)
		{
			h->LastCommTime = SystemTime64();
		}
		h->LastLoginTime = CfgGetInt64(f, "LastLoginTime");
		if (h->LastLoginTime == 0)
		{
			h->LastLoginTime = SystemTime64();
		}
		h->CreatedTime = CfgGetInt64(f, "CreatedTime");
		h->NumLogin = CfgGetInt(f, "NumLogin");

		AddHub(c, h);

		if (online)
		{
			h->Offline = true;
			SetHubOnline(h);
		}
		else
		{
			h->Offline = false;
			SetHubOffline(h);
		}

		WaitLogFlush(h->SecurityLogger);
		WaitLogFlush(h->PacketLogger);

		ReleaseHub(h);
	}
}

void SiWriteHubs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *hub_folder;
	CEDAR *c;
	UINT num;
	HUB **hubs;
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);

		for (i = 0;i < num;i++)
		{
			AddRef(hubs[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num;i++)
	{
		HUB *h = hubs[i];

		Lock(h->lock);
		{
			hub_folder = CfgCreateFolder(f, h->Name);
			SiWriteHubCfg(hub_folder, h);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if ((i % 30) == 1)
		{
			YieldCpu();
		}
	}

	Free(hubs);
}

void SiLoadHubs(SERVER *s, FOLDER *f)
{
	UINT i;
	FOLDER *hub_folder;
	TOKEN_LIST *t;
	if (f == NULL || s == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];

		hub_folder = CfgFindFolder(f, name);
		if (hub_folder != NULL)
		{
			SiLoadHubCfg(s, hub_folder, name);
		}
	}
	FreeToken(t);
}

// Write the machine identity salt (FIX-5, #101) as the "MachineIdSalt" item of ServerConfiguration
void SiWriteMachineIdCfg(FOLDER *f, CEDAR *c)
{
	if (f == NULL || c == NULL)
	{
		return;
	}

	CfgAddByte(f, "MachineIdSalt", c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// Load the machine identity salt. A config file without one, or with one of another size, keeps the random
// salt of NewCedar, and the next save writes it: the identity changes once on the upgrade, then stays.
void SiLoadMachineIdCfg(CEDAR *c, FOLDER *f)
{
	UCHAR salt[MACHINE_ID_SALT_SIZE];
	if (c == NULL || f == NULL)
	{
		return;
	}

	if (CfgGetByte(f, "MachineIdSalt", salt, sizeof(salt)) == sizeof(salt))
	{
		SetCedarMachineIdSalt(c, salt);
	}
}

void SiLoadServerCfg(SERVER *s, FOLDER *f)
{
	BUF *b;
	CEDAR *c;
	char tmp[MAX_SIZE];
	X *x = NULL;
	K *k = NULL;
	LIST *chain = NewList(NULL);
	FOLDER *params_folder;
	UINT i;
	if (s == NULL || f == NULL)
	{
		return;
	}

	s->AutoSaveConfigSpan = CfgGetInt(f, "AutoSaveConfigSpan") * 1000;
	if (s->AutoSaveConfigSpan == 0)
	{
		s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	}
	else
	{
		s->AutoSaveConfigSpan = MAKESURE(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_MIN, SERVER_FILE_SAVE_INTERVAL_MAX);
	}

	i = CfgGetInt(f, "MaxConcurrentDnsClientThreads");
	if (i != 0)
	{
		DnsThreadNumMaxSet(i);
	}
	else
	{
		DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);
	}

	s->DontBackupConfig = CfgGetBool(f, "DontBackupConfig");

	CfgGetIp(f, "ListenIP", &s->ListenIP);

	if (CfgIsItem(f, "BackupConfigOnlyWhenModified"))
	{
		s->BackupConfigOnlyWhenModified = CfgGetBool(f, "BackupConfigOnlyWhenModified");
	}
	else
	{
		s->BackupConfigOnlyWhenModified = true;
	}

	if (CfgIsItem(f, "ServerLogSwitchType"))
	{
		UINT st = CfgGetInt(f, "ServerLogSwitchType");

		SetLogSwitchType(s->Logger, st);
	}

	SetMaxLogSize(CfgGetInt64(f, "LoggerMaxLogSize"));

	params_folder = CfgFindFolder(f, "GlobalParams");
	SiLoadGlobalParamsCfg(params_folder);

	c = s->Cedar;
	Lock(c->lock);
	{
		FOLDER *ff;

		ff = CfgFindFolder(f, "SyslogSettings");
		if (ff != NULL)
		{
			SYSLOG_SETTING set;

			Zero(&set, sizeof(set));

			set.SaveType = CfgGetInt(ff, "SaveType");
			CfgGetStr(ff, "HostName", set.Hostname, sizeof(set.Hostname));
			set.Port = CfgGetInt(ff, "Port");

			SiSetSysLogSetting(s, &set);
		}

		s->Cedar->DisableIPv6Listener = CfgGetBool(f, "DisableIPv6Listener");

		s->DisableDosProtection = CfgGetBool(f, "DisableDosProtection");

		SetMaxConnectionsPerIp(CfgGetInt(f, "MaxConnectionsPerIP"));

		SetMaxUnestablishedConnections(CfgGetInt(f, "MaxUnestablishedConnections"));

		s->DisableDeadLockCheck = CfgGetBool(f, "DisableDeadLockCheck");

		SetEraserCheckInterval(CfgGetInt(f, "AutoDeleteCheckIntervalSecs"));
		s->Eraser = NewEraser(s->Logger, CfgGetInt64(f, "AutoDeleteCheckDiskFreeSpaceMin"));


		s->UseWebTimePage = CfgGetBool(f, "UseWebTimePage");

		s->NoHighPriorityProcess = CfgGetBool(f, "NoHighPriorityProcess");

		s->NoDebugDump = CfgGetBool(f, "NoDebugDump");

		s->SaveDebugLog = CfgGetBool(f, "SaveDebugLog");
		if (s->SaveDebugLog)
		{
			s->DebugLog = NewTinyLog();
		}

		s->NoSendSignature = CfgGetBool(f, "NoSendSignature");

		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			x = BufToX(b, false);
			FreeBuf(b);
		}

		b = CfgGetBuf(f, "ServerKey");
		if (b != NULL)
		{
			k = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}

		SiLoadCertList(chain, CfgFindFolder(f, "ServerChain"));

		if (x == NULL || k == NULL || CheckXandK(x, k) == false)
		{
			FreeX(x);
			FreeK(k);
			FreeXList(chain);
			SiGenerateDefaultCertEx(&x, &k, NULL);

			SetCedarCertAndChain(c, x, k, NULL);

			FreeX(x);
			FreeK(k);
		}
		else
		{
			if (LIST_NUM(chain) == 0)
			{
				SetCedarCertAndChain(c, x, k, NULL);
			}
			else
			{
				SetCedarCertAndChain(c, x, k, chain);
			}

			FreeX(x);
			FreeK(k);
			FreeXList(chain);
		}

		if (CfgGetStr(f, "CipherName", tmp, sizeof(tmp)))
		{
			StrUpper(tmp);
			SetCedarCipherList(c, tmp);
		}

		Lock(c->TrafficLock);
		{
			SiLoadTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		if (CfgGetByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword)) != sizeof(s->HashedPassword))
		{
			Sha0(s->HashedPassword, "", 0);
		}

		// Before SiLoadHubs: the hub MAC addresses and addresses come from the machine identity
		SiLoadMachineIdCfg(c, f);

		// Without the key the accept path does no reverse DNS or NetBIOS probe; an explicit false keeps the lookup
		s->DisableGetHostNameWhenAcceptTcp = true;
		if (CfgIsItem(f, "DisableGetHostNameWhenAcceptTcp"))
		{
			s->DisableGetHostNameWhenAcceptTcp = CfgGetBool(f, "DisableGetHostNameWhenAcceptTcp");
		}

		if (s->DisableGetHostNameWhenAcceptTcp)
		{
			DisableGetHostNameWhenAcceptInit();
		}

		s->DisableCoreDumpOnUnix = CfgGetBool(f, "DisableCoreDumpOnUnix");

		SetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT, CfgGetBool(f, "DisableSessionReconnect"));

		c->SslAcceptSettings.Tls_Disable1_0 = CfgGetBool(f, "Tls_Disable1_0");
		c->SslAcceptSettings.Tls_Disable1_1 = CfgGetBool(f, "Tls_Disable1_1");
		c->SslAcceptSettings.Tls_Disable1_2 = CfgGetBool(f, "Tls_Disable1_2");
		c->SslAcceptSettings.Tls_Disable1_3 = CfgGetBool(f, "Tls_Disable1_3");
		c->SslAcceptSettings.Override_Security_Level = CfgGetBool(f, "Override_Security_Level");
		c->SslAcceptSettings.Override_Security_Level_Value = CfgGetInt(f, "Override_Security_Level_Value");

		s->StrictSyslogDatetimeFormat = CfgGetBool(f, "StrictSyslogDatetimeFormat");

		// Missing or empty StunServer disables STUN
		CfgGetStr(f, "StunServer", c->StunServer, sizeof(c->StunServer));
		Trim(c->StunServer);

		c->DhParamBits = CfgGetInt(f, "DhParamBits");
		if (c->DhParamBits == 0)
		{
			c->DhParamBits = DH_PARAM_BITS_DEFAULT;
		}

		SetDhParam(DhNewFromBits(c->DhParamBits));
	}
	Unlock(c->lock);
}

void SiLoadGlobalParamsCfg(FOLDER *f)
{
	SiLoadGlobalParamItem(GP_MAX_SEND_SOCKET_QUEUE_SIZE, CfgGetInt(f, "MAX_SEND_SOCKET_QUEUE_SIZE"));
	SiLoadGlobalParamItem(GP_MIN_SEND_SOCKET_QUEUE_SIZE, CfgGetInt(f, "MIN_SEND_SOCKET_QUEUE_SIZE"));
	SiLoadGlobalParamItem(GP_MAX_SEND_SOCKET_QUEUE_NUM, CfgGetInt(f, "MAX_SEND_SOCKET_QUEUE_NUM"));
	SiLoadGlobalParamItem(GP_SELECT_TIME, CfgGetInt(f, "SELECT_TIME"));
	SiLoadGlobalParamItem(GP_SELECT_TIME_FOR_NAT, CfgGetInt(f, "SELECT_TIME_FOR_NAT"));
	SiLoadGlobalParamItem(GP_MAX_STORED_QUEUE_NUM, CfgGetInt(f, "MAX_STORED_QUEUE_NUM"));
	SiLoadGlobalParamItem(GP_MAX_BUFFERING_PACKET_SIZE, CfgGetInt(f, "MAX_BUFFERING_PACKET_SIZE"));
	SiLoadGlobalParamItem(GP_HUB_ARP_SEND_INTERVAL, CfgGetInt(f, "HUB_ARP_SEND_INTERVAL"));
	SiLoadGlobalParamItem(GP_MAC_TABLE_EXPIRE_TIME, CfgGetInt(f, "MAC_TABLE_EXPIRE_TIME"));
	SiLoadGlobalParamItem(GP_IP_TABLE_EXPIRE_TIME, CfgGetInt(f, "IP_TABLE_EXPIRE_TIME"));
	SiLoadGlobalParamItem(GP_IP_TABLE_EXPIRE_TIME_DHCP, CfgGetInt(f, "IP_TABLE_EXPIRE_TIME_DHCP"));
	SiLoadGlobalParamItem(GP_STORM_CHECK_SPAN, CfgGetInt(f, "STORM_CHECK_SPAN"));
	SiLoadGlobalParamItem(GP_STORM_DISCARD_VALUE_START, CfgGetInt(f, "STORM_DISCARD_VALUE_START"));
	SiLoadGlobalParamItem(GP_STORM_DISCARD_VALUE_END, CfgGetInt(f, "STORM_DISCARD_VALUE_END"));
	SiLoadGlobalParamItem(GP_MAX_MAC_TABLES, CfgGetInt(f, "MAX_MAC_TABLES"));
	SiLoadGlobalParamItem(GP_MAX_IP_TABLES, CfgGetInt(f, "MAX_IP_TABLES"));
	SiLoadGlobalParamItem(GP_MAX_HUB_LINKS, CfgGetInt(f, "MAX_HUB_LINKS"));
	SiLoadGlobalParamItem(GP_MEM_FIFO_REALLOC_MEM_SIZE, CfgGetInt(f, "MEM_FIFO_REALLOC_MEM_SIZE"));
	SiLoadGlobalParamItem(GP_QUEUE_BUDGET, CfgGetInt(f, "QUEUE_BUDGET"));
	SiLoadGlobalParamItem(GP_FIFO_BUDGET, CfgGetInt(f, "FIFO_BUDGET"));

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);
}

void SiLoadGlobalParamItem(UINT id, UINT value)
{
	if (id == 0)
	{
		return;
	}

	vpn_global_parameters[id] = value;
}

static void SiWriteGlobalParamsCfg(FOLDER *f)
{
	if (f == NULL)
	{
		return;
	}

	CfgAddInt(f, "MAX_SEND_SOCKET_QUEUE_SIZE", MAX_SEND_SOCKET_QUEUE_SIZE);
	CfgAddInt(f, "MIN_SEND_SOCKET_QUEUE_SIZE", MIN_SEND_SOCKET_QUEUE_SIZE);
	CfgAddInt(f, "MAX_SEND_SOCKET_QUEUE_NUM", MAX_SEND_SOCKET_QUEUE_NUM);
	CfgAddInt(f, "SELECT_TIME", SELECT_TIME);
	CfgAddInt(f, "SELECT_TIME_FOR_NAT", SELECT_TIME_FOR_NAT);
	CfgAddInt(f, "MAX_STORED_QUEUE_NUM", MAX_STORED_QUEUE_NUM);
	CfgAddInt(f, "MAX_BUFFERING_PACKET_SIZE", MAX_BUFFERING_PACKET_SIZE);
	CfgAddInt(f, "HUB_ARP_SEND_INTERVAL", HUB_ARP_SEND_INTERVAL);
	CfgAddInt(f, "MAC_TABLE_EXPIRE_TIME", MAC_TABLE_EXPIRE_TIME);
	CfgAddInt(f, "IP_TABLE_EXPIRE_TIME", IP_TABLE_EXPIRE_TIME);
	CfgAddInt(f, "IP_TABLE_EXPIRE_TIME_DHCP", IP_TABLE_EXPIRE_TIME_DHCP);
	CfgAddInt(f, "STORM_CHECK_SPAN", STORM_CHECK_SPAN);
	CfgAddInt(f, "STORM_DISCARD_VALUE_START", STORM_DISCARD_VALUE_START);
	CfgAddInt(f, "STORM_DISCARD_VALUE_END", STORM_DISCARD_VALUE_END);
	CfgAddInt(f, "MAX_MAC_TABLES", MAX_MAC_TABLES);
	CfgAddInt(f, "MAX_IP_TABLES", MAX_IP_TABLES);
	CfgAddInt(f, "MAX_HUB_LINKS", MAX_HUB_LINKS);
	CfgAddInt(f, "MEM_FIFO_REALLOC_MEM_SIZE", MEM_FIFO_REALLOC_MEM_SIZE);
	CfgAddInt(f, "QUEUE_BUDGET", QUEUE_BUDGET);
	CfgAddInt(f, "FIFO_BUDGET", FIFO_BUDGET);
}

void SiWriteServerCfg(FOLDER *f, SERVER *s)
{
	BUF *b;
	CEDAR *c;
	FOLDER *params_folder;
	if (f == NULL || s == NULL)
	{
		return;
	}

	CfgAddInt(f, "MaxConcurrentDnsClientThreads", DnsThreadNumMax());

	CfgAddInt(f, "CurrentBuild", CEDAR_VERSION_BUILD);

	CfgAddInt(f, "AutoSaveConfigSpan", s->AutoSaveConfigSpanSaved / 1000);

	CfgAddBool(f, "DontBackupConfig", s->DontBackupConfig);
	CfgAddBool(f, "BackupConfigOnlyWhenModified", s->BackupConfigOnlyWhenModified);

	CfgAddIp(f, "ListenIP", &s->ListenIP);

	if (s->Logger != NULL)
	{
		CfgAddInt(f, "ServerLogSwitchType", s->Logger->SwitchType);
	}

	CfgAddInt64(f, "LoggerMaxLogSize", GetMaxLogSize());

	params_folder = CfgCreateFolder(f, "GlobalParams");

	if (params_folder != NULL)
	{
		SiWriteGlobalParamsCfg(params_folder);
	}

	c = s->Cedar;

	Lock(c->lock);
	{
		FOLDER *ff;

		ff = CfgCreateFolder(f, "SyslogSettings");
		if (ff != NULL)
		{
			SYSLOG_SETTING set;

			SiGetSysLogSetting(s, &set);

			CfgAddInt(ff, "SaveType", set.SaveType);
			CfgAddStr(ff, "HostName", set.Hostname);
			CfgAddInt(ff, "Port", set.Port);
		}

		CfgAddBool(f, "DisableIPv6Listener", s->Cedar->DisableIPv6Listener);

		CfgAddBool(f, "DisableDosProtection", s->DisableDosProtection);

		CfgAddInt(f, "MaxConnectionsPerIP", GetMaxConnectionsPerIp());

		CfgAddInt(f, "MaxUnestablishedConnections", GetMaxUnestablishedConnections());

		CfgAddBool(f, "DisableDeadLockCheck", s->DisableDeadLockCheck);

		CfgAddInt64(f, "AutoDeleteCheckDiskFreeSpaceMin", s->Eraser->MinFreeSpace);
		CfgAddInt(f, "AutoDeleteCheckIntervalSecs", GetEraserCheckInterval());


		CfgAddBool(f, "NoHighPriorityProcess", s->NoHighPriorityProcess);

		CfgAddBool(f, "NoDebugDump", s->NoDebugDump);

		CfgAddBool(f, "UseWebTimePage", s->UseWebTimePage);

		CfgAddBool(f, "SaveDebugLog", s->SaveDebugLog);

		CfgAddBool(f, "NoSendSignature", s->NoSendSignature);

		b = XToBuf(c->ServerX, false);
		CfgAddBuf(f, "ServerCert", b);
		FreeBuf(b);

		b = KToBuf(c->ServerK, false, NULL);
		CfgAddBuf(f, "ServerKey", b);
		FreeBuf(b);

		SiWriteCertList(CfgCreateFolder(f, "ServerChain"), c->ServerChain);

		Lock(c->TrafficLock);
		{
			SiWriteTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		CfgAddStr(f, "CipherName", s->Cedar->CipherList);

		CfgAddByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));

		SiWriteMachineIdCfg(f, c);

		CfgAddBool(f, "DisableGetHostNameWhenAcceptTcp", s->DisableGetHostNameWhenAcceptTcp);
		CfgAddBool(f, "DisableCoreDumpOnUnix", s->DisableCoreDumpOnUnix);

		CfgAddBool(f, "Tls_Disable1_0", c->SslAcceptSettings.Tls_Disable1_0);
		CfgAddBool(f, "Tls_Disable1_1", c->SslAcceptSettings.Tls_Disable1_1);
		CfgAddBool(f, "Tls_Disable1_2", c->SslAcceptSettings.Tls_Disable1_2);
		CfgAddBool(f, "Tls_Disable1_3", c->SslAcceptSettings.Tls_Disable1_3);
		CfgAddBool(f, "Override_Security_Level", c->SslAcceptSettings.Override_Security_Level);
		CfgAddInt(f, "Override_Security_Level_Value", c->SslAcceptSettings.Override_Security_Level_Value);
		CfgAddInt(f, "DhParamBits", c->DhParamBits);

		CfgAddBool(f, "DisableSessionReconnect", GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT));

		CfgAddBool(f, "StrictSyslogDatetimeFormat", s->StrictSyslogDatetimeFormat);

		CfgAddStr(f, "StunServer", c->StunServer);

	}
	Unlock(c->lock);
}

void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	if (t != NULL)
	{
		Zero(t, sizeof(TRAFFIC));
	}
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgFindFolder(parent, name);

	if (f == NULL)
	{
		return;
	}

	SiLoadTrafficInner(f, "SendTraffic", &t->Send);
	SiLoadTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	if (e != NULL)
	{
		Zero(e, sizeof(TRAFFIC_ENTRY));
	}
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgFindFolder(parent, name);
	if (f == NULL)
	{
		return;
	}

	e->BroadcastCount = CfgGetInt64(f, "BroadcastCount");
	e->BroadcastBytes = CfgGetInt64(f, "BroadcastBytes");
	e->UnicastCount = CfgGetInt64(f, "UnicastCount");
	e->UnicastBytes = CfgGetInt64(f, "UnicastBytes");
}

void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);

	SiWriteTrafficInner(f, "SendTraffic", &t->Send);
	SiWriteTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);
	CfgAddInt64(f, "BroadcastCount", e->BroadcastCount);
	CfgAddInt64(f, "BroadcastBytes", e->BroadcastBytes);
	CfgAddInt64(f, "UnicastCount", e->UnicastCount);
	CfgAddInt64(f, "UnicastBytes", e->UnicastBytes);
}

// Save the configuration file; false when the file could not be written. *size gets the written size (0 when
// nothing changed). A failure, and the first success after one, go to the server log
static bool SiSaveConfiguration(SERVER *s, UINT *size)
{
	UINT ret;
	bool failed;
	bool was_failing;

	*size = 0;

	if (s->CfgRw == NULL || s->NoMoreSave)
	{
		return true;
	}

	Lock(s->SaveCfgLock);
	{
		FOLDER *f;

		f = SiWriteConfigurationToCfg(s);

		ret = SaveCfgRwEx(s->CfgRw, f, s->BackupConfigOnlyWhenModified ? s->ConfigRevision : INFINITE);
		failed = s->CfgRw->SaveFailed;

		CfgDeleteFolder(f);

		was_failing = s->ConfigSaveFailing;
		s->ConfigSaveFailing = failed;
	}
	Unlock(s->SaveCfgLock);

	if (failed)
	{
		SLog(s->Cedar, "LS_SAVE_CONFIG_FAILED", s->CfgRw->FileNameW);
	}
	else if (was_failing)
	{
		SLog(s->Cedar, "LS_SAVE_CONFIG_RESTORED", s->CfgRw->FileNameW);
	}

	*size = ret;

	return failed == false;
}

void SiSaverThread(THREAD *thread, void *param)
{
	SERVER *s = (SERVER *)param;
	UINT retry_span = 0;
	UINT size;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (s->Halt == false)
	{
		UINT span = s->AutoSaveConfigSpan;

		if (s->NoMoreSave == false)
		{
			if (SiSaveConfiguration(s, &size))
			{
				retry_span = 0;
			}
			else
			{
				// Back off: the first retry after SERVER_FILE_SAVE_RETRY_MIN, each next one twice as late
				retry_span = (retry_span == 0 ? SERVER_FILE_SAVE_RETRY_MIN : retry_span * 2);
				retry_span = MIN(retry_span, span);
				span = retry_span;
			}
		}

		Wait(s->SaveHaltEvent, span);
	}
}

UINT SiWriteConfigurationFile(SERVER *s)
{
	UINT size;
	if (s == NULL)
	{
		return 0;
	}

	SiSaveConfiguration(s, &size);

	return size;
}

static void SiFreeConfiguration(SERVER *s)
{
	UINT size;
	UINT i;
	if (s == NULL)
	{
		return;
	}

	// The last save: a short retry for a file that another process holds locked for a moment
	for (i = 0; i < SERVER_FILE_SAVE_FINAL_TRIES; i++)
	{
		if (i != 0)
		{
			SleepThread(SERVER_FILE_SAVE_RETRY_MIN * i);
		}

		if (SiSaveConfiguration(s, &size))
		{
			break;
		}
	}

	s->NoMoreSave = true;
	s->Halt = true;
	Set(s->SaveHaltEvent);
	WaitThread(s->SaveThread, INFINITE);

	ReleaseEvent(s->SaveHaltEvent);
	ReleaseThread(s->SaveThread);

	s->SaveHaltEvent = NULL;
	s->SaveThread = NULL;

	FreeCfgRw(s->CfgRw);
	s->CfgRw = NULL;

	FreeEth();
}

void StInit()
{
	if (server_lock != NULL)
	{
		return;
	}

	server_lock = NewLock();
}

void StFree()
{
	DeleteLock(server_lock);
	server_lock = NULL;
}

void StStartServer(void)
{
	Lock(server_lock);
	{
		if (server != NULL)
		{
			Unlock(server_lock);
			return;
		}

		server = SiNewServer();
	}
	Unlock(server_lock);
}

void StStopServer()
{
	Lock(server_lock);
	{
		if (server == NULL)
		{
			Unlock(server_lock);
			return;
		}

		SiReleaseServer(server);
		server = NULL;
	}
	Unlock(server_lock);
}

static void SiRebootServerThread(THREAD *thread, void *param)
{
	if (thread == NULL)
	{
		return;
	}

	if (server == NULL)
	{
		return;
	}

	StStopServer();

	StStartServer();
}

void SiRebootServerEx(bool reset_setting)
{
	THREAD *t;

	server_reset_setting = reset_setting;

	t = NewThread(SiRebootServerThread, NULL);
	ReleaseThread(t);
}

static void SiStopAllListener(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		UINT i;
		LIST *o = NewListFast(NULL);
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
			Add(o, e);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(o, i);
			SiDeleteListener(s, e->Port);
		}

		ReleaseList(o);
	}
	SiUnlockListenerList(s);

	ReleaseList(s->ServerListenerList);
}

static void SiCleanupServer(SERVER *s)
{
	UINT i;
	CEDAR *c;
	LISTENER **listener_list;
	UINT num_listener;
	HUB **hub_list;
	UINT num_hub;
	if (s == NULL)
	{
		return;
	}

	SiFreeDeadLockCheck(s);


	c = s->Cedar;

	IncrementServerConfigRevision(s);

	SLog(c, "LS_END_2");

	SLog(c, "LS_STOP_ALL_LISTENER");
	LockList(c->ListenerList);
	{
		listener_list = ToArray(c->ListenerList);
		num_listener = LIST_NUM(c->ListenerList);
		for (i = 0;i < num_listener;i++)
		{
			AddRef(listener_list[i]->ref);
		}
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num_listener;i++)
	{
		StopListener(listener_list[i]);
		ReleaseListener(listener_list[i]);
	}
	Free(listener_list);
	SLog(c, "LS_STOP_ALL_LISTENER_2");

	SLog(c, "LS_STOP_ALL_HUB");
	LockList(c->HubList);
	{
		hub_list = ToArray(c->HubList);
		num_hub = LIST_NUM(c->HubList);
		for (i = 0;i < num_hub;i++)
		{
			AddRef(hub_list[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num_hub;i++)
	{
		StopHub(hub_list[i]);
		ReleaseHub(hub_list[i]);
	}
	Free(hub_list);
	SLog(c, "LS_STOP_ALL_HUB_2");

	SiFreeConfiguration(s);

	SLog(c, "LS_STOP_CEDAR");
	StopCedar(s->Cedar);
	SLog(c, "LS_STOP_CEDAR_2");

	SiStopAllListener(s);

	SLog(s->Cedar, "LS_END_1");
	SLog(s->Cedar, "L_LINE");

	ReleaseCedar(s->Cedar);
	DeleteLock(s->lock);
	DeleteLock(s->SaveCfgLock);

	FreeEraser(s->Eraser);


	FreeLog(s->Logger);

	FreeSysLog(s->Syslog);
	DeleteLock(s->SyslogLock);

	SiFreeHubCreateHistory(s);

	FreeTinyLog(s->DebugLog);


	Free(s);
}

void SiReleaseServer(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		SiCleanupServer(s);
	}
}

SERVER *SiNewServer(void)
{
	SERVER *s;

	DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	s = ZeroMalloc(sizeof(SERVER));

	SetEraserCheckInterval(0);

	SiInitHubCreateHistory(s);

	Rand(s->MyRandomKey, sizeof(s->MyRandomKey));

	s->lock = NewLock();


	s->SaveCfgLock = NewLock();
	s->ref = NewRef();
	s->Cedar = NewCedar(NULL, NULL);
	s->Cedar->Server = s;


	s->IsInVm = MsIsInVm();

	s->ServerListenerList = NewList(CompareServerListener);
	s->StartTime = SystemTime64();

	PrepareChainCertDir();

	if (IsHamMode() == false)
	{
		RegistWindowsFirewallAll();
	}

	MakeDir(SERVER_LOG_DIR_NAME);
	s->Logger = NewLog(SERVER_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY);

	SLog(s->Cedar, "L_LINE");
	SLog(s->Cedar, "LS_START_2", s->Cedar->ServerStr, s->Cedar->VerString);
	SLog(s->Cedar, "LS_START_3", s->Cedar->BuildInfo);
	SLog(s->Cedar, "LS_START_UTF8");
	SLog(s->Cedar, "LS_START_1");


	// The config load stores the syslog setting under SyslogLock; the SLOG binds to the ListenIP of the config
	s->SyslogLock = NewLock();

	SiInitConfiguration(s);

	s->Syslog = NewSysLog(NULL, 0, &s->Cedar->Server->ListenIP);

	// Apply the host and port of the stored syslog setting to the new SLOG
	Lock(s->SyslogLock);
	{
		SetSysLog(s->Syslog, s->SyslogSetting.Hostname, s->SyslogSetting.Port);
	}
	Unlock(s->SyslogLock);

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);


	if (s->NoHighPriorityProcess == false)
	{
		OSSetHighPriority();
	}

	SiInitDeadLockCheck(s);

	return s;
}

