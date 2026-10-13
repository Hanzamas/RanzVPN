// Server.c
// VPN Server module

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

static SERVER *server = NULL;
static LOCK *server_lock = NULL;

bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore)
{
	return false;
}

typedef struct SI_DEBUG_PROC_LIST
{
	UINT Id;
	char *Description;
	char *Args;
	SI_DEBUG_PROC *Proc;
} SI_DEBUG_PROC_LIST;

UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str)
{
	SI_DEBUG_PROC_LIST proc_list[] =
	{
		{1, "Hello World", "<test string>", SiDebugProcHelloWorld},
		{2, "Terminate process now", "", SiDebugProcExit},
		{3, "Write memory dumpfile", "", SiDebugProcDump},
		{4, "Restore process priority", "", SiDebugProcRestorePriority},
		{5, "Set the process priority high", "", SiDebugProcSetHighPriority},
		{6, "Get the .exe filename of the process", "", SiDebugProcGetExeFileName},
		{7, "Crash the process", "", SiDebugProcCrash},
		{12, "Get the current TCP send queue length", "", SiDebugProcGetCurrentTcpSendQueueLength},
		{13, "Get the current GetIP thread count", "", SiDebugProcGetCurrentGetIPThreadCount},
	};
	UINT num_proc_list = sizeof(proc_list) / sizeof(proc_list[0]);
	UINT j;
	UINT ret_value = ERR_NO_ERROR;
	if (s == NULL || ret == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (i == 0)
	{
		char tmp[MAX_SIZE];
		Zero(ret, sizeof(RPC_TEST));

		StrCat(ret->StrValue, sizeof(ret->StrValue),
			"\n--- Debug Functions List --\n");

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (IsEmptyStr(p->Args) == false)
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u /ARG:\"%s\"\n",
					p->Id, p->Description, p->Id, p->Args);
			}
			else
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u\n",
					p->Id, p->Description, p->Id);
			}

			StrCat(ret->StrValue, sizeof(ret->StrValue), tmp);
		}
	}
	else
	{
		ret_value = ERR_NOT_SUPPORTED;

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (p->Id == i)
			{
				ret_value = p->Proc(s, str, ret->StrValue, sizeof(ret->StrValue));

				if (ret_value == ERR_NO_ERROR && IsEmptyStr(ret->StrValue))
				{
					StrCpy(ret->StrValue, sizeof(ret->StrValue), "Ok.");
				}
				break;
			}
		}
	}

	return ret_value;
}
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Format(ret_str, ret_str_size, "Hello World %s\n", in_str);

	return ERR_NO_ERROR;
}
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	_exit(1);

	return ERR_NO_ERROR;
}
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	MsWriteMinidump(NULL, NULL);

	return ERR_NO_ERROR;
}
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSRestorePriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSSetHighPriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	GetExeName(ret_str, ret_str_size);

	return ERR_NO_ERROR;
}
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CrashNow();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetCurrentTcpSendQueueLength(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	char tmp1[64], tmp2[64], tmp3[64];
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ToStr3(tmp1, 0, CedarGetCurrentTcpQueueSize(s->Cedar));
	ToStr3(tmp2, 0, CedarGetQueueBudgetConsuming(s->Cedar));
	ToStr3(tmp3, 0, CedarGetFifoBudgetConsuming(s->Cedar));

	Format(ret_str, 0, 
		"CurrentTcpQueueSize  = %s\n"
		"QueueBudgetConsuming = %s\n"
		"FifoBudgetConsuming  = %s\n",
		tmp1, tmp2, tmp3);

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetCurrentGetIPThreadCount(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	char tmp1[64], tmp2[64];
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ToStr3(tmp1, 0, DnsThreadNum());
	ToStr3(tmp2, 0, DnsThreadNumMax());

	Format(ret_str, 0, 
		"Current threads = %s\n"
		"Quota           = %s\n",
		tmp1, tmp2);

	return ERR_NO_ERROR;
}

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

void SiCheckDeadLockMain(SERVER *s, UINT timeout)
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

	CheckDeadLock(s->CapsCacheLock, timeout, "s->CapsCacheLock");

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

void SiDeadLockCheckThread(THREAD *t, void *param)
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

void SiInitDeadLockCheck(SERVER *s)
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

void SiFreeDeadLockCheck(SERVER *s)
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

void SiInitHubCreateHistory(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	s->HubCreateHistoryList = NewList(NULL);
}

void SiFreeHubCreateHistory(SERVER *s)
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

bool IsAdminPackSupportedServerProduct(char *name)
{
	return true;
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

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0)
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
	char *cpu;
	if (s == NULL || name == NULL)
	{
		return;
	}

	GetServerProductNameInternal(s, name, size);

	cpu = " (64 bit)";

	StrCat(name, size, cpu);
}
void GetServerProductNameInternal(SERVER *s, char *name, UINT size)
{
	if (s == NULL || name == NULL)
	{
		return;
	}

	if (s->Cedar->Bridge)
	{
		StrCpy(name, size, CEDAR_BRIDGE_STR);
	}
	else
	{
		StrCpy(name, size, CEDAR_SERVER_STR);
	}
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

void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(SYSLOG_SETTING));
	t->SaveType = PackGetInt(p, "SaveType");
	t->Port = PackGetInt(p, "Port");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
}
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "SaveType", t->SaveType);
	PackAddInt(p, "Port", t->Port);
	PackAddStr(p, "Hostname", t->Hostname);
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
	x = NewRootX(public_key, private_key, name, GetDaysUntil2038Ex(), NULL);

	*server_x = x;
	*server_k = private_key;

	FreeName(name);

	FreeK(public_key);
}

void SiInitDefaultServerCert(SERVER *s)
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

void SiInitCipherName(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
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

void StStartServer(bool bridge)
{
	Lock(server_lock);
	{
		if (server != NULL)
		{
			Unlock(server_lock);
			return;
		}

		server = SiNewServer(bridge);
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

	StopCedarLog();
}

void SiRebootServerThread(THREAD *thread, void *param)
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

	StStartServer((bool)param);
}

void SiCleanupServer(SERVER *s)
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

	FreeServerCapsCache(s);

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

void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size)
{
	ClearStr(region, region_size);
	if (c == NULL || region == NULL)
	{
		return;
	}

	Lock(c->CurrentRegionLock);
	{
		StrCpy(region, region_size, c->CurrentRegion);
	}
	Unlock(c->CurrentRegionLock);

	if (IsEmptyStr(region))
	{
		if (GetCurrentLangId() == SE_LANG_JAPANESE)
		{
			StrCpy(region, region_size, "JP");
		}
		else if (GetCurrentLangId() == SE_LANG_CHINESE_ZH)
		{
			StrCpy(region, region_size, "CN");
		}
	}
}

// Upstream disables these functions in Japan and China for licensing reasons.
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c)
{
	char region[128];
	bool ret = false;
	if (c == NULL)
	{
		return false;
	}


	SiGetCurrentRegion(c, region, sizeof(region));

	if (StrCmpi(region, "JP") == 0 || StrCmpi(region, "CN") == 0)
	{
		ret = true;
	}

	return ret;
}

void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update)
{
	bool changed = false;
	if (c == NULL)
	{
		return;
	}

	if (IsEmptyStr(region) == false)
	{
		Lock(c->CurrentRegionLock);
		{
			if (StrCmpi(c->CurrentRegion, region) != 0)
			{
				StrCpy(c->CurrentRegion, sizeof(c->CurrentRegion), region);
				changed = true;
			}
		}
		Unlock(c->CurrentRegionLock);
	}

	if (force_update)
	{
		changed = true;
	}

	if (changed)
	{
		FlushServerCaps(c->Server);
	}
}

SERVER *SiNewServer(bool bridge)
{
	return SiNewServerEx(bridge, false, false);
}
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server)
{
	SERVER *s;

	DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	s = ZeroMalloc(sizeof(SERVER));

	SetEraserCheckInterval(0);

	SiInitHubCreateHistory(s);

	InitServerCapsCache(s);

	Rand(s->MyRandomKey, sizeof(s->MyRandomKey));

	s->lock = NewLock();


	s->SaveCfgLock = NewLock();
	s->ref = NewRef();
	s->Cedar = NewCedar(NULL, NULL);
	s->Cedar->Server = s;


	s->IsInVm = MsIsInVm();

	s->Cedar->CheckExpires = true;
	s->ServerListenerList = NewList(CompareServerListener);
	s->StartTime = SystemTime64();

	if (bridge)
	{
		SetCedarVpnBridge(s->Cedar);
	}

	if (IsHamMode() == false)
	{
		RegistWindowsFirewallAll();
	}

	MakeDir(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME);
	s->Logger = NewLog(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY);

	SLog(s->Cedar, "L_LINE");
	SLog(s->Cedar, "LS_START_2", s->Cedar->ServerStr, s->Cedar->VerString);
	SLog(s->Cedar, "LS_START_3", s->Cedar->BuildInfo);
	SLog(s->Cedar, "LS_START_UTF8");
	SLog(s->Cedar, "LS_START_1");



	SiInitConfiguration(s);

	s->Syslog = NewSysLog(NULL, 0, &s->Cedar->Server->ListenIP);
	s->SyslogLock = NewLock();

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);


	if (s->NoHighPriorityProcess == false)
	{
		OSSetHighPriority();
	}

	SiInitDeadLockCheck(s);

	SiUpdateCurrentRegion(s->Cedar, "", true);

	return s;
}

