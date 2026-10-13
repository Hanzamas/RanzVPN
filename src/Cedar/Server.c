// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


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

static SERVER *server = NULL;
static LOCK *server_lock = NULL;
char *SERVER_CONFIG_FILE_NAME = "$ranz_server.config";
char *BRIDGE_CONFIG_FILE_NAME = "$vpn_bridge.config";
char *SERVER_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";
char *BRIDGE_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";

static bool server_reset_setting = false;

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

UINT vpn_global_parameters[NUM_GLOBAL_PARAMS] = {0};

// Get whether the number of user objects that are registered in the VPN Server is too many
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

// Debugging function
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
	// Validate arguments
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
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Format(ret_str, ret_str_size, "Hello World %s\n", in_str);

	return ERR_NO_ERROR;
}
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	_exit(1);

	return ERR_NO_ERROR;
}
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	MsWriteMinidump(NULL, NULL);

	return ERR_NO_ERROR;
}
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSRestorePriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSSetHighPriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	GetExeName(ret_str, ret_str_size);

	return ERR_NO_ERROR;
}
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
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
	// Validate arguments
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
	// Validate arguments
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

// Write the debug log
void SiDebugLog(SERVER *s, char *msg)
{
	// Validate arguments
	if (s == NULL || msg == NULL)
	{
		return;
	}

	if (s->DebugLog != NULL)
	{
		WriteTinyLog(s->DebugLog, msg);
	}
}

// Deadlock inspection main
void SiCheckDeadLockMain(SERVER *s, UINT timeout)
{
	CEDAR *cedar;
	// Validate arguments
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

// Deadlock check thread
void SiDeadLockCheckThread(THREAD *t, void *param)
{
	SERVER *s = (SERVER *)param;
	// Validate arguments
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

// Initialize the deadlock check
void SiInitDeadLockCheck(SERVER *s)
{
	// Validate arguments
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

// Release the deadlock check
void SiFreeDeadLockCheck(SERVER *s)
{
	// Validate arguments
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

// Initialize the Virtual HUB creation history
void SiInitHubCreateHistory(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->HubCreateHistoryList = NewList(NULL);
}

// Release the Virtual HUB creation history
void SiFreeHubCreateHistory(SERVER *s)
{
	UINT i;
	// Validate arguments
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

// Identify whether the server can be connected from the VPN Client that is
// created by the installer creating kit of Admin Pack
bool IsAdminPackSupportedServerProduct(char *name)
{
	return true;
}


// Get the saving status of syslog
UINT SiGetSysLogSaveStatus(SERVER *s)
{
	SYSLOG_SETTING set;
	// Validate arguments
	if (s == NULL)
	{
		return SYSLOG_NONE;
	}

	SiGetSysLogSetting(s, &set);

	return set.SaveType;
}

// Send a syslog
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message)
{
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	// Validate arguments
	if (s == NULL || typestr == NULL || message == NULL)
	{
		return;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0)
	{
		return;
	}

	// Host name
	GetMachineName(machinename, sizeof(machinename));

	// Date and time
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

// Write the syslog configuration
void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	SYSLOG_SETTING set;
	// Validate arguments
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

// Read the syslog configuration
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	// Validate arguments
	if (s == NULL || setting == NULL)
	{
		return;
	}

	{
		Copy(setting, &s->SyslogSetting, sizeof(SYSLOG_SETTING));
	}
}


// Get the server product name
void GetServerProductName(SERVER *s, char *name, UINT size)
{
	char *cpu;
	// Validate arguments
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
	// Validate arguments
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

// Check whether the log file with the specified name is contained in the enumerated list
bool CheckLogFileNameFromEnumList(LIST *o, char *name)
{
	LOG_FILE t;
	// Validate arguments
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

// Release the log file enumeration
void FreeEnumLogFile(LIST *o)
{
	UINT i;
	// Validate arguments
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

// Enumerate the log files associated with the virtual HUB (All logs are listed in the case of server administrator)
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

	GetLogDir(exe_dir, sizeof(exe_dir));

	// Enumerate in the server_log
	if (hubname == NULL)
	{
		EnumLogFileDir(o, SERVER_LOG_DIR);
	}

	// Enumerate in the packet_log
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

	// Enumerate in the security_log
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

// Enumerate log files in the specified directory
void EnumLogFileDir(LIST *o, char *dirname)
{
	UINT i;
	char exe_dir[MAX_PATH];
	char dir_full_path[MAX_PATH];
	DIRLIST *dir;
	// Validate arguments
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	GetLogDir(exe_dir, sizeof(exe_dir));
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

// Log file list entry comparison
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

// Get the Caps of the server
UINT GetServerCapsInt(SERVER *s, char *name)
{
	CAPSLIST t;
	UINT ret;
	// Validate arguments
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

// Initialize the Caps cache of the server
void InitServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->CapsCacheLock = NewLock();
	s->CapsListCache = NULL;
}

// Release the Caps cache of the server
void FreeServerCapsCache(SERVER *s)
{
	// Validate arguments
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

// Dispose the Caps cache of the server
void DestroyServerCapsCache(SERVER *s)
{
	// Validate arguments
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

// Flush the Caps list for this server
void FlushServerCaps(SERVER *s)
{
	CAPSLIST t;
	// Validate arguments
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

// Get the Caps list for this server
void GetServerCaps(SERVER *s, CAPSLIST *t)
{
	// Validate arguments
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

// Update the global server flags
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t)
{
	bool is_restricted = false;
	// Validate arguments
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

// Set a global server flag
void SetGlobalServerFlag(UINT index, UINT value)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return;
	}

	global_server_flags[index] = value;
}

// Get a global server flag
UINT GetGlobalServerFlag(UINT index)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return 0;
	}

	return global_server_flags[index];
}

// Main of the acquisition of Caps of the server
void GetServerCapsMain(SERVER *s, CAPSLIST *t)
{
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	// Initialize
	InitCapsList(t);

	// Maximum Ethernet packet size
	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	if (s->Cedar->Bridge == false)
	{
		UINT max_sessions, max_clients, max_bridges, max_user_creations;

		max_clients = INFINITE;
		max_bridges = INFINITE;
		max_sessions = SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION;
		max_user_creations = INFINITE;

		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", max_sessions);

		// Maximum number of creatable users
		AddCapsInt(t, "i_max_user_creation", max_user_creations);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", max_clients);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", max_bridges);

		// Maximum number of registrable users / Virtual HUB
		AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

		// Maximum number of registrable groups / Virtual HUB
		AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

		// Maximum number of registrable access list entries / Virtual HUB
		AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);

		// The policy related to multiple logins
		AddCapsBool(t, "b_support_limit_multilogin", true);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);
	}
	else
	{
		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", 0);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", 0);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", 0);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", 0);

		// Maximum number of registrable users / Virtual HUB
		AddCapsInt(t, "i_max_users_per_hub", 0);

		// Maximum number of registrable groups / Virtual HUB
		AddCapsInt(t, "i_max_groups_per_hub", 0);

		// Maximum number of registrable access list entries / Virtual HUB
		AddCapsInt(t, "i_max_access_lists", 0);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);
	}

	// Maximum MAC address table  size / Virtual HUB
	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	// Maximum IP address table  size / Virtual HUB
	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	// Cascade connection
	AddCapsBool(t, "b_support_cascade", true);

	if (s->Cedar->Bridge)
	{
		// Bridge mode
		AddCapsBool(t, "b_bridge", true);
	}
	else
	{
		// Stand-alone mode
		AddCapsBool(t, "b_standalone", true);
	}

	// Virtual HUB is modifiable
	AddCapsBool(t, "b_support_config_hub", s->Cedar->Bridge == false);

	// VPN client can be connected
	AddCapsBool(t, "b_vpn_client_connect", s->Cedar->Bridge == false ? true : false);

	// Local-bridge function is available
	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (IsBridgeSupported())
	{
		// TUN / TAP device availability (Linux and BSD)
		const UINT OsType = GetOsInfo()->OsType;
		AddCapsBool(t, "b_tap_supported", OsType == OSTYPE_LINUX || OsType == OSTYPE_BSD);
	}

	// Cascade connection
	AddCapsBool(t, "b_support_cascade", true);

	// Server authentication can be used in cascade connection
	AddCapsBool(t, "b_support_cascade_cert", true);

	//  the log file settings is modifiable
	AddCapsBool(t, "b_support_config_log", true);

	// Automatic deletion of log file is available
	AddCapsBool(t, "b_support_autodelete", true);

	// Config file operation is available
	AddCapsBool(t, "b_support_config_rw", true);

	// Attribute of each Virtual HUB can be set
	AddCapsBool(t, "b_support_hub_admin_option", true);

	// Client certificate can be set in a cascade connection
	AddCapsBool(t, "b_support_cascade_client_cert", true);

	// Virtual HUB can be hidden
	AddCapsBool(t, "b_support_hide_hub", true);

	// Flag of open-source version
	AddCapsBool(t, "b_is_softether", true);

	if (s->Cedar->Bridge == false)
	{
		// Support for CRL
		AddCapsBool(t, "b_support_crl", true);

		// Supports AC
		AddCapsBool(t, "b_support_ac", true);
	}

	// Supports downloading a log file
	AddCapsBool(t, "b_support_read_log", true);

	// Cascade connection can be renamed
	AddCapsBool(t, "b_support_rename_cascade", true);


	if (s->Cedar->Beta)
	{
		// Beta version
		AddCapsBool(t, "b_beta_version", true);
	}

	// VM discrimination
	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	// Support for display name of the network connection for the local bridge
	if (IsBridgeSupported())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}

	// Support for MAC address filtering
	AddCapsBool(t, "b_support_check_mac", true);

	// Support for status check of the TCP connection
	AddCapsBool(t, "b_support_check_tcp_state", true);

	// Can manage the ID of the tagged VLAN in the MAC address table
	AddCapsBool(t, "b_support_vlan", true);

	// Support for Virtual HUB extended options
	if (s->Cedar->Bridge == false)
	{
		AddCapsBool(t, "b_support_hub_ext_options", true);
	}
	else
	{
		AddCapsBool(t, "b_support_hub_ext_options", false);
	}

	// Support for Security Policy version 3.0
	AddCapsBool(t, "b_support_policy_ver_3", true);

	// Support for IPv6 access list
	AddCapsBool(t, "b_support_ipv6_acl", true);

	// Support for setting of delay, jitter and packet loss in the access list
	AddCapsBool(t, "b_support_ex_acl", true);

	// Support for URL redirection in the access list
	AddCapsBool(t, "b_support_redirect_url_acl", true);

	// Supports the specification by the group name in the access list
	AddCapsBool(t, "b_support_acl_group", true);

	// Support for IPv6 in connection source IP restriction list
	AddCapsBool(t, "b_support_ipv6_ac", true);

	// Support for VLAN tagged packet transmission configuration tool
	AddCapsBool(t, "b_support_eth_vlan", true);

	// Support for the message display function when the VPN connect to the Virtual HUB
	AddCapsBool(t, "b_support_msg", true);

	// UDP acceleration feature
	AddCapsBool(t, "b_support_udp_acceleration", true);

	// AES acceleration function
	AddCapsBool(t, "b_support_aes_ni", IsAesNiSupported());

	// SeLow driver
	AddCapsBool(t, "b_using_selow_driver", Win32IsUsingSeLow());

	// VPN3
	AddCapsBool(t, "b_vpn3", true);

	// VPN4
	AddCapsBool(t, "b_vpn4", true);


	UpdateGlobalServerFlags(s, t);
}

// SYSLOG_SETTING
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p)
{
	// Validate arguments
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
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "SaveType", t->SaveType);
	PackAddInt(p, "Port", t->Port);
	PackAddStr(p, "Hostname", t->Hostname);
}

// CAPSLIST
void InitCapsList(CAPSLIST *t)
{
	// Validate arguments
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
	// Validate arguments
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
	// Validate arguments
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
	// Validate arguments
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

// Add a bool type to Caps list
void AddCapsBool(CAPSLIST *caps, char *name, bool b)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

// Add the int type to Caps list
void AddCapsInt(CAPSLIST *caps, char *name, UINT i)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, i);
	AddCaps(caps, c);
}

// Get the int type from the Caps list
UINT GetCapsInt(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
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

// Get bool type from the Caps list
bool GetCapsBool(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
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

// Release the Caps list
void FreeCapsList(CAPSLIST *caps)
{
	UINT i;
	// Validate arguments
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

// Get the Caps
CAPS *GetCaps(CAPSLIST *caps, char *name)
{
	UINT i;
	// Validate arguments
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

// Add to the Caps
void AddCaps(CAPSLIST *caps, CAPS *c)
{
	// Validate arguments
	if (caps == NULL || c == NULL)
	{
		return;
	}

	Insert(caps->CapsList, c);
}

// Comparison of Caps
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

// Create a Caps list
CAPSLIST *NewCapsList()
{
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

// Release the Caps
void FreeCaps(CAPS *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Free(c->Name);
	Free(c);
}

// Create a Caps
CAPS *NewCaps(char *name, UINT value)
{
	CAPS *c;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}

// Generate the default certificate
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name)
{
	X *x;
	K *private_key, *public_key;
	NAME *name;
	char tmp[MAX_SIZE];
	wchar_t cn[MAX_SIZE];
	// Validate arguments
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	// Create a key pair
	RsaGen(&private_key, &public_key, 2048);

	if (IsEmptyStr(common_name))
	{
		// Get the host name
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

// Set the server certificate to default
void SiInitDefaultServerCert(SERVER *s)
{
	X *x = NULL;
	K *k = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Generate a server certificate and private key
	SiGenerateDefaultCertEx(&x, &k, NULL);

	// Configure
	SetCedarCert(s->Cedar, x, k);

	FreeX(x);
	FreeK(k);
}

// Set the encryption algorithm name to default
void SiInitCipherName(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
}

// Initialize the listener list
void SiInitListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		{
			// Register the 2 ports (443, 5555) as the default port
			SiAddListener(s, SERVER_DEF_PORTS_1, true);
			SiAddListener(s, SERVER_DEF_PORTS_4, true);
		}
	}
	SiUnlockListenerList(s);
}

// Remove the listener
bool SiDeleteListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	// Stop if still alive
	SiDisableListener(s, port);

	if (e->Listener != NULL)
	{
		ReleaseListener(e->Listener);
	}

	Delete(s->ServerListenerList, e);
	Free(e);

	return true;
}

// Compare the SERVER_LISTENER
int CompareServerListener(void *p1, void *p2)
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

// Stop the listener
bool SiDisableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Get the listener
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled == false || e->Listener == NULL)
	{
		// Already stopped
		return true;
	}

	// Stop the listener
	StopListener(e->Listener);

	// Release the listener
	ReleaseListener(e->Listener);
	e->Listener = NULL;

	e->Enabled = false;

	return true;
}

// Start the listener
bool SiEnableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Get the listener
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled)
	{
		// It has already started
		return true;
	}

	// Create a listener
	e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	if (e->Listener == NULL)
	{
		// Failure
		return false;
	}

	e->Listener->DisableDos = e->DisableDos;

	e->Enabled = true;

	return true;
}

// Get the listener
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port)
{
	UINT i;
	// Validate arguments
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

// Add a listener
bool SiAddListener(SERVER *s, UINT port, bool enabled)
{
	return SiAddListenerEx(s, port, enabled, false);
}
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos)
{
	SERVER_LISTENER *e;
	UINT i;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Check whether the listener exists already
	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			// Already exist
			return false;
		}
	}

	// Register by initializing a new listener
	e = ZeroMalloc(sizeof(SERVER_LISTENER));
	e->Enabled = enabled;
	e->Port = port;
	e->DisableDos = disable_dos;

	if (e->Enabled)
	{
		// Create a listener
		e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
		if (e->Listener != NULL)
		{
			e->Listener->DisableDos = e->DisableDos;
		}
	}

	Insert(s->ServerListenerList, e);

	return true;
}

// Lock the listener list
void SiLockListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
}

// Unlock the listener list
void SiUnlockListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	UnlockList(s->ServerListenerList);
}

// Set the default value of the Virtual HUB options
void SiSetDefaultHubOption(HUB_OPTION *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->MaxSession = 0;
	o->VlanTypeId = MAC_PROTO_TAGVLAN;
	o->NoIPv6DefaultRouterInRAWhenIPv6 = false;
	o->ManageOnlyPrivateIP = true;
	o->ManageOnlyLocalUnicastIPv6 = true;
	o->NoMacAddressLog = true;
	o->NoDhcpPacketLogOutsideHub = true;
	o->AccessListIncludeFileCacheLifetime = ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME;
	o->RemoveDefGwOnDhcpForLocalhost = true;
	o->FloodingSendQueueBufferQuota = DEFAULT_FLOODING_QUEUE_LENGTH;
	o->DhcpDiscoverTimeoutMs = DEFAULT_DHCP_DISCOVER_TIMEOUT;
}

// Create a default virtual HUB
void SiInitDefaultHubList(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	HUB_LOG g;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));

	// Configure a default Virtual HUB management options
	SiSetDefaultHubOption(&o);

	h = NewHub(s->Cedar, s->Cedar->Bridge == false ? SERVER_DEFAULT_HUB_NAME : SERVER_DEFAULT_BRIDGE_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	if (s->Cedar->Bridge)
	{
		// Randomize the password
		Rand(h->HashedPassword, sizeof(h->HashedPassword));
		Rand(h->SecurePassword, sizeof(h->SecurePassword));
	}

	h->Offline = true;
	SetHubOnline(h);

	// Log settings
	SiSetDefaultLogSetting(&g);
	SetHubLogSetting(h, &g);

	ReleaseHub(h);
}

// Set the log settings to default
void SiSetDefaultLogSetting(HUB_LOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = true;
	g->SecurityLogSwitchType = LOG_SWITCH_DAY;
	g->SavePacketLog = true;
	g->PacketLogSwitchType = LOG_SWITCH_DAY;
	g->PacketLogConfig[PACKET_LOG_TCP_CONN] =
		g->PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
}

// Set the initial configuration
void SiLoadInitialConfiguration(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Auto saving interval related
	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	SiLoadGlobalParamsCfg(NULL);

	// Initialize the password
	{
		Sha0(s->HashedPassword, "", 0);
	}

	// Set the encryption algorithm name to default
	SiInitCipherName(s);

	// Set the server certificate to default
	SiInitDefaultServerCert(s);

	// Set the character which separates the username from the hub name
	s->Cedar->UsernameHubSeparator = DEFAULT_USERNAME_HUB_SEPARATOR;

	// Create a default HUB
	{
		SiInitDefaultHubList(s);
	}

	// Set the listener list to default setting
	SiInitListenerList(s);

	s->Eraser = NewEraser(s->Logger, 0);
}

// Read the configuration file (main)
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root)
{
	// Validate arguments
	if (s == NULL || root == NULL)
	{
		return false;
	}

	return SiLoadConfigurationCfg(s, root);
}

// Read the configuration file
bool SiLoadConfigurationFile(SERVER *s)
{
	// Validate arguments
	bool ret = false;
	FOLDER *root;
	char *server_config_filename = SERVER_CONFIG_FILE_NAME;
	if (s == NULL)
	{
		return false;
	}


	s->CfgRw = NewCfgRwEx2A(&root,
		s->Cedar->Bridge == false ? server_config_filename : BRIDGE_CONFIG_FILE_NAME, false,
		s->Cedar->Bridge == false ? SERVER_CONFIG_TEMPLATE_NAME : BRIDGE_CONFIG_TEMPLATE_NAME);

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

	return ret;
}

// Initialize the configuration
void SiInitConfiguration(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	SLog(s->Cedar, "LS_LOAD_CONFIG_1");
	if (SiLoadConfigurationFile(s) == false)
	{
		// Ethernet initialization
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

	// Reduce the storage interval in the case of user mode
	if (MsIsUserMode())
	{
		s->AutoSaveConfigSpan = MIN(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_USERMODE);
	}

	// Create a saving thread
	SLog(s->Cedar, "LS_INIT_SAVE_THREAD", s->AutoSaveConfigSpan / 1000);
	s->SaveHaltEvent = NewEvent();
	s->SaveThread = NewThread(SiSaverThread, s);
}

// Read the server settings from the CFG
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root)
{
	FOLDER *f1, *f2, *f3, *f4, *f6;
	// Validate arguments
	if (s == NULL || root == NULL)
	{
		return false;
	}

	f1 = CfgGetFolder(root, "ServerConfiguration");
	f2 = CfgGetFolder(root, "VirtualHUB");
	f3 = CfgGetFolder(root, "ListenerList");
	f4 = CfgGetFolder(root, "LocalBridgeList");
	f6 = CfgGetFolder(root, "LicenseManager");

	if (f1 == NULL)
	{
		SLog(s->Cedar, "LS_BAD_CONFIG");
		return false;
	}

	if (f4 != NULL)
	{
		// Read the flag of using the SeLow driver
		bool b = true;

		if (CfgIsItem(f4, "EnableSoftEtherKernelModeDriver"))
		{
			b = CfgGetBool(f4, "EnableSoftEtherKernelModeDriver");
		}

		Win32SetEnableSeLow(b);
	}

	// Ethernet initialization
	InitEth();

	s->ConfigRevision = CfgGetInt(root, "ConfigRevision");

	if (s->Cedar->Bridge == false && f6 != NULL)
	{
		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiLoadLicenseManager(s, f6);
		}
	}

	DestroyServerCapsCache(s);

	SiLoadServerCfg(s, f1);

	SiLoadHubs(s, f2);

	SiLoadListeners(s, f3);

	if (f4 != NULL)
	{
		SiLoadLocalBridges(s, f4);
	}

	return true;
}

// Write the listener configuration
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r)
{
	// Validate arguments
	if (f == NULL || r == NULL)
	{
		return;
	}

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
	CfgAddBool(f, "DisableDos", r->DisableDos);
}

// Read the listener configuration
void SiLoadListenerCfg(SERVER *s, FOLDER *f)
{
	bool enable;
	UINT port;
	bool disable_dos;
	// Validate arguments
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

// Read the listener list
void SiLoadListeners(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgGetFolder(f, t->Token[i]);
		if (ff != NULL)
		{
			SiLoadListenerCfg(s, ff);
		}
	}
	FreeToken(t);
}

// Write the listener list
void SiWriteListeners(FOLDER *f, SERVER *s)
{
	// Validate arguments
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

// Write the bridge
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br)
{
	// Validate arguments
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

// Write the bridge list
void SiWriteLocalBridges(FOLDER *f, SERVER *s)
{
	// Validate arguments
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

// Read the bridge
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f)
{
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	bool tapmode = false;
	UCHAR tapaddr[6];
	// Validate arguments
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
		tapmode, tapaddr, CfgGetBool(f, "LimitBroadcast"));
}

// Read the bridge list
void SiLoadLocalBridges(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	Win32EthSetShowAllIf(CfgGetBool(f, "ShowAllInterfaces"));

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];

		SiLoadLocalBridgeCfg(s, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Increment the configuration revision of the server
void IncrementServerConfigRevision(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->ConfigRevision++;
}

// Write the server settings to CFG
FOLDER *SiWriteConfigurationToCfg(SERVER *s)
{
	FOLDER *root;
	char region[128];
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	SiGetCurrentRegion(s->Cedar, region, sizeof(region));

	CfgAddStr(root, "Region", region);

	CfgAddInt(root, "ConfigRevision", s->ConfigRevision);

	SiWriteListeners(CfgCreateFolder(root, "ListenerList"), s);

	SiWriteLocalBridges(CfgCreateFolder(root, "LocalBridgeList"), s);

	SiWriteServerCfg(CfgCreateFolder(root, "ServerConfiguration"), s);

	SiWriteHubs(CfgCreateFolder(root, "VirtualHUB"), s);

	if (s->Cedar->Bridge == false)
	{
		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiWriteLicenseManager(CfgCreateFolder(root, "LicenseManager"), s);
		}
	}

	if (s->Led)
	{
		CfgAddBool(root, "Led", true);
		CfgAddBool(root, "LedSpecial", s->LedSpecial);
	}


	return root;
}

// Read the policy
void SiLoadPolicyCfg(POLICY *p, FOLDER *f)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	Zero(p, sizeof(POLICY));

	// Ver 2
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

	// Ver 3
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

// Write the policy
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	// Ver 2.0
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

	if (cascade_mode == false)
	{
		CfgAddBool(f, "PrivacyFilter", p->PrivacyFilter);
	}

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

	// Ver 3.0
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

// Write the link information of the Virtual HUB
void SiWriteHubLinkCfg(FOLDER *f, LINK *k)
{
	// Validate arguments
	if (f == NULL || k == NULL)
	{
		return;
	}

	Lock(k->lock);
	{
		// Online
		CfgAddBool(f, "Online", k->Offline ? false : true);

		// Client options
		CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), k->Option);

		// Client authentication data
		CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), k->Auth);

		// Policy
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

// Read the link information
void SiLoadHubLinkCfg(FOLDER *f, HUB *h)
{
	bool online;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	FOLDER *pf;
	POLICY p;
	LINK *k;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	pf = CfgGetFolder(f, "Policy");
	if (pf == NULL)
	{
		return;
	}

	SiLoadPolicyCfg(&p, pf);

	online = CfgGetBool(f, "Online");

	o = CiLoadClientOption(CfgGetFolder(f, "ClientOption"));
	a = CiLoadClientAuth(CfgGetFolder(f, "ClientAuth"));
	if (o == NULL || a == NULL)
	{
		Free(o);
		CiFreeClientAuth(a);
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
	CiFreeClientAuth(a);
}

// Read the administration options for the virtual HUB
void SiLoadHubAdminOptions(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	// Validate arguments
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

// Write the administration options for the virtual HUB
void SiWriteHubAdminOptions(FOLDER *f, HUB *h)
{
	// Validate arguments
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

// Write the link list of the Virtual HUB
void SiWriteHubLinks(FOLDER *f, HUB *h)
{
	// Validate arguments
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

// Read the link list
void SiLoadHubLinks(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubLinkCfg(CfgGetFolder(f, name), h);
	}

	FreeToken(t);
}

// Write an item of the access list
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a)
{
	// Validate arguments
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

// Read an item of the access list
void SiLoadHubAccessCfg(HUB *h, FOLDER *f)
{
	ACCESS a;
	char tmp[MAX_PATH];
	// Validate arguments
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

	AddAccessList(h, &a);
}

// Write the access list
void SiWriteHubAccessLists(FOLDER *f, HUB *h)
{
	// Validate arguments
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

// Read the access list
void SiLoadHubAccessLists(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubAccessCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Read the HUB_OPTION
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	o->MaxSession = CfgGetInt(f, "MaxSession");
	o->NoArpPolling = CfgGetBool(f, "NoArpPolling");
	o->NoIPv6AddrPolling = CfgGetBool(f, "NoIPv6AddrPolling");
	o->NoIpTable = CfgGetBool(f, "NoIpTable");
	o->NoEnum = CfgGetBool(f, "NoEnum");
	o->FilterPPPoE = CfgGetBool(f, "FilterPPPoE");
	o->FilterOSPF = CfgGetBool(f, "FilterOSPF");
	o->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	o->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	o->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	o->FilterBPDU = CfgGetBool(f, "FilterBPDU");
	o->NoIPv4PacketLog = CfgGetBool(f, "NoIPv4PacketLog");
	o->NoIPv6PacketLog = CfgGetBool(f, "NoIPv6PacketLog");
	o->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	o->DisableIPParsing = CfgGetBool(f, "DisableIPParsing");
	o->YieldAfterStorePacket = CfgGetBool(f, "YieldAfterStorePacket");
	o->NoSpinLockForPacketDelay = CfgGetBool(f, "NoSpinLockForPacketDelay");
	o->BroadcastStormDetectionThreshold = CfgGetInt(f, "BroadcastStormDetectionThreshold");
	o->ClientMinimumRequiredBuild = CfgGetInt(f, "ClientMinimumRequiredBuild");
	o->RequiredClientId = CfgGetInt(f, "RequiredClientId");
	o->NoManageVlanId = CfgGetBool(f, "NoManageVlanId");
	o->VlanTypeId = 0;
	if (CfgGetStr(f, "VlanTypeId", tmp, sizeof(tmp)))
	{
		o->VlanTypeId = HexToInt(tmp);
	}
	if (o->VlanTypeId == 0)
	{
		o->VlanTypeId = MAC_PROTO_TAGVLAN;
	}
	o->FixForDLinkBPDU = CfgGetBool(f, "FixForDLinkBPDU");
	o->BroadcastLimiterStrictMode = CfgGetBool(f, "BroadcastLimiterStrictMode");
	o->MaxLoggedPacketsPerMinute = CfgGetInt(f, "MaxLoggedPacketsPerMinute");
	if (CfgIsItem(f, "FloodingSendQueueBufferQuota"))
	{
		o->FloodingSendQueueBufferQuota = CfgGetInt(f, "FloodingSendQueueBufferQuota");
	}
	else
	{
		o->FloodingSendQueueBufferQuota = DEFAULT_FLOODING_QUEUE_LENGTH;
	}
	o->DoNotSaveHeavySecurityLogs = CfgGetBool(f, "DoNotSaveHeavySecurityLogs");

	if (CfgIsItem(f, "DropBroadcastsInPrivacyFilterMode"))
	{
		o->DropBroadcastsInPrivacyFilterMode = CfgGetBool(f, "DropBroadcastsInPrivacyFilterMode");
	}
	else
	{
		o->DropBroadcastsInPrivacyFilterMode = true;
	}

	if (CfgIsItem(f, "DropArpInPrivacyFilterMode"))
	{
		o->DropArpInPrivacyFilterMode = CfgGetBool(f, "DropArpInPrivacyFilterMode");
	}
	else
	{
		o->DropArpInPrivacyFilterMode = true;
	}

	if (CfgIsItem(f, "AllowSameUserInPrivacyFilterMode"))
        {
                o->AllowSameUserInPrivacyFilterMode = CfgGetBool(f, "AllowSameUserInPrivacyFilterMode");
        }
        else
        {
                o->AllowSameUserInPrivacyFilterMode = false;
        }


	o->NoLookBPDUBridgeId = CfgGetBool(f, "NoLookBPDUBridgeId");
	o->AdjustTcpMssValue = CfgGetInt(f, "AdjustTcpMssValue");
	o->DisableAdjustTcpMss = CfgGetBool(f, "DisableAdjustTcpMss");
	if (CfgIsItem(f, "NoDhcpPacketLogOutsideHub"))
	{
		o->NoDhcpPacketLogOutsideHub = CfgGetBool(f, "NoDhcpPacketLogOutsideHub");
	}
	else
	{
		o->NoDhcpPacketLogOutsideHub = true;
	}
	o->DisableHttpParsing = CfgGetBool(f, "DisableHttpParsing");
	o->DisableUdpAcceleration = CfgGetBool(f, "DisableUdpAcceleration");
	o->DisableUdpFilterForLocalBridgeNic = CfgGetBool(f, "DisableUdpFilterForLocalBridgeNic");
	o->ApplyIPv4AccessListOnArpPacket = CfgGetBool(f, "ApplyIPv4AccessListOnArpPacket");
	if (CfgIsItem(f, "RemoveDefGwOnDhcpForLocalhost"))
	{
		o->RemoveDefGwOnDhcpForLocalhost = CfgGetBool(f, "RemoveDefGwOnDhcpForLocalhost");
	}
	else
	{
		o->RemoveDefGwOnDhcpForLocalhost = true;
	}
	o->AccessListIncludeFileCacheLifetime = CfgGetInt(f, "AccessListIncludeFileCacheLifetime");

	if (o->AccessListIncludeFileCacheLifetime == 0)
	{
		o->AccessListIncludeFileCacheLifetime = ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME;
	}

	o->DisableCheckMacOnLocalBridge = CfgGetBool(f, "DisableCheckMacOnLocalBridge");
	o->DisableCorrectIpOffloadChecksum = CfgGetBool(f, "DisableCorrectIpOffloadChecksum");
	o->SuppressClientUpdateNotification = CfgGetBool(f, "SuppressClientUpdateNotification");
	o->DetectDormantSessionInterval = CfgGetInt(f, "DetectDormantSessionInterval");
	o->NoPhysicalIPOnPacketLog = CfgGetBool(f, "NoPhysicalIPOnPacketLog");
	o->UseHubNameAsDhcpUserClassOption = CfgGetBool(f, "UseHubNameAsDhcpUserClassOption");
	o->AllowEapMatchUserByCert = CfgGetBool(f, "AllowEapMatchUserByCert");
	o->DhcpDiscoverTimeoutMs = CfgGetInt(f, "DhcpDiscoverTimeoutMs");
	if (o->DhcpDiscoverTimeoutMs == 0)
	{
		o->DhcpDiscoverTimeoutMs = DEFAULT_DHCP_DISCOVER_TIMEOUT;
	}

	// Enabled by default
	if (CfgIsItem(f, "ManageOnlyPrivateIP"))
	{
		o->ManageOnlyPrivateIP = CfgGetBool(f, "ManageOnlyPrivateIP");
	}
	else
	{
		o->ManageOnlyPrivateIP = true;
	}
	if (CfgIsItem(f, "ManageOnlyLocalUnicastIPv6"))
	{
		o->ManageOnlyLocalUnicastIPv6 = CfgGetBool(f, "ManageOnlyLocalUnicastIPv6");
	}
	else
	{
		o->ManageOnlyLocalUnicastIPv6 = true;
	}
	if (CfgIsItem(f, "NoMacAddressLog"))
	{
		o->NoMacAddressLog = CfgGetBool(f, "NoMacAddressLog");
	}
	else
	{
		o->NoMacAddressLog = true;
	}
}

// Write the HUB_OPTION
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	CfgAddInt(f, "MaxSession", o->MaxSession);
	CfgAddBool(f, "NoArpPolling", o->NoArpPolling);
	CfgAddBool(f, "NoIPv6AddrPolling", o->NoIPv6AddrPolling);
	CfgAddBool(f, "NoIpTable", o->NoIpTable);
	CfgAddBool(f, "NoEnum", o->NoEnum);
	CfgAddBool(f, "FilterPPPoE", o->FilterPPPoE);
	CfgAddBool(f, "FilterOSPF", o->FilterOSPF);
	CfgAddBool(f, "FilterIPv4", o->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", o->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", o->FilterNonIP);
	CfgAddBool(f, "NoIPv4PacketLog", o->NoIPv4PacketLog);
	CfgAddBool(f, "NoIPv6PacketLog", o->NoIPv6PacketLog);
	CfgAddBool(f, "FilterBPDU", o->FilterBPDU);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddBool(f, "NoMacAddressLog", o->NoMacAddressLog);
	CfgAddBool(f, "ManageOnlyPrivateIP", o->ManageOnlyPrivateIP);
	CfgAddBool(f, "ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6);
	CfgAddBool(f, "DisableIPParsing", o->DisableIPParsing);
	CfgAddBool(f, "YieldAfterStorePacket", o->YieldAfterStorePacket);
	CfgAddBool(f, "NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay);
	CfgAddInt(f, "BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold);
	CfgAddInt(f, "ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild);
	CfgAddInt(f, "RequiredClientId", o->RequiredClientId);
	CfgAddBool(f, "NoManageVlanId", o->NoManageVlanId);
	Format(tmp, sizeof(tmp), "0x%x", o->VlanTypeId);
	CfgAddStr(f, "VlanTypeId", tmp);
	if (o->FixForDLinkBPDU)
	{
		CfgAddBool(f, "FixForDLinkBPDU", o->FixForDLinkBPDU);
	}
	CfgAddBool(f, "BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode);
	CfgAddInt(f, "MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute);
	CfgAddInt(f, "FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota);
	CfgAddBool(f, "DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs);
	CfgAddBool(f, "DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode);
	CfgAddBool(f, "DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode);
	CfgAddBool(f, "AllowSameUserInPrivacyFilterMode", o->AllowSameUserInPrivacyFilterMode);
	CfgAddBool(f, "SuppressClientUpdateNotification", o->SuppressClientUpdateNotification);
	CfgAddBool(f, "NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog);
	CfgAddInt(f, "DetectDormantSessionInterval", o->DetectDormantSessionInterval);
	CfgAddBool(f, "NoLookBPDUBridgeId", o->NoLookBPDUBridgeId);
	CfgAddInt(f, "AdjustTcpMssValue", o->AdjustTcpMssValue);
	CfgAddBool(f, "DisableAdjustTcpMss", o->DisableAdjustTcpMss);
	CfgAddBool(f, "NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub);
	CfgAddBool(f, "DisableHttpParsing", o->DisableHttpParsing);
	CfgAddBool(f, "DisableUdpAcceleration", o->DisableUdpAcceleration);
	CfgAddBool(f, "DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic);
	CfgAddBool(f, "ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket);
	CfgAddBool(f, "RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost);
	CfgAddInt(f, "AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime);
	CfgAddBool(f, "DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge);
	CfgAddBool(f, "DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum);
	CfgAddBool(f, "UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption);
	CfgAddBool(f, "AllowEapMatchUserByCert", o->AllowEapMatchUserByCert);
	CfgAddInt(f, "DhcpDiscoverTimeoutMs", o->DhcpDiscoverTimeoutMs);
}

// Write the user
void SiWriteUserCfg(FOLDER *f, USER *u)
{
	BUF *b;
	AUTHPASSWORD *password;
	AUTHNT *nt;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	// Validate arguments
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

// Read an user
void SiLoadUserCfg(HUB *h, FOLDER *f)
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
	// Validate arguments
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
	pf = CfgGetFolder(f, "Policy");
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

	// Add an user
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

// Write the user list
void SiWriteUserList(FOLDER *f, LIST *o)
{
	// Validate arguments
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

// Read the user list
void SiLoadUserList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff;
		name = t->Token[i];
		ff = CfgGetFolder(f, name);
		SiLoadUserCfg(h, ff);
	}

	FreeToken(t);
}

// Write the group information
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g)
{
	// Validate arguments
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

// Read the group information
void SiLoadGroupCfg(HUB *h, FOLDER *f)
{
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char *name;
	FOLDER *pf;
	POLICY p;
	TRAFFIC t;
	USERGROUP *g;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	name = f->Name;

	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));

	pf = CfgGetFolder(f, "Policy");
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

// Write the group list
void SiWriteGroupList(FOLDER *f, LIST *o)
{
	// Validate arguments
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

// Read the group List
void SiLoadGroupList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		name = t->Token[i];
		SiLoadGroupCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Write the AC list
void SiWriteAcList(FOLDER *f, LIST *o)
{
	// Validate arguments
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

// Read the AC list
void SiLoadAcList(LIST *o, FOLDER *f)
{
	// Validate arguments
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
				FOLDER *ff = CfgGetFolder(f, t->Token[i]);

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

// Write the certificate revocation list
void SiWriteCrlList(FOLDER *f, LIST *o)
{
	// Validate arguments
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

// Read the certificate revocation list
void SiLoadCrlList(LIST *o, FOLDER *f)
{
	// Validate arguments
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
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
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

// Write the certificates list
void SiWriteCertList(FOLDER *f, LIST *o)
{
	// Validate arguments
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

// Read the certificates list
void SiLoadCertList(LIST *o, FOLDER *f)
{
	// Validate arguments
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
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
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

// Write the database
void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list)
{
	// Validate arguments
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

// Read the database
void SiLoadHubDb(HUB *h, FOLDER *f)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	SiLoadGroupList(h, CfgGetFolder(f, "GroupList"));
	SiLoadUserList(h, CfgGetFolder(f, "UserList"));

	if (h->HubDb != NULL)
	{
		SiLoadCertList(h->HubDb->RootCertList, CfgGetFolder(f, "CertList"));
		SiLoadCrlList(h->HubDb->CrlList, CfgGetFolder(f, "CrlList"));
		SiLoadAcList(h->HubDb->AcList, CfgGetFolder(f, "IPAccessControlList"));
	}
}

// Write the Virtual HUB setting
void SiWriteHubCfg(FOLDER *f, HUB *h)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	// Password
	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	// Online / Offline flag
	if (h->Cedar->Bridge == false)
	{
		CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);
	}

	// Traffic information
	SiWriteTraffic(f, "Traffic", h->Traffic);

	// HUB options
	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	// Message
	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (IsEmptyUniStr(h->Msg) == false)
		{
			CfgAddUniStr(folder, "MessageText", h->Msg);
		}
	}

	// HUB_LOG
	SiWriteHubLogCfgEx(CfgCreateFolder(f, "LogSetting"), &h->LogSetting, false);

	// Link list
	SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);

	// Access list
	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	// Administration options
	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	// Database
	if (h->Cedar->Bridge == false)
	{
		SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb,
			false
			);
	}

	// Usage status
	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

// Read the logging options
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f)
{
	// Validate arguments
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

// Write the logging options
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode)
{
	// Validate arguments
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

// Read the Virtual HUB settings
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name)
{
	HUB *h;
	CEDAR *c;
	HUB_OPTION o;
	bool online;
	// Validate arguments
	if (s == NULL || f == NULL || name == NULL)
	{
		return;
	}

	c = s->Cedar;

	// Get the option
	Zero(&o, sizeof(o));
	SiLoadHubOptionCfg(CfgGetFolder(f, "Option"), &o);

	// Create a HUB
	h = NewHub(c, name, &o);
	if (h != NULL)
	{
		HUB_LOG g;
		// Password
		if (CfgGetByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword)) != sizeof(h->HashedPassword))
		{
			Sha0(h->HashedPassword, "", 0);
		}
		if (CfgGetByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword)) != sizeof(h->SecurePassword))
		{
			HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
		}

		// Log Settings
		Zero(&g, sizeof(g));
		SiLoadHubLogCfg(&g, CfgGetFolder(f, "LogSetting"));
		SetHubLogSetting(h, &g);

		// Online / Offline flag
		if (h->Cedar->Bridge == false)
		{
			online = CfgGetBool(f, "Online");
		}
		else
		{
			online = true;
		}

		// Traffic information
		SiLoadTraffic(f, "Traffic", h->Traffic);

		// Access list
		SiLoadHubAccessLists(h, CfgGetFolder(f, "AccessList"));

		// Message
		{
			FOLDER *folder = CfgGetFolder(f, "Message");
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

		// Link list
		SiLoadHubLinks(h, CfgGetFolder(f, "CascadeList"));

		// Administration options
		SiLoadHubAdminOptions(h, CfgGetFolder(f, "AdminOption"));

		// Database
		if (h->Cedar->Bridge == false)
		{
			SiLoadHubDb(h, CfgGetFolder(f, "SecurityAccountDatabase"));
		}

		// Usage status
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

		// Start the operation of the HUB
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

// Write the license list
void SiWriteLicenseManager(FOLDER *f, SERVER *s)
{
}

// Read the license list
void SiLoadLicenseManager(SERVER *s, FOLDER *f)
{
}

// Write the Virtual HUB list
void SiWriteHubs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *hub_folder;
	CEDAR *c;
	UINT num;
	HUB **hubs;
	// Validate arguments
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

// Read the Virtual HUB list
void SiLoadHubs(SERVER *s, FOLDER *f)
{
	UINT i;
	FOLDER *hub_folder;
	TOKEN_LIST *t;
	bool b = false;
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];


		if (s->Cedar->Bridge)
		{
			if (StrCmpi(name, SERVER_DEFAULT_BRIDGE_NAME) == 0)
			{
				// Read only the setting of Virtual HUB named "BRIDGE"
				// in the case of the Bridge
				b = true;
			}
			else
			{
				continue;
			}
		}
		hub_folder = CfgGetFolder(f, name);
		if (hub_folder != NULL)
		{
			SiLoadHubCfg(s, hub_folder, name);
		}
	}
	FreeToken(t);

	if (s->Cedar->Bridge && b == false)
	{
		// If there isn't "BRIDGE" virtual HUB setting, create it newly
		SiInitDefaultHubList(s);
	}
}

// Read the server-specific settings
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
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	// Save interval related
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

	// Server log switch type
	if (CfgIsItem(f, "ServerLogSwitchType"))
	{
		UINT st = CfgGetInt(f, "ServerLogSwitchType");

		SetLogSwitchType(s->Logger, st);
	}

	SetMaxLogSize(CfgGetInt64(f, "LoggerMaxLogSize"));

	params_folder = CfgGetFolder(f, "GlobalParams");
	SiLoadGlobalParamsCfg(params_folder);

	c = s->Cedar;
	Lock(c->lock);
	{
		FOLDER *ff;

		// syslog
		ff = CfgGetFolder(f, "SyslogSettings");
		if (ff != NULL && GetServerCapsBool(s, "b_support_syslog"))
		{
			SYSLOG_SETTING set;

			Zero(&set, sizeof(set));

			set.SaveType = CfgGetInt(ff, "SaveType");
			CfgGetStr(ff, "HostName", set.Hostname, sizeof(set.Hostname));
			set.Port = CfgGetInt(ff, "Port");

			SiSetSysLogSetting(s, &set);
		}

		// Whether to disable the IPv6 listener
		s->Cedar->DisableIPv6Listener = CfgGetBool(f, "DisableIPv6Listener");

		// DoS
		s->DisableDosProtection = CfgGetBool(f, "DisableDosProtection");

		// Num Connections Per IP
		SetMaxConnectionsPerIp(CfgGetInt(f, "MaxConnectionsPerIP"));

		// MaxUnestablishedConnections
		SetMaxUnestablishedConnections(CfgGetInt(f, "MaxUnestablishedConnections"));

		// DeadLock
		s->DisableDeadLockCheck = CfgGetBool(f, "DisableDeadLockCheck");

		// Eraser
		SetEraserCheckInterval(CfgGetInt(f, "AutoDeleteCheckIntervalSecs"));
		s->Eraser = NewEraser(s->Logger, CfgGetInt64(f, "AutoDeleteCheckDiskFreeSpaceMin"));


		// WebTimePage
		s->UseWebTimePage = CfgGetBool(f, "UseWebTimePage");

		// NoLinuxArpFilter
		s->NoLinuxArpFilter = CfgGetBool(f, "NoLinuxArpFilter");

		// NoHighPriorityProcess
		s->NoHighPriorityProcess = CfgGetBool(f, "NoHighPriorityProcess");

		// NoDebugDump
		s->NoDebugDump = CfgGetBool(f, "NoDebugDump");
		if (s->NoDebugDump)
		{
			MsSetEnableMinidump(false);
		}

		// Debug log
		s->SaveDebugLog = CfgGetBool(f, "SaveDebugLog");
		if (s->SaveDebugLog)
		{
			s->DebugLog = NewTinyLog();
		}

		// Let the client not to send a signature
		s->NoSendSignature = CfgGetBool(f, "NoSendSignature");

		// Server certificate
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			x = BufToX(b, false);
			FreeBuf(b);
		}

		// Server private key
		b = CfgGetBuf(f, "ServerKey");
		if (b != NULL)
		{
			k = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}

		// Server trust chain
		SiLoadCertList(chain, CfgGetFolder(f, "ServerChain"));

		if (x == NULL || k == NULL || CheckXandK(x, k) == false)
		{
			FreeX(x);
			FreeK(k);
			FreeXList(chain);
			SiGenerateDefaultCertEx(&x, &k, NULL);

			SetCedarCert(c, x, k);

			FreeX(x);
			FreeK(k);
		}
		else
		{
			if (LIST_NUM(chain) == 0)
			{
				SetCedarCert(c, x, k);
			}
			else
			{
				SetCedarCertAndChain(c, x, k, chain);
			}

			FreeX(x);
			FreeK(k);
			FreeXList(chain);
		}

		// Character which separates the username from the hub name
		if (CfgGetStr(f, "UsernameHubSeparator", tmp, sizeof(tmp)))
		{
			c->UsernameHubSeparator = IsPrintableAsciiChar(tmp[0]) ? tmp[0] : DEFAULT_USERNAME_HUB_SEPARATOR;
		}

		// Cipher Name
		if (CfgGetStr(f, "CipherName", tmp, sizeof(tmp)))
		{
			StrUpper(tmp);
			SetCedarCipherList(c, tmp);
		}

		// Traffic information
		Lock(c->TrafficLock);
		{
			SiLoadTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// Password
		if (CfgGetByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword)) != sizeof(s->HashedPassword))
		{
			Sha0(s->HashedPassword, "", 0);
		}

		// Disable GetHostName when accepting TCP
		s->DisableGetHostNameWhenAcceptTcp = CfgGetBool(f, "DisableGetHostNameWhenAcceptTcp");

		if (s->DisableGetHostNameWhenAcceptTcp)
		{
			DisableGetHostNameWhenAcceptInit();
		}

		// Disable core dump on UNIX
		s->DisableCoreDumpOnUnix = CfgGetBool(f, "DisableCoreDumpOnUnix");

		// Disable session reconnect
		SetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT, CfgGetBool(f, "DisableSessionReconnect"));

		c->SslAcceptSettings.Tls_Disable1_0 = CfgGetBool(f, "Tls_Disable1_0");
		c->SslAcceptSettings.Tls_Disable1_1 = CfgGetBool(f, "Tls_Disable1_1");
		c->SslAcceptSettings.Tls_Disable1_2 = CfgGetBool(f, "Tls_Disable1_2");
		c->SslAcceptSettings.Tls_Disable1_3 = CfgGetBool(f, "Tls_Disable1_3");
		c->SslAcceptSettings.Override_Security_Level = CfgGetBool(f, "Override_Security_Level");
		c->SslAcceptSettings.Override_Security_Level_Value = CfgGetInt(f, "Override_Security_Level_Value");

		s->StrictSyslogDatetimeFormat = CfgGetBool(f, "StrictSyslogDatetimeFormat");

		// STUN server for UDP acceleration (missing or empty = STUN disabled)
		CfgGetStr(f, "StunServer", c->StunServer, sizeof(c->StunServer));
		Trim(c->StunServer);

		// Disable JSON-RPC Web API

		// Bits of Diffie-Hellman parameters
		c->DhParamBits = CfgGetInt(f, "DhParamBits");
		if (c->DhParamBits == 0)
		{
			c->DhParamBits = DH_PARAM_BITS_DEFAULT;
		}

		SetDhParam(DhNewFromBits(c->DhParamBits));
	}
	Unlock(c->lock);
}

// Load global params
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

// Load global param itesm
void SiLoadGlobalParamItem(UINT id, UINT value)
{
	// Validate arguments
	if (id == 0)
	{
		return;
	}

	vpn_global_parameters[id] = value;
}

// Write global params
void SiWriteGlobalParamsCfg(FOLDER *f)
{
	// Validate arguments
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

// Write the server-specific settings
void SiWriteServerCfg(FOLDER *f, SERVER *s)
{
	BUF *b;
	CEDAR *c;
	FOLDER *params_folder;
	// Validate arguments
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

		// syslog
		ff = CfgCreateFolder(f, "SyslogSettings");
		if (ff != NULL)
		{
			SYSLOG_SETTING set;

			SiGetSysLogSetting(s, &set);

			CfgAddInt(ff, "SaveType", set.SaveType);
			CfgAddStr(ff, "HostName", set.Hostname);
			CfgAddInt(ff, "Port", set.Port);
		}

		// IPv6 listener disable setting
		CfgAddBool(f, "DisableIPv6Listener", s->Cedar->DisableIPv6Listener);

		// DoS
		CfgAddBool(f, "DisableDosProtection", s->DisableDosProtection);

		// MaxConnectionsPerIP
		CfgAddInt(f, "MaxConnectionsPerIP", GetMaxConnectionsPerIp());

		// MaxUnestablishedConnections
		CfgAddInt(f, "MaxUnestablishedConnections", GetMaxUnestablishedConnections());

		// DeadLock
		CfgAddBool(f, "DisableDeadLockCheck", s->DisableDeadLockCheck);

		// Eraser related
		CfgAddInt64(f, "AutoDeleteCheckDiskFreeSpaceMin", s->Eraser->MinFreeSpace);
		CfgAddInt(f, "AutoDeleteCheckIntervalSecs", GetEraserCheckInterval());


		// NoHighPriorityProcess
		CfgAddBool(f, "NoHighPriorityProcess", s->NoHighPriorityProcess);

		CfgAddBool(f, "NoDebugDump", s->NoDebugDump);

		// WebTimePage
		CfgAddBool(f, "UseWebTimePage", s->UseWebTimePage);

		// Debug log
		CfgAddBool(f, "SaveDebugLog", s->SaveDebugLog);

		// Let the client not to send a signature
		CfgAddBool(f, "NoSendSignature", s->NoSendSignature);

		// Server certificate
		b = XToBuf(c->ServerX, false);
		CfgAddBuf(f, "ServerCert", b);
		FreeBuf(b);

		// Server private key
		b = KToBuf(c->ServerK, false, NULL);
		CfgAddBuf(f, "ServerKey", b);
		FreeBuf(b);

		// Server trust chain
		SiWriteCertList(CfgCreateFolder(f, "ServerChain"), c->ServerChain);

		{
			// Character which separates the username from the hub name
			char str[2];
			StrCpy(str, sizeof(str), &c->UsernameHubSeparator);
			CfgAddStr(f, "UsernameHubSeparator", str);
		}

		// Traffic information
		Lock(c->TrafficLock);
		{
			SiWriteTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// Cipher Name
		CfgAddStr(f, "CipherName", s->Cedar->CipherList);

		// Password
		CfgAddByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));

		CfgAddBool(f, "DisableGetHostNameWhenAcceptTcp", s->DisableGetHostNameWhenAcceptTcp);
		CfgAddBool(f, "DisableCoreDumpOnUnix", s->DisableCoreDumpOnUnix);

		CfgAddBool(f, "Tls_Disable1_0", c->SslAcceptSettings.Tls_Disable1_0);
		CfgAddBool(f, "Tls_Disable1_1", c->SslAcceptSettings.Tls_Disable1_1);
		CfgAddBool(f, "Tls_Disable1_2", c->SslAcceptSettings.Tls_Disable1_2);
		CfgAddBool(f, "Tls_Disable1_3", c->SslAcceptSettings.Tls_Disable1_3);
		CfgAddBool(f, "Override_Security_Level", c->SslAcceptSettings.Override_Security_Level);
		CfgAddInt(f, "Override_Security_Level_Value", c->SslAcceptSettings.Override_Security_Level_Value);
		CfgAddInt(f, "DhParamBits", c->DhParamBits);

		// Disable session reconnect
		CfgAddBool(f, "DisableSessionReconnect", GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT));

		CfgAddBool(f, "StrictSyslogDatetimeFormat", s->StrictSyslogDatetimeFormat);

		// STUN server for UDP acceleration
		CfgAddStr(f, "StunServer", c->StunServer);

		// Disable JSON-RPC Web API
	}
	Unlock(c->lock);
}

// Read the traffic information
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// Validate arguments
	if (t != NULL)
	{
		Zero(t, sizeof(TRAFFIC));
	}
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);

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
	// Validate arguments
	if (e != NULL)
	{
		Zero(e, sizeof(TRAFFIC_ENTRY));
	}
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);
	if (f == NULL)
	{
		return;
	}

	e->BroadcastCount = CfgGetInt64(f, "BroadcastCount");
	e->BroadcastBytes = CfgGetInt64(f, "BroadcastBytes");
	e->UnicastCount = CfgGetInt64(f, "UnicastCount");
	e->UnicastBytes = CfgGetInt64(f, "UnicastBytes");
}

// Write the traffic information
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// Validate arguments
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
	// Validate arguments
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

// Thread for writing configuration file
void SiSaverThread(THREAD *thread, void *param)
{
	SERVER *s = (SERVER *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (s->Halt == false)
	{
		// Save to the configuration file
		if (s->NoMoreSave == false)
		{
			SiWriteConfigurationFile(s);
		}

		Wait(s->SaveHaltEvent, s->AutoSaveConfigSpan);
	}
}

// Write to the configuration file
UINT SiWriteConfigurationFile(SERVER *s)
{
	UINT ret;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	if (s->CfgRw == NULL)
	{
		return 0;
	}

	if (s->NoMoreSave)
	{
		return 0;
	}

	Lock(s->SaveCfgLock);
	{
		FOLDER *f;

		f = SiWriteConfigurationToCfg(s);

		ret = SaveCfgRwEx(s->CfgRw, f, s->BackupConfigOnlyWhenModified ? s->ConfigRevision : INFINITE);

		CfgDeleteFolder(f);
	}
	Unlock(s->SaveCfgLock);

	return ret;
}

// Release the configuration
void SiFreeConfiguration(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Write to the configuration file
	SiWriteConfigurationFile(s);

	// Terminate the configuration file saving thread
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

	// Release the Ethernet 
	FreeEth();
}

// Initialize the StXxx related function
void StInit()
{
	if (server_lock != NULL)
	{
		return;
	}

	server_lock = NewLock();
}

// Release the StXxx related function
void StFree()
{
	DeleteLock(server_lock);
	server_lock = NULL;
}

// Start the server
void StStartServer(bool bridge)
{
	Lock(server_lock);
	{
		if (server != NULL)
		{
			// It has already started
			Unlock(server_lock);
			return;
		}

		// Create a server
		server = SiNewServer(bridge);
	}
	Unlock(server_lock);
}

// Stop the server
void StStopServer()
{
	Lock(server_lock);
	{
		if (server == NULL)
		{
			// Not started
			Unlock(server_lock);
			return;
		}

		// Release the server
		SiReleaseServer(server);
		server = NULL;
	}
	Unlock(server_lock);

	StopCedarLog();
}

// Thread to restart the server
void SiRebootServerThread(THREAD *thread, void *param)
{
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	if (server == NULL)
	{
		return;
	}

	// Stop the server
	StStopServer();

	// Start the server
	StStartServer((bool)param);
}

// Restart the server
void SiRebootServer(bool bridge)
{
	SiRebootServerEx(bridge, false);
}
void SiRebootServerEx(bool bridge, bool reset_setting)
{
	THREAD *t;

	server_reset_setting = reset_setting;

	t = NewThread(SiRebootServerThread, (void *)bridge);
	ReleaseThread(t);
}

// Stop all listeners
void SiStopAllListener(SERVER *s)
{
	// Validate arguments
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

// Clean-up the server
void SiCleanupServer(SERVER *s)
{
	UINT i;
	CEDAR *c;
	LISTENER **listener_list;
	UINT num_listener;
	HUB **hub_list;
	UINT num_hub;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SiFreeDeadLockCheck(s);


	c = s->Cedar;

	IncrementServerConfigRevision(s);

	SLog(c, "LS_END_2");

	SLog(c, "LS_STOP_ALL_LISTENER");
	// Stop all listeners
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
	// Stop all HUBs
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

	// Release the configuration
	SiFreeConfiguration(s);

	// Stop the Cedar
	SLog(c, "LS_STOP_CEDAR");
	StopCedar(s->Cedar);
	SLog(c, "LS_STOP_CEDAR_2");

	// Stop all listeners
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

	// Stop the debug log
	FreeTinyLog(s->DebugLog);


	Free(s);
}

// Release the server
void SiReleaseServer(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		SiCleanupServer(s);
	}
}

// Get the current version
void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size)
{
	ClearStr(region, region_size);
	// Validate arguments
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

// Check whether some enterprise functions are restricted
// 
// ** Hints by Daiyuu Nobori, written on March 19, 2014 **
// 
// The following 'enterprise functions' are implemented on SoftEther VPN Server
// since March 19, 2014. However, these functions are disabled on
// SoftEther VPN Servers which run in Japan and China.
// 
// - NT Domain user authentication
// - RSA certificate authentication
// - Deep-inspect packet logging
// - Source IP address control list
// - syslog transfer
// 
// The SoftEther VPN Project intentionally disables these functions for users
// in Japan and China. The reason is: Daiyuu Nobori, the chief author of
// SoftEther VPN, has been liable to observe the existing agreements and
// restrictions between him and some companies. The agreements have regulated
// the region-limited restriction to implement and distribute the above
// enterprise functions on the SoftEther VPN open-source program.
// 
// Therefore, the SoftEther VPN Project distributes the binary program and
// the source code with the "SiIsEnterpriseFunctionsRestrictedOnOpenSource"
// function. This function identifies whether the SoftEther VPN Server
// program is running in either Japan or China. If the restricted region is
// detected, then the above enterprise functions will be disabled.
// 
// Please note that the above restriction has been imposed only on the
// original binaries and source codes from the SoftEther VPN Project.
// Anyone, except Daiyuu Nobori, who understands and writes the C language
// program can remove this restriction at his own risk.
// 
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c)
{
	char region[128];
	bool ret = false;
	// Validate arguments
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

// Update the current region
void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update)
{
	bool changed = false;
	// Validate arguments
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

// Create a server
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

	// Log related
	MakeDir(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME);
	s->Logger = NewLog(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY);

	SLog(s->Cedar, "L_LINE");
	SLog(s->Cedar, "LS_START_2", s->Cedar->ServerStr, s->Cedar->VerString);
	SLog(s->Cedar, "LS_START_3", s->Cedar->BuildInfo);
	SLog(s->Cedar, "LS_START_UTF8");
	SLog(s->Cedar, "LS_START_1");



	// Initialize the configuration
	SiInitConfiguration(s);

	s->Syslog = NewSysLog(NULL, 0, &s->Cedar->Server->ListenIP);
	s->SyslogLock = NewLock();

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);


	// Raise the priority
	if (s->NoHighPriorityProcess == false)
	{
		OSSetHighPriority();
	}

	SiInitDeadLockCheck(s);

	SiUpdateCurrentRegion(s->Cedar, "", true);

	return s;
}

