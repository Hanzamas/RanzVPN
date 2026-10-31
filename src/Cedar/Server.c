// Server.c
// VPN Server module

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "HttpListener.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "RpcField.h"
#include "Sam.h"
#include "Tunables.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include "ServerInternal.h"

static SERVER *server = NULL;
static LOCK *server_lock = NULL;
char *SERVER_CONFIG_FILE_NAME = "$ranz_server.config";
static char *SERVER_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";

static bool server_reset_setting = false;

void SiDebugLog(SERVER *s, char *msg) {
	if (s == NULL || msg == NULL)
		return;

	if (s->DebugLog != NULL)
		WriteTinyLog(s->DebugLog, msg);
}

static void SiCheckDeadLockMain(SERVER *s, UINT timeout) {
	if (s == NULL)
		return;



	CEDAR *cedar = s->Cedar;

	if (s->ServerListenerList != NULL)
		CheckDeadLock(s->ServerListenerList->lock, timeout, "s->ServerListenerList->lock");

	CheckDeadLock(s->lock, timeout, "s->lock");

	if (cedar != NULL) {
		if (cedar->HubList != NULL)
			CheckDeadLock(cedar->HubList->lock, timeout, "cedar->HubList->lock");

		if (cedar->ListenerList != NULL)
			CheckDeadLock(cedar->ListenerList->lock, timeout, "cedar->ListenerList->lock");

		if (cedar->ConnectionList != NULL)
			CheckDeadLock(cedar->ConnectionList->lock, timeout, "cedar->ConnectionList->lock");

		if (cedar->TrafficLock != NULL)
			CheckDeadLock(cedar->TrafficLock, timeout, "cedar->TrafficLock");

		if (cedar->LocalBridgeList != NULL)
			CheckDeadLock(cedar->LocalBridgeList->lock, timeout, "cedar->LocalBridgeList->lock");
	}
}

static void SiDeadLockCheckThread(THREAD *t, void *param) {
	SERVER *s = (SERVER *)param;
	if (s == NULL || t == NULL)
		return;

	while (true) {
		Wait(s->DeadLockWaitEvent, SERVER_DEADLOCK_CHECK_SPAN);

		if (s->HaltDeadLockThread)
			break;

		SiCheckDeadLockMain(s, SERVER_DEADLOCK_CHECK_TIMEOUT);
	}
}

static void SiInitDeadLockCheck(SERVER *s) {
	if (s == NULL)
		return;
	if (s->DisableDeadLockCheck)
		return;

	s->HaltDeadLockThread = false;
	s->DeadLockWaitEvent = NewEvent();
	s->DeadLockCheckThread = NewThread(SiDeadLockCheckThread, s);
}

static void SiFreeDeadLockCheck(SERVER *s) {
	if (s == NULL)
		return;

	if (s->DeadLockCheckThread == NULL)
		return;

	s->HaltDeadLockThread = true;
	Set(s->DeadLockWaitEvent);

	WaitThread(s->DeadLockCheckThread, INFINITE);

	ReleaseThread(s->DeadLockCheckThread);
	s->DeadLockCheckThread = NULL;

	ReleaseEvent(s->DeadLockWaitEvent);
	s->DeadLockWaitEvent = NULL;

	s->HaltDeadLockThread = false;
}

// The syslog save types: SYSLOG_NONE, SYSLOG_SERVER_AND_HUB_SECURITY_LOG and SYSLOG_SERVER_AND_HUB_ALL_LOG. Type 1
// (the server log only) is gone
bool SiIsSysLogSaveType(UINT save_type) {
	return save_type == SYSLOG_NONE || save_type == SYSLOG_SERVER_AND_HUB_SECURITY_LOG ||
	       save_type == SYSLOG_SERVER_AND_HUB_ALL_LOG;
}

void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting) {
	SYSLOG_SETTING set;
	if (s == NULL || setting == NULL)
		return;

	Copy(&set, setting, sizeof(SYSLOG_SETTING));

	// Another save type, such as a type 1 of an older configuration file, turns syslog sending off
	if (IsEmptyStr(set.Hostname) || set.Port == 0 || SiIsSysLogSaveType(set.SaveType) == false)
		set.SaveType = SYSLOG_NONE;

	Lock(s->SyslogLock);
	{
		Copy(&s->SyslogSetting, &set, sizeof(SYSLOG_SETTING));

		SetSysLog(s->Syslog, set.Hostname, set.Port);
	}
	Unlock(s->SyslogLock);
}


void GetServerProductName(SERVER *s, char *name, UINT size) {
	if (s == NULL || name == NULL)
		return;

	StrCpy(name, size, CEDAR_SERVER_STR " (64 bit)");
}

static const RPC_FIELD rpc_syslog_setting_fields[] =
    {
        RPC_ROW_INT(SYSLOG_SETTING, SaveType, "SaveType"),
        RPC_ROW_INT(SYSLOG_SETTING, Port, "Port"),
        RPC_ROW_STR(SYSLOG_SETTING, Hostname, "Hostname"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_syslog_setting_table, SYSLOG_SETTING, rpc_syslog_setting_fields);

void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p) {
	RpcFieldIn(&rpc_syslog_setting_table, t, p);
}
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t) {
	RpcFieldOut(&rpc_syslog_setting_table, p, t);
}

// Validity of the default server certificate in days: until 2038-01-01, or from 2030 on until
// 2049-12-30. Certificate times themselves have no 2050 limit (UINT64ToAsn1Time writes GeneralizedTime);
// the default certificate keeps its existing end date
static UINT SiGetDefaultCertDays() {
	UINT64 now = SystemTime64();
	SYSTEMTIME st;

	Zero(&st, sizeof(st));
	SystemTime(&st);
	if (st.wYear >= 2030) {
		Zero(&st, sizeof(st));
		st.wYear = 2049;
		st.wMonth = 12;
		st.wDay = 30;
	} else {
		Zero(&st, sizeof(st));
		st.wYear = 2038;
		st.wMonth = 1;
		st.wDay = 1;
	}

	UINT64 target = SystemToUINT64(&st);
	if (now >= target)
		return 0;

	return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
}

bool SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name) {
	K *private_key = NULL, *public_key = NULL;
	char tmp[MAX_SIZE];
	wchar_t cn[MAX_SIZE];
	if (server_x == NULL || server_k == NULL)
		return false;

	*server_x = NULL;
	*server_k = NULL;

	if (RsaGen(&private_key, &public_key, 2048) == false)
		return false;

	if (IsEmptyStr(common_name)) {
		GetMachineName(tmp, sizeof(tmp));
		StrToUni(cn, sizeof(cn), tmp);
	} else {
		StrToUni(cn, sizeof(cn), common_name);
	}

	NAME *name = NewName(cn, cn, cn,
	                     L"US", NULL, NULL);
	X *x = NewRootX(public_key, private_key, name, SiGetDefaultCertDays(), NULL);

	FreeName(name);

	FreeK(public_key);

	if (x == NULL) {
		FreeK(private_key);
		return false;
	}

	*server_x = x;
	*server_k = private_key;

	return true;
}

static void SiInitDefaultServerCert(SERVER *s) {
	X *x = NULL;
	K *k = NULL;
	if (s == NULL)
		return;

	if (SiGenerateDefaultCertEx(&x, &k, NULL) == false) {
		SLog(s->Cedar, "LS_DEFAULT_CERT_FAILED");
		return;
	}

	SetCedarCertAndChain(s->Cedar, x, k, NULL);

	FreeX(x);
	FreeK(k);
}

static void SiInitCipherName(SERVER *s) {
	if (s == NULL)
		return;

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
}

// The one VPN listener of a default configuration (ADR-0020 decision 6): TCP 443, or TCP 5555 when 443 cannot be bound
// at this first start. The probe binds as the listener does, without address reuse, and closes the socket at once.
// With 5555 taken too the listener stays on 443 and retries it like any listener. A loaded configuration never comes
// here, so a fallback listener on 5555 stays until the operator changes it.
static void SiInitListenerList(SERVER *s) {
	UINT port = SERVER_DEF_PORTS_1;
	UINT err_1, err_4;
	if (s == NULL)
		return;

	bool ipv4_only = s->Cedar->DisableIPv6Listener;

	if (ListenProbe(SERVER_DEF_PORTS_1, &s->ListenIP, ipv4_only, &err_1) == false) {
		if (ListenProbe(SERVER_DEF_PORTS_4, &s->ListenIP, ipv4_only, &err_4)) {
			port = SERVER_DEF_PORTS_4;
			SLog(s->Cedar, "LS_DEFAULT_LISTENER_FALLBACK", SERVER_DEF_PORTS_1, err_1, SERVER_DEF_PORTS_4,
			     SERVER_DEF_PORTS_4, SERVER_DEF_PORTS_1, SERVER_DEF_PORTS_1, SERVER_DEF_PORTS_4);
		} else {
			SLog(s->Cedar, "LS_DEFAULT_LISTENER_BOTH_TAKEN", SERVER_DEF_PORTS_1, SERVER_DEF_PORTS_4, err_1, err_4,
			     SERVER_DEF_PORTS_1);
		}
	}

	SiLockListenerList(s);
	{
		SiAddListenerEx(s, port, true, false);
	}
	SiUnlockListenerList(s);
}

static int CompareServerListener(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	SERVER_LISTENER *s1 = *(SERVER_LISTENER **)p1;
	SERVER_LISTENER *s2 = *(SERVER_LISTENER **)p2;
	if (s1 == NULL || s2 == NULL)
		return 0;

	if (s1->Port > s2->Port)
		return 1;
	else if (s1->Port < s2->Port)
		return -1;
	else
		return 0;
}

static void SiInitDefaultHubList(SERVER *s) {
	HUB_OPTION o;
	if (s == NULL)
		return;

	Zero(&o, sizeof(o));

	SiSetDefaultHubOption(&o);

	HUB *h = NewHub(s->Cedar, SERVER_DEFAULT_HUB_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	HubApplyInitialState(h, true);

	ReleaseHub(h);
}

// Start the eraser of s: while the free disk space is below min_size it deletes the oldest backups of the
// configuration and log files (LogPaths), checking every interval seconds (AutoDeleteCheckIntervalSecs)
static ERASER *SiNewEraser(SERVER *s, UINT64 min_size, UINT interval) {
	char packet_log_dir[MAX_PATH];
	char security_log_dir[MAX_PATH];
	char server_log_dir[MAX_PATH];
	char *targets[4];

	HubPacketLogDir(packet_log_dir, sizeof(packet_log_dir), NULL);
	HubSecurityLogDir(security_log_dir, sizeof(security_log_dir), NULL);
	ServerLogDir(server_log_dir, sizeof(server_log_dir));

	targets[0] = "backup.ranz_server.config";
	targets[1] = packet_log_dir;
	targets[2] = security_log_dir;
	targets[3] = server_log_dir;

	return NewEraser(s->Logger, min_size, interval, targets, _countof(targets));
}

// Set the maximum size of a log file (LoggerMaxLogSize, 0 for MAX_LOG_SIZE_DEFAULT) of the server log and of the
// logs of every hub; a hub made later takes it from the Cedar in NewHub
static void SiSetMaxLogSize(SERVER *s, UINT64 size) {
	CEDAR *c = s->Cedar;

	c->MaxLogSize = size;
	SetMaxLogSize(s->Logger, size);

	LockList(c->HubList);
	{
		for (UINT i = 0; i < LIST_NUM(c->HubList); i++) {
			HUB *h = LIST_DATA(c->HubList, i);

			SetMaxLogSize(h->PacketLogger, size);
			SetMaxLogSize(h->SecurityLogger, size);
		}
	}
	UnlockList(c->HubList);
}

static void SiLoadInitialConfiguration(SERVER *s) {
	if (s == NULL)
		return;

	TunablesLoad(NULL);

	Sha0(s->HashedPassword, "", 0);

	SiInitCipherName(s);

	SiInitDefaultServerCert(s);

	// A fresh config does no reverse DNS or NetBIOS probe on the accept path
	s->DisableGetHostNameWhenAcceptTcp = true;
	DisableGetHostNameWhenAcceptInit();

	SiInitDefaultHubList(s);

	SiInitListenerList(s);

	s->Eraser = SiNewEraser(s, 0, 0);
}

// Log what happened to a configuration file that could not be read: renamed to .bad, or still in place
static void SiLogBadConfigurationFile(SERVER *s) {
	CFG_RW *rw = s->CfgRw;

	if (rw->BadFileRenamed)
		SLog(s->Cedar, "LS_CONFIG_SET_ASIDE", rw->FileNameW, rw->FileNameW);
	else if (rw->BadFilePending)
		SLog(s->Cedar, "LS_CONFIG_SET_ASIDE_FAILED", rw->FileNameW, rw->FileNameW);
}

static bool SiLoadConfigurationFile(SERVER *s) {
	bool ret = false;
	FOLDER *root;
	if (s == NULL)
		return false;


	s->CfgRw = NewCfgRwEx2A(&root, SERVER_CONFIG_FILE_NAME, false, SERVER_CONFIG_TEMPLATE_NAME);

	SiLogBadConfigurationFile(s);

	if (server_reset_setting) {
		CfgDeleteFolder(root);
		root = NULL;
		server_reset_setting = false;
	}

	if (root == NULL)
		return false;

	ret = SiLoadConfigurationCfg(s, root);

	CfgDeleteFolder(root);

	if (ret == false && s->CfgRw->BadFileRenamed == false) {
		// A parsed file without a server configuration: keep it as .bad, the server starts with the initial
		// settings
		CfgRwSetAsideBadFile(s->CfgRw);
		SiLogBadConfigurationFile(s);
	}

	return ret;
}

static void SiInitConfiguration(SERVER *s) {
	if (s == NULL)
		return;

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	SLog(s->Cedar, "LS_LOAD_CONFIG_1");
	if (SiLoadConfigurationFile(s) == false) {
		InitEth();

		SLog(s->Cedar, "LS_LOAD_CONFIG_3");
		SiLoadInitialConfiguration(s);
	} else {
		SLog(s->Cedar, "LS_LOAD_CONFIG_2");
	}

	s->CfgRw->DontBackup = s->DontBackupConfig;

	if (s->DisableDosProtection)
		DisableDosProtect();
	else
		EnableDosProtect();

	s->AutoSaveConfigSpanSaved = s->AutoSaveConfigSpan;

	// User mode: save more often
	if (MsIsUserMode())
		s->AutoSaveConfigSpan = MIN(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_USERMODE);

	SLog(s->Cedar, "LS_INIT_SAVE_THREAD", s->AutoSaveConfigSpan / 1000);
	s->SaveHaltEvent = NewEvent();
	s->SaveThread = NewThread(SiSaverThread, s);
}

bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root) {
	if (s == NULL || root == NULL)
		return false;

	FOLDER *f1 = CfgFindFolder(root, "ServerConfiguration");
	FOLDER *f2 = CfgFindFolder(root, "VirtualHUB");
	FOLDER *f3 = CfgFindFolder(root, "ListenerList");
	FOLDER *f4 = CfgFindFolder(root, "LocalBridgeList");

	if (f1 == NULL) {
		SLog(s->Cedar, "LS_BAD_CONFIG");
		return false;
	}

	if (f4 != NULL) {
		bool b = true;

		if (CfgIsItem(f4, "EnableSoftEtherKernelModeDriver"))
			b = CfgGetBool(f4, "EnableSoftEtherKernelModeDriver");

		Win32SetEnableSeLow(b);
	}

	InitEth();

	s->ConfigRevision = CfgGetInt(root, "ConfigRevision");

	SiLoadServerCfg(s, f1);

	SiLoadHubs(s, f2);

	SiLoadListeners(s, f3);

	SiLoadHttpListenerCfg(s, CfgFindFolder(root, "HttpListener"));

	if (f4 != NULL)
		SiLoadLocalBridges(s, f4);

	return true;
}

static void SiWriteListenerCfg(FOLDER *f, const SERVER_LISTENER *r) {
	if (f == NULL || r == NULL)
		return;

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
	CfgAddBool(f, "DisableDos", r->DisableDos);
}

static void SiLoadListenerCfg(SERVER *s, FOLDER *f) {
	if (s == NULL || f == NULL)
		return;

	bool enable = CfgGetBool(f, "Enabled");
	UINT port = CfgGetInt(f, "Port");
	bool disable_dos = CfgGetBool(f, "DisableDos");

	if (port == 0)
		return;

	SiAddListenerEx(s, port, enable, disable_dos);
}

void SiLoadListeners(SERVER *s, FOLDER *f) {
	if (s == NULL || f == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);
	for (UINT i = 0; i < t->NumTokens; i++) {
		FOLDER *ff = CfgFindFolder(f, t->Token[i]);
		if (ff != NULL)
			SiLoadListenerCfg(s, ff);
	}
	FreeToken(t);
}

static void SiWriteListeners(FOLDER *f, SERVER *s) {
	if (f == NULL || s == NULL)
		return;

	LockList(s->ServerListenerList);
	{
		for (UINT i = 0; i < LIST_NUM(s->ServerListenerList); i++) {
			SERVER_LISTENER *r = LIST_DATA(s->ServerListenerList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Listener%u", i);
			SiWriteListenerCfg(CfgCreateFolder(f, name), r);
		}
	}
	UnlockList(s->ServerListenerList);
}

static void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br) {
	if (f == NULL || br == NULL)
		return;

	CfgAddStr(f, "DeviceName", br->DeviceName);
	CfgAddStr(f, "HubName", br->HubName);
	CfgAddBool(f, "NoPromiscuousMode", br->Local);
	CfgAddBool(f, "MonitorMode", br->Monitor);
	CfgAddBool(f, "LimitBroadcast", br->LimitBroadcast);
}

static void SiWriteLocalBridges(FOLDER *f, const SERVER *s) {
	if (s == NULL || f == NULL)
		return;

	CfgAddBool(f, "ShowAllInterfaces", Win32EthGetShowAllIf());

	CfgAddBool(f, "EnableSoftEtherKernelModeDriver", Win32GetEnableSeLow());

	LockList(s->Cedar->LocalBridgeList);
	{
		for (UINT i = 0; i < LIST_NUM(s->Cedar->LocalBridgeList); i++) {
			LOCALBRIDGE *br = LIST_DATA(s->Cedar->LocalBridgeList, i);
			char name[MAX_SIZE];

			Format(name, sizeof(name), "LocalBridge%u", i);
			SiWriteLocalBridgeCfg(CfgCreateFolder(f, name), br);
		}
	}
	UnlockList(s->Cedar->LocalBridgeList);
}

static void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f) {
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	if (s == NULL || f == NULL)
		return;

	Zero(hub, sizeof(hub));
	Zero(nic, sizeof(nic));

	CfgGetStr(f, "HubName", hub, sizeof(hub));
	CfgGetStr(f, "DeviceName", nic, sizeof(nic));

	if (IsEmptyStr(hub) || IsEmptyStr(nic))
		return;

	AddLocalBridge(s->Cedar, hub, nic, CfgGetBool(f, "NoPromiscuousMode"), CfgGetBool(f, "MonitorMode"),
	               CfgGetBool(f, "LimitBroadcast"));
}

void SiLoadLocalBridges(SERVER *s, FOLDER *f) {
	if (s == NULL || f == NULL)
		return;

	Win32EthSetShowAllIf(CfgGetBool(f, "ShowAllInterfaces"));

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; i < t->NumTokens; i++) {
		char *name = t->Token[i];

		SiLoadLocalBridgeCfg(s, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

void IncrementServerConfigRevision(SERVER *s) {
	if (s == NULL)
		return;

	s->ConfigRevision++;
}

// Stages an uploaded configuration that the next start loads in place of the live file. An upload
// that does not parse, is truncated or holds no ServerConfiguration folder gives ERR_INVALID_PARAMETER
// and a failed write ERR_INTERNAL_ERROR; either way the live configuration stays.
UINT SiStageConfiguration(SERVER *s, char *data, UINT size) {
	if (s == NULL || s->CfgRw == NULL)
		return ERR_INTERNAL_ERROR;
	if (data == NULL)
		return ERR_INVALID_PARAMETER;

	BUF *b = NewBufFromMemory(data, size);
	FOLDER *root = CfgBufToFolder(b, true);
	FreeBuf(b);

	bool valid = (root != NULL && CfgFindFolder(root, "ServerConfiguration") != NULL);
	CfgDeleteFolder(root);
	if (valid == false)
		return ERR_INVALID_PARAMETER;

	if (CfgStageNewFile(s->CfgRw, data, size) == false)
		return ERR_INTERNAL_ERROR;

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

FOLDER *SiWriteConfigurationToCfg(SERVER *s) {
	if (s == NULL)
		return NULL;

	FOLDER *root = CfgCreateFolder(NULL, TAG_ROOT);

	CfgAddInt(root, "ConfigRevision", s->ConfigRevision);

	SiWriteListeners(CfgCreateFolder(root, "ListenerList"), s);

	SiWriteHttpListenerCfg(CfgCreateFolder(root, "HttpListener"), s);

	SiWriteLocalBridges(CfgCreateFolder(root, "LocalBridgeList"), s);

	SiWriteServerCfg(CfgCreateFolder(root, "ServerConfiguration"), s);

	SiWriteHubs(CfgCreateFolder(root, "VirtualHUB"), s);

	return root;
}

static void SiLoadPolicyCfg(POLICY *p, FOLDER *f) {
	if (f == NULL || p == NULL)
		return;

	Zero(p, sizeof(POLICY));

	for (UINT i = 0; i < NUM_POLICY_ITEM; i++) {
		POLICY_ITEM *item = &policy_item[i];

		SetPolicyValue(p, i, item->TypeInt ? CfgGetInt(f, item->Name) : CfgGetBool(f, item->Name));
	}
}

static void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode) {
	if (f == NULL || p == NULL)
		return;

	for (UINT i = 0; i < NUM_POLICY_ITEM; i++) {
		POLICY_ITEM *item = &policy_item[i];

		if (cascade_mode && item->CascadeCfg == false)
			continue;

		if (item->TypeInt)
			CfgAddInt(f, item->Name, GetPolicyValue(p, i));
		else
			CfgAddBool(f, item->Name, GetPolicyValue(p, i) != 0);
	}
}

static void SiWriteHubLinkCfg(FOLDER *f, LINK *k) {
	if (f == NULL || k == NULL)
		return;

	Lock(k->lock);
	{
		CfgAddBool(f, "Online", k->Offline ? false : true);

		CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), k->Option);

		CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), k->Auth);

		if (k->Policy != NULL)
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), k->Policy, true);

		CfgAddBool(f, "CheckServerCert", k->CheckServerCert);
		CfgAddBool(f, "AddDefaultCA", k->AddDefaultCA);

		if (k->ServerCert != NULL) {
			BUF *b = XToBuf(k->ServerCert, false);
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}
	Unlock(k->lock);
}

static void SiLoadHubLinkCfg(FOLDER *f, HUB *h) {
	POLICY p;
	if (f == NULL || h == NULL)
		return;

	FOLDER *pf = CfgFindFolder(f, "Policy");
	if (pf == NULL)
		return;

	SiLoadPolicyCfg(&p, pf);

	bool online = CfgGetBool(f, "Online");

	CLIENT_OPTION *o = CiLoadClientOption(CfgFindFolder(f, "ClientOption"));
	CLIENT_AUTH *a = CiLoadClientAuth(CfgFindFolder(f, "ClientAuth"));
	if (o == NULL || a == NULL) {
		Free(o);
		ClientAuthFree(a);
		return;
	}

	LINK *k = NewLink(h->Cedar, h, o, a, &p);
	if (k != NULL) {
		k->CheckServerCert = CfgGetBool(f, "CheckServerCert");
		k->AddDefaultCA = CfgGetBool(f, "AddDefaultCA");
		BUF *b = CfgGetBuf(f, "ServerCert");
		if (b != NULL) {
			k->ServerCert = BufToX(b, false);
			FreeBuf(b);
		}

		k->Offline = !online;

		ReleaseLink(k);
	}

	Free(o);
	ClientAuthFree(a);
}

static void SiLoadHubAdminOptions(HUB *h, FOLDER *f) {
	if (h == NULL || f == NULL)
		return;

	TOKEN_LIST *t = CfgEnumItemToTokenList(f);
	if (t != NULL) {
		LockList(h->AdminOptionList);
		{
			DeleteAllHubAdminOption(h);

			for (UINT i = 0; i < t->NumTokens; i++) {
				char *name = t->Token[i];
				UINT value = CfgGetInt(f, name);
				;

				Trim(name);

				ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));
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

static void SiWriteHubAdminOptions(FOLDER *f, HUB *h) {
	if (f == NULL || h == NULL)
		return;

	LockList(h->AdminOptionList);
	{
		for (UINT i = 0; i < LIST_NUM(h->AdminOptionList); i++) {
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);

			CfgAddInt(f, a->Name, a->Value);
		}
	}
	UnlockList(h->AdminOptionList);
}

static void SiWriteHubLinks(FOLDER *f, HUB *h) {
	if (f == NULL || h == NULL)
		return;

	LockList(h->LinkList);
	{
		for (UINT i = 0; i < LIST_NUM(h->LinkList); i++) {
			LINK *k = LIST_DATA(h->LinkList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Cascade%u", i);
			SiWriteHubLinkCfg(CfgCreateFolder(f, name), k);
		}
	}
	UnlockList(h->LinkList);
}

static void SiLoadHubLinks(HUB *h, FOLDER *f) {
	if (h == NULL || f == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; i < t->NumTokens; i++) {
		char *name = t->Token[i];
		SiLoadHubLinkCfg(CfgFindFolder(f, name), h);
	}

	FreeToken(t);
}

static void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a) {
	if (f == NULL || a == NULL)
		return;

	CfgAddUniStr(f, "Note", a->Note);
	CfgAddBool(f, "Active", a->Active);
	CfgAddInt(f, "Priority", a->Priority);
	CfgAddBool(f, "Discard", a->Discard);
	CfgAddBool(f, "IsIPv6", a->IsIPv6);

	if (a->IsIPv6 == false) {
		CfgAddIp32(f, "SrcIpAddress", a->SrcIpAddress);
		CfgAddIp32(f, "SrcSubnetMask", a->SrcSubnetMask);
		CfgAddIp32(f, "DestIpAddress", a->DestIpAddress);
		CfgAddIp32(f, "DestSubnetMask", a->DestSubnetMask);
	} else {
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

	if (a->CheckSrcMac) {
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->SrcMacAddress);
		CfgAddStr(f, "SrcMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->SrcMacMask);
		CfgAddStr(f, "SrcMacMask", tmp);
	}

	CfgAddBool(f, "CheckDstMac", a->CheckDstMac);

	if (a->CheckDstMac) {
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

static void SiLoadHubAccessCfg(HUB *h, FOLDER *f) {
	ACCESS a;
	char tmp[MAX_PATH];
	if (h == NULL || f == NULL)
		return;

	Zero(&a, sizeof(a));

	CfgGetUniStr(f, "Note", a.Note, sizeof(a.Note));
	a.Active = CfgGetBool(f, "Active");
	a.Priority = CfgGetInt(f, "Priority");
	a.Discard = CfgGetBool(f, "Discard");
	a.IsIPv6 = CfgGetBool(f, "IsIPv6");

	if (a.IsIPv6 == false) {
		a.SrcIpAddress = CfgGetIp32(f, "SrcIpAddress");
		a.SrcSubnetMask = CfgGetIp32(f, "SrcSubnetMask");
		a.DestIpAddress = CfgGetIp32(f, "DestIpAddress");
		a.DestSubnetMask = CfgGetIp32(f, "DestSubnetMask");
	} else {
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

	if (CfgGetByte(f, "SrcMacAddress", a.SrcMacAddress, sizeof(a.SrcMacAddress)) == 0) {
		CfgGetStr(f, "SrcMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacAddress, tmp) == false)
			a.CheckSrcMac = false;
	}

	if (CfgGetByte(f, "SrcMacMask", a.SrcMacMask, sizeof(a.SrcMacMask)) == 0) {
		CfgGetStr(f, "SrcMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacMask, tmp) == false)
			a.CheckSrcMac = false;
	}

	a.CheckDstMac = CfgGetBool(f, "CheckDstMac");

	if (CfgGetByte(f, "DstMacAddress", a.DstMacAddress, sizeof(a.DstMacAddress)) == 0) {
		CfgGetStr(f, "DstMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacAddress, tmp) == false)
			a.CheckDstMac = false;
	}

	if (CfgGetByte(f, "DstMacMask", a.DstMacMask, sizeof(a.DstMacMask)) == 0) {
		CfgGetStr(f, "DstMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacMask, tmp) == false)
			a.CheckDstMac = false;
	}

	a.CheckTcpState = CfgGetBool(f, "CheckTcpState");
	a.Established = CfgGetBool(f, "Established");
	a.Delay = MAKESURE(CfgGetInt(f, "Delay"), 0, HUB_ACCESSLIST_DELAY_MAX);
	a.Jitter = MAKESURE(CfgGetInt(f, "Jitter"), 0, HUB_ACCESSLIST_JITTER_MAX);
	a.Loss = MAKESURE(CfgGetInt(f, "Loss"), 0, HUB_ACCESSLIST_LOSS_MAX);

	CfgGetStr(f, "RedirectUrl", a.RedirectUrl, sizeof(a.RedirectUrl));

	AddAccessListEx(h, &a, false, false);
}

static void SiWriteHubAccessLists(FOLDER *f, HUB *h) {
	if (f == NULL || h == NULL)
		return;

	LockList(h->AccessList);
	{
		for (UINT i = 0; i < LIST_NUM(h->AccessList); i++) {
			ACCESS *a = LIST_DATA(h->AccessList, i);
			char name[MAX_SIZE];
			ToStr(name, a->Id);
			SiWriteHubAccessCfg(CfgCreateFolder(f, name), a);
		}
	}
	UnlockList(h->AccessList);
}

static void SiLoadHubAccessLists(HUB *h, FOLDER *f) {
	if (f == NULL || h == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; i < t->NumTokens; i++) {
		char *name = t->Token[i];
		SiLoadHubAccessCfg(h, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

static void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o) {
	if (f == NULL || o == NULL)
		return;

	// An item the file does not have keeps its default
	Zero(o, sizeof(HUB_OPTION));
	SiSetDefaultHubOption(o);

	for (UINT i = 0; i < num_hub_option_fields; i++) {
		HUB_OPTION_FIELD *t = &hub_option_fields[i];
		UINT value = GetHubOptionField(o, t);
		char tmp[MAX_SIZE];

		if (CfgIsItem(f, t->CfgName) == false)
			continue;

		switch (t->Type) {
		case HUB_OPTION_BOOL:
			value = CfgGetBool(f, t->CfgName);
			break;

		case HUB_OPTION_UINT:
			value = CfgGetInt(f, t->CfgName);
			break;

		case HUB_OPTION_HEX:
			if (CfgGetStr(f, t->CfgName, tmp, sizeof(tmp)))
				value = HexToInt(tmp);
			break;
		}

		if ((t->Flags & HUB_OPTION_ZERO_IS_DEFAULT) != 0 && value == 0)
			value = t->Default;

		SetHubOptionField(o, t, value);
	}
}

static void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o) {
	if (f == NULL || o == NULL)
		return;

	for (UINT i = 0; i < num_hub_option_fields; i++) {
		HUB_OPTION_FIELD *t = &hub_option_fields[i];
		UINT value = GetHubOptionField(o, t);
		char tmp[MAX_SIZE];

		if ((t->Flags & HUB_OPTION_WRITE_IF_TRUE) != 0 && value == 0)
			continue;

		switch (t->Type) {
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

static void SiWriteUserCfg(FOLDER *f, USER *u) {
	BUF *b;
	AUTHPASSWORD *password;
	AUTHNT *nt;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	if (f == NULL || u == NULL)
		return;

	Lock(u->lock);
	{
		CfgAddUniStr(f, "RealName", u->RealName);
		CfgAddUniStr(f, "Note", u->Note);
		if (u->Group != NULL)
			CfgAddStr(f, "GroupName", u->GroupName);
		CfgAddInt64(f, "CreatedTime", u->CreatedTime);
		CfgAddInt64(f, "UpdatedTime", u->UpdatedTime);
		CfgAddInt64(f, "ExpireTime", u->ExpireTime);
		CfgAddInt64(f, "LastLoginTime", u->LastLoginTime);
		CfgAddInt(f, "NumLogin", u->NumLogin);
		if (u->Policy != NULL)
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), u->Policy, false);
		SiWriteTraffic(f, "Traffic", u->Traffic);

		CfgAddInt(f, "AuthType", u->AuthType);
		if (u->AuthData != NULL) {
			switch (u->AuthType) {
			case AUTHTYPE_ANONYMOUS:
				break;

			case AUTHTYPE_PASSWORD:
				password = (AUTHPASSWORD *)u->AuthData;
				CfgAddByte(f, "AuthPassword", password->HashedKey, sizeof(password->HashedKey));

				if (IsZero(password->NtLmSecureHash, sizeof(password->NtLmSecureHash)) == false)
					CfgAddByte(f, "AuthNtLmSecureHash", password->NtLmSecureHash, sizeof(password->NtLmSecureHash));
				break;

			case AUTHTYPE_NT:
				nt = (AUTHNT *)u->AuthData;
				CfgAddUniStr(f, "AuthNtUserName", nt->NtUsername);
				break;

			case AUTHTYPE_USERCERT:
				usercert = (AUTHUSERCERT *)u->AuthData;
				b = XToBuf(usercert->UserX, false);
				if (b != NULL) {
					CfgAddBuf(f, "AuthUserCert", b);
					FreeBuf(b);
				}
				break;

			case AUTHTYPE_ROOTCERT:
				rootcert = (AUTHROOTCERT *)u->AuthData;
				if (rootcert->Serial != NULL && rootcert->Serial->size >= 1)
					CfgAddByte(f, "AuthSerial", rootcert->Serial->data, rootcert->Serial->size);
				if (rootcert->CommonName != NULL && UniIsEmptyStr(rootcert->CommonName) == false)
					CfgAddUniStr(f, "AuthCommonName", rootcert->CommonName);
				break;
			}
		}
	}
	Unlock(u->lock);
}

static void SiLoadUserCfg(HUB *h, FOLDER *f) {
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char groupname[MAX_SIZE];
	POLICY p;
	TRAFFIC t;
	BUF *b;
	X_SERIAL *serial = NULL;
	wchar_t common_name[MAX_SIZE];
	UCHAR hashed_password[SHA1_SIZE];
	UCHAR md4_password[MD5_SIZE];
	wchar_t tmp[MAX_SIZE];
	USER *u;
	USERGROUP *g;
	if (h == NULL || f == NULL)
		return;

	char *username = f->Name;
	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));
	CfgGetStr(f, "GroupName", groupname, sizeof(groupname));

	UINT64 created_time = CfgGetInt64(f, "CreatedTime");
	UINT64 updated_time = CfgGetInt64(f, "UpdatedTime");
	UINT64 expire_time = CfgGetInt64(f, "ExpireTime");
	UINT64 last_login_time = CfgGetInt64(f, "LastLoginTime");
	UINT num_login = CfgGetInt(f, "NumLogin");
	FOLDER *pf = CfgFindFolder(f, "Policy");
	if (pf != NULL)
		SiLoadPolicyCfg(&p, pf);
	SiLoadTraffic(f, "Traffic", &t);

	UINT authtype = CfgGetInt(f, "AuthType");
	void *authdata = NULL;

	switch (authtype) {
	case AUTHTYPE_PASSWORD:
		Zero(hashed_password, sizeof(hashed_password));
		Zero(md4_password, sizeof(md4_password));
		CfgGetByte(f, "AuthPassword", hashed_password, sizeof(hashed_password));
		CfgGetByte(f, "AuthNtLmSecureHash", md4_password, sizeof(md4_password));
		authdata = NewPasswordAuthDataRaw(hashed_password, md4_password);
		break;

	case AUTHTYPE_NT:
		if (CfgGetUniStr(f, "AuthNtUserName", tmp, sizeof(tmp)))
			authdata = NewNTAuthData(tmp);
		else
			authdata = NewNTAuthData(NULL);
		break;

	case AUTHTYPE_USERCERT:
		b = CfgGetBuf(f, "AuthUserCert");
		if (b != NULL) {
			X *x = BufToX(b, false);
			if (x != NULL) {
				authdata = NewUserCertAuthData(x);
				FreeX(x);
			}
			FreeBuf(b);
		}
		break;

	case AUTHTYPE_ROOTCERT:
		b = CfgGetBuf(f, "AuthSerial");
		if (b != NULL) {
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
			g = AcGetGroup(h, groupname);
		else
			g = NULL;

		u = NewUser(username, realname, note, authtype, authdata);
		if (u != NULL) {
			if (g != NULL)
				JoinUserToGroup(u, g);

			SetUserTraffic(u, &t);

			if (pf != NULL)
				SetUserPolicy(u, &p);

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
			ReleaseGroup(g);
	}
	AcUnlock(h);

	if (serial != NULL)
		FreeXSerial(serial);
}

static void SiWriteUserList(FOLDER *f, LIST *o) {
	if (f == NULL || o == NULL)
		return;

	LockList(o);
	{
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			USER *u = LIST_DATA(o, i);
			SiWriteUserCfg(CfgCreateFolder(f, u->Name), u);
		}
	}
	UnlockList(o);
}

static void SiLoadUserList(HUB *h, FOLDER *f) {
	char *name;
	if (f == NULL || h == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; i < t->NumTokens; i++) {
		name = t->Token[i];
		FOLDER *ff = CfgFindFolder(f, name);
		SiLoadUserCfg(h, ff);
	}

	FreeToken(t);
}

static void SiWriteGroupCfg(FOLDER *f, USERGROUP *g) {
	if (f == NULL || g == NULL)
		return;

	Lock(g->lock);
	{
		CfgAddUniStr(f, "RealName", g->RealName);
		CfgAddUniStr(f, "Note", g->Note);
		if (g->Policy != NULL)
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), g->Policy, false);
		SiWriteTraffic(f, "Traffic", g->Traffic);
	}
	Unlock(g->lock);
}

static void SiLoadGroupCfg(HUB *h, FOLDER *f) {
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	POLICY p;
	TRAFFIC t;
	if (h == NULL || f == NULL)
		return;

	char *name = f->Name;

	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));

	FOLDER *pf = CfgFindFolder(f, "Policy");
	if (pf != NULL)
		SiLoadPolicyCfg(&p, pf);

	SiLoadTraffic(f, "Traffic", &t);

	USERGROUP *g = NewGroup(name, realname, note);
	if (g == NULL)
		return;

	if (pf != NULL)
		SetGroupPolicy(g, &p);

	SetGroupTraffic(g, &t);

	AcLock(h);
	{
		AcAddGroup(h, g);
	}
	AcUnlock(h);

	ReleaseGroup(g);
}

static void SiWriteGroupList(FOLDER *f, LIST *o) {
	if (f == NULL || o == NULL)
		return;

	LockList(o);
	{
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			USERGROUP *g = LIST_DATA(o, i);
			SiWriteGroupCfg(CfgCreateFolder(f, g->Name), g);
		}
	}
	UnlockList(o);
}

static void SiLoadGroupList(HUB *h, FOLDER *f) {
	char *name;
	if (f == NULL || h == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; i < t->NumTokens; i++) {
		name = t->Token[i];
		SiLoadGroupCfg(h, CfgFindFolder(f, name));
	}

	FreeToken(t);
}

static void SiWriteAcList(FOLDER *f, LIST *o) {
	if (f == NULL || o == NULL)
		return;

	LockList(o);
	{
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			char name[MAX_SIZE];
			AC *ac = LIST_DATA(o, i);

			Format(name, sizeof(name), "Acl%u", i + 1);

			FOLDER *ff = CfgCreateFolder(f, name);

			CfgAddBool(ff, "Deny", ac->Deny);
			CfgAddInt(ff, "Priority", ac->Priority);
			CfgAddIp(ff, "IpAddress", &ac->IpAddress);

			if (ac->Masked)
				CfgAddIp(ff, "NetMask", &ac->SubnetMask);
		}
	}
	UnlockList(o);
}

static void SiLoadAcList(LIST *o, FOLDER *f) {
	if (o == NULL || f == NULL)
		return;

	LockList(o);
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

		if (t != NULL) {
			for (UINT i = 0; i < t->NumTokens; i++) {
				FOLDER *ff = CfgFindFolder(f, t->Token[i]);

				if (ff != NULL) {
					AC ac;

					Zero(&ac, sizeof(ac));
					ac.Deny = CfgGetBool(ff, "Deny");
					ac.Priority = CfgGetInt(ff, "Priority");
					CfgGetIp(ff, "IpAddress", &ac.IpAddress);

					if (CfgGetIp(ff, "NetMask", &ac.SubnetMask))
						ac.Masked = true;

					AddAc(o, &ac);
				}
			}

			FreeToken(t);
		}
	}
	UnlockList(o);
}

static void SiWriteCrlList(FOLDER *f, LIST *o) {
	if (f == NULL || o == NULL)
		return;

	LockList(o);
	{
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			char name[MAX_SIZE];
			CRL *crl = LIST_DATA(o, i);

			Format(name, sizeof(name), "Crl%u", i);

			FOLDER *ff = CfgCreateFolder(f, name);
			NAME *n = crl->Name;

			if (UniIsEmptyStr(n->CommonName) == false)
				CfgAddUniStr(ff, "CommonName", n->CommonName);

			if (UniIsEmptyStr(n->Organization) == false)
				CfgAddUniStr(ff, "Organization", n->Organization);

			if (UniIsEmptyStr(n->Unit) == false)
				CfgAddUniStr(ff, "Unit", n->Unit);

			if (UniIsEmptyStr(n->Country) == false)
				CfgAddUniStr(ff, "Country", n->Country);

			if (UniIsEmptyStr(n->State) == false)
				CfgAddUniStr(ff, "State", n->State);

			if (UniIsEmptyStr(n->Local) == false)
				CfgAddUniStr(ff, "Local", n->Local);

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false) {
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestMD5, MD5_SIZE);
				CfgAddStr(ff, "DigestMD5", tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false) {
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestSHA1, SHA1_SIZE);
				CfgAddStr(ff, "DigestSHA1", tmp);
			}

			if (crl->Serial != NULL) {
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->Serial->data, crl->Serial->size);
				CfgAddStr(ff, "Serial", tmp);
			}
		}
	}
	UnlockList(o);
}

static void SiLoadCrlList(LIST *o, FOLDER *f) {
	if (o == NULL || f == NULL)
		return;

	LockList(o);
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

		for (UINT i = 0; i < t->NumTokens; i++) {
			CRL *crl;
			FOLDER *ff = CfgFindFolder(f, t->Token[i]);
			wchar_t cn[MAX_SIZE], org[MAX_SIZE], u[MAX_SIZE], c[MAX_SIZE],
			    st[MAX_SIZE], l[MAX_SIZE];
			char tmp[MAX_SIZE];

			if (ff != NULL) {
				BUF *b;

				crl = ZeroMalloc(sizeof(CRL));

				CfgGetUniStr(ff, "CommonName", cn, sizeof(cn));
				CfgGetUniStr(ff, "Organization", org, sizeof(org));
				CfgGetUniStr(ff, "Unit", u, sizeof(u));
				CfgGetUniStr(ff, "Country", c, sizeof(c));
				CfgGetUniStr(ff, "State", st, sizeof(st));
				CfgGetUniStr(ff, "Local", l, sizeof(l));

				crl->Name = NewName(cn, org, u, c, st, l);

				if (CfgGetStr(ff, "Serial", tmp, sizeof(tmp))) {
					b = StrToBin(tmp);

					if (b != NULL) {
						if (b->Size >= 1)
							crl->Serial = NewXSerial(b->Buf, b->Size);

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestMD5", tmp, sizeof(tmp))) {
					b = StrToBin(tmp);

					if (b != NULL) {
						if (b->Size == MD5_SIZE)
							Copy(crl->DigestMD5, b->Buf, MD5_SIZE);

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestSHA1", tmp, sizeof(tmp))) {
					b = StrToBin(tmp);

					if (b != NULL) {
						if (b->Size == SHA1_SIZE)
							Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);

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

static void SiWriteCertList(FOLDER *f, LIST *o) {
	if (f == NULL || o == NULL)
		return;

	LockList(o);
	{
		X *x;
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			char name[MAX_SIZE];
			x = LIST_DATA(o, i);
			Format(name, sizeof(name), "Cert%u", i);
			BUF *b = XToBuf(x, false);
			if (b != NULL) {
				CfgAddBuf(CfgCreateFolder(f, name), "X509", b);
				FreeBuf(b);
			}
		}
	}
	UnlockList(o);
}

static void SiLoadCertList(LIST *o, FOLDER *f) {
	if (o == NULL || f == NULL)
		return;

	LockList(o);
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

		for (UINT i = 0; i < t->NumTokens; i++) {
			FOLDER *ff = CfgFindFolder(f, t->Token[i]);

			BUF *b = CfgGetBuf(ff, "X509");
			if (b != NULL) {
				X *x = BufToX(b, false);
				if (x != NULL)
					Insert(o, x);
				FreeBuf(b);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

static void SiWriteHubDb(FOLDER *f, HUBDB *db) {
	if (f == NULL || db == NULL)
		return;

	SiWriteUserList(CfgCreateFolder(f, "UserList"), db->UserList);
	SiWriteGroupList(CfgCreateFolder(f, "GroupList"), db->GroupList);
	SiWriteCertList(CfgCreateFolder(f, "CertList"), db->RootCertList);
	SiWriteCrlList(CfgCreateFolder(f, "CrlList"), db->CrlList);
	SiWriteAcList(CfgCreateFolder(f, "IPAccessControlList"), db->AcList);
}

static void SiLoadHubDb(HUB *h, FOLDER *f) {
	if (f == NULL || h == NULL)
		return;

	SiLoadGroupList(h, CfgFindFolder(f, "GroupList"));
	SiLoadUserList(h, CfgFindFolder(f, "UserList"));

	if (h->HubDb != NULL) {
		SiLoadCertList(h->HubDb->RootCertList, CfgFindFolder(f, "CertList"));
		SiLoadCrlList(h->HubDb->CrlList, CfgFindFolder(f, "CrlList"));
		SiLoadAcList(h->HubDb->AcList, CfgFindFolder(f, "IPAccessControlList"));
	}
}

static void SiWriteHubCfg(FOLDER *f, HUB *h) {
	if (f == NULL || h == NULL)
		return;

	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);

	SiWriteTraffic(f, "Traffic", h->Traffic);

	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (UniIsEmptyStr(h->Msg) == false)
			CfgAddUniStr(folder, "MessageText", h->Msg);
	}

	SiWriteHubLogCfg(CfgCreateFolder(f, "LogSetting"), &h->LogSetting);

	SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);

	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb);

	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

static void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f) {
	if (f == NULL || g == NULL)
		return;

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

void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g) {
	if (f == NULL || g == NULL)
		return;

	CfgAddBool(f, "SaveSecurityLog", g->SaveSecurityLog);
	CfgAddInt(f, "SecurityLogSwitchType", g->SecurityLogSwitchType);
	CfgAddBool(f, "SavePacketLog", g->SavePacketLog);
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

static void SiLoadHubCfg(const SERVER *s, FOLDER *f, char *name) {
	HUB_OPTION o;
	bool online;
	if (s == NULL || f == NULL || name == NULL)
		return;

	CEDAR *c = s->Cedar;

	Zero(&o, sizeof(o));
	SiLoadHubOptionCfg(CfgFindFolder(f, "Option"), &o);

	HUB *h = NewHub(c, name, &o);
	if (h != NULL) {
		HUB_LOG g;
		if (CfgGetByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword)) != sizeof(h->HashedPassword))
			Sha0(h->HashedPassword, "", 0);
		if (CfgGetByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword)) != sizeof(h->SecurePassword))
			HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");

		Zero(&g, sizeof(g));
		SiLoadHubLogCfg(&g, CfgFindFolder(f, "LogSetting"));
		SetHubLogSettingEx(h, &g, false);

		online = CfgGetBool(f, "Online");

		SiLoadTraffic(f, "Traffic", h->Traffic);

		SiLoadHubAccessLists(h, CfgFindFolder(f, "AccessList"));

		{
			FOLDER *folder = CfgFindFolder(f, "Message");
			if (folder != NULL) {
				wchar_t *tmp = Malloc(sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1));
				if (CfgGetUniStr(folder, "MessageText", tmp, sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1)))
					SetHubMsg(h, tmp);
				Free(tmp);
			}
		}

		SiLoadHubLinks(h, CfgFindFolder(f, "CascadeList"));

		SiLoadHubAdminOptions(h, CfgFindFolder(f, "AdminOption"));

		SiLoadHubDb(h, CfgFindFolder(f, "SecurityAccountDatabase"));

		h->LastCommTime = CfgGetInt64(f, "LastCommTime");
		if (h->LastCommTime == 0)
			h->LastCommTime = SystemTime64();
		h->LastLoginTime = CfgGetInt64(f, "LastLoginTime");
		if (h->LastLoginTime == 0)
			h->LastLoginTime = SystemTime64();
		h->CreatedTime = CfgGetInt64(f, "CreatedTime");
		h->NumLogin = CfgGetInt(f, "NumLogin");

		AddHub(c, h);

		HubApplyInitialState(h, online);

		WaitLogFlush(h->SecurityLogger);
		WaitLogFlush(h->PacketLogger);

		ReleaseHub(h);
	}
}

void SiWriteHubs(FOLDER *f, SERVER *s) {
	FOLDER *hub_folder;
	UINT num;
	HUB **hubs;
	if (f == NULL || s == NULL)
		return;
	CEDAR *c = s->Cedar;

	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);

		for (UINT i = 0; i < num; i++)
			AddRef(hubs[i]->ref);
	}
	UnlockList(c->HubList);

	for (UINT i = 0; i < num; i++) {
		HUB *h = hubs[i];

		Lock(h->lock);
		{
			hub_folder = CfgCreateFolder(f, h->Name);
			SiWriteHubCfg(hub_folder, h);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if ((i % 30) == 1)
			YieldCpu();
	}

	Free(hubs);
}

void SiLoadHubs(SERVER *s, FOLDER *f) {
	FOLDER *hub_folder;
	if (f == NULL || s == NULL)
		return;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);
	for (UINT i = 0; i < t->NumTokens; i++) {
		char *name = t->Token[i];

		hub_folder = CfgFindFolder(f, name);
		if (hub_folder != NULL)
			SiLoadHubCfg(s, hub_folder, name);
	}
	FreeToken(t);
}

// Write the machine identity salt (FIX-5, #101) as the "MachineIdSalt" item of ServerConfiguration
void SiWriteMachineIdCfg(FOLDER *f, CEDAR *c) {
	if (f == NULL || c == NULL)
		return;

	CfgAddByte(f, "MachineIdSalt", c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// Load the machine identity salt. A config file without one, or with one of another size, keeps the random
// salt of NewCedar, and the next save writes it: the identity changes once on the upgrade, then stays.
void SiLoadMachineIdCfg(CEDAR *c, FOLDER *f) {
	UCHAR salt[MACHINE_ID_SALT_SIZE];
	if (c == NULL || f == NULL)
		return;

	if (CfgGetByte(f, "MachineIdSalt", salt, sizeof(salt)) == sizeof(salt))
		SetCedarMachineIdSalt(c, salt);
}

void SiLoadServerCfg(SERVER *s, FOLDER *f) {
	BUF *b;
	char tmp[MAX_SIZE];
	X *x = NULL;
	K *k = NULL;
	LIST *chain = NewList(NULL);
	if (s == NULL || f == NULL)
		return;

	s->AutoSaveConfigSpan = CfgGetInt(f, "AutoSaveConfigSpan") * 1000;
	if (s->AutoSaveConfigSpan == 0)
		s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	else
		s->AutoSaveConfigSpan = MAKESURE(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_MIN, SERVER_FILE_SAVE_INTERVAL_MAX);

	UINT i = CfgGetInt(f, "MaxConcurrentDnsClientThreads");
	if (i != 0)
		DnsThreadNumMaxSet(i);
	else
		DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	s->DontBackupConfig = CfgGetBool(f, "DontBackupConfig");

	CfgGetIp(f, "ListenIP", &s->ListenIP);

	if (CfgIsItem(f, "BackupConfigOnlyWhenModified"))
		s->BackupConfigOnlyWhenModified = CfgGetBool(f, "BackupConfigOnlyWhenModified");
	else
		s->BackupConfigOnlyWhenModified = true;

	if (CfgIsItem(f, "ServerLogSwitchType")) {
		UINT st = CfgGetInt(f, "ServerLogSwitchType");

		SetLogSwitchType(s->Logger, st);
	}

	SiSetMaxLogSize(s, CfgGetInt64(f, "LoggerMaxLogSize"));

	FOLDER *params_folder = CfgFindFolder(f, "GlobalParams");
	TunablesLoad(params_folder);

	CEDAR *c = s->Cedar;
	Lock(c->lock);
	{
		FOLDER *ff = CfgFindFolder(f, "SyslogSettings");
		if (ff != NULL) {
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

		s->Eraser = SiNewEraser(s, CfgGetInt64(f, "AutoDeleteCheckDiskFreeSpaceMin"),
		                        CfgGetInt(f, "AutoDeleteCheckIntervalSecs"));

		s->NoHighPriorityProcess = CfgGetBool(f, "NoHighPriorityProcess");

		s->SaveDebugLog = CfgGetBool(f, "SaveDebugLog");
		if (s->SaveDebugLog)
			s->DebugLog = NewTinyLog();

		s->NoSendSignature = CfgGetBool(f, "NoSendSignature");

		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL) {
			x = BufToX(b, false);
			FreeBuf(b);
		}

		b = CfgGetBuf(f, "ServerKey");
		if (b != NULL) {
			k = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}

		SiLoadCertList(chain, CfgFindFolder(f, "ServerChain"));

		if (x == NULL || k == NULL || CheckXandK(x, k) == false) {
			FreeX(x);
			FreeK(k);
			FreeXList(chain);
			if (SiGenerateDefaultCertEx(&x, &k, NULL)) {
				SetCedarCertAndChain(c, x, k, NULL);

				FreeX(x);
				FreeK(k);
			} else {
				SLog(c, "LS_DEFAULT_CERT_FAILED");
			}
		} else {
			if (LIST_NUM(chain) == 0)
				SetCedarCertAndChain(c, x, k, NULL);
			else
				SetCedarCertAndChain(c, x, k, chain);

			FreeX(x);
			FreeK(k);
			FreeXList(chain);
		}

		if (CfgGetStr(f, "CipherName", tmp, sizeof(tmp))) {
			StrUpper(tmp);
			SetCedarCipherList(c, tmp);
		}

		Lock(c->TrafficLock);
		{
			SiLoadTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		if (CfgGetByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword)) != sizeof(s->HashedPassword))
			Sha0(s->HashedPassword, "", 0);

		// Before SiLoadHubs: the hub MAC addresses and addresses come from the machine identity
		SiLoadMachineIdCfg(c, f);

		// Without the key the accept path does no reverse DNS or NetBIOS probe; an explicit false keeps the lookup
		s->DisableGetHostNameWhenAcceptTcp = true;
		if (CfgIsItem(f, "DisableGetHostNameWhenAcceptTcp"))
			s->DisableGetHostNameWhenAcceptTcp = CfgGetBool(f, "DisableGetHostNameWhenAcceptTcp");

		if (s->DisableGetHostNameWhenAcceptTcp)
			DisableGetHostNameWhenAcceptInit();

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
			c->DhParamBits = DH_PARAM_BITS_DEFAULT;

		SetDhParam(DhNewFromBits(c->DhParamBits));
	}
	Unlock(c->lock);
}

void SiWriteServerCfg(FOLDER *f, SERVER *s) {
	BUF *b;
	if (f == NULL || s == NULL)
		return;

	CfgAddInt(f, "MaxConcurrentDnsClientThreads", DnsThreadNumMax());

	CfgAddInt(f, "CurrentBuild", CEDAR_VERSION_BUILD);

	CfgAddInt(f, "AutoSaveConfigSpan", s->AutoSaveConfigSpanSaved / 1000);

	CfgAddBool(f, "DontBackupConfig", s->DontBackupConfig);
	CfgAddBool(f, "BackupConfigOnlyWhenModified", s->BackupConfigOnlyWhenModified);

	CfgAddIp(f, "ListenIP", &s->ListenIP);

	if (s->Logger != NULL)
		CfgAddInt(f, "ServerLogSwitchType", s->Logger->SwitchType);

	CfgAddInt64(f, "LoggerMaxLogSize", GetMaxLogSize(s->Logger));

	FOLDER *params_folder = CfgCreateFolder(f, "GlobalParams");

	if (params_folder != NULL)
		TunablesSave(params_folder);

	CEDAR *c = s->Cedar;

	Lock(c->lock);
	{
		FOLDER *ff = CfgCreateFolder(f, "SyslogSettings");
		if (ff != NULL) {
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
		CfgAddInt(f, "AutoDeleteCheckIntervalSecs", GetEraserCheckInterval(s->Eraser));


		CfgAddBool(f, "NoHighPriorityProcess", s->NoHighPriorityProcess);

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

void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t) {
	if (t != NULL)
		Zero(t, sizeof(TRAFFIC));
	if (parent == NULL || name == NULL || t == NULL)
		return;

	FOLDER *f = CfgFindFolder(parent, name);

	if (f == NULL)
		return;

	SiLoadTrafficInner(f, "SendTraffic", &t->Send);
	SiLoadTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e) {
	if (e != NULL)
		Zero(e, sizeof(TRAFFIC_ENTRY));
	if (parent == NULL || name == NULL || e == NULL)
		return;

	FOLDER *f = CfgFindFolder(parent, name);
	if (f == NULL)
		return;

	e->BroadcastCount = CfgGetInt64(f, "BroadcastCount");
	e->BroadcastBytes = CfgGetInt64(f, "BroadcastBytes");
	e->UnicastCount = CfgGetInt64(f, "UnicastCount");
	e->UnicastBytes = CfgGetInt64(f, "UnicastBytes");
}

void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t) {
	if (parent == NULL || name == NULL || t == NULL)
		return;

	FOLDER *f = CfgCreateFolder(parent, name);

	SiWriteTrafficInner(f, "SendTraffic", &t->Send);
	SiWriteTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e) {
	if (parent == NULL || name == NULL || e == NULL)
		return;

	FOLDER *f = CfgCreateFolder(parent, name);
	CfgAddInt64(f, "BroadcastCount", e->BroadcastCount);
	CfgAddInt64(f, "BroadcastBytes", e->BroadcastBytes);
	CfgAddInt64(f, "UnicastCount", e->UnicastCount);
	CfgAddInt64(f, "UnicastBytes", e->UnicastBytes);
}

// Save the configuration file; false when the file could not be written. *size gets the written size (0 when
// nothing changed). A failure, and the first success after one, go to the server log
static bool SiSaveConfiguration(SERVER *s, UINT *size) {
	UINT ret;
	bool failed;
	bool was_failing;

	*size = 0;

	if (s->CfgRw == NULL || s->NoMoreSave)
		return true;

	Lock(s->SaveCfgLock);
	{
		FOLDER *f = SiWriteConfigurationToCfg(s);

		ret = SaveCfgRwEx(s->CfgRw, f, s->BackupConfigOnlyWhenModified ? s->ConfigRevision : INFINITE);
		failed = s->CfgRw->SaveFailed;

		CfgDeleteFolder(f);

		was_failing = s->ConfigSaveFailing;
		s->ConfigSaveFailing = failed;
	}
	Unlock(s->SaveCfgLock);

	if (failed)
		SLog(s->Cedar, "LS_SAVE_CONFIG_FAILED", s->CfgRw->FileNameW);
	else if (was_failing)
		SLog(s->Cedar, "LS_SAVE_CONFIG_RESTORED", s->CfgRw->FileNameW);

	*size = ret;

	return failed == false;
}

void SiSaverThread(THREAD *thread, void *param) {
	SERVER *s = (SERVER *)param;
	UINT retry_span = 0;
	UINT size;
	if (thread == NULL || param == NULL)
		return;

	while (s->Halt == false) {
		UINT span = s->AutoSaveConfigSpan;

		if (s->NoMoreSave == false) {
			if (SiSaveConfiguration(s, &size)) {
				retry_span = 0;
			} else {
				// Back off: the first retry after SERVER_FILE_SAVE_RETRY_MIN, each next one twice as late
				retry_span = (retry_span == 0 ? SERVER_FILE_SAVE_RETRY_MIN : retry_span * 2);
				retry_span = MIN(retry_span, span);
				span = retry_span;
			}
		}

		Wait(s->SaveHaltEvent, span);
	}
}

UINT SiWriteConfigurationFile(SERVER *s) {
	UINT size;
	if (s == NULL)
		return 0;

	SiSaveConfiguration(s, &size);

	return size;
}

static void SiFreeConfiguration(SERVER *s) {
	UINT size;
	if (s == NULL)
		return;

	// The last save: a short retry for a file that another process holds locked for a moment
	for (UINT i = 0; i < SERVER_FILE_SAVE_FINAL_TRIES; i++) {
		if (i != 0)
			SleepThread(SERVER_FILE_SAVE_RETRY_MIN * i);

		if (SiSaveConfiguration(s, &size))
			break;
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

void StInit() {
	if (server_lock != NULL)
		return;

	server_lock = NewLock();
}

void StFree() {
	DeleteLock(server_lock);
	server_lock = NULL;
}

void StStartServer(void) {
	Lock(server_lock);
	{
		if (server != NULL) {
			Unlock(server_lock);
			return;
		}

		server = SiNewServer();
	}
	Unlock(server_lock);
}

void StStopServer() {
	Lock(server_lock);
	{
		if (server == NULL) {
			Unlock(server_lock);
			return;
		}

		SiReleaseServer(server);
		server = NULL;
	}
	Unlock(server_lock);
}

static void SiRebootServerThread(THREAD *thread, void *param) {
	if (thread == NULL)
		return;

	if (server == NULL)
		return;

	StStopServer();

	StStartServer();
}

void SiRebootServerEx(bool reset_setting) {
	server_reset_setting = reset_setting;

	THREAD *t = NewThread(SiRebootServerThread, NULL);
	ReleaseThread(t);
}

static void SiStopAllListener(SERVER *s) {
	if (s == NULL)
		return;

	SiLockListenerList(s);
	{
		LIST *o = NewListFast(NULL);
		for (UINT i = 0; i < LIST_NUM(s->ServerListenerList); i++) {
			SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
			Add(o, e);
		}

		for (UINT i = 0; i < LIST_NUM(o); i++) {
			SERVER_LISTENER *e = LIST_DATA(o, i);
			SiDeleteListener(s, e->Port);
		}

		ReleaseList(o);
	}
	SiUnlockListenerList(s);

	SiFreeHttpListener(s);

	ReleaseList(s->ServerListenerList);
}

void SiReleaseServer(SERVER *s) {
	LISTENER **listener_list;
	UINT num_listener;
	HUB **hub_list;
	UINT num_hub;
	if (s == NULL)
		return;

	SiFreeDeadLockCheck(s);


	CEDAR *c = s->Cedar;

	IncrementServerConfigRevision(s);

	SLog(c, "LS_END_2");

	SLog(c, "LS_STOP_ALL_LISTENER");
	LockList(c->ListenerList);
	{
		listener_list = ToArray(c->ListenerList);
		num_listener = LIST_NUM(c->ListenerList);
		for (UINT i = 0; i < num_listener; i++)
			AddRef(listener_list[i]->ref);
	}
	UnlockList(c->ListenerList);

	for (UINT i = 0; i < num_listener; i++) {
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
		for (UINT i = 0; i < num_hub; i++)
			AddRef(hub_list[i]->ref);
	}
	UnlockList(c->HubList);

	for (UINT i = 0; i < num_hub; i++) {
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

	FreeTinyLog(s->DebugLog);


	Free(s);
}

SERVER *SiNewServer(void) {
	DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	SERVER *s = ZeroMalloc(sizeof(SERVER));

	s->lock = NewLock();


	s->SaveCfgLock = NewLock();
	s->Cedar = NewCedar(NULL, NULL);
	s->Cedar->Server = s;


	s->IsInVm = MsIsInVm();

	s->ServerListenerList = NewList(CompareServerListener);
	s->HttpListenerPort = HTTP_LISTENER_DEFAULT_PORT;
	s->StartTime = SystemTime64();

	PrepareChainCertDir();

	MakeDir(SERVER_LOG_DIR_NAME);
	s->Logger = NewLog(SERVER_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY, s->Cedar->MaxLogSize);

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

	if (s->NoHighPriorityProcess == false)
		Win32SetHighPriority();

	SiInitDeadLockCheck(s);

	return s;
}

