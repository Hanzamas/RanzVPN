// ServerConfig.c
// VPN Server configuration: load and write of the configuration file, including the Virtual Hub sub-configuration, and the reboot that can reset it (they share server_reset_setting)

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

char *SERVER_CONFIG_FILE_NAME = "$ranz_server.config";

char *BRIDGE_CONFIG_FILE_NAME = "$vpn_bridge.config";

char *SERVER_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";

char *BRIDGE_CONFIG_TEMPLATE_NAME = "$ranz_server_template.config";

static bool server_reset_setting = false;

UINT vpn_global_parameters[NUM_GLOBAL_PARAMS] = {0};

void SiSetDefaultHubOption(HUB_OPTION *o)
{
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

void SiInitDefaultHubList(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	HUB_LOG g;
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));

	SiSetDefaultHubOption(&o);

	h = NewHub(s->Cedar, s->Cedar->Bridge == false ? SERVER_DEFAULT_HUB_NAME : SERVER_DEFAULT_BRIDGE_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	if (s->Cedar->Bridge)
	{
		Rand(h->HashedPassword, sizeof(h->HashedPassword));
		Rand(h->SecurePassword, sizeof(h->SecurePassword));
	}

	h->Offline = true;
	SetHubOnline(h);

	SiSetDefaultLogSetting(&g);
	SetHubLogSettingEx(h, &g, false);

	ReleaseHub(h);
}

void SiSetDefaultLogSetting(HUB_LOG *g)
{
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

void SiLoadInitialConfiguration(SERVER *s)
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

	s->Cedar->UsernameHubSeparator = DEFAULT_USERNAME_HUB_SEPARATOR;

	{
		SiInitDefaultHubList(s);
	}

	SiInitListenerList(s);

	s->Eraser = NewEraser(s->Logger, 0);
}

bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root)
{
	if (s == NULL || root == NULL)
	{
		return false;
	}

	return SiLoadConfigurationCfg(s, root);
}

bool SiLoadConfigurationFile(SERVER *s)
{
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

void SiInitConfiguration(SERVER *s)
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
	FOLDER *f1, *f2, *f3, *f4, *f6;
	if (s == NULL || root == NULL)
	{
		return false;
	}

	f1 = CfgFindFolder(root, "ServerConfiguration");
	f2 = CfgFindFolder(root, "VirtualHUB");
	f3 = CfgFindFolder(root, "ListenerList");
	f4 = CfgFindFolder(root, "LocalBridgeList");
	f6 = CfgFindFolder(root, "LicenseManager");

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

void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r)
{
	if (f == NULL || r == NULL)
	{
		return;
	}

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
	CfgAddBool(f, "DisableDos", r->DisableDos);
}

void SiLoadListenerCfg(SERVER *s, FOLDER *f)
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

void SiWriteListeners(FOLDER *f, SERVER *s)
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

void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br)
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

void SiWriteLocalBridges(FOLDER *f, SERVER *s)
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

void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f)
{
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	bool tapmode = false;
	UCHAR tapaddr[6];
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

FOLDER *SiWriteConfigurationToCfg(SERVER *s)
{
	FOLDER *root;
	char region[128];
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

void SiLoadPolicyCfg(POLICY *p, FOLDER *f)
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

void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode)
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

void SiWriteHubLinkCfg(FOLDER *f, LINK *k)
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

void SiLoadHubLinkCfg(FOLDER *f, HUB *h)
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

void SiLoadHubAdminOptions(HUB *h, FOLDER *f)
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

void SiWriteHubAdminOptions(FOLDER *f, HUB *h)
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

void SiWriteHubLinks(FOLDER *f, HUB *h)
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

void SiLoadHubLinks(HUB *h, FOLDER *f)
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

void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a)
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

void SiLoadHubAccessCfg(HUB *h, FOLDER *f)
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

void SiWriteHubAccessLists(FOLDER *f, HUB *h)
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

void SiLoadHubAccessLists(HUB *h, FOLDER *f)
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

void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
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

	// Missing item means enabled
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

void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
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

void SiWriteUserCfg(FOLDER *f, USER *u)
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

void SiWriteUserList(FOLDER *f, LIST *o)
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

void SiLoadUserList(HUB *h, FOLDER *f)
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

void SiWriteGroupCfg(FOLDER *f, USERGROUP *g)
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

void SiLoadGroupCfg(HUB *h, FOLDER *f)
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

void SiWriteGroupList(FOLDER *f, LIST *o)
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

void SiLoadGroupList(HUB *h, FOLDER *f)
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

void SiWriteAcList(FOLDER *f, LIST *o)
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

void SiLoadAcList(LIST *o, FOLDER *f)
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

void SiWriteCrlList(FOLDER *f, LIST *o)
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

void SiLoadCrlList(LIST *o, FOLDER *f)
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

void SiWriteCertList(FOLDER *f, LIST *o)
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

void SiLoadCertList(LIST *o, FOLDER *f)
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

void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list)
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

void SiLoadHubDb(HUB *h, FOLDER *f)
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

void SiWriteHubCfg(FOLDER *f, HUB *h)
{
	if (f == NULL || h == NULL)
	{
		return;
	}

	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	if (h->Cedar->Bridge == false)
	{
		CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);
	}

	SiWriteTraffic(f, "Traffic", h->Traffic);

	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (IsEmptyUniStr(h->Msg) == false)
		{
			CfgAddUniStr(folder, "MessageText", h->Msg);
		}
	}

	SiWriteHubLogCfgEx(CfgCreateFolder(f, "LogSetting"), &h->LogSetting, false);

	SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);

	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	if (h->Cedar->Bridge == false)
	{
		SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb,
			false
			);
	}

	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f)
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

void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name)
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

		if (h->Cedar->Bridge == false)
		{
			online = CfgGetBool(f, "Online");
		}
		else
		{
			online = true;
		}

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

		if (h->Cedar->Bridge == false)
		{
			SiLoadHubDb(h, CfgFindFolder(f, "SecurityAccountDatabase"));
		}

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

void SiWriteLicenseManager(FOLDER *f, SERVER *s)
{
}

void SiLoadLicenseManager(SERVER *s, FOLDER *f)
{
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
	bool b = false;
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
				// In bridge mode, load only the hub named "BRIDGE"
				b = true;
			}
			else
			{
				continue;
			}
		}
		hub_folder = CfgFindFolder(f, name);
		if (hub_folder != NULL)
		{
			SiLoadHubCfg(s, hub_folder, name);
		}
	}
	FreeToken(t);

	if (s->Cedar->Bridge && b == false)
	{
		SiInitDefaultHubList(s);
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
		if (ff != NULL && GetServerCapsBool(s, "b_support_syslog"))
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
		if (s->NoDebugDump)
		{
			MsSetEnableMinidump(false);
		}

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

		if (CfgGetStr(f, "UsernameHubSeparator", tmp, sizeof(tmp)))
		{
			c->UsernameHubSeparator = IsPrintableAsciiChar(tmp[0]) ? tmp[0] : DEFAULT_USERNAME_HUB_SEPARATOR;
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

		s->DisableGetHostNameWhenAcceptTcp = CfgGetBool(f, "DisableGetHostNameWhenAcceptTcp");

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

void SiWriteGlobalParamsCfg(FOLDER *f)
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

		{
			char str[2];
			StrCpy(str, sizeof(str), &c->UsernameHubSeparator);
			CfgAddStr(f, "UsernameHubSeparator", str);
		}

		Lock(c->TrafficLock);
		{
			SiWriteTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		CfgAddStr(f, "CipherName", s->Cedar->CipherList);

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

void SiSaverThread(THREAD *thread, void *param)
{
	SERVER *s = (SERVER *)param;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (s->Halt == false)
	{
		if (s->NoMoreSave == false)
		{
			SiWriteConfigurationFile(s);
		}

		Wait(s->SaveHaltEvent, s->AutoSaveConfigSpan);
	}
}

UINT SiWriteConfigurationFile(SERVER *s)
{
	UINT ret;
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

void SiFreeConfiguration(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SiWriteConfigurationFile(s);

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

void SiRebootServerEx(bool bridge, bool reset_setting)
{
	THREAD *t;

	server_reset_setting = reset_setting;

	t = NewThread(SiRebootServerThread, (void *)bridge);
	ReleaseThread(t);
}
