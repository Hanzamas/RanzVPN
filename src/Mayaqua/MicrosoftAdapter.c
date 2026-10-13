// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// MicrosoftAdapter.c
// Windows network adapters and network configuration: adapter list, TCP configuration, firewall registration

#ifdef OS_WIN32

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

#include <AclAPI.h>
#include <DbgHelp.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <Msi.h>
#include <nb30.h>
#include <NTSecAPI.h>
#include <Psapi.h>
#include <sddl.h>
#include <security.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <SoftPub.h>
#include <WtsApi32.h>

// Adapter list related
static LOCK *lock_adapter_list = NULL;

static MS_ADAPTER_LIST *last_adapter_list = NULL;

// Windows Firewall registration
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir)
{
	char tmp[MAX_PATH];
	// Validate arguments
	if (title == NULL || exe == NULL)
	{
		return;
	}
	if (dir == NULL || IsEmptyStr(dir))
	{
		dir = MsGetExeDirName();
	}

	ConbinePath(tmp, sizeof(tmp), dir, exe);

	if (IsFileExists(tmp) == false)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, tmp);
}

void MsRegistWindowsFirewallEx(char *title, char *exe)
{
	char *data;
	char *tmp;
	UINT tmp_size;
	char filename[MAX_PATH];
	char cscript[MAX_PATH];
	char arg[MAX_PATH];
	IO *o;
	char hash[MAX_PATH];
	UCHAR hashbin[SHA1_SIZE];
	UCHAR file_hash_bin[SHA1_SIZE];
	char file_hash_str[MAX_SIZE];
	// Validate arguments
	if (title == NULL || exe == NULL)
	{
		return;
	}

	if (MsIsAdmin() == false)
	{
		return;
	}

	data = "Option Explicit\r\n\r\nConst PROFILES_ALL = 7\r\nConst NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW = 1\r\n"
		"\r\nDim policy2\r\nDim rules\r\nDim new_rule\r\n\r\nOn Error Resume Next\r\n\r\n"
		"Set policy2 = CreateObject(\"HNetCfg.FwPolicy2\")\r\nSet rules = policy2.Rules\r\n"
		"Set new_rule = CreateObject(\"HNetCfg.FWRule\")\r\nnew_rule.Name = \"$TITLE$\"\r\n"
		"new_rule.Description = \"$TITLE$\"\r\nnew_rule.ApplicationName = \"$PATH$\"\r\n"
		"new_rule.Enabled = TRUE\r\nnew_rule.Profiles = PROFILES_ALL\r\nnew_rule.Action = "
		"NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW\r\nrules.Add new_rule\r\n\r\n";

	tmp_size = StrLen(data) * 4;
	tmp = ZeroMalloc(tmp_size);

	Sha1(hashbin, exe, StrLen(exe));
	BinToStr(hash, sizeof(hash), hashbin, 6);

	ReplaceStrEx(tmp, tmp_size, data, "$TITLE$", title, false);
	ReplaceStrEx(tmp, tmp_size, tmp, "$PATH$", exe, false);

	Sha1(file_hash_bin, tmp, StrLen(tmp));
	BinToStr(file_hash_str, sizeof(file_hash_str), file_hash_bin, sizeof(file_hash_bin));

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, false, true) == 0)
	{
		Format(filename, sizeof(filename), "%s\\winfire_%s.vbs", MsGetMyTempDir(), hash);
		o = FileCreate(filename);
		FileWrite(o, tmp, StrLen(tmp));
		FileClose(o);

		Format(cscript, sizeof(cscript), "%s\\cscript.exe", MsGetSystem32Dir());
		Format(arg, sizeof(arg), "\"%s\"", filename);

		if (Run(cscript, arg, true, false))
		{
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, 1, false, true);
		}

		Debug("cscript %s\n", arg);
	}

	Free(tmp);
}

// Search for the adapter by GUID
MS_ADAPTER *MsGetAdapterByGuid(char *guid)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	ret = MsGetAdapterByGuidFromList(o, guid);

	MsFreeAdapterList(o);

	return ret;
}

MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid)
{
	MS_ADAPTER *ret = NULL;
	UINT i;
	// Validate arguments
	if (o == NULL || guid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Guid, guid) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	return ret;
}

// 32-bit overflow checking
#define	CHECK_32BIT_OVERFLOW(old_value, new_value)				\
{																\
	if ((old_value) > (new_value))								\
	{															\
		(new_value) += ((UINT64)4294967296ULL);					\
	}															\
}

// Get the TCP/IP information of the specified adapter
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a)
{
	IP_ADAPTER_INFO *info, *info_top;
	ULONG info_size;
	ULONG ret;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	info_top = ZeroMalloc(sizeof(IP_ADAPTER_INFO));
	info_size = sizeof(IP_ADAPTER_INFO);

	ret = GetAdaptersInfo(info_top, &info_size);
	if (ret == ERROR_INSUFFICIENT_BUFFER || ret == ERROR_BUFFER_OVERFLOW)
	{
		Free(info_top);
		info_size *= 2;
		info_top = ZeroMalloc(info_size);

		if (GetAdaptersInfo(info_top, &info_size) != NO_ERROR)
		{
			Free(info_top);
			return;
		}
	}
	else if (ret != NO_ERROR)
	{
		Free(info_top);
		return;
	}

	// Search for their own entry
	info = info_top;

	while (info != NULL)
	{
		if (info->Index == a->Index)
		{
			IP_ADDR_STRING *s;

			// IP address
			a->NumIpAddress = 0;
			s = &info->IpAddressList;
			while (s != NULL)
			{
				if (a->NumIpAddress < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->IpAddresses[a->NumIpAddress], s->IpAddress.String);
					StrToIP(&a->SubnetMasks[a->NumIpAddress], s->IpMask.String);
					a->NumIpAddress++;
				}
				s = s->Next;
			}

			// Gateway
			a->NumGateway = 0;
			s = &info->GatewayList;
			while (s != NULL)
			{
				if (a->NumGateway < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->Gateways[a->NumGateway], s->IpAddress.String);
					a->NumGateway++;
				}
				s = s->Next;
			}

			// DHCP Server
			a->UseDhcp = (info->DhcpEnabled == 0 ? false : true);
			if (a->UseDhcp)
			{
				SYSTEMTIME st;

				StrToIP(&a->DhcpServer, info->DhcpServer.IpAddress.String);
				TimeToSystem(&st, info->LeaseObtained);
				a->DhcpLeaseStart = SystemToUINT64(&st);

				TimeToSystem(&st, info->LeaseExpires);
				a->DhcpLeaseExpires = SystemToUINT64(&st);
			}

			// WINS server
			a->UseWins = info->HaveWins;
			if (a->UseWins)
			{
				StrToIP(&a->PrimaryWinsServer, info->PrimaryWinsServer.IpAddress.String);
				StrToIP(&a->SecondaryWinsServer, info->SecondaryWinsServer.IpAddress.String);
			}

			StrCpy(a->Guid, sizeof(a->Guid), info->AdapterName);

			a->Info = true;

			break;
		}

		info = info->Next;
	}

	Free(info_top);
}

// Generation of adapter list
MS_ADAPTER_LIST *MsCreateAdapterList()
{
	return MsCreateAdapterListEx(false);
}

MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info)
{
	MS_ADAPTER_LIST *ret;

	if (no_info)
	{
		ret = MsCreateAdapterListInnerEx(true);

		return ret;
	}

	Lock(lock_adapter_list);
	{
		MS_ADAPTER_LIST *old = last_adapter_list;
		UINT i;

		// Fetch a new adapter list
		ret = MsCreateAdapterListInner();

		if (ret == NULL)
		{
			Unlock(lock_adapter_list);
			return NULL;
		}

		// Check whether the previously acquired item exists for each entry
		// in the list of adapters have been taken
		for (i = 0;i < ret->Num;i++)
		{
			UINT j;
			for (j = 0;j < old->Num;j++)
			{
				MS_ADAPTER *o = old->Adapters[j];
				MS_ADAPTER *n = ret->Adapters[i];

				if (StrCmpi(o->Title, n->Title) == 0)
				{
					// If the value of older item is small, increment it
					CHECK_32BIT_OVERFLOW(o->RecvBytes, n->RecvBytes);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsBroadcast, n->RecvPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsUnicast, n->RecvPacketsUnicast);
					CHECK_32BIT_OVERFLOW(o->SendBytes, n->SendBytes);
					CHECK_32BIT_OVERFLOW(o->SendPacketsBroadcast, n->SendPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->SendPacketsUnicast, n->SendPacketsUnicast);
					break;
				}
			}
		}

		// Release the old adapter list
		MsFreeAdapterList(old);

		// Save a clone of the adapter list that newly acquired
		last_adapter_list = MsCloneAdapterList(ret);
	}
	Unlock(lock_adapter_list);

	return ret;
}

// Initialization of the adapter module list
void MsInitAdapterListModule()
{
	lock_adapter_list = NewLock(NULL);

	last_adapter_list = MsCreateAdapterListInner();
}

// Release of the adapter module list
void MsFreeAdapterListModule()
{
	if (last_adapter_list != NULL)
	{
		MsFreeAdapterList(last_adapter_list);
		last_adapter_list = NULL;
	}

	DeleteLock(lock_adapter_list);
	lock_adapter_list = NULL;
}

// Clone the adapter list
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o)
{
	MS_ADAPTER_LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = o->Num;
	ret->Adapters = ZeroMalloc(sizeof(MS_ADAPTER *) * ret->Num);

	for (i = 0;i < ret->Num;i++)
	{
		ret->Adapters[i] = ZeroMalloc(sizeof(MS_ADAPTER));
		Copy(ret->Adapters[i], o->Adapters[i], sizeof(MS_ADAPTER));
	}

	return ret;
}

// Clone the adapter
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

// Creating an adapters list
MS_ADAPTER_LIST *MsCreateAdapterListInner()
{
	return MsCreateAdapterListInnerEx(false);
}

MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info)
{
	return MsCreateAdapterListInnerExVista(no_info);
}

// Creating an adapters list (Windows Vista version)
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info)
{
	LIST *o;
	UINT i;
	UINT retcode;
	PMIB_IF_TABLE2 table;
	MS_ADAPTER_LIST *ret;

	retcode = GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		MS_ADAPTER *a;
		UINT j;

		//if (r->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || r->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
		{
			//if (r->dwType & IF_TYPE_ETHERNET_CSMACD)
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						UniStrCpy(title, sizeof(title), r->Description);
					}
					else
					{
						UniFormat(title, sizeof(title), L"%s (%u)", r->Description, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (UniStrCmpi(a->TitleW, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				// Create an adapter information
				UniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				UniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->MediaConnectState = r->MediaConnectState;
				a->Type = r->Type;
				a->Status = ConvertMidStatusVistaToXp(r->OperStatus);
				a->Mtu = r->Mtu;
				a->Speed = MAX((UINT)r->TransmitLinkSpeed, (UINT)r->ReceiveLinkSpeed);
				a->AddressSize = MIN(sizeof(a->Address), r->PhysicalAddressLength);
				Copy(a->Address, r->PhysicalAddress, a->AddressSize);
				a->RecvBytes = r->InOctets;
				a->RecvPacketsBroadcast = r->InNUcastPkts;
				a->RecvPacketsUnicast = r->InUcastPkts;
				a->SendBytes = r->OutOctets;
				a->SendPacketsBroadcast = r->OutNUcastPkts;
				a->SendPacketsUnicast = r->OutUcastPkts;

				if (r->MediaType == NdisMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWirelessLan ||
					r->PhysicalMediumType == NdisPhysicalMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWiMax ||
					r->Type == IF_TYPE_IEEE80211)
				{
					a->IsWireless = true;
				}

				if (a->IsWireless ||
					r->Type != IF_TYPE_ETHERNET_CSMACD ||
					r->MediaType != NdisMedium802_3 || 
					(r->PhysicalMediumType != 0 && r->PhysicalMediumType != NdisPhysicalMedium802_3))
				{
					a->IsNotEthernetLan = true;
				}

				// TCP/IP information acquisition
				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	FreeMibTable(table);

	return ret;
}

// Convert the MIB Operational Status from Vista format to XP format
UINT ConvertMidStatusVistaToXp(UINT st)
{
	switch (st)
	{
	case IfOperStatusUp:
		return MIB_IF_OPER_STATUS_CONNECTED;

	case IfOperStatusDown:
		return MIB_IF_OPER_STATUS_DISCONNECTED;
	}

	return MIB_IF_OPER_STATUS_NON_OPERATIONAL;
}

// Release the adapter list
void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	Free(o->Adapters);

	Free(o);
}

// Release the adapter information
void MsFreeAdapter(MS_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	Free(a);
}

// Apply the temporary settings data of registry to the TCP parameter of the Windows
void MsApplyTcpConfig()
{
	if (MsIsTcpConfigSupported())
	{
		MS_TCP tcp;

		if (MsLoadTcpConfigReg(&tcp))
		{
			MsSetTcpConfig(&tcp);
		}
	}
}

// Check whether the dynamic configuration of TCP is supported in current state
bool MsIsTcpConfigSupported()
{
	return MsIsAdmin();
}

// Read the TCP settings from the registry setting
bool MsLoadTcpConfigReg(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return false;
	}

	Zero(tcp, sizeof(MS_TCP));

	if (MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true) == false ||
		MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true) == false)
	{
		return false;
	}

	tcp->RecvWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true);
	tcp->SendWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true);

	return true;
}

// Write the TCP settings
void MsSetTcpConfig(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsAdmin())
	{
		bool window_scaling = false;
		UINT tcp1323opts;

		if (tcp->RecvWindowSize >= 65536 || tcp->SendWindowSize >= 65536)
		{
			window_scaling = true;
		}

		// Set the Tcp1323Opts
		tcp1323opts = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts");
		if (window_scaling)
		{
			if (tcp1323opts == 0)
			{
				tcp1323opts = 1;
			}
			if (tcp1323opts == 2)
			{
				tcp1323opts = 3;
			}
		}
		else
		{
			if (tcp1323opts == 1)
			{
				tcp1323opts = 0;
			}
			if (tcp1323opts == 3)
			{
				tcp1323opts = 2;
			}
		}
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts", tcp1323opts);

		// Set the Receive Window
		if (tcp->RecvWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize", tcp->RecvWindowSize);
		}

		// Setting the Send Window
		if (tcp->SendWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow", tcp->SendWindowSize);
		}
	}
}

// Initialize the global network settings
void MsInitGlobalNetworkConfig()
{
	UINT current_window_size = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize");

	if (current_window_size == 65535 || current_window_size == 5980160 ||
		current_window_size == 16777216 || current_window_size == 16777214)
	{
		// Remove the strange value which is written by older version of PacketiX VPN
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
			"DefaultReceiveWindow");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
			"DefaultSendWindow");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"Tcp1323Opts");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"TcpWindowSize");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"GlobalMaxTcpWindowSize");

		// Set vpn_no_change = true
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "vpn_no_change", 1);
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "vpn_no_change", 1);
	}

	MsApplyTcpConfig();
}

// Get the network connection name
wchar_t *MsGetNetworkConnectionName(char *guid)
{
	wchar_t *ncname = NULL;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	// Get the network connection name
	Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid);
	ncname = MsRegReadStrW(REG_LOCAL_MACHINE, tmp, "Name");

	return ncname;
}

#endif	// WIN32

