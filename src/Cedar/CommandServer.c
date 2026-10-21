// CommandServer.c
// vpncmd server administration commands (Ps*) that the dispatch tables reach through Command.h, and the argument parsers, evaluators and printers that only they use

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include "CommandInternal.h"

void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	char vv[128];
	if (s == NULL)
	{
		return;
	}

	if (server_mode == false)
	{
		CtInsert(ct, _UU("CM_ST_ACCOUNT_NAME"), s->AccountName);

		if (s->Connected == false)
		{
			wchar_t *st = _UU("CM_ST_CONNECTED_FALSE");
			switch (s->SessionStatus)
			{
			case CLIENT_STATUS_CONNECTING:
				st = _UU("CM_ST_CONNECTING");
				break;
			case CLIENT_STATUS_NEGOTIATION:
				st = _UU("CM_ST_NEGOTIATION");
				break;
			case CLIENT_STATUS_AUTH:
				st = _UU("CM_ST_AUTH");
				break;
			case CLIENT_STATUS_ESTABLISHED:
				st = _UU("CM_ST_ESTABLISHED");
				break;
			case CLIENT_STATUS_RETRY:
				st = _UU("CM_ST_RETRY");
				break;
			case CLIENT_STATUS_IDLE:
				st = _UU("CM_ST_IDLE");
				break;
			}
			CtInsert(ct, _UU("CM_ST_CONNECTED"), st);
		}
		else
		{
			CtInsert(ct, _UU("CM_ST_CONNECTED"), _UU("CM_ST_CONNECTED_TRUE"));
		}
	}

	if (s->Connected)
	{
		if (s->VLanId == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp, s->VLanId);
		}

		CtInsert(ct, _UU("CM_ST_VLAN_ID"), tmp);

		if (server_mode == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ServerName);
			CtInsert(ct, _UU("CM_ST_SERVER_NAME"), tmp);

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_PORT_TCP"), s->ServerPort);
			CtInsert(ct, _UU("CM_ST_SERVER_PORT"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), s->ServerProductName);
		CtInsert(ct, _UU("CM_ST_SERVER_P_NAME"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", s->ServerProductVer / 100, s->ServerProductVer % 100);
		CtInsert(ct, _UU("CM_ST_SERVER_P_VER"), tmp);
		UniFormat(tmp, sizeof(tmp), L"Build %u", s->ServerProductBuild);
		CtInsert(ct, _UU("CM_ST_SERVER_P_BUILD"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->StartTime), NULL);
	CtInsert(ct, _UU("CM_ST_START_TIME"), tmp);
	// FirstConnectionEstablisiedTime is misspelt on purpose: the name is part of the protocol
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->FirstConnectionEstablisiedTime), NULL);
	CtInsert(ct, _UU("CM_ST_FIRST_ESTAB_TIME"), s->FirstConnectionEstablisiedTime == 0 ? _UU("CM_ST_NONE") : tmp);

	if (s->Connected)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->CurrentConnectionEstablishTime), NULL);
		CtInsert(ct, _UU("CM_ST_CURR_ESTAB_TIME"), tmp);
	}

	if (server_mode == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_STR"), s->NumConnectionsEstablished);
		CtInsert(ct, _UU("CM_ST_NUM_ESTABLISHED"), tmp);
	}

	if (s->Connected)
	{
		CtInsert(ct, _UU("CM_ST_HALF_CONNECTION"), s->HalfConnection ? _UU("CM_ST_HALF_TRUE") : _UU("CM_ST_HALF_FALSE"));

		CtInsert(ct, _UU("CM_ST_QOS"), s->QoS ? _UU("CM_ST_QOS_TRUE") : _UU("CM_ST_QOS_FALSE"));

		UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnections);
		CtInsert(ct, _UU("CM_ST_NUM_TCP"), tmp);

		if (s->HalfConnection)
		{
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsUpload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_UPLOAD"), tmp);
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsDownload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_DOWNLOAD"), tmp);
		}

		UniFormat(tmp, sizeof(tmp), L"%u", s->MaxTcpConnections);
		CtInsert(ct, _UU("CM_ST_MAX_TCP"), tmp);

		if (s->UseEncrypt == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_FALSE"));
		}
		else
		{
			if (StrLen(s->CipherName) != 0 && StrLen(s->ProtocolName) != 0)
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE3"), s->ProtocolName, s->CipherName);
			}
			else if (StrLen(s->CipherName) != 0)
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE"), s->CipherName);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE2"));
			}
		}
		CtInsert(ct, _UU("CM_ST_USE_ENCRYPT"), tmp);

		if (s->UseCompress)
		{
			UINT percent = 0;
			if ((s->TotalRecvSize + s->TotalSendSize) > 0)
			{
				percent = (UINT)((UINT64)100 - (UINT64)(s->TotalRecvSizeReal + s->TotalSendSizeReal) * (UINT64)100 /
					(s->TotalRecvSize + s->TotalSendSize));
				percent = MAKESURE(percent, 0, 100);
			}

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_TRUE"), percent);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_FALSE"));
		}
		CtInsert(ct, _UU("CM_ST_USE_COMPRESS"), tmp);

		if (IsEmptyStr(s->UnderlayProtocol) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->UnderlayProtocol);
			CtInsert(ct, _UU("CM_ST_UNDERLAY_PROTOCOL"), tmp);
		}

		if (IsEmptyStr(s->ProtocolDetails) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ProtocolDetails);
			CtInsert(ct, _UU("CM_ST_PROTOCOL_DETAILS"), tmp);
		}

		CtInsert(ct, _UU("CM_ST_UDP_ACCEL_ENABLED"), (s->IsUdpAccelerationEnabled ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));
		CtInsert(ct, _UU("CM_ST_UDP_ACCEL_USING"), (s->IsUsingUdpAcceleration ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));

		StrToUni(tmp, sizeof(tmp), s->SessionName);
		CtInsert(ct, _UU("CM_ST_SESSION_NAME"), tmp);

		StrToUni(tmp, sizeof(tmp), s->ConnectionName);
		if (UniStrCmpi(tmp, L"INITING") != 0)
		{
			CtInsert(ct, _UU("CM_ST_CONNECTION_NAME"), tmp);
		}

		BinToStr(str, sizeof(str), s->SessionKey, sizeof(s->SessionKey));
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("CM_ST_SESSION_KEY"), tmp);

		CtInsert(ct, _UU("CM_ST_BRIDGE_MODE"), s->IsBridgeMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		CtInsert(ct, _UU("CM_ST_MONITOR_MODE"), s->IsMonitorMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		ToStr3(vv, sizeof(vv), s->TotalSendSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->TotalRecvSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_SIZE"), tmp);
	}
}

UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_SET_PASSWORD t;
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	char *pw = GetParamStr(o, "[password]");

	Zero(&t, sizeof(t));
	Sha0(t.HashedPassword, pw, StrLen(pw));

	UINT ret = ScSetServerPassword(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param)
{
	if (c == NULL)
	{
		return NULL;
	}

	char *s = CmdPasswordPrompt(c);

	if (s == NULL)
	{
		return NULL;
	}
	else
	{
		wchar_t *ret = CopyStrToUni(s);

		Free(s);

		return ret;
	}
}

char *CmdPasswordPrompt(CONSOLE *c)
{
	char *pw1, *pw2;
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_VPNCMD_PWPROMPT_0"));

RETRY:
	c->Write(c, L"");


	pw1 = c->ReadPassword(c, _UU("CMD_VPNCMD_PWPROMPT_1"));
	if (pw1 == NULL)
	{
		return NULL;
	}

	pw2 = c->ReadPassword(c, _UU("CMD_VPNCMD_PWPROMPT_2"));
	if (pw2 == NULL)
	{
		Free(pw1);
		return NULL;
	}

	c->Write(c, L"");

	if (StrCmp(pw1, pw2) != 0)
	{
		Free(pw1);
		Free(pw2);
		c->Write(c, _UU("CMD_VPNCMD_PWPROMPT_3"));
		goto RETRY;
	}

	Free(pw1);

	return pw2;
}

UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDisable_PortPrompt"), CmdEvalPort, NULL},
	};

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = false;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	UINT ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerEnable_PortPrompt"), CmdEvalPort, NULL},
	};

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	UINT ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_LISTENER_LIST t;

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	UINT ret = ScEnumListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_2"), false);

	for (UINT i = 0;i < t.NumPort;i++)
	{
		wchar_t *status = _UU("CM_LISTENER_OFFLINE");
		wchar_t tmp[128];

		if (t.Errors[i])
		{
			status = _UU("CM_LISTENER_ERROR");
		}
		else if (t.Enables[i])
		{
			status = _UU("CM_LISTENER_ONLINE");
		}

		UniFormat(tmp, sizeof(tmp), _UU("CM_LISTENER_TCP_PORT"), t.Ports[i]);

		CtInsert(ct, tmp, status);
	}

	CtFree(ct, c);

	FreeRpcListenerList(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDelete_PortPrompt"), CmdEvalPort, NULL},
	};

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	UINT ret = ScDeleteListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_SERVER_INFO t;
	wchar_t tmp[MAX_SIZE];

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	UINT ret = ScGetServerInfo(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	CtInsert(ct, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	CtInsert(ct, _UU("SM_INFO_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	CtInsert(ct, _UU("SM_INFO_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	CtInsert(ct, _UU("SM_INFO_HOSTNAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsSystemName);
	CtInsert(ct, _UU("SM_OS_SYSTEM_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsProductName);
	CtInsert(ct, _UU("SM_OS_PRODUCT_NAME"), tmp);

	if (t.OsInfo.OsServicePack != 0)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_OS_SP_TAG"), t.OsInfo.OsServicePack);
		CtInsert(ct, _UU("SM_OS_SERVICE_PACK"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVendorName);
	CtInsert(ct, _UU("SM_OS_VENDER_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVersion);
	CtInsert(ct, _UU("SM_OS_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelName);
	CtInsert(ct, _UU("SM_OS_KERNEL_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelVersion);
	CtInsert(ct, _UU("SM_OS_KERNEL_VERSION"), tmp);

	CtFree(ct, c);

	FreeRpcServerInfo(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_SERVER_STATUS t;
	wchar_t tmp[MAX_PATH];
	char tmp2[MAX_PATH];

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	UINT ret = ScGetServerStatus(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	UniToStru(tmp, t.NumTcpConnections);
	CtInsert(ct, _UU("SM_ST_NUM_TCP"), tmp);

	UniToStru(tmp, t.NumHubTotal);
	CtInsert(ct, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	UniToStru(tmp, t.NumSessionsTotal);
	CtInsert(ct, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	UniToStru(tmp, t.NumMacTables);
	CtInsert(ct, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	UniToStru(tmp, t.NumIpTables);
	CtInsert(ct, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	UniToStru(tmp, t.NumUsers);
	CtInsert(ct, _UU("SM_ST_NUM_USERS"), tmp);

	UniToStru(tmp, t.NumGroups);
	CtInsert(ct, _UU("SM_ST_NUM_GROUPS"), tmp);

	UniToStru(tmp, t.AssignedClientLicenses);
	CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE"), tmp);

	UniToStru(tmp, t.AssignedBridgeLicenses);
	CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	CmdInsertTrafficInfo(ct, &t.Traffic);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	CtInsert(ct, _UU("SM_ST_START_TIME"), tmp);

	GetDateTimeStrMilli64(tmp2, sizeof(tmp2), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), tmp2);
	CtInsert(ct, _UU("SM_ST_CURRENT_TIME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	CtInsert(ct, _UU("SM_ST_CURRENT_TICK"), tmp);

	if (t.MemInfo.TotalMemory != 0)
	{
		char vv[128];

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreeMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreePhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_PHYS"), tmp);
	}

	CtFree(ct, c);

	FreeParamValueList(o);

	return 0;
}

void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	if (ct == NULL || t == NULL)
	{
		return;
	}

	ToStr3(vv, sizeof(vv), t->Send.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_SIZE"), tmp);
}

wchar_t *CmdPromptPort(CONSOLE *c, void *param)
{
	wchar_t *prompt_str;

	if (param != NULL)
	{
		prompt_str = (wchar_t *)param;
	}
	else
	{
		prompt_str = _UU("CMD_PROMPT_PORT");
	}

	return c->ReadLine(c, prompt_str, true);
}

bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param)
{
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UINT i = UniToInt(str);

	if (i >= 1 && i <= 65535)
	{
		return true;
	}

	c->Write(c, _UU("CMD_EVAL_PORT"));

	return false;
}

UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	UINT ret = ScCreateListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	BUF *b = ReadDump("|legal.txt");

	CmdPrintAbout(c);
	c->Write(c, L"\r\n");

	if (b != NULL)
	{
		SeekBufToEnd(b);
		WriteBufChar(b, 13);
		WriteBufChar(b, 10);
		WriteBufChar(b, 0);

		wchar_t *s = CopyUtfToUni(b->Buf);

		c->Write(c, s);

		Free(s);
	}

	c->Write(c, _UU("D_ABOUT@S_INFO3"));
	c->Write(c, L"\r\n");
	c->Write(c, _UU("D_ABOUT@S_INFO4"));
	c->Write(c, L"\r\n");
	CmdPrintAbout(c);
	c->Write(c, L"\r\n");

	FreeParamValueList(o);

	FreeBuf(b);

	return 0;
}
