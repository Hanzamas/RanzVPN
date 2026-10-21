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

UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK_STATUS t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLinkStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CmdPrintStatusToListViewEx(ct, &t.Status, false);

		CtFree(ct, c);

		FreeRpcLinkStatus(&t);
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RENAME_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), GetParamUniStr(o, "[name]"));

	ret = ScRenameLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScSetLinkOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScSetLinkOffline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static void CmdPrintNodeInfo(CT *ct, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	if (ct == NULL || info == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), info->ClientProductName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_NAME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", Endian32(info->ClientProductVer) / 100, Endian32(info->ClientProductVer) % 100);
	CtInsert(ct, _UU("SM_NODE_CLIENT_VER"), tmp);

	UniFormat(tmp, sizeof(tmp), L"Build %u", Endian32(info->ClientProductBuild));
	CtInsert(ct, _UU("SM_NODE_CLIENT_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsVer);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_VER"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsProductId);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_PID"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientHostname);
	CtInsert(ct, _UU("SM_NODE_CLIENT_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ClientIpAddress, info->ClientIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_CLIENT_IP"), tmp);

	UniToStru(tmp, Endian32(info->ClientPort));
	CtInsert(ct, _UU("SM_NODE_CLIENT_PORT"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ServerHostname);
	CtInsert(ct, _UU("SM_NODE_SERVER_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ServerIpAddress, info->ServerIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_SERVER_IP"), tmp);

	UniToStru(tmp, Endian32(info->ServerPort));
	CtInsert(ct, _UU("SM_NODE_SERVER_PORT"), tmp);

	if (StrLen(info->ProxyHostname) != 0)
	{
		StrToUni(tmp, sizeof(tmp), info->ProxyHostname);
		CtInsert(ct, _UU("SM_NODE_PROXY_HOSTNAME"), tmp);

		IPToStr4or6(str, sizeof(str), info->ProxyIpAddress, info->ProxyIpAddress6);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("SM_NODE_PROXY_IP"), tmp);

		UniToStru(tmp, Endian32(info->ProxyPort));
		CtInsert(ct, _UU("SM_NODE_PROXY_PORT"), tmp);
	}
}

UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SESSION_STATUS t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetSessionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		CT *ct = CtNewStandard();

		if (t.ClientIp != 0 || IsZero(t.ClientIp6, sizeof(t.ClientIp6)) == false)
		{
			IPToStr4or6(str, sizeof(str), t.ClientIp, t.ClientIp6);
			StrToUni(tmp, sizeof(tmp), str);
			CtInsert(ct, _UU("SM_CLIENT_IP"), tmp);
		}

		if (StrLen(t.ClientHostName) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientHostName);
			CtInsert(ct, _UU("SM_CLIENT_HOSTNAME"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), t.Username);
		CtInsert(ct, _UU("SM_SESS_STATUS_USERNAME"), tmp);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.RealUsername);
			CtInsert(ct, _UU("SM_SESS_STATUS_REALUSER"), tmp);
		}

		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("SM_SESS_STATUS_GROUPNAME"), tmp);
		}


		CmdPrintStatusToListViewEx(ct, &t.Status, true);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
		{
			CmdPrintNodeInfo(ct, &t.NodeInfo);
		}

		CtFree(ct, c);
	}

	FreeRpcSessionStatus(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	CT *ct;
	UINT i;
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_0"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_1"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_3"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_6"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_4"), false);

	for (i = 0;i < t.NumAccess;i++)
	{
		ACCESS *a = &t.Accesses[i];
		char tmp[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];

		GetAccessListStr(tmp, sizeof(tmp), a);
		UniToStru(tmp1, a->Priority);
		StrToUni(tmp2, sizeof(tmp2), tmp);
		UniToStru(tmp4, a->UniqueId);
		if (a->UniqueId == 0)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SEC_NONE"));
		}

		UniToStru(tmp3, a->Id);

		CtInsert(ct,
			tmp3,
			a->Discard ? _UU("SM_ACCESS_DISCARD") : _UU("SM_ACCESS_PASS"),
			a->Active ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"),
			tmp1,
			tmp4,
			tmp2,
			a->Note);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumAccessList(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_ACCESS t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Id = GetParamInt(o, "[id]");

	ret = ScDeleteAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = true;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = false;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

wchar_t *GetAuthTypeStr(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_AUTHTYPE_%u", id);

	return _UU(tmp);
}

UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	Trim(t.Name);
	if (StrCmpi(t.Name, "*") == 0)
	{
		t.AuthType = AUTHTYPE_NT;
		t.AuthData = NewNTAuthData(NULL);
	}
	else
	{
		UCHAR random_pass[SHA1_SIZE];
		UCHAR random_pass2[MD5_SIZE];

		Rand(random_pass, sizeof(random_pass));
		Rand(random_pass2, sizeof(random_pass2));
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = NewPasswordAuthDataRaw(random_pass, random_pass2);
	}

	ret = ScCreateUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDeleteUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	t.AuthType = AUTHTYPE_ANONYMOUS;
	t.AuthData = NULL;

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHPASSWORD *pw;

		pw = NewPasswordAuthData(t.Name, GetParamStr(o, "PASSWORD"));

		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = pw;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	X *x;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));

		FreeParamValueList(o);

		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHUSERCERT *c;

		c = NewUserCertAuthData(x);

		FreeX(x);

		t.AuthType = AUTHTYPE_USERCERT;
		t.AuthData = c;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"CN", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_CN"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_SERIAL"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHROOTCERT *c;
		BUF *b;
		X_SERIAL *serial = NULL;

		b = StrToBin(GetParamStr(o, "SERIAL"));

		if (b != NULL && b->Size >= 1)
		{
			serial = NewXSerial(b->Buf, b->Size);
		}

		FreeBuf(b);

		c = NewRootCertAuthData(serial, GetParamUniStr(o, "CN"));

		FreeXSerial(serial);

		t.AuthType = AUTHTYPE_ROOTCERT;
		t.AuthData = c;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHNT *a;

		a = NewNTAuthData(GetParamUniStr(o, "ALIAS"));

		t.AuthType = AUTHTYPE_NT;
		t.AuthData = a;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Policy != NULL)
	{
		Free(t.Policy);
		t.Policy = NULL;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT64 StrToDateTime64(char *str)
{
	UINT64 ret = 0;
	TOKEN_LIST *t;
	UINT a, b, c, d, e, f;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StrCmpi(str, "none") == 0)
	{
		return 0;
	}

	t = ParseToken(str, ":/,. \"");
	if (t->NumTokens != 6)
	{
		FreeToken(t);
		return INFINITE;
	}

	a = ToInt(t->Token[0]);
	b = ToInt(t->Token[1]);
	c = ToInt(t->Token[2]);
	d = ToInt(t->Token[3]);
	e = ToInt(t->Token[4]);
	f = ToInt(t->Token[5]);

	ret = INFINITE;

	if (a >= 1000 && a <= 9999 && b >= 1 && b <= 12 && c >= 1 && c <= 31 &&
		d <= 23 && e <= 59 && f <= 59)
	{
		SYSTEMTIME t;

		Zero(&t, sizeof(t));
		t.wYear = a;
		t.wMonth = b;
		t.wDay = c;
		t.wHour = d;
		t.wMinute = e;
		t.wSecond = f;

		ret = SystemToUINT64(&t);
	}

	FreeToken(t);

	return ret;
}

static bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param)
{
	UINT64 ret;
	char tmp[MAX_SIZE];
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	ret = StrToDateTime64(tmp);

	if (ret == INFINITE)
	{
		c->Write(c, _UU("CMD_EVAL_DATE_TIME_FAILED"));
		return false;
	}

	return true;
}

UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	UINT64 expires;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_UserExpiresSet_Prompt_EXPIRES"), CmdEvalDateTime, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	expires = StrToDateTime64(GetParamStr(o, "EXPIRES"));

	if (expires != 0)
	{
		expires = LocalToSystem64(expires);
	}

	t.ExpireTime = expires;

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_GROUP t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_GROUPLIST_NAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_REALNAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NOTE"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NUMUSERS"), false);

		for (i = 0;i < t.NumGroup;i++)
		{
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			RPC_ENUM_GROUP_ITEM *e = &t.Groups[i];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->NumUsers);

			CtInsert(ct, tmp1, e->Realname, e->Note, tmp2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScCreateGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScSetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDeleteGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_GroupJoin_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "USERNAME"));

	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "[name]"));

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupUnjoin_Prompt_name"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		StrCpy(t.GroupName, sizeof(t.GroupName), "");

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.Policy != NULL)
		{
			Free(t.Policy);
			t.Policy = NULL;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_SESSION t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_5"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), true);

		for (i = 0;i < t.NumSession;i++)
		{
			RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t *tmp2;
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];
			wchar_t tmp7[MAX_SIZE];
			wchar_t tmp8[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);

			tmp2 = _UU("SM_SESS_NORMAL");
			if (e->LinkMode)
			{
				tmp2 = _UU("SM_SESS_LINK");
			}

			StrToUni(tmp3, sizeof(tmp3), e->Username);

			StrToUni(tmp4, sizeof(tmp4), e->Hostname);
			if (e->LinkMode)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LINK_HOSTNAME"));
			}
			else if (e->BridgeMode)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_BRIDGE_HOSTNAME"));
			}

			UniFormat(tmp5, sizeof(tmp5), L"%u / %u", e->CurrentNumTcp, e->MaxNumTcp);
			if (e->LinkMode)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_LINK_TCP"));
			}
			else if (e->BridgeMode)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_BRIDGE_TCP"));
			}

			UniToStr3(tmp6, sizeof(tmp6), e->PacketSize);
			UniToStr3(tmp7, sizeof(tmp7), e->PacketNum);

			if (e->VLanId == 0)
			{
				UniStrCpy(tmp8, sizeof(tmp8), _UU("CM_ST_NO_VLAN"));
			}
			else
			{
				UniToStru(tmp8, e->VLanId);
			}

			CtInsert(ct, tmp1, tmp8, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7);
		}


		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumSession(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_SESSION t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDeleteSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_MAC_TABLE t;
	UINT i;

	PARAM args[] =
	{
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1A"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_4"), false);

		for (i = 0;i < t.NumMacTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];

			RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				MacToStr(str, sizeof(str), e->MacAddress);
				StrToUni(tmp2, sizeof(tmp2), str);

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				UniToStru(tmp6, e->VlanId);
				if (e->VlanId == 0)
				{
					UniStrCpy(tmp6, sizeof(tmp6), _UU("CM_ST_NONE"));
				}

				CtInsert(ct,
					tmp0, tmp1, tmp6, tmp2, tmp3, tmp4);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumMacTable(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScDeleteMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	PARAM args[] =
	{
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				IPToStr(str, sizeof(str), &e->IpV6);
				if (e->DhcpAllocated == false)
				{
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScDeleteIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));
				
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubAdminOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));

		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubExtOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CRL t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_CRL_COLUMN_1"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[64];
			RPC_ENUM_CRL_ITEM *e = &t.Items[i];

			UniToStru(tmp, e->Key);
			CtInsert(ct, tmp, e->CrlInfo);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	{
		{"SERIAL", NULL, NULL, NULL, NULL},
		{"MD5", NULL, NULL, NULL, NULL},
		{"SHA1", NULL, NULL, NULL, NULL},
		{"CN", NULL, NULL, NULL, NULL},
		{"O", NULL, NULL, NULL, NULL},
		{"OU", NULL, NULL, NULL, NULL},
		{"C", NULL, NULL, NULL, NULL},
		{"ST", NULL, NULL, NULL, NULL},
		{"L", NULL, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	{
		bool param_exists = false;
		CRL *crl = ZeroMalloc(sizeof(CRL));
		NAME *n;

		// Each option in its own field; NewName copies only the non-empty ones and FreeName frees them
		n = crl->Name = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"),
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		if (n->CommonName != NULL || n->Organization != NULL || n->Unit != NULL ||
			n->Country != NULL || n->State != NULL || n->Local != NULL)
		{
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "SERIAL")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SERIAL"));

			if (b != NULL && b->Size >= 1)
			{
				crl->Serial = NewXSerial(b->Buf, b->Size);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "MD5")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "MD5"));

			if (b != NULL && b->Size == MD5_SIZE)
			{
				Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "SHA1")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SHA1"));

			if (b != NULL && b->Size == SHA1_SIZE)
			{
				Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		t.Crl = crl;

		if (param_exists == false)
		{
			FreeRpcCrl(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	ret = ScAddCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CrlDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScDelCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CrlGet_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScGetCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		CRL *crl = t.Crl;
		NAME *n;

		if (crl != NULL)
		{
			n = crl->Name;

			if (n != NULL)
			{
				if (UniIsEmptyStr(n->CommonName) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_CN"), n->CommonName);
				}
				if (UniIsEmptyStr(n->Organization) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_O"), n->Organization);
				}
				if (UniIsEmptyStr(n->Unit) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_OU"), n->Unit);
				}
				if (UniIsEmptyStr(n->Country) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_C"), n->Country);
				}
				if (UniIsEmptyStr(n->State) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_ST"), n->State);
				}
				if (UniIsEmptyStr(n->Local) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_L"), n->Local);
				}
			}

			if (crl->Serial != NULL && crl->Serial->size >= 1)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SERI"), tmp);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_MD5_HASH"), tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SHA1_HASH"), tmp);
			}
		}
		CtFree(ct, c);
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct;

		ct = CtNew();
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_1"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_4"), false);

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			wchar_t tmp1[32], *tmp2, tmp3[MAX_SIZE], tmp4[32];
			char *tmp_str;
			AC *ac = LIST_DATA(t.o, i);

			UniToStru(tmp1, ac->Id);
			tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
			tmp_str = GenerateAcStr(ac);
			StrToUni(tmp3, sizeof(tmp3), tmp_str);

			Free(tmp_str);

			UniToStru(tmp4, ac->Priority);

			CtInsert(ct, tmp1, tmp4, tmp2, tmp3);
		}

		CtFree(ct, c);
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	RPC_TEST t;
	UINT ret;
	wchar_t tmp[MAX_SIZE];
	char sizestr[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	c->Write(c, _UU("CMD_Flush_Msg1"));

	Zero(&t, sizeof(t));

	ret = ScFlush(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ToStr3(sizestr, sizeof(sizestr), (UINT64)t.IntValue);
	UniFormat(tmp, sizeof(tmp), _UU("CMD_Flush_Msg2"), sizestr);
	c->Write(c, tmp);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	char *yes;
	PARAM args[] =
	{
		{"[yes]", CmdPrompt, _UU("CMD_Crash_Confirm"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	yes = GetParamStr(o, "[yes]");

	if (StrCmpi(yes, "yes") != 0)
	{
		c->Write(c, _UU("CMD_Crash_Aborted"));
	}
	else
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Crash_Msg"));

		Zero(&t, sizeof(t));

		ret = ScCrash(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_AcDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			AC *ac = LIST_DATA(t.o, i);

			if (ac->Id == GetParamInt(o, "[id]"))
			{
				Delete(t.o, ac);
				Free(ac);
				b = true;
				break;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			FreeRpcAcList(&t);
		}
		else
		{
			ret = ScSetAcList(ps->Rpc, &t);
		}
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);
	FreeParamValueList(o);

	return 0;
}

UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	PARAM args[] =
	{
		{"[CN]", CmdPrompt, _UU("CMD_ServerCertRegenerate_Prompt_CN"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[CN]"));

	ret = ScRegenerateServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	c->Write(c, L"");
	c->Write(c, _UU("CM_CERT_SET_MSG"));
	c->Write(c, L"");

	FreeParamValueList(o);

	return 0;
}

UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SET_PASSWORD t;
	char *pw;
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	pw = GetParamStr(o, "[password]");

	Zero(&t, sizeof(t));
	Sha0(t.HashedPassword, pw, StrLen(pw));

	ret = ScSetServerPassword(ps->Rpc, &t);

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
	char *s;
	if (c == NULL)
	{
		return NULL;
	}

	s = CmdPasswordPrompt(c);

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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDisable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = false;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerEnable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER_LIST t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_2"), false);

	for (i = 0;i < t.NumPort;i++)
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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDelete_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScDeleteListener(ps->Rpc, &t);

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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerInfo(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

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
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_STATUS t;
	wchar_t tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerStatus(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

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
	UINT i;
	if (c == NULL || str == NULL)
	{
		return false;
	}

	i = UniToInt(str);

	if (i >= 1 && i <= 65535)
	{
		return true;
	}

	c->Write(c, _UU("CMD_EVAL_PORT"));

	return false;
}

UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScCreateListener(ps->Rpc, &t);

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
	LIST *o;
	BUF *b;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	b = ReadDump("|legal.txt");

	CmdPrintAbout(c);
	c->Write(c, L"\r\n");

	if (b != NULL)
	{
		wchar_t *s;

		SeekBufToEnd(b);
		WriteBufChar(b, 13);
		WriteBufChar(b, 10);
		WriteBufChar(b, 0);

		s = CopyUtfToUni(b->Buf);

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
