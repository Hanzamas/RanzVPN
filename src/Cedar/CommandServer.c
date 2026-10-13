// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// CommandServer.c
// vpncmd server administration commands (Ps*) and the argument parsers and printers they use

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Database.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Mayaqua/Crypto/Key.h"

#include <stdlib.h>
#include "CommandInternal.h"

// Check the string of the form of the host name and port number
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param)
{
	char *tmp;
	bool ret = false;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	tmp = CopyUniToStr(str);

	ret = ParseHostPort(tmp, NULL, NULL, (UINT)param);

	if (ret == false)
	{
		c->Write(c, param == NULL ? _UU("CMD_HOSTPORT_EVAL_FAILED") : (wchar_t *)param);
	}

	Free(tmp);

	return ret;
}

// Get the SSL certificate of the VPN Server
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[cert]", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (XToFileW(t.Cert, GetParamUniStr(o, "[cert]"), true) == false)
	{
		c->Write(c, _UU("CMD_SAVECERT_FAILED"));
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the private key of the SSL certificate of the VPN Server
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[key]", CmdPrompt, _UU("CMD_SAVEKEYPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Key != NULL)
	{
		if (KToFileW(t.Key, GetParamUniStr(o, "[key]"), true, NULL) == false)
		{
			c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
		}
	}
	else
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
		CmdPrintError(c, ret);
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return ret;
}

// Read the certificate and the private key
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, wchar_t *cert_filename, wchar_t *key_filename)
{
	return CmdLoadCertChainAndKey(c, xx, kk, NULL, cert_filename, key_filename);
}

bool CmdLoadCertChainAndKey(CONSOLE *c, X **xx, K **kk, LIST **cc, wchar_t *cert_filename, wchar_t *key_filename)
{
	X *x = NULL;
	K *k;
	LIST *chain = NULL;
	// Validate arguments
	if (c == NULL || cert_filename == NULL || key_filename == NULL || xx == NULL || kk == NULL)
	{
		return false;
	}

	BUF *b = ReadDumpW(cert_filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return false;
	}

	// DER-encoded X509 files can't hold multiple certificates
	if (cc == NULL || IsBase64(b) == false)
	{
		x = BufToX(b, IsBase64(b));
	}
	else
	{
		chain = BufToXList(b, true);
		if (LIST_NUM(chain) > 0)
		{
			x = LIST_DATA(chain, 0);
			Delete(chain, x);

			if (LIST_NUM(chain) == 0)
			{
				ReleaseList(chain);
				chain = NULL;
			}
		}
	}
	FreeBuf(b);
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		FreeXList(chain);
		return false;
	}

	k = CmdLoadKey(c, key_filename);
	if (k == NULL)
	{
		c->Write(c, _UU("CMD_LOADKEY_FAILED"));
		FreeX(x);
		FreeXList(chain);
		return false;
	}

	if (CheckXandK(x, k) == false)
	{
		c->Write(c, _UU("CMD_KEYPAIR_FAILED"));
		FreeX(x);
		FreeK(k);
		FreeXList(chain);

		return false;
	}

	*xx = x;
	*kk = k;
	if (cc != NULL)
	{
		*cc = chain;
	}

	return true;
}

// Read the secret key
K *CmdLoadKey(CONSOLE *c, wchar_t *filename)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return NULL;
	}
	else
	{
		K *key;
		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_1"));

			while (true)
			{
				char *pass = c->ReadPassword(c, _UU("CMD_LOADKEY_ENCRYPTED_2"));

				if (pass == NULL)
				{
					FreeBuf(b);
					return NULL;
				}

				key = BufToK(b, true, IsBase64(b), pass);
				Free(pass);

				if (key != NULL)
				{
					break;
				}

				c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_3"));
			}
		}

		FreeBuf(b);

		return key;
	}
}

// Set the SSL certificate and the private key of the VPN Server
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (CmdLoadCertChainAndKey(c, &t.Cert, &t.Key, &t.Chain,
		GetParamUniStr(o, "LOADCERT"),
		GetParamUniStr(o, "LOADKEY")))
	{
		// RPC call
		ret = ScSetServerCert(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		if (t.Flag1 == 0)
		{
			// Show the warning message
			c->Write(c, L"");
			c->Write(c, _UU("SM_CERT_NEED_ROOT"));
			c->Write(c, L"");
		}

		FreeRpcKeyPair(&t);
	}
	else
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// Get the encryption algorithm used for the VPN communication
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	TOKEN_LIST *ciphers;
	UINT i;
	wchar_t tmp[4096];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UniFormat(tmp, sizeof(tmp), L" %S", t.String);
	FreeRpcStr(&t);
	Zero(&t, sizeof(RPC_STR));

	c->Write(c, _UU("CMD_ServerCipherGet_SERVER"));
	c->Write(c, tmp);

	ret = ScGetServerCipherList(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		ciphers = ParseToken(t.String, ";");

		FreeRpcStr(&t);

		c->Write(c, L"");
		c->Write(c, _UU("CMD_ServerCipherGet_CIPHERS"));

		for (i = 0; i < ciphers->NumTokens; i++)
		{
			UniFormat(tmp, sizeof(tmp), L" %S", ciphers->Token[i]);
			c->Write(c, tmp);
		}

		FreeToken(ciphers);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the encryption algorithm used for the VPN communication
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ServerCipherSet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.String = CopyStr(GetParamStr(o, "[name]"));

	// RPC call
	ret = ScSetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcStr(&t);

	FreeParamValueList(o);

	return 0;
}

// Enable the syslog configuration
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;
	CMD_EVAL_MIN_MAX minmax = {"CMD_SyslogEnable_MINMAX", 1, 3};
	char *host;
	UINT port;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[1|2|3]", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_123"), CmdEvalMinMax, &minmax},
		{"HOST", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_HOST"), CmdEvalHostAndPort, (void *)SYSLOG_PORT},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, SYSLOG_PORT))
	{
		StrCpy(t.Hostname, sizeof(t.Hostname), host);
		t.Port = port;
		t.SaveType = GetParamInt(o, "[1|2|3]");

		Free(host);

		// RPC call
		ret = ScSetSysLog(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the syslog configuration
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.SaveType = SYSLOG_NONE;

	// RPC call
	ret = ScSetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the syslog configuration
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_1"), GetSyslogSettingName(t.SaveType));

		if (t.SaveType != SYSLOG_NONE)
		{
			StrToUni(tmp, sizeof(tmp), t.Hostname);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_2"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_3"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the syslog configuration name
wchar_t *GetSyslogSettingName(UINT n)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), "SM_SYSLOG_%u", n);

	return _UU(tmp);
}

// Get the connection type string
wchar_t *GetConnectionTypeStr(UINT type)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_CONNECTION_TYPE_%u", type);

	return _UU(tmp);
}

// Get the list of TCP connections connected to VPN Server
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CONNECTION t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_4"), false);

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		CtInsert(ct, name, tmp, datetime,
			GetConnectionTypeStr(e->Type));
	}

	CtFree(ct, c);

	FreeRpcEnumConnection(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the TCP connection information currently connected to the VPN Server
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONNECTION_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetConnectionInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("SM_CONNINFO_NAME"), tmp);

		CtInsert(ct, _UU("SM_CONNINFO_TYPE"), GetConnectionTypeStr(t.Type));

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_CONNINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Port);
		CtInsert(ct, _UU("SM_CONNINFO_PORT"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_CONNINFO_TIME"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ServerStr);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_VER"), tmp);

		UniToStru(tmp, t.ServerBuild);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

		if (StrLen(t.ClientStr) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientStr);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

			UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

			UniToStru(tmp, t.ClientBuild);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Disconnect the TCP connection connected to the VPN Server
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DISCONNECT_CONNECTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionDisconnect_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDisconnectConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the LAN card list that can be used for local bridge
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ETH t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumEthernet(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *item = &t.Items[i];
		wchar_t tmp[MAX_SIZE * 2];

		StrToUni(tmp, sizeof(tmp), item->DeviceName);
		c->Write(c, tmp);
	}

	FreeRpcEnumEth(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the list of local bridge connection
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_4"), false);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];
		wchar_t name[MAX_SIZE];
		wchar_t nic[MAX_SIZE];
		wchar_t hub[MAX_SIZE];
		wchar_t *status = _UU("SM_BRIDGE_OFFLINE");

		UniToStru(name, i + 1);
		StrToUni(nic, sizeof(nic), e->DeviceName);
		StrToUni(hub, sizeof(hub), e->HubName);

		if (e->Online)
		{
			status = e->Active ? _UU("SM_BRIDGE_ONLINE") : _UU("SM_BRIDGE_ERROR");
		}

		CtInsert(ct, name, hub, nic, status);
	}

	CtFree(ct, c);

	FreeRpcEnumLocalBridge(&t);

	FreeParamValueList(o);

	return 0;
}

// Create a local bridge connection
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
		{"TAP", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Active = true;
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));
	t.Online = true;
	t.TapMode = GetParamYes(o, "TAP");

	// RPC call
	ret = ScAddLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		c->Write(c, _UU("SM_BRIDGE_INTEL"));
		c->Write(c, L"");

		if (GetCapsBool(ps->CapsList, "b_is_in_vm"))
		{
			// Message in the case of operating in a VM
			c->Write(c, _UU("D_SM_VMBRIDGE@CAPTION"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_1"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_2"));
			c->Write(c, L"");
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the local bridge connection
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));

	// RPC call
	ret = ScDeleteLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of features and capabilities of the server
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	CAPSLIST *t;
	UINT i;
	CT *ct;


	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	t = ScGetCapsEx(ps->Rpc);

	ct = CtNewStandard();

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);
		wchar_t title[MAX_SIZE];
		char name[256];

		Format(name, sizeof(name), "CT_%s", c->Name);

		UniStrCpy(title, sizeof(title), _UU(name));

		if (UniIsEmptyStr(title))
		{
			UniFormat(title, sizeof(title), L"%S", (StrLen(c->Name) >= 2) ? c->Name + 2 : c->Name);
		}

		if (StartWith(c->Name, "b_"))
		{
			CtInsert(ct, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
		}
		else
		{
			wchar_t str[64];
			UniToStru(str, c->Value);
			CtInsert(ct, title, str);
		}
	}

	CtFree(ct, c);

	FreeCapsList(t);

	FreeParamValueList(o);

	return 0;
}

// Restart the VPN Server service
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"RESETCONFIG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.IntValue = GetParamYes(o, "RESETCONFIG") ? 1 : 0;

	// RPC call
	ret = ScRebootServer(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcTest(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the current configuration of the VPN Server
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetConfig(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t *filename = GetParamUniStr(o, "[path]");

		if (IsEmptyUniStr(filename))
		{
			// Display on the screen
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *buf;
			UNI_TOKEN_LIST *lines;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_ConfigGet_FILENAME"), t.FileName,
				StrLen(t.FileData));
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)t.FileData, StrLen(t.FileData));
			buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(buf, buf_size, (BYTE *)t.FileData, StrLen(t.FileData));

			lines = UniGetLines(buf);
			if (lines != NULL)
			{
				UINT i;

				for (i = 0;i < lines->NumTokens;i++)
				{
					c->Write(c, lines->Token[i]);
				}

				UniFreeToken(lines);
			}

			c->Write(c, L"");

			Free(buf);
		}
		else
		{
			// Save to the file
			IO *io = FileCreateW(filename);

			if (io == NULL)
			{
				c->Write(c, _UU("CMD_ConfigGet_FILE_SAVE_FAILED"));

				ret = ERR_INTERNAL_ERROR;
			}
			else
			{
				FileWrite(io, t.FileData, StrLen(t.FileData));
				FileClose(io);
			}
		}
	}

	FreeRpcConfig(&t);

	FreeParamValueList(o);

	return ret;
}

// Write the configuration to the VPN Server
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	wchar_t *filename;
	BUF *buf;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_ConfigSet_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamUniStr(o, "[path]");

	buf = ReadDumpW(filename);
	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_ConfigSet_FILE_LOAD_FAILED"));
	}
	else
	{
		Zero(&t, sizeof(t));

		t.FileData = ZeroMalloc(buf->Size + 1);
		Copy(t.FileData, buf->Buf, buf->Size);
		FreeBuf(buf);

		// RPC call
		ret = ScSetConfig(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcConfig(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Evaluate the IP address and mask
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1"));
		return false;
	}

	return true;
}

bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	IP ip, mask;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask6(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1_6"));
		return false;
	}

	return true;
}

// Get the log files list
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOG_FILE t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	c->Write(c, _UU("CMD_LogFileList_START"));
	c->Write(c, L"");

	// RPC call
	ret = ScEnumLogFile(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileList_NUM_LOGS"), t.NumItem);
		c->Write(c, tmp);

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_3"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_LOG_FILE_ITEM *e = &t.Items[i];
			wchar_t tmp1[MAX_PATH], tmp2[128], tmp3[128];
			char tmp[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->FilePath);

			ToStrByte(tmp, sizeof(tmp), e->FileSize);
			StrToUni(tmp2, sizeof(tmp2), tmp);

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->UpdatedTime));

			CtInsert(ct, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLogFile(&t);

	FreeParamValueList(o);

	return 0;
}

// Download a log file
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	BUF *buf;
	char *filename = NULL;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_LogFileGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVEPATH", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamStr(o, "SAVE");
	if (IsEmptyStr(filename))
	{
		filename = GetParamStr(o, "SAVEPATH");
	}

	c->Write(c, _UU("CMD_LogFileGet_START"));

	buf = DownloadFileFromServer(ps->Rpc,
		GetParamStr(o, "[name]"), 0, NULL, NULL);

	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_LogFileGet_FAILED"));

		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		if (IsEmptyStr(filename) == false)
		{
			// Save to the file
			if (DumpBuf(buf, filename) == false)
			{
				ret = ERR_INTERNAL_ERROR;
				c->Write(c, _UU("CMD_LogFileGet_SAVE_FAILED"));
			}
		}
		else
		{
			// Display on the screen
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *uni_buf;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileGet_FILESIZE"),
				buf->Size);
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)buf->Buf, buf->Size);
			uni_buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(uni_buf, buf_size, (BYTE *)buf->Buf, buf->Size);

			c->Write(c, uni_buf);
			c->Write(c, L"");

			Free(uni_buf);
		}

		FreeBuf(buf);
	}

	FreeParamValueList(o);

	return ret;
}

// Create a New Virtual HUB
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Sha0(t.HashedPassword, pass, StrLen(pass));
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC call
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete a Virtual HUB
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDeleteHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of Virtual HUB
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_HUB t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_9"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_10"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_11"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t name[MAX_HUBNAME_LEN + 1];
			wchar_t s1[64], s2[64], s3[64], s4[64], s5[64];
			wchar_t s6[64], s7[128], s8[128];
			wchar_t s9[64], s10[64];

			UniToStru(s1, e->NumUsers);
			UniToStru(s2, e->NumGroups);
			UniToStru(s3, e->NumSessions);
			UniToStru(s4, e->NumMacTables);
			UniToStru(s5, e->NumIpTables);

			UniToStru(s6, e->NumLogin);

			if (e->LastLoginTime != 0)
			{
				GetDateTimeStr64Uni(s7, sizeof(s7), SystemToLocal64(e->LastLoginTime));
			}
			else
			{
				UniStrCpy(s7, sizeof(s7), _UU("COMMON_UNKNOWN"));
			}

			if (e->LastCommTime != 0)
			{
				GetDateTimeStr64Uni(s8, sizeof(s8), SystemToLocal64(e->LastCommTime));
			}
			else
			{
				UniStrCpy(s8, sizeof(s8), _UU("COMMON_UNKNOWN"));
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(s9, sizeof(s9), _UU("CM_ST_NONE"));
				UniStrCpy(s10, sizeof(s10), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(s9, sizeof(s9),
					e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

				UniToStr3(s10, sizeof(s10),
					e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
					e->Traffic.Send.BroadcastCount + e->Traffic.Send.UnicastCount);
			}

			StrToUni(name, sizeof(name), e->HubName);

			CtInsert(ct,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				s1, s2, s3, s4, s5, s6, s7, s8, s9, s10);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumHub(&t);

	FreeParamValueList(o);

	return 0;
}

// Select a Virtual HUB to manage
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "[name]")) == false)
	{
		wchar_t tmp[MAX_SIZE];
		Zero(&t, sizeof(t));

		// Examine whether the specified Virtual HUB is accessible
		StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

		// RPC call
		ret = ScGetHubStatus(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		// Change the selection
		if (ps->HubName != NULL)
		{
			Free(ps->HubName);
		}
		ps->HubName = CopyStr(t.HubName);

		UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);
		c->Write(c, tmp);
	}
	else
	{
		// Deselect
		if (ps->HubName != NULL)
		{
			c->Write(c, _UU("CMD_Hub_Unselected"));
			Free(ps->HubName);
		}
		ps->HubName = NULL;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to online
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// If virtual HUB is not selected, it's an error
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
	t.Online = true;

	// RPC call
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to offline
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// If virtual HUB is not selected, it's an error
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
	t.Online = false;

	// RPC call
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the maximum number of concurrent connecting sessions of the Virtual HUB
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[max_session]", CmdPrompt, _UU("CMD_SetMaxSession_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.MaxSession = GetParamInt(o, "[max_session]");

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the administrative password of the Virtual HUB
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pw;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Change the settings
	pw = GetParamStr(o, "[password]");
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pw);
	Sha0(t.HashedPassword, pw, StrLen(pw));

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to permit to be enumerated for anonymous users
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
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

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = false;

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to deny to be enumerated for anonymous users
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
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

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = true;

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the option settings for the virtual HUB
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), _UU("CMD_OptionsGet_TITLE"), ps->HubName);
		c->Write(c, tmp);

		// Display settings
		ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_OptionsGet_ENUM"),
			t.HubOption.NoEnum ? _UU("CMD_MSG_DENY") : _UU("CMD_MSG_ALLOW"));

		if (t.HubOption.MaxSession == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		else
		{
			UniToStru(tmp, t.HubOption.MaxSession);
		}
		CtInsert(ct, _UU("CMD_OptionsGet_MAXSESSIONS"), tmp);

		CtInsert(ct, _UU("CMD_OptionsGet_STATUS"), t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the current status of the Virtual HUB
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];

		// HUB name
		s = CopyStrToUni(t.HubName);
		CtInsert(ct, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		// Online
		CtInsert(ct, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		// Other values
		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS"), tmp);

		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		CtInsert(ct, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		UniToStru(tmp, t.NumUsers);
		CtInsert(ct, _UU("SM_HUB_NUM_USERS"), tmp);
		UniToStru(tmp, t.NumGroups);
		CtInsert(ct, _UU("SM_HUB_NUM_GROUPS"), tmp);

		UniToStru(tmp, t.NumMacTables);
		CtInsert(ct, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		CtInsert(ct, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		// Usage status
		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_CREATED_TIME"), tmp);

		// Traffic information
		CmdInsertTrafficInfo(ct, &t.Traffic);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the log switching string
wchar_t *GetLogSwitchStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "SM_LOG_SWITCH_%u", i);

	return _UU(tmp);
}

// Get the packet log name string
wchar_t *GetPacketLogNameStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "CMD_Log_%u", i);

	return _UU(tmp);
}

// Get the log storage settings for the virtual HUB
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_Log_SecurityLog"),
			t.LogSetting.SaveSecurityLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SaveSecurityLog)
		{
			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.SecurityLogSwitchType));
		}

		CtInsert(ct, L"", L"");

		CtInsert(ct, _UU("CMD_Log_PacketLog"),
			t.LogSetting.SavePacketLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SavePacketLog)
		{
			UINT i;

			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.PacketLogSwitchType));

			for (i = 0;i <= 7;i++)
			{
				wchar_t *tmp = NULL;

				switch (t.LogSetting.PacketLogConfig[i])
				{
				case PACKET_LOG_NONE:
					tmp = _UU("D_SM_LOG@B_PACKET_0_0");
					break;

				case PACKET_LOG_HEADER:
					tmp = _UU("D_SM_LOG@B_PACKET_0_1");
					break;

				case PACKET_LOG_ALL:
					tmp = _UU("D_SM_LOG@B_PACKET_0_2");
					break;
				}

				CtInsert(ct, GetPacketLogNameStr(i),
					tmp);
			}
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// LogEnable command
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ret;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = true;
	}
	else
	{
		t.LogSetting.SavePacketLog = true;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the packet log or the security log
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = false;
	}
	else
	{
		t.LogSetting.SavePacketLog = false;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the string to log switching type
UINT StrToLogSwitchType(char *str)
{
	UINT ret = INFINITE;
	// Validate arguments
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StartWith("none", str))
	{
		ret = LOG_SWITCH_NO;
	}
	else if (StartWith("second", str))
	{
		ret = LOG_SWITCH_SECOND;
	}
	else if (StartWith("minute", str))
	{
		ret = LOG_SWITCH_MINUTE;
	}
	else if (StartWith("hour", str))
	{
		ret = LOG_SWITCH_HOUR;
	}
	else if (StartWith("day", str))
	{
		ret = LOG_SWITCH_DAY;
	}
	else if (StartWith("month", str))
	{
		ret = LOG_SWITCH_MONTH;
	}

	return ret;
}

// Set the switching period of the log file
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	UINT new_switch_type = 0;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
		{"SWITCH", CmdPrompt, _UU("CMD_LogSwitchSet_Prompt"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}
	
	new_switch_type = StrToLogSwitchType(GetParamStr(o, "SWITCH"));

	if (new_switch_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SecurityLogSwitchType = new_switch_type;
	}
	else
	{
		t.LogSetting.PacketLogSwitchType = new_switch_type;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the type string of the packet log contents to an integer
UINT StrToPacketLogSaveInfoType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (StartWith("none", str) || IsEmptyStr(str))
	{
		ret = PACKET_LOG_NONE;
	}
	else if (StartWith("header", str))
	{
		ret = PACKET_LOG_HEADER;
	}
	else if (StartWith("full", str) || StartWith("all", str))
	{
		ret = PACKET_LOG_ALL;
	}

	return ret;
}

// Convert a packet type string of the packet log to an integer
UINT StrToPacketLogType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL || IsEmptyStr(str))
	{
		return INFINITE;
	}

	if (StartWith("tcpconn", str))
	{
		ret = PACKET_LOG_TCP_CONN;
	}
	else if (StartWith("tcpdata", str))
	{
		ret = PACKET_LOG_TCP;
	}
	else if (StartWith("dhcp", str))
	{
		ret = PACKET_LOG_DHCP;
	}
	else if (StartWith("udp", str))
	{
		ret = PACKET_LOG_UDP;
	}
	else if (StartWith("icmp", str))
	{
		ret = PACKET_LOG_ICMP;
	}
	else if (StartWith("ip", str))
	{
		ret = PACKET_LOG_IP;
	}
	else if (StartWith("arp", str))
	{
		ret = PACKET_LOG_ARP;
	}
	else if (StartWith("ethernet", str))
	{
		ret = PACKET_LOG_ETHERNET;
	}

	return ret;
}

// Set the detail level and type of packet to be stored in the packet log
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	UINT packet_type = INFINITE;
	UINT packet_save_info_type = INFINITE;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"TYPE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_TYPE"), NULL, NULL},
		{"SAVE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_SAVE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	
	packet_type = StrToPacketLogType(GetParamStr(o, "TYPE"));
	packet_save_info_type = StrToPacketLogSaveInfoType(GetParamStr(o, "SAVE"));

	if (packet_type == INFINITE || packet_save_info_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.LogSetting.PacketLogConfig[packet_type] = packet_save_info_type;

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of certificates of the trusted certification authority
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ENUM_CA t;
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumCa;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumCa - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);
	}

	FreeRpcHubEnumCa(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a certificate to the trusted certification authority
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ADD_CA t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	x = FileToXW(GetParamUniStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Cert = x;

	// RPC call
	ret = ScAddCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcHubAddCa(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the certificate of the trusted certification authority
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_DELETE_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the certificate of the trusted certification authority
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_GET_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (XToFileW(t.Cert, GetParamUniStr(o, "SAVECERT"), true))
		{
			// Success
		}
		else
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}
	}

	FreeRpcHubGetCa(&t);

	FreeParamValueList(o);

	return ret;
}

// Get the cascade connection list
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LINK t;
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_5"), false);

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];

			GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
			StrToUni(tmp2, sizeof(tmp2), e->Hostname);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			if (e->Online == false)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_OFFLINE"));
			}
			else
			{
				if (e->Connected)
				{
					UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ONLINE"));
				}
				else
				{
					if (e->LastError != 0)
					{
						UniFormat(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ERROR"), e->LastError, _E(e->LastError));
					}
					else
					{
						UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_CONNECTING"));
					}
				}
			}

			CtInsert(ct, e->AccountName, tmp4, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Creat a new cascade
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.Online = false;

	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 15;
	t.ClientOption->MaxConnection = 8;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	t.ClientOption->RequireBridgeRoutingMode = true;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	// RPC call
	ret = ScCreateLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the user name and destination of the cascade connection
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		Free(host);
		return ret;
	}

	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

	Free(host);

	// RPC call
	ret = ScSetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the type string of proxy
wchar_t *GetProxyTypeStr(UINT i)
{
	switch (i)
	{
	case PROXY_DIRECT:

		return _UU("PROTO_DIRECT_TCP");

	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");

	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");

	default:
		return _UU("PROTO_UNKNOWN");
	}
}

// Get type string in user authentication for client
wchar_t *GetClientAuthTypeStr(UINT i)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "PW_TYPE_%u", i);

	return _UU(tmp);
}

// Get the setting of cascade connection
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
		GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Show the contents of the connection settings
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		// Connection settings name
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		// Host name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		// The port number to connect to VPN Server
		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		// Virtual HUB name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		// Type of proxy server to go through
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			// Host name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			// Port number of the proxy server
			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			// User name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		// To verify the server certificate
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Registered specific certificate
		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		if (t.CheckServerCert)
		{
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ADD_DEFAULT_CA"),
				t.AddDefaultCA ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		}

		// Device name to be used for the connection
		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		// Authentication type
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		// User name
		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				// Client certificate name
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		// Number of TCP connections to be used for VPN communication
		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		// Establishment interval of each TCP connection
		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		// Life span of each TCP connection
		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		// Use of half-duplex mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Encryption by SSL
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Data compression
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in bridge / router mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in monitoring mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Not to rewrite the routing table
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Disable the QoS control
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);

		// Security policy
		c->Write(c, L"");
		c->Write(c, _UU("CMD_CascadeGet_Policy"));
		PrintPolicy(c, &t.Policy, true);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the cascade connection
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScDeleteLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the user name to use for the cascade connection
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username),
			GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_CascadeUsername_Notice"));
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

//Set the type of user authentication of cascade connection to the anonymous authentication
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the type of user authentication of cascade connection to the password authentication
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		char *typestr = GetParamStr(o, "TYPE");

		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			// An error has occured
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			FreeRpcCreateLink(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the type of user authentication of cascade connection to the client certificate authentication
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	K *k;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	if (CmdLoadCertAndKey(c, &x, &k, GetParamUniStr(o, "LOADCERT"), GetParamUniStr(o, "LOADKEY")) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		FreeX(x);
		FreeK(k);
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change authentication data
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = x;
		t.ClientAuth->ClientK = k;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the client certificate to be used in the cascade connection
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			XToFileW(t.ClientAuth->ClientX, GetParamUniStr(o, "SAVECERT"), true);
		}
		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Enable encryption of communication at the time of the cascade connection
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseEncrypt = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable encryption of communication at the time of the cascade connection
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseEncrypt = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable data compression at the time of communication of the cascade connection
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseCompress = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable data compression at the time of communication of the cascade connection
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseCompress = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"DATA", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Data"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		HTTP_HEADER *header = NULL;
		char *name = GetParamStr(o, "NAME");

		Trim(name);

		header = NewHttpHeader("", "", "");

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");
		for (i = 0; i < tokens->NumTokens; i++)
		{
			AddHttpValueStr(header, tokens->Token[i]);
		}
		FreeToken(tokens);

		if (GetHttpValue(header, name) == NULL)
		{
			char s[HTTP_CUSTOM_HEADER_MAX_SIZE];
			Format(s, sizeof(s), "%s: %s\r\n", name, GetParamStr(o, "DATA"));
			EnSafeHttpHeaderValueStr(s, ' ');

			if ((StrLen(s) + StrLen(t.ClientOption->CustomHttpHeader)) < sizeof(t.ClientOption->CustomHttpHeader)) {
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(s), s);
				ret = ScSetLink(ps->Rpc, &t);
			}
			else
			{
				// Error has occurred
				ret = ERR_TOO_MANT_ITEMS;
			}
		}
		else
		{
			// Error has occurred
			ret = ERR_OBJECT_EXISTS;
		}

		FreeHttpHeader(header);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PsCascadeHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		char *value = GetParamStr(o, "NAME");

		Zero(t.ClientOption->CustomHttpHeader, sizeof(t.ClientOption->CustomHttpHeader));

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			if (StartWith(tokens->Token[i], value) == false)
			{
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(t.ClientOption->CustomHttpHeader), tokens->Token[i]);
				StrCat(t.ClientOption->CustomHttpHeader, 1, "\r\n");
			}
		}

		ret = ScSetLink(ps->Rpc, &t);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PsCascadeHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	// Release of the parameter list
	FreeParamValueList(o);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t unistr[HTTP_CUSTOM_HEADER_MAX_SIZE];
		TOKEN_LIST *tokens = NULL;
		UINT i = 0;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			StrToUni(unistr, sizeof(unistr), tokens->Token[i]);
			CtInsert(ct, unistr);
		}

		CtFreeEx(ct, c, false);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	return ret;
}

// Set the cascade connection method to the TCP/IP direct connection mode
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->ProxyType = PROXY_DIRECT;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via HTTP proxy server
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_HTTP;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via SOCKS4 proxy server
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via SOCKS5 proxy server
UINT PsCascadeProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS5;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the validation options for the server certificate of cascade connection
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.CheckServerCert = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the validation options for the server certificate of cascade connection
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.CheckServerCert = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable trusting default CA list for cascade connection
UINT PsCascadeDefaultCAEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.AddDefaultCA = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable trusting default CA list for cascade connection
UINT PsCascadeDefaultCADisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.AddDefaultCA = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Server-specific certificate settings of cascade connection
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}
	else
	{
		// Data change
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = x;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the server-specific certificate of cascade connection
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the server-specific certificate of cascade connection
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Save the certificate
		if (t.ServerCert == NULL)
		{
			c->Write(c, _UU("CMD_CERT_NOT_EXISTS"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			if (XToFileW(t.ServerCert, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
				ret = ERR_INTERNAL_ERROR;
			}
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Set the advanced settings of the cascade connection
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_HALF"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Show a security policy
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode)
{
	UINT i;
	CT *ct;
	PACK *p;
	// Validate arguments
	if (c == NULL || pol == NULL)
	{
		return;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_3"), false);

	p = NewPack();
	OutRpcPolicy(p, pol);

	// Show the list of all policies
	for (i = 0; i < PolicyNum();i++)
	{
		char name[64];
		wchar_t *tmp;

		if (cascade_mode == false || PolicyIsSupportedForCascade(i))
		{
			wchar_t value_str[256];
			UINT value;
			char tmp2[256];

			Format(tmp2, sizeof(tmp2), "policy:%s", PolicyIdToStr(i));
			value = PackGetInt(p, tmp2);

			tmp = CopyStrToUni(PolicyIdToStr(i));

			FormatPolicyValue(value_str, sizeof(value_str),
				i, value);

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name), value_str);

			Free(tmp);
		}
	}

	FreePack(p);

	CtFree(ct, c);
}

// Show the security policy list
void PrintPolicyList(CONSOLE *c, char *name)
{
	UINT id;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (IsEmptyStr(name))
	{
		name = NULL;
	}

	if (name != NULL)
	{
		id = PolicyStrToId(name);
		if (id == INFINITE)
		{
			// Invalid ID
			c->Write(c, _UU("CMD_PolicyList_Invalid_Name"));
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			char name1[64], name2[64];
			wchar_t *title, *descript;
			wchar_t policy_name[MAX_SIZE];

			Format(name1, sizeof(name1), "POL_%u", id);
			Format(name2, sizeof(name2), "POL_EX_%u", id);

			title = _UU(name1);
			descript = _UU(name2);

			StrToUni(policy_name, sizeof(policy_name), PolicyIdToStr(id));

			// Policy name
			c->Write(c, _UU("CMD_PolicyList_Help_1"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", policy_name);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Simple description of the policy
			c->Write(c, _UU("CMD_PolicyList_Help_2"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", title);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Range of the value that can be set
			GetPolicyValueRangeStr(tmp, sizeof(tmp), id);
			c->Write(c, _UU("CMD_PolicyList_Help_3"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Default value
			FormatPolicyValue(tmp, sizeof(tmp), id, GetPolicyItem(id)->DefaultValue);
			c->Write(c, _UU("CMD_PolicyList_Help_4"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Detailed description of the policy
			c->Write(c, _UU("CMD_PolicyList_Help_5"));
			c->Write(c, descript);
			c->Write(c, L"");
		}
	}
	else
	{
		UINT i;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);

		// Show the list of all policies
		for (i = 0; i < PolicyNum();i++)
		{
			char name[64];
			wchar_t *tmp;

			tmp = CopyStrToUni(PolicyIdToStr(i));

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name));

			Free(tmp);
		}

		CtFree(ct, c);
	}
}

// Editing the contents of the policy
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode)
{
	PACK *p;
	ELEMENT *e;
	POLICY_ITEM *item;
	UINT id;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char pack_name[128];
	// Validate arguments
	if (c == NULL || pol == NULL || name == NULL || value == NULL)
	{
		return false;
	}

	p = NewPack();

	OutRpcPolicy(p, pol);

	Format(pack_name, sizeof(pack_name), "policy:%s", PolicyIdToStr(PolicyStrToId(name)));

	if ((e = GetElement(p, pack_name, VALUE_INT)) == NULL || (id = PolicyStrToId(name)) == INFINITE)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	if (cascade_mode && (PolicyIsSupportedForCascade(id) == false))
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name_For_Cascade"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	item = GetPolicyItem(id);

	if (item->TypeInt == false)
	{
		// bool type
		e->values[0]->IntValue = (
			StartWith(value, "y") || StartWith(value, "t") ||
			ToInt(value) != 0) ? 1 : 0;
	}
	else
	{
		UINT n = ToInt(value);
		bool b = true;

		// int type
		GetPolicyValueRangeStr(tmp, sizeof(tmp), id);

		if (item->AllowZero == false)
		{
			if (n == 0)
			{
				b = false;
			}
		}

		if (n != 0 && (n < item->MinValue || n > item->MaxValue))
		{
			b = false;
		}

		if (b == false)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("CMD_CascadePolicySet_Invalid_Range"), PolicyIdToStr(id), tmp);
			c->Write(c, tmp2);
			FreePack(p);
			return false;
		}

		e->values[0]->IntValue = n;
	}

	Zero(pol, sizeof(POLICY));

	InRpcPolicy(pol, p);

	FreePack(p);

	return true;
}

// Show the list of the type of security policy and possible values
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	PrintPolicyList(c, GetParamStr(o, "[name]"));

	FreeParamValueList(o);

	return ERR_NO_ERROR;
}

// Set the security policy of the cascade session
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (EditPolicy(c, &t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), true) == false)
		{
			// An error has occured
			FreeRpcCreateLink(&t);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Display the status information of the session
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s)
{
	CmdPrintStatusToListViewEx(ct, s, false);
}

void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	char vv[128];
	// Validate arguments
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
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->FirstConnectionEstablisiedTime), NULL);
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
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

// Get the current state of the cascade connection
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetLinkStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Get the cascade connection state
		CT *ct = CtNewStandard();

		CmdPrintStatusToListView(ct, &t.Status);

		CtFree(ct, c);

		FreeRpcLinkStatus(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Rename the cascade connection
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RENAME_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScRenameLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection to on-line state
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScSetLinkOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection to the off-line state
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScSetLinkOffline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the string to pass / discard flag
bool StrToPassOrDiscard(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (ToInt(str) != 0)
	{
		return true;
	}

	if (StartWith(str, "p") || StartWith(str, "y") || StartWith(str, "t"))
	{
		return true;
	}

	return false;
}

// Convert the string to the protocol
UINT StrToProtocol(char *str)
{
	if (IsEmptyStr(str))
	{
		return 0;
	}

	if (StartWith("ip", str))
	{
		return 0;
	}
	else if (StartWith("tcp", str))
	{
		return IP_PROTO_TCP;
	}
	else if (StartWith("udp", str))
	{
		return IP_PROTO_UDP;
	}
	else if (StartWith("icmpv4", str))
	{
		return IP_PROTO_ICMPV4;
	}
	else if (StartWith("icmpv6", str))
	{
		return IP_PROTO_ICMPV6;
	}

	if (ToInt(str) == 0)
	{
		if (StrCmpi(str, "0") == 0)
		{
			return 0;
		}
		else
		{
			return INFINITE;
		}
	}

	if (ToInt(str) >= 256)
	{
		return INFINITE;
	}

	return ToInt(str);
}

// Check the protocol name
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (StrToProtocol(tmp) == INFINITE)
	{
		c->Write(c, _UU("CMD_PROTOCOL_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Parse the port range
bool ParsePortRange(char *str, UINT *start, UINT *end)
{
	UINT a = 0, b = 0;
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (IsEmptyStr(str) == false)
	{

		t = ParseToken(str, "\t -");

		if (t->NumTokens == 1)
		{
			a = b = ToInt(t->Token[0]);
		}
		else if (t->NumTokens == 2)
		{
			a = ToInt(t->Token[0]);
			b = ToInt(t->Token[1]);
		}

		FreeToken(t);

		if (a > b)
		{
			return false;
		}

		if (a >= 65536 || b >= 65536)
		{
			return false;
		}

		if (a == 0 && b != 0)
		{
			return false;
		}
	}

	if (start != NULL)
	{
		*start = a;
	}
	if (end != NULL)
	{
		*end = b;
	}

	return true;
}

// Check the port range
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParsePortRange(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_PORT_RANGE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Parse the MAC address and the mask
bool ParseMacAddressAndMask(char *src, bool *check_mac, UCHAR *mac_bin, UCHAR *mask_bin)
{
	TOKEN_LIST *t;
	char *macstr, *maskstr;
	UCHAR mac[6], mask[6];
	bool ok = false;

	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	//Zero(mac, sizeof(mac));
	//Zero(mask, sizeof(mask));

	if(check_mac != NULL && mac_bin != NULL && mask_bin != NULL)
	{
		ok = true;
	}
	if(IsEmptyStr(src) != false)
	{
		if(ok != false)
		{
			*check_mac = false;
			Zero(mac_bin, 6);
			Zero(mask_bin, 6);
		}
		return true;
	}

	t = ParseToken(src, "/");
	if(t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	macstr = t->Token[0];
	maskstr = t->Token[1];

	Trim(macstr);
	Trim(maskstr);

	if(StrToMac(mac, macstr) == false || StrToMac(mask, maskstr) == false)
	{
		FreeToken(t);
		return false;
	}
	else
	{
		if(ok != false)
		{
			Copy(mac_bin, mac, 6);
			Copy(mask_bin, mask, 6);
			*check_mac = true;
		}
	}
	FreeToken(t);

	return true;
}

// Check the MAC address and mask
bool CmdEvalMacAddressAndMask(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);


	if(ParseMacAddressAndMask(tmp, NULL, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_MAC_ADDRESS_AND_MASK_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Parse the status of TCP connection
bool ParseTcpState(char *src, bool *check_tcp_state, bool *established)
{
	bool ok = false;
	// Validate arguments
	if(src == NULL)
	{
		return false;
	}

	if(check_tcp_state != NULL && established != NULL)
	{
		ok = true;
	}

	if (IsEmptyStr(src) == false)
	{
		if (StartWith("Established", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = true;
			}
		}
		else if (StartWith("Unestablished", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = false;
			}
		}
		else
		{
			// Illegal string
			return false;
		}
	}
	else
	{
		if(ok != false)
		{
			*check_tcp_state = false;
			*established = false;
		}
	}

	return true;
}

// Check the status of the TCP connection
bool CmdEvalTcpState(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if(ParseTcpState(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_TCP_CONNECTION_STATE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Adding a rule to the access list (Standard, IPv4)
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Extended, IPv4)
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Standard, IPv6)
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Extended, IPv6)
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx6_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx6_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx6_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of rules in the access list
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	CT *ct;
	UINT i;
	
	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Remove a rule from the access list
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_ACCESS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the rule of access list
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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
			// The specified ID is not found
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Disable the rule of access list
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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
			// The specified ID is not found
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Get the user list
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_USER t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_USER_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumUser;i++)
		{
			RPC_ENUM_USER_ITEM *e = &t.Users[i];
			wchar_t name[MAX_SIZE];
			wchar_t group[MAX_SIZE];
			wchar_t num[MAX_SIZE];
			wchar_t time[MAX_SIZE];
			wchar_t exp[MAX_SIZE];
			wchar_t num1[64], num2[64];

			StrToUni(name, sizeof(name), e->Name);

			if (StrLen(e->GroupName) != 0)
			{
				StrToUni(group, sizeof(group), e->GroupName);
			}
			else
			{
				UniStrCpy(group, sizeof(group), _UU("SM_NO_GROUP"));
			}

			UniToStru(num, e->NumLogin);

			GetDateTimeStrEx64(time, sizeof(time), SystemToLocal64(e->LastLoginTime), NULL);

			if (e->IsExpiresFilled == false)
			{
				UniStrCpy(exp, sizeof(exp), _UU("CM_ST_NONE"));
			}
			else
			{
				if (e->Expires == 0)
				{
					UniStrCpy(exp, sizeof(exp), _UU("SM_LICENSE_NO_EXPIRES"));
				}
				else
				{
					GetDateTimeStrEx64(exp, sizeof(exp), SystemToLocal64(e->Expires), NULL);
				}
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(num1, sizeof(num1), _UU("CM_ST_NONE"));
				UniStrCpy(num2, sizeof(num2), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(num1, sizeof(num1),
					e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

				UniToStr3(num2, sizeof(num2),
					e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastCount);
			}

			CtInsert(ct,
				name, e->Realname, group, e->Note, GetAuthTypeStr(e->AuthType),
				num, time, exp, num1, num2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get a string of user authentication method
wchar_t *GetAuthTypeStr(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_AUTHTYPE_%u", id);

	return _UU(tmp);
}

// Creating a user
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScCreateUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Change the user information
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the user
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the user information
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		// Display the user's data
		ct = CtNewStandard();

		// User name
		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_UserGet_Column_Name"), tmp);

		// Real name
		CtInsert(ct, _UU("CMD_UserGet_Column_RealName"), t.Realname);

		// Description
		CtInsert(ct, _UU("CMD_UserGet_Column_Note"), t.Note);

		// Group name
		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("CMD_UserGet_Column_Group"), tmp);
		}

		// Expiration date
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		CtInsert(ct, _UU("CMD_UserGet_Column_Expires"), tmp);

		// Authentication method
		CtInsert(ct, _UU("CMD_UserGet_Column_AuthType"), GetAuthTypeStr(t.AuthType));

		switch (t.AuthType)
		{
		case AUTHTYPE_USERCERT:
			if (t.AuthData != NULL)
			{
				AUTHUSERCERT *auc = (AUTHUSERCERT *)t.AuthData;

				if (auc != NULL && auc->UserX != NULL)
				{
					// Registered user-specific certificate
					GetAllNameFromX(tmp, sizeof(tmp), auc->UserX);
					CtInsert(ct, _UU("CMD_UserGet_Column_UserCert"), tmp);
				}
			}
			break;

		case AUTHTYPE_ROOTCERT:
			if (t.AuthData != NULL)
			{
				AUTHROOTCERT *arc = (AUTHROOTCERT *)t.AuthData;

				if (IsEmptyUniStr(arc->CommonName) == false)
				{
					// Limitation the value of the certificate's CN
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_CN"), arc->CommonName);
				}

				if (arc->Serial != NULL && arc->Serial->size >= 1)
				{
					char tmp2[MAX_SIZE];

					// Limitation the serial number of the certificate
					BinToStrEx(tmp2, sizeof(tmp2), arc->Serial->data, arc->Serial->size);
					StrToUni(tmp, sizeof(tmp), tmp2);
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_SERIAL"), tmp);
				}
			}
			break;

		case AUTHTYPE_NT:
			if (t.AuthData != NULL)
			{
				AUTHNT *an = (AUTHNT *)t.AuthData;

				// Authentication user name of the external authentication server
				if (IsEmptyUniStr(an->NtUsername) == false)
				{
					CtInsert(ct, _UU("CMD_UserGet_Column_RadiusAlias"), an->NtUsername);
				}
			}
			break;
		}

		CtInsert(ct, L"---", L"---");

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_CREATE"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_UPDATE"), tmp);

		CmdInsertTrafficInfo(ct, &t.Traffic);

		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_USERINFO_NUMLOGIN"), tmp);


		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_UserGet_Policy"));
			PrintPolicy(c, t.Policy, false);
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the anonymous authentication
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	// Set to anonymous authentication
	t.AuthType = AUTHTYPE_ANONYMOUS;
	t.AuthData = NULL;

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the password authentication and set a password
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHPASSWORD *pw;

		pw = NewPasswordAuthData(t.Name, GetParamStr(o, "PASSWORD"));

		// Set to the password authentication
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = pw;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the specific certificate authentication and set a certificate
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// Read the certificate
	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));

		FreeParamValueList(o);

		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHUSERCERT *c;

		c = NewUserCertAuthData(x);

		FreeX(x);

		// Set to the password authentication
		t.AuthType = AUTHTYPE_USERCERT;
		t.AuthData = c;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get certificates that are registered in the user which uses certificate authentication
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	AUTHUSERCERT *a;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	a = (AUTHUSERCERT *)t.AuthData;

	if (t.AuthType != AUTHTYPE_USERCERT || a == NULL || a->UserX == NULL)
	{
		// The user is not using specific certificate authentication
		ret = ERR_INVALID_PARAMETER;

		c->Write(c, _UU("CMD_UserCertGet_Not_Cert"));
	}
	else
	{
		if (XToFileW(a->UserX, GetParamUniStr(o, "SAVECERT"), true) == false)
		{
			c->Write(c, _UU("CMD_SAVECERT_FAILED"));
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// Set the authentication method for the user to the signed certificate authentication
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"CN", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_CN"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_SERIAL"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
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

		// Set to the signed certificate authentication
		t.AuthType = AUTHTYPE_ROOTCERT;
		t.AuthData = c;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the NT domain authentication
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHNT *a;

		a = NewNTAuthData(GetParamUniStr(o, "ALIAS"));

		// Set to the NT domain authentication
		t.AuthType = AUTHTYPE_NT;
		t.AuthData = a;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the security policy of the user
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update
	if (t.Policy != NULL)
	{
		Free(t.Policy);
		t.Policy = NULL;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set a security policy of the user
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update
	if (t.Policy == NULL)
	{
		t.Policy = ClonePolicy(GetDefaultPolicy());
	}

	// Edit
	if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
	{
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		// Write the user object
		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// Convert the string to a date and time
UINT64 StrToDateTime64(char *str)
{
	UINT64 ret = 0;
	TOKEN_LIST *t;
	UINT a, b, c, d, e, f;
	// Validate arguments
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

// Evaluate the date and time string
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param)
{
	UINT64 ret;
	char tmp[MAX_SIZE];
	// Validate arguments
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

// Set the expiration date of the user
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	UINT64 expires;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_UserExpiresSet_Prompt_EXPIRES"), CmdEvalDateTime, NULL},
	};

	// If virtual HUB is not selected, it's an error
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
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	expires = StrToDateTime64(GetParamStr(o, "EXPIRES"));

	if (expires != 0)
	{
		expires = LocalToSystem64(expires);
	}

	t.ExpireTime = expires;

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the group list
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_GROUP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Create a group
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScCreateGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the group information
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Information update
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// RPC call
	ret = ScSetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete a group
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the group information and the list of users who belong to the group
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char groupname[MAX_USERNAME_LEN + 1];
		CT *ct = CtNewStandard();

		StrCpy(groupname, sizeof(groupname), t.Name);

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NAME"), tmp);
		CtInsert(ct, _UU("CMD_GroupGet_Column_REALNAME"), t.Realname);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NOTE"), t.Note);

		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_GroupGet_Column_POLICY"));

			PrintPolicy(c, t.Policy, false);
		}

		{
			RPC_ENUM_USER t;
			bool b = false;

			Zero(&t, sizeof(t));

			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

			if (ScEnumUser(ps->Rpc, &t) == ERR_NO_ERROR)
			{
				UINT i;

				for (i = 0;i < t.NumUser;i++)
				{
					RPC_ENUM_USER_ITEM *u = &t.Users[i];

					if (StrCmpi(u->GroupName, groupname) == 0)
					{
						if (b == false)
						{
							b = true;
							c->Write(c, L"");
							c->Write(c, _UU("CMD_GroupGet_Column_MEMBERS"));
						}

						UniFormat(tmp, sizeof(tmp), L" %S", u->Name);
						c->Write(c, tmp);
					}
				}
				FreeRpcEnumUser(&t);

				if (b)
				{
					c->Write(c, L"");
				}
			}
		}

	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Add an user to the group
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_GroupJoin_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update the Group
		StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "[name]"));

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the user from a group
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupUnjoin_Prompt_name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update the Group
		StrCpy(t.GroupName, sizeof(t.GroupName), "");

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the security policy of the group
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update
		if (t.Policy != NULL)
		{
			Free(t.Policy);
			t.Policy = NULL;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Set a security policy to a group
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update
		if (t.Policy == NULL)
		{
			t.Policy = ClonePolicy(GetDefaultPolicy());
		}

		if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
		{
			// An error has occured
			FreeRpcSetGroup(&t);
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the connected session list
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_SESSION t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Display the NODE_INFO
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
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

// Get the session information
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SESSION_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetSessionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Disconnect the session
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_SESSION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the MAC address table database
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_MAC_TABLE t;
	UINT i;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Delete a MAC address table entry
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the IP address table database
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
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

// Delete the IP address table entry
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDeleteIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of Virtual HUB management options
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Set the value of a Virtual HUB management option
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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
			// An error has occured
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
				// An error has occured
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

// Get the list of Virtual HUB extended options
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Set the value of a Virtual HUB extended option
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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
			// An error has occured
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
				// An error has occured
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

// Get the list of revoked certificate list
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CRL t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScEnumCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Add a revoked certificate
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
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

	// If virtual HUB is not selected, it's an error
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
		n = crl->Name = ZeroMalloc(sizeof(NAME));

		if (IsEmptyStr(GetParamStr(o, "CN")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "CN"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "O")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "O"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "OU")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "OU"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "C")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "C"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "ST")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "ST"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "L")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "L"));
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

	// RPC call
	ret = ScAddCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the revoked certificate
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScDelCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the revoked certificate
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlGet_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Show contents
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

// Get the rules of IP access control list
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Add a rule to the IP access control list (IPv4)
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd_Prompt_IP"), CmdEvalIpAndMask4, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Add a new item to the list
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		UINT u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask4(GetParamStr(o, "IP"), &u_ip, &u_mask);
		UINTToIP(&ac->IpAddress, u_ip);

		if (u_mask == 0xffffffff)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			UINTToIP(&ac->SubnetMask, u_mask);
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a rule to the IP access control list (IPv6)
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd6_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd6_Prompt_IP"), CmdEvalIpAndMask6, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Add a new item to the list
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		IP u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask6(GetParamStr(o, "IP"), &u_ip, &u_mask);
		Copy(&ac->IpAddress, &u_ip, sizeof(IP));

		if (SubnetMaskToInt6(&u_mask) == 128)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			Copy(&ac->SubnetMask, &u_mask, sizeof(IP));
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// Run the debug command
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT id;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", NULL, NULL, NULL, NULL},
		{"ARG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	id = GetParamInt(o, "[id]");

	if (true)
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Debug_Msg1"));

		Zero(&t, sizeof(t));

		t.IntValue = id;
		StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "ARG"));

		ret = ScDebug(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			wchar_t tmp[sizeof(t.StrValue)];

			UniFormat(tmp, sizeof(tmp), _UU("CMD_Debug_Msg2"), t.StrValue);
			c->Write(c, tmp);
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Flush the configuration file on the server
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (true)
	{
		RPC_TEST t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];
		char sizestr[MAX_SIZE];

		c->Write(c, _UU("CMD_Flush_Msg1"));

		Zero(&t, sizeof(t));

		ret = ScFlush(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		ToStr3(sizestr, sizeof(sizestr), (UINT64)t.IntValue);
		UniFormat(tmp, sizeof(tmp), _UU("CMD_Flush_Msg2"), sizestr);
		c->Write(c, tmp);
	}

	FreeParamValueList(o);

	return 0;
}

// Crash
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	char *yes;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
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
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Remove a rule in the IP access control list
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_AcDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
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

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Remove matched ID
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
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);
	FreeParamValueList(o);

	return 0;
}

// Register to the VPN Server by creating a new self-signed certificate with the specified CN (Common Name)
UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[CN]", CmdPrompt, _UU("CMD_ServerCertRegenerate_Prompt_CN"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[CN]"));

	// RPC call
	ret = ScRegenerateServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
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

// Register a new license key
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[key]", CmdPrompt, _UU("CMD_LicenseAdd_Prompt_Key"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[key]"));

	// RPC call
	ret = ScAddLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the registered license
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_LicenseDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.IntValue = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDelLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the registered license list
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LICENSE_KEY t;
	CT *ct;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_4"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_6"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_7"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_8"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_9"), false);

	for (i = 0;i < t.NumItem;i++)
	{
		wchar_t tmp1[32], tmp2[LICENSE_KEYSTR_LEN + 1], tmp3[LICENSE_MAX_PRODUCT_NAME_LEN + 1],
			*tmp4, tmp5[128], tmp6[LICENSE_LICENSEID_STR_LEN + 1], tmp7[64],
			tmp8[64], tmp9[64];
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t.Items[i];

		UniToStru(tmp1, e->Id);
		StrToUni(tmp2, sizeof(tmp2), e->LicenseKey);
		StrToUni(tmp3, sizeof(tmp3), e->LicenseName);
		tmp4 = LiGetLicenseStatusStr(e->Status);
		if (e->Expires == 0)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp5, sizeof(tmp5), e->Expires, NULL);
		}
		StrToUni(tmp6, sizeof(tmp6), e->LicenseId);
		UniToStru(tmp7, e->ProductId);
		UniFormat(tmp8, sizeof(tmp8), L"%I64u", e->SystemId);
		UniToStru(tmp9, e->SerialId);

		CtInsert(ct,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumLicenseKey(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the license status of the current VPN Server
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LICENSE_STATUS st;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&st, sizeof(st));

	// RPC call
	ret = ScGetLicenseStatus(ps->Rpc, &st);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNewStandard();

	if (st.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE)
	{
		CtInsert(ct, _UU("SM_NO_LICENSE_COLUMN"), _UU("SM_NO_LICENSE"));
	}
	else
	{
		// Product edition name
		StrToUni(tmp, sizeof(tmp), st.EditionStr);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_EDITION"), tmp);

		// Release date
		if (st.ReleaseDate != 0)
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.ReleaseDate, NULL);
			CtInsert(ct, _UU("SM_LICENSE_STATUS_RELEASE"), tmp);
		}

		// Current system ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// Expiration date of the current license product
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		CtInsert(ct,  _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);

		// Subscription (support) contract
		if (st.NeedSubscription == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONEED"));
		}
		else
		{
			if (st.SubscriptionExpires == 0)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONE"));
			}
			else
			{
				wchar_t dtstr[MAX_PATH];

				GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

				UniFormat(tmp, sizeof(tmp),
					st.IsSubscriptionExpired ? _UU("SM_LICENSE_STATUS_SUBSCRIPTION_EXPIRED") :  _UU("SM_LICENSE_STATUS_SUBSCRIPTION_VALID"),
					dtstr);
			}
		}
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION"), tmp);

		if (st.NeedSubscription == false && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), tmp);
		}

		if (GetCapsBool(ps->CapsList, "b_vpn3"))
		{
			// Maximum creatable number of users
			if (st.NumClientConnectLicense == INFINITE)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
			}
			else
			{
				UniToStru(tmp, st.NumClientConnectLicense);
			}
			CtInsert(ct, _UU("SM_LICENSE_NUM_CLIENT"), tmp);
		}

		// Available number of concurrent client connections
		if (st.NumBridgeConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumBridgeConnectLicense);
		}
		CtInsert(ct, _UU("SM_LICENSE_NUM_BRIDGE"), tmp);

		// Availability of enterprise features
		CtInsert(ct, _UU("SM_LICENSE_STATUS_ENTERPRISE"),
			st.AllowEnterpriseFunction ? _UU("SM_LICENSE_STATUS_ENTERPRISE_YES") : _UU("SM_LICENSE_STATUS_ENTERPRISE_NO"));
	}

	CtFreeEx(ct, c, false);

	FreeParamValueList(o);

	return 0;
}

// Set the server password
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

// Password decision prompt (for Prompt function)
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param)
{
	char *s;
	// Validate arguments
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

// Password input prompt (general-purpose)
char *CmdPasswordPrompt(CONSOLE *c)
{
	char *pw1, *pw2;
	// Validate arguments
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

// Disable the listener
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

// Enable the listener
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

// Get the TCP listener list
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

// Delete the TCP listener
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

// ServerInfoGet command
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

	// Product name
	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	CtInsert(ct, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	// Version
	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	CtInsert(ct, _UU("SM_INFO_VERSION"), tmp);

	// Build
	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	CtInsert(ct, _UU("SM_INFO_BUILD"), tmp);

	// Host name
	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	CtInsert(ct, _UU("SM_INFO_HOSTNAME"), tmp);

	// OS
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

// ServerStatusGet command
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

	// Number of TCP connections
	UniToStru(tmp, t.NumTcpConnections);
	CtInsert(ct, _UU("SM_ST_NUM_TCP"), tmp);

	// Number of Virtual HUBs
	UniToStru(tmp, t.NumHubTotal);
	CtInsert(ct, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	// Number of sessions
	UniToStru(tmp, t.NumSessionsTotal);
	CtInsert(ct, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	// Number of MAC tables
	UniToStru(tmp, t.NumMacTables);
	CtInsert(ct, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	// Number of IP tables
	UniToStru(tmp, t.NumIpTables);
	CtInsert(ct, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	// Number of users
	UniToStru(tmp, t.NumUsers);
	CtInsert(ct, _UU("SM_ST_NUM_USERS"), tmp);

	// Number of groups
	UniToStru(tmp, t.NumGroups);
	CtInsert(ct, _UU("SM_ST_NUM_GROUPS"), tmp);

	// Number of assigned licenses
	UniToStru(tmp, t.AssignedClientLicenses);
	CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE"), tmp);

	UniToStru(tmp, t.AssignedBridgeLicenses);
	CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	// Traffic
	CmdInsertTrafficInfo(ct, &t.Traffic);

	// Server start-up time
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	CtInsert(ct, _UU("SM_ST_START_TIME"), tmp);

	// Current time
	GetDateTimeStrMilli64(tmp2, sizeof(tmp2), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), tmp2);
	CtInsert(ct, _UU("SM_ST_CURRENT_TIME"), tmp);

	// Tick value
	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	CtInsert(ct, _UU("SM_ST_CURRENT_TICK"), tmp);

	// Memory information
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

// Add traffic information to LVB
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	// Validate arguments
	if (ct == NULL || t == NULL)
	{
		return;
	}

	// Transmission information
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

	// Reception information
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

// Input a port number
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

// Verify the port number
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param)
{
	UINT i;
	// Validate arguments
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

// ListenerCreate command
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

// About command
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

	// Display the version information
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
