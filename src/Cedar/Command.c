// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Command.c
// vpncmd Command Line Management Utility

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





// VPN Tools main function
void PtMain(PT *pt)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (pt == NULL)
	{
		return;
	}

	// Display a message that start-up is complete
	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_TOOLS_CONNECTED"));
	pt->Console->Write(pt->Console, tmp);
	pt->Console->Write(pt->Console, L"");

	while (true)
	{
		// Definition of command
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert2048},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"Check", PtCheck},
		};

		// Generate a prompt
		StrCpy(prompt, sizeof(prompt), "VPN Tools>");

		if (DispatchNextCmdEx(pt->Console, pt->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pt) == false)
		{
			break;
		}
		pt->LastError = pt->Console->RetCode;

		if (pt->LastError == ERR_NO_ERROR && pt->Console->ConsoleType != CONSOLE_CSV)
		{
			pt->Console->Write(pt->Console, _UU("CMD_MSG_OK"));
			pt->Console->Write(pt->Console, L"");
		}

		if (pt->CmdLine != NULL)
		{
			break;
		}
	}
}

// Create a VPN Tools context
PT *NewPt(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pt = ZeroMalloc(sizeof(PT));
	pt->Console = c;
	pt->CmdLine = CopyUniStr(cmdline);

	return pt;
}

// Release the VPN Tools context
void FreePt(PT *pt)
{
	// Validate arguments
	if (pt == NULL)
	{
		return;
	}

	Free(pt->CmdLine);
	Free(pt);
}

// Start VPN Tools
UINT PtConnect(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	UINT ret = 0;
	// Validate arguments
	if (c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	pt = NewPt(c, cmdline);

	PtMain(pt);

	ret = pt->LastError;

	FreePt(pt);

	return ret;
}

// Initialize the execution path information of vpncmd command
void VpnCmdInitBootPath()
{
#ifdef	OS_WIN32
	char exe_path[MAX_PATH];
	char tmp[MAX_PATH];
	GetExeName(exe_path, sizeof(exe_path));

	if (SearchStrEx(exe_path, "ham.exe", 0, false) != INFINITE)
	{
		return;
	}

	if (MsIsAdmin())
	{
		UINT current_ver;

		// Get the version of vpncmd that is currently installed
		current_ver = MsRegReadInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER);

		if ((CEDAR_VERSION_BUILD >= current_ver) ||
			MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
		{
			bool b = false;
			// Copy the vpncmdsys.exe to system32
			Format(tmp, sizeof(tmp), "%s\\vpncmd.exe", MsGetSystem32Dir());

			if (MsIs64BitWindows() == false || Is64())
			{
				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}
			}
			else
			{
				void *wow = MsDisableWow64FileSystemRedirection();

				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}

				MsRestoreWow64FileSystemRedirection(wow);

				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}
			}

			// Because the currently running prompt is newer version, overwrite the registry
			if (MsIs64BitWindows() == false)
			{
				MsRegWriteStr(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path);
				MsRegWriteInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD);
			}
			else
			{
				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, true, false);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD, true, false);

				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, false, true);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD, false, true);
			}
		}
	}
#endif	// OS_WIN32
}


// Server Administration Tool Processor Main
void PsMain(PS *ps)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (ps == NULL)
	{
		return;
	}

	// If it's not in CSV mode, to display a message that the connection has been made
	if(ps->Console->ConsoleType != CONSOLE_CSV)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED"),
			ps->ServerName, ps->ServerPort);
		ps->Console->Write(ps->Console, tmp);
		ps->Console->Write(ps->Console, L"");

		if (ps->HubName == NULL)
		{
			// Server management mode
			ps->Console->Write(ps->Console, _UU("CMD_VPNCMD_SERVER_CONNECTED_1"));
		}
		else
		{
			// Virtual HUB management mode
			UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED_2"),
				ps->HubName);
			ps->Console->Write(ps->Console, tmp);
		}
		ps->Console->Write(ps->Console, L"");
	}

	// Get the Caps
	ps->CapsList = ScGetCapsEx(ps->Rpc);

	if (ps->AdminHub != NULL)
	{
		RPC_HUB_STATUS t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];

		// Choose the Virtual HUB that is specified in the ADMINHUB
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->AdminHub);

		ret = ScGetHubStatus(ps->Rpc, &t);
		if (ret == ERR_NO_ERROR)
		{
			// Success
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);

			if (ps->HubName != NULL)
			{
				Free(ps->HubName);
			}
			ps->HubName = CopyStr(t.HubName);

			if( ps->Console->ConsoleType != CONSOLE_CSV)
			{
				ps->Console->Write(ps->Console, tmp);
			}
		}
		else
		{
			// Failure
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Select_Failed"), ps->AdminHub);

			ps->Console->Write(ps->Console, tmp);
			CmdPrintError(ps->Console, ret);
		}
	}

	if (ps->HubName == NULL)
	{
		RPC_KEY_PAIR t;

		Zero(&t, sizeof(t));

		if (ScGetServerCert(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.Cert != NULL && t.Cert->has_basic_constraints == false)
			{
				if (t.Cert->root_cert)
				{
					ps->Console->Write(ps->Console, L"");
					ps->Console->Write(ps->Console, _UU("SM_CERT_MESSAGE_CLI"));
					ps->Console->Write(ps->Console, L"");
				}
			}

			FreeRpcKeyPair(&t);
		}
	}

	while (true)
	{
		// Definition of command
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"Crash", PsCrash},
			{"Flush", PsFlush},
			{"Debug", PsDebug},
			{"ServerInfoGet", PsServerInfoGet},
			{"ServerStatusGet", PsServerStatusGet},
			{"ListenerCreate", PsListenerCreate},
			{"ListenerDelete", PsListenerDelete},
			{"ListenerList", PsListenerList},
			{"ListenerEnable", PsListenerEnable},
			{"ListenerDisable", PsListenerDisable},
			{"ServerPasswordSet", PsServerPasswordSet},
			{"ServerCertGet", PsServerCertGet},
			{"ServerKeyGet", PsServerKeyGet},
			{"ServerCertSet", PsServerCertSet},
			{"ServerCipherGet", PsServerCipherGet},
			{"ServerCipherSet", PsServerCipherSet},
			{"SyslogGet", PsSyslogGet},
			{"SyslogDisable", PsSyslogDisable},
			{"SyslogEnable", PsSyslogEnable},
			{"ConnectionList", PsConnectionList},
			{"ConnectionGet", PsConnectionGet},
			{"ConnectionDisconnect", PsConnectionDisconnect},
			{"BridgeDeviceList", PsBridgeDeviceList},
			{"BridgeList", PsBridgeList},
			{"BridgeCreate", PsBridgeCreate},
			{"BridgeDelete", PsBridgeDelete},
			{"Caps", PsCaps},
			{"Reboot", PsReboot},
			{"ConfigGet", PsConfigGet},
			{"ConfigSet", PsConfigSet},
			{"LogFileList", PsLogFileList},
			{"LogFileGet", PsLogFileGet},
			{"HubCreate", PsHubCreate},
			{"HubDelete", PsHubDelete},
			{"HubList", PsHubList},
			{"Hub", PsHub},
			{"Online", PsOnline},
			{"Offline", PsOffline},
			{"SetMaxSession", PsSetMaxSession},
			{"SetHubPassword", PsSetHubPassword},
			{"SetEnumAllow", PsSetEnumAllow},
			{"SetEnumDeny", PsSetEnumDeny},
			{"OptionsGet", PsOptionsGet},
			{"StatusGet", PsStatusGet},
			{"LogGet", PsLogGet},
			{"LogEnable", PsLogEnable},
			{"LogDisable", PsLogDisable},
			{"LogSwitchSet", PsLogSwitchSet},
			{"LogPacketSaveType", PsLogPacketSaveType},
			{"CAList", PsCAList},
			{"CAAdd", PsCAAdd},
			{"CADelete", PsCADelete},
			{"CAGet", PsCAGet},
			{"CascadeList", PsCascadeList},
			{"CascadeCreate", PsCascadeCreate},
			{"CascadeSet", PsCascadeSet},
			{"CascadeGet", PsCascadeGet},
			{"CascadeDelete", PsCascadeDelete},
			{"CascadeUsernameSet", PsCascadeUsernameSet},
			{"CascadeAnonymousSet", PsCascadeAnonymousSet},
			{"CascadePasswordSet", PsCascadePasswordSet},
			{"CascadeCertSet", PsCascadeCertSet},
			{"CascadeCertGet", PsCascadeCertGet},
			{"CascadeEncryptEnable", PsCascadeEncryptEnable},
			{"CascadeEncryptDisable", PsCascadeEncryptDisable},
			{"CascadeCompressEnable", PsCascadeCompressEnable},
			{"CascadeCompressDisable", PsCascadeCompressDisable},
			{"CascadeProxyNone", PsCascadeProxyNone},
			{"CascadeHttpHeaderAdd", PsCascadeHttpHeaderAdd},
			{"CascadeHttpHeaderDelete", PsCascadeHttpHeaderDelete},
			{"CascadeHttpHeaderGet", PsCascadeHttpHeaderGet},
			{"CascadeProxyHttp", PsCascadeProxyHttp},
			{"CascadeProxySocks", PsCascadeProxySocks},
			{"CascadeProxySocks5", PsCascadeProxySocks5},
			{"CascadeServerCertEnable", PsCascadeServerCertEnable},
			{"CascadeServerCertDisable", PsCascadeServerCertDisable},
			{"CascadeDefaultCAEnable", PsCascadeDefaultCAEnable},
			{"CascadeDefaultCADisable", PsCascadeDefaultCADisable},
			{"CascadeServerCertSet", PsCascadeServerCertSet},
			{"CascadeServerCertDelete", PsCascadeServerCertDelete},
			{"CascadeServerCertGet", PsCascadeServerCertGet},
			{"CascadeDetailSet", PsCascadeDetailSet},
			{"CascadePolicySet", PsCascadePolicySet},
			{"PolicyList", PsPolicyList},
			{"CascadeStatusGet", PsCascadeStatusGet},
			{"CascadeRename", PsCascadeRename},
			{"CascadeOnline", PsCascadeOnline},
			{"CascadeOffline", PsCascadeOffline},
			{"AccessAdd", PsAccessAdd},
			{"AccessAddEx", PsAccessAddEx},
			{"AccessAdd6", PsAccessAdd6},
			{"AccessAddEx6", PsAccessAddEx6},
			{"AccessList", PsAccessList},
			{"AccessDelete", PsAccessDelete},
			{"AccessEnable", PsAccessEnable},
			{"AccessDisable", PsAccessDisable},
			{"UserList", PsUserList},
			{"UserCreate", PsUserCreate},
			{"UserSet", PsUserSet},
			{"UserDelete", PsUserDelete},
			{"UserGet", PsUserGet},
			{"UserAnonymousSet", PsUserAnonymousSet},
			{"UserPasswordSet", PsUserPasswordSet},
			{"UserCertSet", PsUserCertSet},
			{"UserCertGet", PsUserCertGet},
			{"UserSignedSet", PsUserSignedSet},
			{"UserNTLMSet", PsUserNTLMSet},
			{"UserPolicyRemove", PsUserPolicyRemove},
			{"UserPolicySet", PsUserPolicySet},
			{"UserExpiresSet", PsUserExpiresSet},
			{"GroupList", PsGroupList},
			{"GroupCreate", PsGroupCreate},
			{"GroupSet", PsGroupSet},
			{"GroupDelete", PsGroupDelete},
			{"GroupGet", PsGroupGet},
			{"GroupJoin", PsGroupJoin},
			{"GroupUnjoin", PsGroupUnjoin},
			{"GroupPolicyRemove", PsGroupPolicyRemove},
			{"GroupPolicySet", PsGroupPolicySet},
			{"SessionList", PsSessionList},
			{"SessionGet", PsSessionGet},
			{"SessionDisconnect", PsSessionDisconnect},
			{"MacTable", PsMacTable},
			{"MacDelete", PsMacDelete},
			{"IpTable", PsIpTable},
			{"IpDelete", PsIpDelete},
			{"AdminOptionList", PsAdminOptionList},
			{"AdminOptionSet", PsAdminOptionSet},
			{"ExtOptionList", PsExtOptionList},
			{"ExtOptionSet", PsExtOptionSet},
			{"CrlList", PsCrlList},
			{"CrlAdd", PsCrlAdd},
			{"CrlDel", PsCrlDel},
			{"CrlGet", PsCrlGet},
			{"AcList", PsAcList},
			{"AcAdd", PsAcAdd},
			{"AcAdd6", PsAcAdd6},
			{"AcDel", PsAcDel},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert2048},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"LicenseAdd", PsLicenseAdd},
			{"LicenseDel", PsLicenseDel},
			{"LicenseList", PsLicenseList},
			{"LicenseStatus", PsLicenseStatus},
			{"ServerCertRegenerate", PsServerCertRegenerate},
		};

		// Generate a prompt
		if (ps->HubName == NULL)
		{
			Format(prompt, sizeof(prompt), "VPN Server>");
		}
		else
		{
			Format(prompt, sizeof(prompt), "VPN Server/%s>", ps->HubName);
		}

		if (DispatchNextCmdEx(ps->Console, ps->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), ps) == false)
		{
			break;
		}
		ps->LastError = ps->Console->RetCode;

		if (ps->LastError == ERR_NO_ERROR && ps->Console->ConsoleType != CONSOLE_CSV)
		{
			ps->Console->Write(ps->Console, _UU("CMD_MSG_OK"));
			ps->Console->Write(ps->Console, L"");
		}

		if (ps->CmdLine != NULL)
		{
			break;
		}
	}

	// Release the Caps
	FreeCapsList(ps->CapsList);
	ps->CapsList = NULL;
}




// Creat a new server management context
PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline)
{
	PS *ps;
	// Validate arguments
	if (c == NULL || rpc == NULL || servername == NULL)
	{
		return NULL;
	}

	if (IsEmptyStr(hubname))
	{
		hubname = NULL;
	}
	if (IsEmptyStr(adminhub))
	{
		adminhub = NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	ps = ZeroMalloc(sizeof(PS));
	ps->ConsoleForServer = true;
	ps->ServerPort = serverport;
	ps->ServerName = CopyStr(servername);
	ps->Console = c;
	ps->Rpc = rpc;
	ps->HubName = CopyStr(hubname);
	ps->LastError = 0;
	ps->AdminHub = CopyStr(adminhub);
	ps->CmdLine = CopyUniStr(cmdline);

	return ps;
}

// Release the server management context
void FreePs(PS *ps)
{
	// Validate arguments
	if (ps == NULL)
	{
		return;
	}

	Free(ps->HubName);
	Free(ps->AdminHub);
	Free(ps->CmdLine);
	Free(ps->ServerName);

	Free(ps);
}

// Server Administration Tool
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password)
{
	UINT retcode = 0;
	RPC *rpc = NULL;
	CEDAR *cedar;
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	bool b = false;
	// Validate arguments
	if (c == NULL || host == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (port == 0)
	{
		port = 443;
	}
	if (hub != NULL)
	{
		adminhub = NULL;
	}

	cedar = NewCedar(NULL, NULL);

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"VPNCMD");
	StrCpy(o.Hostname, sizeof(o.Hostname), host);
	o.Port = port;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, password, StrLen(password));

	if (IsEmptyStr(password) == false)
	{
		b = true;
	}

	// Connect
	while (true)
	{
		UINT err;

		rpc = AdminConnectEx(cedar, &o, hub, hashed_password, &err, CEDAR_CUI_STR);
		if (rpc == NULL)
		{
			// Failure
			retcode = err;

			if (err == ERR_ACCESS_DENIED && c->ProgrammingMode == false)
			{
				char *pass;
				// Password is incorrect
				if (b)
				{
					// Input the password
					c->Write(c, _UU("CMD_VPNCMD_PASSWORD_1"));
				}

				b = true;

				pass = c->ReadPassword(c, _UU("CMD_VPNCMD_PASSWORD_2"));
				c->Write(c, L"");

				if (pass != NULL)
				{
					Sha0(hashed_password, pass, StrLen(pass));
					Free(pass);
				}
				else
				{
					break;
				}
			}
			else
			{
				// Other errors
				CmdPrintError(c, err);
				break;
			}
		}
		else
		{
			PS *ps;

			// Success
			ps = NewPs(c, rpc, o.Hostname, port, hub, adminhub, cmdline);
			PsMain(ps);
			retcode = ps->LastError;
			FreePs(ps);
			AdminDisconnect(rpc);
			break;
		}
	}

	ReleaseCedar(cedar);

	return retcode;
}

// Display the error
void CmdPrintError(CONSOLE *c, UINT err)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ERROR"),
		err, GetUniErrorStr(err));
	c->Write(c, tmp);

	if (err == ERR_DISCONNECTED)
	{
		c->Write(c, _UU("CMD_DISCONNECTED_MSG"));
	}
}

// Display the version information
void CmdPrintAbout(CONSOLE *c)
{
	CEDAR *cedar;
	wchar_t tmp[MAX_SIZE];
	char exe[MAX_PATH];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	cedar = NewCedar(NULL, NULL);

	GetExeName(exe, sizeof(exe));

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ABOUT"),
		cedar->VerString, cedar->BuildInfo);

	c->Write(c, tmp);

	ReleaseCedar(cedar);
}

// Parse the host name and port number (Separated by @)
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	t = ParseToken(src, "@");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// Parse the host name and port number
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	if (StartWith(src, "["))
	{
		if (InStr(src, "]"))
		{
			// Format of [target]:port
			UINT i, n;
			char tmp[MAX_SIZE];

			StrCpy(tmp, sizeof(tmp), src);

			n = SearchStrEx(tmp, "]", 0, false);
			if (n != INFINITE)
			{
				UINT len = StrLen(tmp);

				for (i = n;i < len;i++)
				{
					if (tmp[i] == ':')
					{
						tmp[i] = '@';
					}
				}
			}

			return ParseHostPortAtmark(tmp, host, port, default_port);
		}
	}

	if (InStr(src, "@"))
	{
		// It is separated by @
		return ParseHostPortAtmark(src, host, port, default_port);
	}

	t = ParseToken(src, ":");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// Vpncmd command procedure
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	char *target;
	bool server = false;
	bool tools = false;
	char *hostname = NULL;
	char *password;
	wchar_t *cmdline;
	bool host_inputted = false;
	UINT port = 0;
	UINT retcode = 0;
	PARAM args[] =
	{
		{"[host:port]", NULL, NULL, NULL, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"TOOLS", NULL, NULL, NULL, NULL},
		{"HUB", NULL, NULL, NULL, NULL},
		{"ADMINHUB", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
		{"IN", NULL, NULL, NULL, NULL},
		{"OUT", NULL, NULL, NULL, NULL},
		{"CMD", NULL, NULL, NULL, NULL},
		{"CSV", NULL, NULL, NULL, NULL},
		{"PROGRAMMING", NULL, NULL, NULL, NULL},
	};

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		// Initialize the execute path information
		VpnCmdInitBootPath();
	}

	if(c->ConsoleType != CONSOLE_CSV)
	{
		CmdPrintAbout(c);
		c->Write(c, L"");
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));

	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Specification of the mode of Tools or Server
	if (GetParamStr(o, "SERVER") == NULL && GetParamStr(o, "TOOLS") == NULL)
	{
		wchar_t *ret;
		UINT code;
		// The mode of Tools or Server is not specified
		c->Write(c, _UU("CMD_VPNCMD_CS_1"));

		ret = c->ReadLine(c, _UU("CMD_VPNCMD_CS_2"), true);

		code = UniToInt(ret);
		Free(ret);

		switch (code)
		{
		case 1:
			// Server
			server = true;
			break;

		case 3:
			// Tools
			tools = true;
			break;

		default:
			// Unspecified
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		c->Write(c, L"");
	}
	else
	{
		if (GetParamStr(o, "SERVER") != NULL)
		{
			server = true;
		}
		else
		{
			tools = true;
		}
	}

	// Destination host name
	target = CopyStr(GetParamStr(o, "[host:port]"));

	if (target == NULL && tools == false)
	{
		wchar_t *str;
		// Input a host name
		if (server)
		{
			c->Write(c, _UU("CMD_VPNCMD_HOST_1"));
		}

		str = c->ReadLine(c, _UU("CMD_VPNCMD_HOST_3"), true);
		c->Write(c, L"");
		target = CopyUniToStr(str);
		Free(str);

		if (target == NULL)
		{
			// Cancel
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		if (IsEmptyStr(target))
		{
			Free(target);
			target = CopyStr("localhost");
		}
	}
	else
	{
		// User specifies a host name
		host_inputted = true;
	}

	if (tools == false)
	{
		if (ParseHostPort(target, &hostname, &port, 443) == false)
		{
			c->Write(c, _UU("CMD_MSG_INVALID_HOSTNAME"));
			Free(target);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}
	}

	// Password
	password = GetParamStr(o, "PASSWORD");
	if (password == NULL)
	{
		password = "";
	}

	// Command line
	cmdline = GetParamUniStr(o, "CMD");

	if (server)
	{
		// Process as the server
		char *hub;
		char *adminhub = NULL;

		hub = CopyStr(GetParamStr(o, "HUB"));
		adminhub = GetParamStr(o, "ADMINHUB");

		// Decide the Virtual HUB to be specified in the Virtual HUB management mode
		if (hub == NULL)
		{
			if (host_inputted == false)
			{
				wchar_t *s;
				// If the user does not specify a host name on the command line,
				// get also a Virtual HUB name by displaying the prompt
				c->Write(c, _UU("CMD_VPNCMD_HUB_1"));

				s = c->ReadLine(c, _UU("CMD_VPNCMD_HUB_2"), true);

				hub = CopyUniToStr(s);
				Free(s);
			}
		}

		if (IsEmptyStr(hub))
		{
			Free(hub);
			hub = NULL;
		}
		if (IsEmptyStr(adminhub))
		{
			adminhub = NULL;
		}

		retcode = PsConnect(c, hostname, port, hub, adminhub, cmdline, password);

		Free(hub);
	}
	else if (tools)
	{
		// Treated as a VPN Tools
		retcode = PtConnect(c, cmdline);
	}

	Free(hostname);
	Free(target);
	FreeParamValueList(o);

	return retcode;
}

// Entry point of vpncmd
UINT CommandMain(wchar_t *command_line)
{
	UINT ret = 0;
	wchar_t *infile, *outfile;
	char *a_infile, *a_outfile;
	wchar_t *csvmode;
	wchar_t *programming_mode;
	CONSOLE *c;

	// Validate arguments
	if (command_line == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Look ahead only items of /in and /out
	infile = ParseCommand(command_line, L"in");
	outfile = ParseCommand(command_line, L"out");
	if (UniIsEmptyStr(infile))
	{
		Free(infile);
		infile = NULL;
	}
	if (UniIsEmptyStr(outfile))
	{
		Free(outfile);
		outfile = NULL;
	}

	a_infile = CopyUniToStr(infile);
	a_outfile = CopyUniToStr(outfile);

	// Allocate the local console
	c = NewLocalConsole(infile, outfile);
	if (c != NULL)
	{
		// Definition of commands of vpncmd
		CMD cmd[] =
		{
			{"vpncmd", VpnCmdProc},
		};

		// Read ahead to check the CSV mode
		csvmode = ParseCommand(command_line, L"csv");
		if(csvmode != NULL)
		{
			Free(csvmode);
			c->ConsoleType = CONSOLE_CSV;
		}

		programming_mode = ParseCommand(command_line, L"programming");
		if (programming_mode != NULL)
		{
			Free(programming_mode);
			c->ProgrammingMode = true;
		}

		if (DispatchNextCmdEx(c, command_line, ">", cmd, sizeof(cmd) / sizeof(cmd[0]), NULL) == false)
		{
			ret = ERR_INVALID_PARAMETER;
		}
		else
		{
			ret = c->RetCode;
		}

		// Release the local console
		c->Free(c);
	}
	else
	{
		Print("Error: Couldn't open local console.\n");
	}

	Free(a_infile);
	Free(a_outfile);
	Free(infile);
	Free(outfile);

	return ret;
}

