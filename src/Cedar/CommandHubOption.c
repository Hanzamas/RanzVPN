// CommandHubOption.c
// vpncmd commands of the Admin RPC area hub options (AdminHubOption.c): the admin options and the extended options of a Virtual Hub

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
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

		for (UINT i = 0;i < t.NumItem;i++)
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

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
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
		bool b = false;

		for (UINT i = 0;i < t.NumItem;i++)
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
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
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

		for (UINT i = 0;i < t.NumItem;i++)
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

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
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
		bool b = false;

		for (UINT i = 0;i < t.NumItem;i++)
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
