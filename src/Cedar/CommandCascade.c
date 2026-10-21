// CommandCascade.c
// vpncmd commands of the Admin RPC area cascade connections (AdminLink.c): status, rename, online and offline of a cascade connection

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK_STATUS t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLinkStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		CT *ct = CtNewStandard();

		CmdPrintStatusToListViewEx(ct, &t.Status, false);

		CtFree(ct, c);

		FreeRpcLinkStatus(&t);
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RENAME_LINK t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
	        {"NEW", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), GetParamUniStr(o, "[name]"));

	ret = ScRenameLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScSetLinkOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = ScSetLinkOffline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}
