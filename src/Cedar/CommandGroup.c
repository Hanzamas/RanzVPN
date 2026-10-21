// CommandGroup.c
// vpncmd commands of the Admin RPC area groups (AdminGroup.c): create, set, list and delete groups, and remove a group policy

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

UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_GROUP t;

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_GROUPLIST_NAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_REALNAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NOTE"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NUMUSERS"), false);

		for (UINT i = 0; i < t.NumGroup; i++) {
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

UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
	        {"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScCreateGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
	        {"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScSetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDeleteGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		if (t.Policy != NULL) {
			Free(t.Policy);
			t.Policy = NULL;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR) {
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}
