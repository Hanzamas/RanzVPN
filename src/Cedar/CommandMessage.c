// CommandMessage.c
// vpncmd commands of the Admin RPC area maintenance (AdminMessage.c): flush, crash and server certificate regeneration

#include "Command.h"

#include "Admin.h"
#include "Console.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	RPC_TEST t;
	wchar_t tmp[MAX_SIZE];
	char sizestr[MAX_SIZE];

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	c->Write(c, _UU("CMD_Flush_Msg1"));

	Zero(&t, sizeof(t));

	UINT ret = ScFlush(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
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

UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	PARAM args[] =
	    {
	        {"[yes]", CmdPrompt, _UU("CMD_Crash_Confirm"), NULL, NULL},
	    };

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	char *yes = GetParamStr(o, "[yes]");

	if (StrCmpi(yes, "yes") != 0) {
		c->Write(c, _UU("CMD_Crash_Aborted"));
	} else {
		RPC_TEST t;

		c->Write(c, _UU("CMD_Crash_Msg"));

		Zero(&t, sizeof(t));

		UINT ret = ScCrash(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR) {
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	PARAM args[] =
	    {
	        {"[CN]", CmdPrompt, _UU("CMD_ServerCertRegenerate_Prompt_CN"), CmdEvalNotEmpty, NULL},
	    };

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[CN]"));

	ret = ScRegenerateServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
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
