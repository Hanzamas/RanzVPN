// CommandHttpListener.c
// vpncmd commands of the Admin RPC area HTTP listener (AdminHttpListener.c): show the HTTP listener, turn it on and off

#include "Command.h"

#include "Admin.h"
#include "Console.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsHttpListenerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	RPC_HTTP_LISTENER t;
	wchar_t tmp[MAX_SIZE];

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));

	UINT ret = ScGetHttpListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	CT *ct = CtNewStandard();

	CtInsert(ct, _UU("CMD_HttpListenerGet_COLUMN_1"), t.Enabled ? _UU("CMD_HttpListenerGet_ON") : _UU("CMD_HttpListenerGet_OFF"));

	UniToStru(tmp, t.Port);
	CtInsert(ct, _UU("CMD_HttpListenerGet_COLUMN_2"), tmp);

	CtInsert(ct, _UU("CMD_HttpListenerGet_COLUMN_3"), t.Listening ? _UU("CMD_HttpListenerGet_LISTENING") : _UU("CMD_HttpListenerGet_NOT_LISTENING"));

	CtFree(ct, c);

	FreeParamValueList(o);

	return 0;
}

UINT PsHttpListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	RPC_HTTP_LISTENER t;
	// The port is optional: without it the saved port stays
	PARAM args[] =
	    {
	        {"[port]", NULL, NULL, CmdEvalPort, NULL},
	    };

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	t.Enabled = true;
	t.Port = GetParamInt(o, "[port]");

	UINT ret = ScSetHttpListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsHttpListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	RPC_HTTP_LISTENER t;

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	t.Enabled = false;

	UINT ret = ScSetHttpListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}
