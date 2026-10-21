// CommandAc.c
// vpncmd commands of the Admin RPC area IP access control (AdminAc.c): list and delete the IP access control rules of a Virtual Hub

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;

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

	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_1"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_4"), false);

		for (UINT i = 0;i < LIST_NUM(t.o);i++)
		{
			wchar_t tmp1[32], tmp3[MAX_SIZE], tmp4[32];
			AC *ac = LIST_DATA(t.o, i);

			UniToStru(tmp1, ac->Id);
			wchar_t *tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
			char *tmp_str = GenerateAcStr(ac);
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

UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
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

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
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
		bool b = false;

		for (UINT i = 0;i < LIST_NUM(t.o);i++)
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
