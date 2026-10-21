// CommandUser.c
// vpncmd commands of the Admin RPC area users (AdminUser.c): create, set and delete users, their authentication, policy and expiry, and the group join and unjoin, which set the group of a user through the user RPCs; with GetAuthTypeStr

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

wchar_t *GetAuthTypeStr(UINT id) {
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_AUTHTYPE_%u", id);

	return _UU(tmp);
}

UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
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

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	Trim(t.Name);
	if (StrCmpi(t.Name, "*") == 0) {
		t.AuthType = AUTHTYPE_NT;
		t.AuthData = NewNTAuthData(NULL);
	} else {
		UCHAR random_pass[SHA1_SIZE];
		UCHAR random_pass2[MD5_SIZE];

		Rand(random_pass, sizeof(random_pass));
		Rand(random_pass2, sizeof(random_pass2));
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = NewPasswordAuthDataRaw(random_pass, random_pass2);
	}

	ret = ScCreateUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
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

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDeleteUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	t.AuthType = AUTHTYPE_ANONYMOUS;
	t.AuthData = NULL;

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHPASSWORD *pw = NewPasswordAuthData(t.Name, GetParamStr(o, "PASSWORD"));

		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = pw;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL)
		return ERR_INVALID_PARAMETER;

	X *x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL) {
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));

		FreeParamValueList(o);

		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHUSERCERT *c = NewUserCertAuthData(x);

		FreeX(x);

		t.AuthType = AUTHTYPE_USERCERT;
		t.AuthData = c;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"CN", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_CN"), NULL, NULL},
	        {"SERIAL", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_SERIAL"), NULL, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		X_SERIAL *serial = NULL;

		BUF *b = StrToBin(GetParamStr(o, "SERIAL"));

		if (b != NULL && b->Size >= 1)
			serial = NewXSerial(b->Buf, b->Size);

		FreeBuf(b);

		AUTHROOTCERT *c = NewRootCertAuthData(serial, GetParamUniStr(o, "CN"));

		FreeXSerial(serial);

		t.AuthType = AUTHTYPE_ROOTCERT;
		t.AuthData = c;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"ALIAS", CmdPrompt, _UU("CMD_UserNTLMSet_Prompt_ALIAS"), NULL, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHNT *a = NewNTAuthData(GetParamUniStr(o, "ALIAS"));

		t.AuthType = AUTHTYPE_NT;
		t.AuthData = a;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Policy != NULL) {
		Free(t.Policy);
		t.Policy = NULL;
	}

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT64 StrToDateTime64(const char *str) {
	UINT64 ret = 0;
	if (str == NULL)
		return INFINITE;

	if (IsEmptyStr(str) || StrCmpi(str, "none") == 0)
		return 0;

	TOKEN_LIST *t = ParseToken(str, ":/,. \"");
	if (t->NumTokens != 6) {
		FreeToken(t);
		return INFINITE;
	}

	UINT a = ToInt(t->Token[0]);
	UINT b = ToInt(t->Token[1]);
	UINT c = ToInt(t->Token[2]);
	UINT d = ToInt(t->Token[3]);
	UINT e = ToInt(t->Token[4]);
	UINT f = ToInt(t->Token[5]);

	ret = INFINITE;

	if (a >= 1000 && a <= 9999 && b >= 1 && b <= 12 && c >= 1 && c <= 31 &&
	    d <= 23 && e <= 59 && f <= 59) {
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

static bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param) {
	char tmp[MAX_SIZE];
	if (c == NULL || str == NULL)
		return false;

	UniToStr(tmp, sizeof(tmp), str);

	UINT64 ret = StrToDateTime64(tmp);

	if (ret == INFINITE) {
		c->Write(c, _UU("CMD_EVAL_DATE_TIME_FAILED"));
		return false;
	}

	return true;
}

UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"EXPIRES", CmdPrompt, _UU("CMD_UserExpiresSet_Prompt_EXPIRES"), CmdEvalDateTime, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UINT64 expires = StrToDateTime64(GetParamStr(o, "EXPIRES"));

	if (expires != 0)
		expires = LocalToSystem64(expires);

	t.ExpireTime = expires;

	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	        {"USERNAME", CmdPrompt, _UU("CMD_GroupJoin_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "USERNAME"));

	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "[name]"));

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR) {
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	    {
	        {"[name]", CmdPrompt, _UU("CMD_GroupUnjoin_Prompt_name"), CmdEvalNotEmpty, NULL},
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
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		StrCpy(t.GroupName, sizeof(t.GroupName), "");

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR) {
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}
