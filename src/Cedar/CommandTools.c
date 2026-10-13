// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// CommandTools.c
// vpncmd tools commands (Pt*): system check command and certificate creation

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

// Behavior checker
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (SystemCheck() == false)
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// Certificate easy creation tool (1024 bit)
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToXW(GetParamUniStr(o, "SIGNCERT"));
		root_k = FileToKW(GetParamUniStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		RsaGen(&pri, &pub, 1024);

		if (root_x == NULL)
		{
			x = NewRootX(pub, pri, n, days, x_serial);
		}
		else
		{
			x = NewX(pub, root_k, root_x, n, days, x_serial);
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFileW(x, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
			}
			else if (KToFileW(pri, GetParamUniStr(o, "SAVEKEY"), true, NULL) == false)
			{
				c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}

// Certificate easy creation tool (2048 bit)
UINT PtMakeCert2048(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToXW(GetParamUniStr(o, "SIGNCERT"));
		root_k = FileToKW(GetParamUniStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		RsaGen(&pri, &pub, 2048);

		if (root_x == NULL)
		{
			x = NewRootX(pub, pri, n, days, x_serial);
		}
		else
		{
			x = NewX(pub, root_k, root_x, n, days, x_serial);
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFileW(x, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
			}
			else if (KToFileW(pri, GetParamUniStr(o, "SAVEKEY"), true, NULL) == false)
			{
				c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}
