// Console.c
// Console Service

#include "Console.h"

#include "Cedar.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdio.h>
#include <stdlib.h>

#include <conio.h>

static void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t *description, *args, *help;
	if (c == NULL || cmd_name == NULL || param_list == NULL)
	{
		return;
	}

	UINT width = GetConsoleWidth(c) - 2;

	UINT buf_size = sizeof(wchar_t) * (width + 32);
	wchar_t *buf = Malloc(buf_size);

	GetCommandHelpStr(cmd_name, &description, &args, &help);

	char *space = MakeCharArray(' ', 2);

	UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_TITLE"), cmd_name);
	c->Write(c, tmp);
	c->Write(c, L"");

	c->Write(c, _UU("CMD_HELP_DESCRIPTION"));
	UNI_TOKEN_LIST *t = SeparateStringByWidth(description, width - 2);
	for (UINT i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	c->Write(c, _UU("CMD_HELP_HELP"));
	t = SeparateStringByWidth(help, width - 2);
	for (UINT i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);
	c->Write(c, L"");

	c->Write(c, _UU("CMD_HELP_USAGE"));
	t = SeparateStringByWidth(args, width - 2);
	for (UINT i = 0;i < t->NumTokens;i++)
	{
		UniFormat(buf, buf_size, L"%S%s", space, t->Token[i]);
		c->Write(c, buf);
	}
	UniFreeToken(t);

	if (param_list->NumTokens >= 1)
	{
		c->Write(c, L"");
		c->Write(c, _UU("CMD_HELP_ARGS"));
		PrintCandidateHelp(c, cmd_name, param_list, 2);
	}

	Free(space);

	Free(buf);
}

bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_SAFE") : (wchar_t *)param;

	if (IsSafeUniStr(str))
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

wchar_t *CmdPrompt(CONSOLE *c, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_PROMPT") : (wchar_t *)param;

	return c->ReadLine(c, p, true);
}

bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t tmp[MAX_PATH];
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniStrCpy(tmp, sizeof(tmp), str);

	if (UniIsEmptyStr(tmp))
	{
		c->Write(c, _UU("CMD_FILE_NAME_EMPTY"));
		return false;
	}

	if (IsFileExistsW(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2), _UU("CMD_FILE_NOT_FOUND"), tmp);
		c->Write(c, tmp2);

		return false;
	}

	return true;
}

bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *p = (param == NULL) ? _UU("CMD_EVAL_NOT_EMPTY") : (wchar_t *)param;

	if (UniIsEmptyStr(str) == false)
	{
		return true;
	}

	c->Write(c, p);

	return false;
}

bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param)
{
	wchar_t *tag;
	if (param == NULL)
	{
		return false;
	}

	CMD_EVAL_MIN_MAX *e = (CMD_EVAL_MIN_MAX *)param;

	if (e->StrName == NULL)
	{
		tag = _UU("CMD_EVAL_MIN_MAX");
	}
	else
	{
		tag = _UU(e->StrName);
	}

	UINT v = UniToInt(str);

	if (v >= e->MinValue && v <= e->MaxValue)
	{
		return true;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), tag, e->MinValue, e->MaxValue);
		c->Write(c, tmp);

		return false;
	}
}

void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help)
{
	char tmp1[128], tmp2[128], tmp3[128];

	Format(tmp1, sizeof(tmp1), "CMD_%s", command_name);
	Format(tmp2, sizeof(tmp2), "CMD_%s_ARGS", command_name);
	Format(tmp3, sizeof(tmp3), "CMD_%s_HELP", command_name);

	if (description != NULL)
	{
		*description = _UU(tmp1);
		if (UniIsEmptyStr(*description))
		{
			*description = _UU("CMD_UNKNOWM");
		}
	}

	if (args != NULL)
	{
		*args = _UU(tmp2);
		if (UniIsEmptyStr(*args))
		{
			*args = _UU("CMD_UNKNOWN_ARGS");
		}
	}

	if (help != NULL)
	{
		*help = _UU(tmp3);
		if (UniIsEmptyStr(*help))
		{
			*help = _UU("CMD_UNKNOWN_HELP");
		}
	}
}

static void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description)
{
	char tmp[160];
	if (description == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "CMD_%s_%s", command_name, param_name);

	*description = _UU(tmp);

	if (UniIsEmptyStr(*description))
	{
		*description = _UU("CMD_UNKNOWN_PARAM");
	}
}

static int CompareCandidateStr(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	char *s1 = *(char **)p1;
	char *s2 = *(char **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1[0] == '[' && s2[0] != '[')
	{
		return -1;
	}
	else if (s2[0] == '[' && s1[0] != '[')
	{
		return 1;
	}

	return StrCmp(s1, s2);
}

void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space)
{
	if (c == NULL || candidate_list == NULL)
	{
		return;
	}

	UINT console_width = GetConsoleWidth(c) - 1;

	UINT tmpbuf_size = sizeof(wchar_t) * (console_width + 32);
	wchar_t *tmpbuf = Malloc(tmpbuf_size);

	char *left_space_array = MakeCharArray(' ', left_space);

	LIST *o = NewListFast(cmd_name == NULL ? CompareCandidateStr : NULL);

	UINT max_keyword_width = 0;

	for (UINT i = 0;i < candidate_list->NumTokens;i++)
	{
		Insert(o, candidate_list->Token[i]);

		UINT keyword_width = StrWidth(candidate_list->Token[i]);
		if (cmd_name != NULL)
		{
			if (candidate_list->Token[i][0] != '[')
			{
				keyword_width += 1;
			}
			else
			{
				keyword_width -= 2;
			}
		}

		max_keyword_width = MAX(max_keyword_width, keyword_width);
	}

	char *max_space_array = MakeCharArray(' ', max_keyword_width);

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		char tmp[128];
		char *name = LIST_DATA(o, i);
		wchar_t *help;
		UINT descript_start_width = left_space + max_keyword_width + 1;
		UINT descript_width;

		if (console_width >= (descript_start_width + 5))
		{
			descript_width = console_width - descript_start_width - 3;
		}
		else
		{
			descript_width = 2;
		}

		if (cmd_name != NULL && name[0] != '[')
		{
			Format(tmp, sizeof(tmp), "/%s", name);
		}
		else
		{
			if (cmd_name == NULL)
			{
				StrCpy(tmp, sizeof(tmp), name);
			}
			else
			{
				StrCpy(tmp, sizeof(tmp), name + 1);
				if (StrLen(tmp) >= 1)
				{
					tmp[StrLen(tmp) - 1] = 0;
				}
			}
		}

		if (cmd_name == NULL)
		{
			GetCommandHelpStr(name, &help, NULL, NULL);
		}
		else
		{
			GetCommandParamHelpStr(cmd_name, name, &help);
		}

		char *space = MakeCharArray(' ', max_keyword_width - StrWidth(name) - (cmd_name == NULL ? 0 : (name[0] != '[' ? 1 : -2)));

		UNI_TOKEN_LIST *t = SeparateStringByWidth(help, descript_width);

		for (UINT j = 0;j < t->NumTokens;j++)
		{
			if (j == 0)
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S%S - %s",
					left_space_array, tmp, space, t->Token[j]);
			}
			else
			{
				UniFormat(tmpbuf, tmpbuf_size, L"%S%S   %s",
					left_space_array, max_space_array, t->Token[j]);
			}

			c->Write(c, tmpbuf);
		}

		Free(space);

		UniFreeToken(t);
	}

	ReleaseList(o);

	Free(max_space_array);
	Free(tmpbuf);
	Free(left_space_array);
}

static bool IsWordChar(wchar_t c)
{
	if (c >= L'a' && c <= 'z')
	{
		return true;
	}
	if (c >= L'A' && c <= 'Z')
	{
		return true;
	}
	if (c >= L'0' && c <= '9')
	{
		return true;
	}
	if (c == L'_')
	{
		return true;
	}
	if (c == L'.')
	{
		return true;
	}
	if (c == L'\"')
	{
		return true;
	}
	if (c == L'\'')
	{
		return true;
	}
	if (c == L',')
	{
		return true;
	}
	if (c == L')')
	{
		return true;
	}
	if (c == L']')
	{
		return true;
	}

	return false;
}

static UINT GetNextWordWidth(const wchar_t *str)
{
	if (str == NULL)
	{
		return 0;
	}

	UINT ret = 0;

	for (UINT i = 0;;i++)
	{
		wchar_t c = str[i];

		if (c == 0)
		{
			break;
		}

		if (IsWordChar(c) == false)
		{
			break;
		}

		ret++;
	}

	return ret;
}

UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width)
{
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (width == 0)
	{
		width = 1;
	}

	LIST *o = NewListFast(NULL);

	UINT len = UniStrLen(str);
	wchar_t *tmp = ZeroMalloc(sizeof(wchar_t) * (len + 32));
	UINT wp = 0;

	for (UINT i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];
		UINT next_word_width;
		UINT remain_width;

		switch (c)
		{
		case 0:
		case L'\r':
		case L'\n':
			if (c == L'\r')
			{
				if (str[i + 1] == L'\n')
				{
					i++;
				}
			}

			tmp[wp++] = 0;
			wp = 0;

			Insert(o, CopyUniStr(tmp));
			break;

		default:
			next_word_width = GetNextWordWidth(&str[i]);
			remain_width = (width - UniStrWidth(tmp));

			if ((remain_width >= 1) && (next_word_width > remain_width) && (next_word_width <= width))
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyUniStr(tmp));
			}

			tmp[wp++] = c;
			tmp[wp] = 0;
			if (UniStrWidth(tmp) >= width)
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyUniStr(tmp));
			}
			break;
		}
	}

	if (LIST_NUM(o) == 0)
	{
		Insert(o, CopyUniStr(L""));
	}

	UNI_TOKEN_LIST *ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);

		UniTrimLeft(s);

		ret->Token[i] = s;
	}

	ReleaseList(o);
	Free(tmp);

	return ret;
}

static bool IsHelpStr(const char *str)
{
	if (str == NULL)
	{
		return false;
	}

	if (StrCmpi(str, "help") == 0 || StrCmpi(str, "?") == 0 ||
		StrCmpi(str, "man") == 0 || StrCmpi(str, "/man") == 0 ||
		StrCmpi(str, "-man") == 0 || StrCmpi(str, "--man") == 0 ||
		StrCmpi(str, "/help") == 0 || StrCmpi(str, "/?") == 0 ||
		StrCmpi(str, "-help") == 0 || StrCmpi(str, "-?") == 0 ||
		StrCmpi(str, "/h") == 0 || StrCmpi(str, "--help") == 0 ||
		StrCmpi(str, "--?") == 0)
	{
		return true;
	}

	return false;
}

bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param)
{
	wchar_t *str;
	wchar_t *tmp;
	char *cmd_name;
	bool b_exit = false;
	wchar_t *cmd_param;
	UINT ret = ERR_NO_ERROR;
	TOKEN_LIST *t;
	TOKEN_LIST *candidate;
	UINT i;
	if (c == NULL || (num_cmd >= 1 && cmd == NULL))
	{
		return false;
	}

	if (exec_command == NULL)
	{
RETRY:
		tmp = CopyStrToUni(prompt);

		if (c->ProgrammingMode)
		{
			wchar_t tmp2[MAX_PATH];

			UniFormat(tmp2, sizeof(tmp2), L"[PROMPT:%u:%s]\r\n", c->RetCode, tmp);

			Free(tmp);

			tmp = CopyUniStr(tmp2);
		}

		str = c->ReadLine(c, tmp, false);
		Free(tmp);

		if (str != NULL && UniIsEmptyStr(str))
		{
			Free(str);
			goto RETRY;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		if (UniStartWith(exec_command, L"vpncmd") == false)
		{
			if (prompt != NULL)
			{
				if (c->ConsoleType != CONSOLE_CSV)
				{
					UniFormat(tmp, sizeof(tmp), L"%S%s", prompt, exec_command);
					c->Write(c, tmp);
				}
			}
		}
		str = CopyUniStr(exec_command);
	}

	if (str == NULL)
	{
		return false;
	}

	UniTrimCrlf(str);
	UniTrim(str);

	if (UniIsEmptyStr(str))
	{
		Free(str);
		return true;
	}

	if (SeparateCommandAndParam(str, &cmd_name, &cmd_param) == false)
	{
		Free(str);
		return true;
	}

	if (StrLen(cmd_name) >= 2 && cmd_name[0] == '?' && cmd_name[1] != '?')
	{
		char tmp[MAX_SIZE];
		wchar_t *s;

		StrCpy(tmp, sizeof(tmp), cmd_name + 1);
		StrCpy(cmd_name, 0, tmp);

		s = CopyUniStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	if (StrLen(cmd_name) >= 2 && EndWith(cmd_name, "?") && cmd_name[StrLen(cmd_name) - 2] != '?')
	{
		wchar_t *s;

		cmd_name[StrLen(cmd_name) - 1] = 0;

		s = CopyUniStr(L"/?");
		Free(cmd_param);

		cmd_param = s;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = num_cmd;
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = CopyStr(cmd[i].Name);
	}

	if (IsHelpStr(cmd_name))
	{
		if (UniIsEmptyStr(cmd_param))
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CMD_HELP_1"), t->NumTokens);
			c->Write(c, tmp);

			PrintCandidateHelp(c, NULL, t, 1);

			c->Write(c, L"");
			c->Write(c, _UU("CMD_HELP_2"));
		}
		else
		{
			char *cmd_name;

			if (SeparateCommandAndParam(cmd_param, &cmd_name, NULL))
			{
				bool b = true;

				if (IsHelpStr(cmd_name))
				{
					b = false;
				}

				if (b)
				{
					wchar_t str[MAX_SIZE];

					UniFormat(str, sizeof(str), L"%S /help", cmd_name);
					DispatchNextCmdEx(c, str, NULL, cmd, num_cmd, param);
				}

				Free(cmd_name);
			}
		}
	}
	else if (StrCmpi(cmd_name, "exit") == 0 || StrCmpi(cmd_name, "quit") == 0)
	{
		b_exit = true;
	}
	else
	{
		candidate = GetRealnameCandidate(cmd_name, t);

		if (candidate == NULL || candidate->NumTokens == 0)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_UNKNOWN_CMD"), cmd_name);
			c->Write(c, tmp);

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else if (candidate->NumTokens >= 2)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGUOUS_CMD"), cmd_name);
			c->Write(c, tmp);
			c->Write(c, _UU("CON_AMBIGUOUS_CMD_1"));
			PrintCandidateHelp(c, NULL, candidate, 1);
			c->Write(c, _UU("CON_AMBIGUOUS_CMD_2"));

			c->RetCode = ERR_BAD_COMMAND_OR_PARAM;
		}
		else
		{
			char *real_cmd_name;

			real_cmd_name = candidate->Token[0];

			for (UINT i = 0;i < num_cmd;i++)
			{
				if (StrCmpi(cmd[i].Name, real_cmd_name) == 0)
				{
					if (cmd[i].Proc != NULL)
					{
						if(c->ConsoleType != CONSOLE_CSV)
						{
							wchar_t tmp[256];
							wchar_t *note;

							GetCommandHelpStr(cmd[i].Name, &note, NULL, NULL);
							UniFormat(tmp, sizeof(tmp), _UU("CMD_EXEC_MSG_NAME"), cmd[i].Name, note);
							c->Write(c, tmp);
						}

						ret = cmd[i].Proc(c, cmd[i].Name, cmd_param, param);

						if (ret == INFINITE)
						{
							b_exit = true;
						}
						else
						{
							c->RetCode = ret;
						}
					}
				}
			}
		}

		FreeToken(candidate);
	}

	FreeToken(t);
	Free(str);
	Free(cmd_name);
	Free(cmd_param);

	if (b_exit)
	{
		return false;
	}

	return true;
}

UINT GetConsoleWidth(CONSOLE *c)
{
	UINT size = c->GetWidth(c);

	if (size == 0)
	{
		size = 80;
	}

	if (size < 32)
	{
		size = 32;
	}

	if (size > 65536)
	{
		size = 65535;
	}

	return size;
}

bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param)
{
	UINT len, wp;
	wchar_t *tmp;
	wchar_t *src_tmp;
	if (src == NULL)
	{
		return false;
	}
	if (cmd != NULL)
	{
		*cmd = NULL;
	}
	if (param != NULL)
	{
		*param = NULL;
	}

	src_tmp = CopyUniStr(src);
	UniTrimCrlf(src_tmp);
	UniTrim(src_tmp);

	len = UniStrLen(src_tmp);
	tmp = Malloc(sizeof(wchar_t) * (len + 32));
	wp = 0;

	for (UINT i = 0;i < (len + 1);i++)
	{
		wchar_t c = src_tmp[i];

		switch (c)
		{
		case 0:
		case L' ':
		case L'\t':
			tmp[wp] = 0;
			if (UniIsEmptyStr(tmp))
			{
				Free(tmp);
				Free(src_tmp);
				return false;
			}
			if (cmd != NULL)
			{
				*cmd = CopyUniToStr(tmp);
				Trim(*cmd);
			}
			goto ESCAPE;

		default:
			tmp[wp++] = c;
			break;
		}
	}

ESCAPE:
	if (param != NULL)
	{
		*param = CopyUniStr(&src_tmp[wp]);
		UniTrim(*param);
	}

	Free(tmp);
	Free(src_tmp);

	return true;
}

TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list)
{
	TOKEN_LIST *ret;
	bool ok = false;
	if (input_name == NULL || real_name_list == NULL)
	{
		return NullToken();
	}

	LIST *o = NewListFast(NULL);

	for (UINT i = 0;i < real_name_list->NumTokens;i++)
	{
		char *name = real_name_list->Token[i];

		if (StrCmpi(name, input_name) == 0)
		{
			Insert(o, name);
			ok = true;
			break;
		}
	}

	if (ok == false)
	{
		for (UINT i = 0;i < real_name_list->NumTokens;i++)
		{
			char *name = real_name_list->Token[i];

			if (IsOmissionName(input_name, name) || IsNameInRealName(input_name, name))
			{
				Insert(o, name);
				ok = true;
			}
		}
	}

	if (ok)
	{
		ret = ListToTokenList(o);
	}
	else
	{
		ret = NullToken();
	}

	ReleaseList(o);

	return ret;
}

bool IsOmissionName(char *input_name, char *real_name)
{
	char oname[128];
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (IsAllUpperStr(real_name))
	{
		// Command of all capital letters do not take abbreviations
		return false;
	}

	GetOmissionName(oname, sizeof(oname), real_name);

	if (IsEmptyStr(oname))
	{
		return false;
	}

	if (StartWith(oname, input_name))
	{
		// e.g. the short name of AccountSecureCertSet is "ascs", so "asc" matches
		return true;
	}

	if (StartWith(input_name, oname))
	{
		// e.g. with AccountCreate and AccountConnect, "aconnect" matches only AccountConnect

		if (EndWith(real_name, &input_name[StrLen(oname)]))
		{
			return true;
		}
	}

	return false;
}

void GetOmissionName(char *dst, UINT size, char *src)
{
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, "");
	UINT len = StrLen(src);

	for (UINT i = 0;i < len;i++)
	{
		char c = src[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
			char tmp[2];
			tmp[0] = c;
			tmp[1] = 0;

			StrCat(dst, size, tmp);
		}
	}
}

bool IsNameInRealName(char *input_name, char *real_name)
{
	if (input_name == NULL || real_name == NULL)
	{
		return false;
	}

	if (StartWith(real_name, input_name))
	{
		return true;
	}

	return false;
}

LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param)
{
	UINT i;
	LIST *o;
	bool ok = true;
	TOKEN_LIST *param_list;
	TOKEN_LIST *real_name_list;
	bool help_mode = false;
	wchar_t *tmp;
	if (c == NULL || command == NULL || (num_param >= 1 && param == NULL) || cmd_name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num_param;i++)
	{
		if (IsEmptyStr(param[i].Name) == false)
		{
			if (param[i].Name[0] == '[')
			{
				param[i].Tmp = "";
			}
			else
			{
				param[i].Tmp = NULL;
			}
		}
		else
		{
			param[i].Tmp = "";
		}
	}

	real_name_list = ZeroMalloc(sizeof(TOKEN_LIST));
	real_name_list->NumTokens = num_param;
	real_name_list->Token = ZeroMalloc(sizeof(char *) * real_name_list->NumTokens);

	for (i = 0;i < real_name_list->NumTokens;i++)
	{
		real_name_list->Token[i] = CopyStr(param[i].Name);
	}

	param_list = GetCommandNameList(command);

	for (i = 0;i < param_list->NumTokens;i++)
	{
		char *s = param_list->Token[i];

		if (StrCmpi(s, "help") == 0 || StrCmpi(s, "?") == 0)
		{
			help_mode = true;
			break;
		}
	}

	tmp = ParseCommandEx(command, L"", NULL);
	if (tmp != NULL)
	{
		if (UniStrCmpi(tmp, L"?") == 0)
		{
			help_mode = true;
		}
		Free(tmp);
	}

	if (help_mode)
	{
		PrintCmdHelp(c, cmd_name, real_name_list);
		FreeToken(param_list);
		FreeToken(real_name_list);
		return NULL;
	}

	for (i = 0;i < param_list->NumTokens;i++)
	{
		TOKEN_LIST *candidate = GetRealnameCandidate(param_list->Token[i], real_name_list);

		if (candidate != NULL && candidate->NumTokens >= 1)
		{
			if (candidate->NumTokens >= 2)
			{
				wchar_t tmp[MAX_SIZE];

				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGUOUS_PARAM"), param_list->Token[i]);
				c->Write(c, tmp);
				UniFormat(tmp, sizeof(tmp), _UU("CON_AMBIGUOUS_PARAM_1"), cmd_name);
				c->Write(c, tmp);

				PrintCandidateHelp(c, cmd_name, candidate, 1);

				c->Write(c, _UU("CON_AMBIGUOUS_PARAM_2"));

				ok = false;
			}
			else
			{
				char *real_name = candidate->Token[0];

				for (UINT j = 0;j < num_param;j++)
				{
					if (StrCmpi(param[j].Name, real_name) == 0)
					{
						param[j].Tmp = param_list->Token[i];
					}
				}
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INVALID_PARAM"), param_list->Token[i], cmd_name, cmd_name);
			c->Write(c, tmp);

			ok = false;
		}

		FreeToken(candidate);
	}

	if (ok == false)
	{
		FreeToken(param_list);
		FreeToken(real_name_list);

		return NULL;
	}

	o = NewParamValueList();

	for (i = 0;i < num_param;i++)
	{
		bool prompt_input_value = false;
		PARAM *p = &param[i];

		if (p->Tmp != NULL || p->PromptProc != NULL)
		{
			wchar_t *name = CopyStrToUni(p->Name);
			wchar_t *tmp;
			wchar_t *str;

			if (p->Tmp != NULL)
			{
				tmp = CopyStrToUni(p->Tmp);
			}
			else
			{
				tmp = CopyStrToUni(p->Name);
			}

			str = ParseCommandEx(command, tmp, NULL);
			Free(tmp);
			if (str != NULL)
			{
				wchar_t *unistr;
				bool ret;
EVAL_VALUE:
				unistr = str;

				if (p->EvalProc != NULL)
				{
					ret = p->EvalProc(c, unistr, p->EvalProcParam);
				}
				else
				{
					ret = true;
				}

				if (ret == false)
				{
					if (p->PromptProc == NULL)
					{
						ok = false;
						Free(name);
						Free(str);
						break;
					}
					else if (c->ProgrammingMode)
					{
						// In programming mode, fail at once instead of asking again
						ok = false;
						Free(name);
						Free(str);
						break;
					}
					else
					{
						Free(str);
						str = NULL;
						goto SHOW_PROMPT;
					}
				}
				else
				{
					PARAM_VALUE *v;
					v = ZeroMalloc(sizeof(PARAM_VALUE));
					v->Name = CopyStr(p->Name);
					v->StrValue = CopyUniToStr(str);
					v->UniStrValue = CopyUniStr(str);
					v->IntValue = ToInt(v->StrValue);
					Insert(o, v);
				}
			}
			else
			{
				if (p->PromptProc != NULL)
				{
					wchar_t *tmp;
SHOW_PROMPT:
					tmp = NULL;
					if (c->ProgrammingMode == false)
					{
						tmp = p->PromptProc(c, p->PromptProcParam);
					}
					if (tmp == NULL)
					{
						ok = false;
						Free(str);
						Free(name);
						break;
					}
					else
					{
						c->Write(c, L"");
						str = tmp;
						prompt_input_value = true;
						goto EVAL_VALUE;
					}
				}
			}

			Free(str);
			Free(name);
		}
	}

	FreeToken(param_list);
	FreeToken(real_name_list);

	if (ok)
	{
		return o;
	}
	else
	{
		FreeParamValueList(o);
		return NULL;
	}
}

bool GetParamYes(LIST *o, char *name)
{
	char tmp[64];
	if (o == NULL)
	{
		return false;
	}

	char *s = GetParamStr(o, name);
	if (s == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), s);
	Trim(tmp);

	if (StartWith(tmp, "y"))
	{
		return true;
	}

	if (StartWith(tmp, "t"))
	{
		return true;
	}

	if (ToInt(tmp) != 0)
	{
		return true;
	}

	return false;
}

UINT GetParamInt(LIST *o, char *name)
{
	if (o == NULL)
	{
		return 0;
	}

	PARAM_VALUE *v = FindParamValue(o, name);
	if (v == NULL)
	{
		return 0;
	}
	else
	{
		return v->IntValue;
	}
}

wchar_t *GetParamUniStr(LIST *o, char *name)
{
	if (o == NULL)
	{
		return NULL;
	}

	PARAM_VALUE *v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->UniStrValue;
	}
}

char *GetParamStr(LIST *o, char *name)
{
	if (o == NULL)
	{
		return NULL;
	}

	PARAM_VALUE *v = FindParamValue(o, name);
	if (v == NULL)
	{
		return NULL;
	}
	else
	{
		return v->StrValue;
	}
}

PARAM_VALUE *FindParamValue(LIST *o, char *name)
{
	PARAM_VALUE t;
	if (o == NULL)
	{
		return NULL;
	}
	if (name == NULL)
	{
		name = "";
	}

	Zero(&t, sizeof(t));
	t.Name = name;

	PARAM_VALUE *ret = Search(o, &t);

	return ret;
}

void FreeParamValueList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		PARAM_VALUE *v = LIST_DATA(o, i);

		Free(v->StrValue);
		Free(v->UniStrValue);
		Free(v->Name);
		Free(v);
	}

	ReleaseList(o);
}

static int CmpParamValue(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	PARAM_VALUE *v1 = *(PARAM_VALUE **)p1;
	PARAM_VALUE *v2 = *(PARAM_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	if (IsEmptyStr(v1->Name) && IsEmptyStr(v2->Name))
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

LIST *NewParamValueList()
{
	return NewListFast(CmpParamValue);
}

TOKEN_LIST *GetCommandNameList(wchar_t *str)
{
	TOKEN_LIST *t;
	if (str == NULL)
	{
		return NullToken();
	}

	Free(ParseCommandEx(str, L"dummy_str", &t));

	return t;
}

wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list)
{
	static const wchar_t cmd_prefixes[2] = {L'/', L'-'};
	static const wchar_t cmd_suffixes[4] = {L' ', L'\t', L':', L'='};
	UNI_TOKEN_LIST *t;
	wchar_t *ret = NULL;
	if (str == NULL)
	{
		return NULL;
	}
	if (name != NULL && UniIsEmptyStr(name))
	{
		name = NULL;
	}

	LIST *o = NULL;
	if (param_list != NULL)
	{
		o = NewListFast(CompareStr);
	}

	wchar_t *tmp = CopyUniStr(str);
	UniTrim(tmp);

	// Look for /CMD or -CMD followed by a space, a tab, ':' or '=', in that
	// order. A match preceded by its own prefix character (//CMD, --CMD) does
	// not count.
	UINT i = INFINITE;
	for (UINT prefix_index = 0;prefix_index < 2 && i == INFINITE;prefix_index++)
	{
		for (UINT suffix_index = 0;suffix_index < 4 && i == INFINITE;suffix_index++)
		{
			wchar_t key[6];

			key[0] = cmd_prefixes[prefix_index];
			key[1] = L'C';
			key[2] = L'M';
			key[3] = L'D';
			key[4] = cmd_suffixes[suffix_index];
			key[5] = 0;

			i = UniSearchStrEx(tmp, key, 0, false);
			if (i != INFINITE && i >= 1 && tmp[i - 1] == cmd_prefixes[prefix_index])
			{
				i = INFINITE;
			}
		}
	}

	if (i != INFINITE)
	{
		char *s = CopyStr("CMD");
		if (InsertStr(o, s) == false)
		{
			Free(s);
		}
		if (UniStrCmpi(name, L"CMD") == 0)
		{
			ret = CopyUniStr(&str[i + 5]);
			UniTrim(ret);
		}
		else
		{
			tmp[i] = 0;
		}
	}

	if (ret == NULL)
	{
		t = UniParseCmdLine(tmp);

		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				wchar_t *token = t->Token[i];

				if ((token[0] == L'-' && token[1] != L'-') ||
					(UniStrCmpi(token, L"--help") == 0) ||
					(token[0] == L'/' && token[1] != L'/'))
				{

					if (UniStrCmpi(token, L"--help") == 0)
					{
						token++;
					}

					UINT i = UniSearchStrEx(token, L":", 0, false);
					if (i == INFINITE)
					{
						i = UniSearchStrEx(token, L"=", 0, false);
					}
					if (i != INFINITE)
					{
						wchar_t *tmp = CopyUniStr(token);
						tmp[i] = 0;

						char *a = CopyUniToStr(&tmp[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &tmp[1]) == 0)
						{
							if (ret == NULL)
							{
								ret = CopyUniStr(&token[i + 1]);
							}
						}

						Free(tmp);
					}
					else
					{
						char *a = CopyUniToStr(&token[1]);
						if (InsertStr(o, a) == false)
						{
							Free(a);
						}

						if (UniStrCmpi(name, &token[1]) == 0)
						{
							if (ret == NULL)
							{
								ret = CopyUniStr(L"");
							}
						}
					}
				}
				else
				{
					if (name == NULL)
					{
						if (ret == NULL)
						{
							if (token[0] == L'-' && token[1] == L'-')
							{
								ret = CopyUniStr(&token[1]);
							}
							else if (token[0] == L'/' && token[1] == L'/')
							{
								ret = CopyUniStr(&token[1]);
							}
							else
							{
								ret = CopyUniStr(token);
							}
						}
					}
				}
			}

			UniFreeToken(t);
		}
	}

	Free(tmp);

	if (o != NULL)
	{
		TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));

		t->NumTokens = LIST_NUM(o);
		t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

		for (UINT i = 0;i < t->NumTokens;i++)
		{
			t->Token[i] = LIST_DATA(o, i);
		}

		ReleaseList(o);

		*param_list = t;
	}

	if (UniStrCmpi(ret, L"none") == 0 || UniStrCmpi(ret, L"null") == 0)
	{
		// Null and none are reserved words
		ret[0] = 0;
	}

	return ret;
}

static bool PasswordPrompt(char *password, UINT size)
{
	UINT wp;
	bool escape = false;
	void *console;
	if (password == NULL || size <= 1)
	{
		if (size >= 1)
		{
			password[0] = 0;
		}
		return false;
	}

	wp = 0;

	Zero(password, size);

	console = SetConsoleRaw();

	while (true)
	{
		int c;

		c = _getch();

		if (c >= 0x20 && c <= 0x7E)
		{
			if ((wp + 1) < size)
			{
				password[wp++] = (char)c;
				putc('*', stdout);
			}
		}
		else if (c == 0x03)
		{
			RestoreConsole(console);
			exit(0);
		}
		else if (c == 0x04 || c == 0x1a || c == 0x0D || c==0x0A)
		{
			if (c == 0x04 || c == 0x1a)
			{
				escape = true;
			}
			break;
		}
		else if (c == 0xE0)
		{
			c = _getch();
			if (c == 0x4B || c == 0x53)
			{
				goto BACKSPACE;
			}
		}
		else if (c == 0x08 || c == 0x7F)
		{
BACKSPACE:
			if (wp >= 1)
			{
				password[--wp] = 0;
				putc(0x08, stdout);
				putc(' ', stdout);
				putc(0x08, stdout);
			}
		}
	}
	Print("\n");

	RestoreConsole(console);

	return (escape ? false : true);
}

static wchar_t *Prompt(wchar_t *prompt_str)
{
	wchar_t *ret = NULL;
	wchar_t *tmp = NULL;
	if (prompt_str == NULL)
	{
		prompt_str = L"";
	}

	UniPrint(L"%s", prompt_str);
	tmp = Malloc(MAX_PROMPT_STRSIZE);
	// The size is in bytes: at most MAX_PROMPT_STRSIZE / sizeof(wchar_t) - 1 characters and the terminator
	if (UniGetLineWin32(tmp, MAX_PROMPT_STRSIZE))
	{
		bool escape = false;

		UINT len = UniStrLen(tmp);
		for (UINT i = 0;i < len;i++)
		{
			if (tmp[i] == 0x04 || tmp[i] == 0x1A)
			{
				escape = true;
				break;
			}
		}

		if (escape == false)
		{
			UniTrimCrlf(tmp);

			ret = CopyUniStr(tmp);
		}
	}
	Free(tmp);

	if (ret == NULL)
	{
		Print("\n");
	}

	return ret;
}

void *SetConsoleRaw()
{
	return Malloc(0);
}

void RestoreConsole(void *p)
{
	if (p != NULL)
	{
		Free(p);
	}
}


CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile)
{
	IO *in_io = NULL, *out_io = NULL;
	CONSOLE *c = ZeroMalloc(sizeof(CONSOLE));

	c->ConsoleType = CONSOLE_LOCAL;
	c->Free = ConsoleLocalFree;
	c->ReadLine = ConsoleLocalReadLine;
	c->ReadPassword = ConsoleLocalReadPassword;
	c->Write = ConsoleLocalWrite;
	c->GetWidth = ConsoleLocalGetWidth;
	c->OutputLock = NewLock();

	if (UniIsEmptyStr(infile) == false)
	{
		in_io = FileOpenW(infile, false);
		if (in_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_ERROR"), infile);
			c->Write(c, tmp);
			Free(c);
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_INFILE_START"), infile);
			c->Write(c, tmp);
		}
	}

	if (UniIsEmptyStr(outfile) == false)
	{
		out_io = FileCreateW(outfile);
		if (out_io == NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_ERROR"), outfile);
			c->Write(c, tmp);
			Free(c);

			if (in_io != NULL)
			{
				FileClose(in_io);
			}
			return NULL;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), _UU("CON_OUTFILE_START"), outfile);
			c->Write(c, tmp);
		}
	}

	LOCAL_CONSOLE_PARAM *p = ZeroMalloc(sizeof(LOCAL_CONSOLE_PARAM));
	c->Param = p;

	p->InFile = in_io;
	p->OutFile = out_io;

	if (in_io != NULL)
	{
		UINT size = FileSize(in_io);
		void *buf = ZeroMalloc(size + 1);
		FileRead(in_io, buf, size);

		p->InBuf = NewBuf();
		WriteBuf(p->InBuf, buf, size);
		Free(buf);

		p->InBuf->Current = 0;
	}

	return c;
}

void ConsoleLocalFree(CONSOLE *c)
{
	if (c == NULL)
	{
		return;
	}

	LOCAL_CONSOLE_PARAM *p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p != NULL)
	{
		if (p->InFile != NULL)
		{
			FileClose(p->InFile);
			FreeBuf(p->InBuf);
		}

		if (p->OutFile != NULL)
		{
			FileClose(p->OutFile);
		}

		Free(p);
	}

	DeleteLock(c->OutputLock);

	Free(c);
}

UINT ConsoleLocalGetWidth(CONSOLE *c)
{
	UINT ret = 0;
	if (c == NULL)
	{
		return 0;
	}

	ret = MsGetConsoleWidth();

	return ret;
}

wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile)
{
	wchar_t *ret;
	if (c == NULL)
	{
		return NULL;
	}
	LOCAL_CONSOLE_PARAM *p = (LOCAL_CONSOLE_PARAM *)c->Param;
	if (prompt == NULL)
	{
		prompt = L">";
	}

	ConsoleWriteOutFile(c, prompt, false);

	if (nofile == false && p->InBuf != NULL)
	{
		ret = ConsoleReadNextFromInFile(c);

		if (ret != NULL)
		{
			UniPrint(L"%s", prompt);

			UniPrint(L"%s\n", ret);
		}
	}
	else
	{
		ret = Prompt(prompt);
	}

	if (ret != NULL)
	{
		ConsoleWriteOutFile(c, ret, true);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
	}

	return ret;
}

char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt)
{
	char tmp[64];
	if (c == NULL)
	{
		return NULL;
	}
	if (prompt == NULL)
	{
		prompt = L"Password>";
	}

	UniPrint(L"%s", prompt);
	ConsoleWriteOutFile(c, prompt, false);

	if (PasswordPrompt(tmp, sizeof(tmp)))
	{
		ConsoleWriteOutFile(c, L"********", true);
		return CopyStr(tmp);
	}
	else
	{
		ConsoleWriteOutFile(c, _UU("CON_USER_CANCEL"), true);
		return NULL;
	}
}

bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str)
{
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniPrint(L"%s%s", str, (UniEndWith(str, L"\n") ? L"" : L"\n"));

	ConsoleWriteOutFile(c, str, true);

	return true;
}

wchar_t *ConsoleReadNextFromInFile(CONSOLE *c)
{
	char *str;
	if (c == NULL)
	{
		return NULL;
	}

	LOCAL_CONSOLE_PARAM *p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p->InBuf == NULL)
	{
		return NULL;
	}

	while (true)
	{
		str = CfgReadNextLine(p->InBuf);

		if (str == NULL)
		{
			return NULL;
		}

		Trim(str);

		if (IsEmptyStr(str) == false)
		{
			UINT size = CalcUtf8ToUni((BYTE *)str, StrLen(str));
			wchar_t *ret = ZeroMalloc(size + 32);
			Utf8ToUni(ret, size, (BYTE *)str, StrLen(str));

			Free(str);

			return ret;
		}

		Free(str);
	}
}

void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf)
{
	if (c == NULL || str == NULL)
	{
		return;
	}

	LOCAL_CONSOLE_PARAM *p = (LOCAL_CONSOLE_PARAM *)c->Param;

	if (p != NULL && p->OutFile != NULL)
	{
		wchar_t *tmp = UniNormalizeCrlf(str);

		UINT utf8_size = CalcUniToUtf8(tmp);
		UCHAR *utf8 = ZeroMalloc(utf8_size + 1);
		UniToUtf8(utf8, utf8_size + 1, tmp);

		FileWrite(p->OutFile, utf8, utf8_size);

		if (UniEndWith(str, L"\n") == false && add_last_crlf)
		{
			char *crlf = "\r\n";
			FileWrite(p->OutFile, "\r\n", StrLen(crlf));
		}

		Free(utf8);
		Free(tmp);
	}

}

