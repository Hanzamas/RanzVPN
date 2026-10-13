// Console.h
// Header of Console.c

#ifndef	CONSOLE_H
#define	CONSOLE_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

#define	MAX_PROMPT_STRSIZE			65536

#define	CONSOLE_LOCAL				0
#define	CONSOLE_CSV					1

typedef wchar_t *(PROMPT_PROC)(CONSOLE *c, void *param);

typedef bool (EVAL_PROC)(CONSOLE *c, wchar_t *str, void *param);

struct PARAM
{
	char *Name;
	PROMPT_PROC *PromptProc;	// Called when the parameter is not given; skipped if NULL
	void *PromptProcParam;
	EVAL_PROC *EvalProc;
	void *EvalProcParam;
	char *Tmp;
};

struct PARAM_VALUE
{
	char *Name;
	char *StrValue;
	wchar_t *UniStrValue;
	UINT IntValue;
};

struct CONSOLE
{
	UINT ConsoleType;
	UINT RetCode;
	void *Param;
	void (*Free)(CONSOLE *c);
	wchar_t *(*ReadLine)(CONSOLE *c, wchar_t *prompt, bool nofile);
	char *(*ReadPassword)(CONSOLE *c, wchar_t *prompt);
	bool (*Write)(CONSOLE *c, wchar_t *str);
	UINT (*GetWidth)(CONSOLE *c);
	bool ProgrammingMode;
	LOCK *OutputLock;
};

struct LOCAL_CONSOLE_PARAM
{
	IO *InFile;
	BUF *InBuf;
	IO *OutFile;
	UINT Win32_OldConsoleWidth;
};

typedef UINT (COMMAND_PROC)(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

struct CMD
{
	char *Name;
	COMMAND_PROC *Proc;
};

struct CMD_EVAL_MIN_MAX
{
	char *StrName;
	UINT MinValue, MaxValue;
};


wchar_t *Prompt(wchar_t *prompt_str);
bool PasswordPrompt(char *password, UINT size);
void *SetConsoleRaw();
void RestoreConsole(void *p);
wchar_t *ParseCommandEx(wchar_t *str, wchar_t *name, TOKEN_LIST **param_list);
TOKEN_LIST *GetCommandNameList(wchar_t *str);
LIST *NewParamValueList();
int CmpParamValue(void *p1, void *p2);
void FreeParamValueList(LIST *o);
PARAM_VALUE *FindParamValue(LIST *o, char *name);
char *GetParamStr(LIST *o, char *name);
wchar_t *GetParamUniStr(LIST *o, char *name);
UINT GetParamInt(LIST *o, char *name);
bool GetParamYes(LIST *o, char *name);
LIST *ParseCommandList(CONSOLE *c, char *cmd_name, wchar_t *command, PARAM param[], UINT num_param);
bool IsNameInRealName(char *input_name, char *real_name);
void GetOmissionName(char *dst, UINT size, char *src);
bool IsOmissionName(char *input_name, char *real_name);
TOKEN_LIST *GetRealnameCandidate(char *input_name, TOKEN_LIST *real_name_list);
bool SeparateCommandAndParam(wchar_t *src, char **cmd, wchar_t **param);
UINT GetConsoleWidth(CONSOLE *c);
bool DispatchNextCmdEx(CONSOLE *c, wchar_t *exec_command, char *prompt, CMD cmd[], UINT num_cmd, void *param);
void PrintCandidateHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *candidate_list, UINT left_space);
UNI_TOKEN_LIST *SeparateStringByWidth(wchar_t *str, UINT width);
UINT GetNextWordWidth(wchar_t *str);
bool IsWordChar(wchar_t c);
void GetCommandHelpStr(char *command_name, wchar_t **description, wchar_t **args, wchar_t **help);
void GetCommandParamHelpStr(char *command_name, char *param_name, wchar_t **description);
bool CmdEvalMinMax(CONSOLE *c, wchar_t *str, void *param);
wchar_t *CmdPrompt(CONSOLE *c, void *param);
bool CmdEvalNotEmpty(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIsFile(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalSafe(CONSOLE *c, wchar_t *str, void *param);
void PrintCmdHelp(CONSOLE *c, char *cmd_name, TOKEN_LIST *param_list);
int CompareCandidateStr(void *p1, void *p2);
bool IsHelpStr(char *str);

CONSOLE *NewLocalConsole(wchar_t *infile, wchar_t *outfile);
void ConsoleLocalFree(CONSOLE *c);
wchar_t *ConsoleLocalReadLine(CONSOLE *c, wchar_t *prompt, bool nofile);
char *ConsoleLocalReadPassword(CONSOLE *c, wchar_t *prompt);
bool ConsoleLocalWrite(CONSOLE *c, wchar_t *str);
void ConsoleWriteOutFile(CONSOLE *c, wchar_t *str, bool add_last_crlf);
wchar_t *ConsoleReadNextFromInFile(CONSOLE *c);
UINT ConsoleLocalGetWidth(CONSOLE *c);


#endif

