// consoleline.c
// Named console input test of vpntest ("consoleline" command, SEC-7 #96)
//
// Pins the console line readers of vpncmd (Cedar/Console.c) and UniToInt (Mayaqua/Internat.c) on
// input longer than their buffers. Prompt, the standard input reader behind ConsoleLocalReadLine,
// allocated MAX_PROMPT_STRSIZE bytes and let fgetws write up to MAX_PROMPT_STRSIZE - 1 wide
// characters into them: a line of more than 32767 characters ran past the heap block. UniToInt
// copied its string into a 128-byte stack buffer through UniToStrForSingleChars, which never read
// its size: a string of 128 or more characters ran past the stack buffer.
//
// Prompt reads the standard input of the process, so each standard input case runs this program
// again as a child ("consoleline child") with a prepared file as its standard input and another
// file as its standard output. The child reads lines through ConsoleLocalReadLine until a read is
// cancelled and prints one CONSOLELINE line per read; the parent compares those lines. The /IN
// file reader (ConsoleReadNextFromInFile) runs the same way and must keep a long line whole.
// ConsoleLocalReadPassword is not run: it reads key presses from the console (_getch), which a CI
// runner does not have, and it already stops at its 64-byte buffer.
//
// A redirected standard input is UTF-8, as the /IN file is (FND-9 #106): a line with a non-ASCII hub
// name comes back unchanged. The child prints such a line as its UTF-16 code units ("CODES"), so the
// result does not depend on the code page of its standard output.
//
// The former Prompt overran its block on the 40000-character line: the child ended in the heap
// canary check of Free or in an AddressSanitizer report, and that case fails. The former
// UniToStrForSingleChars wrote past its size (the bounded copy case fails) and the 302-character
// UniToInt case overran the stack of this process, so it runs last. Prints "CONSOLELINE TEST OK"
// only when every check passes, and frees everything it allocates.

#include "Cedar/Console.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <windows.h>

#define	CONSOLELINE_LONG_LEN		40000		// Characters of the long line, more than a prompt line holds
#define	CONSOLELINE_PROMPT_MAX		((UINT)(MAX_PROMPT_STRSIZE / sizeof(wchar_t) - 1))	// Characters a prompt line holds
#define	CONSOLELINE_SHORT_MAX		64			// The child prints longer lines by their length only
#define	CONSOLELINE_MAX_READS		16			// Reads of one child at most
#define	CONSOLELINE_CHILD_TIMEOUT	120000		// Milliseconds a child may run
#define	CONSOLELINE_INT_LEN			302			// Characters of the long UniToInt string
#define	CONSOLELINE_SENTINEL		'U'			// Bytes past the size of UniToStrForSingleChars
#define	CONSOLELINE_MARK			"CONSOLELINE "	// Prefix of the result lines of the child
#define	CONSOLELINE_ENV_INFILE		L"RANZ_CONSOLELINE_INFILE"	// /IN file of the child; none: the standard input

// Files of the child in the temporary directory of the process (MsGetMyTempDirW)
#define	CONSOLELINE_STDIN_FILE		L"consoleline_stdin.txt"
#define	CONSOLELINE_STDOUT_FILE		L"consoleline_stdout.txt"
#define	CONSOLELINE_IN_FILE			L"consoleline_in.txt"

// Run state of the test
typedef struct CONSOLELINE_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} CONSOLELINE_CTX;

// Record one check: print [PASS] or [FAIL]
static bool ConsoleLineCheck(CONSOLELINE_CTX *ctx, bool ok, char *what)
{
	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	Print("  [FAIL] %s\n", what);

	ctx->NumFailed++;

	return false;
}

// True when the len characters of s are all 'A'
static bool ConsoleLineAllA(const wchar_t *s, UINT len)
{
	for (UINT i = 0;i < len;i++)
	{
		if (s[i] != L'A')
		{
			return false;
		}
	}

	return true;
}

// True when every character of s is printable ASCII
static bool ConsoleLineIsAscii(const wchar_t *s)
{
	for (UINT i = 0;s[i] != 0;i++)
	{
		if (s[i] < 0x20 || s[i] > 0x7e)
		{
			return false;
		}
	}

	return true;
}

// The UTF-16 code units of s in hexadecimal, each after a space (" 0048 00E9")
static void ConsoleLineCodes(char *dst, UINT size, const wchar_t *s)
{
	char *hex = "0123456789ABCDEF";

	dst[0] = 0;

	for (UINT i = 0;s[i] != 0;i++)
	{
		UINT v = (UINT)s[i];
		char one[6];

		one[0] = ' ';
		one[1] = hex[(v >> 12) & 0xf];
		one[2] = hex[(v >> 8) & 0xf];
		one[3] = hex[(v >> 4) & 0xf];
		one[4] = hex[v & 0xf];
		one[5] = 0;

		StrCat(dst, size, one);
	}
}

// Child: read lines through ConsoleLocalReadLine until a read is cancelled, one result line per read
static void ConsoleLineChild()
{
	wchar_t infile[MAX_PATH];

	UINT len = GetEnvironmentVariableW(CONSOLELINE_ENV_INFILE, infile, MAX_PATH);
	if (len == 0 || len >= MAX_PATH)
	{
		infile[0] = 0;
	}

	CONSOLE *c = NewLocalConsole(infile, NULL);
	if (c == NULL)
	{
		Print(CONSOLELINE_MARK "NO CONSOLE\n");
		return;
	}

	for (UINT i = 0;i < CONSOLELINE_MAX_READS;i++)
	{
		wchar_t *s = c->ReadLine(c, L"", false);

		if (s == NULL)
		{
			Print(CONSOLELINE_MARK "CANCEL\n");
			break;
		}

		len = UniStrLen(s);
		if (len <= CONSOLELINE_SHORT_MAX && ConsoleLineIsAscii(s))
		{
			Print(CONSOLELINE_MARK "LINE [%S]\n", s);
		}
		else if (len <= CONSOLELINE_SHORT_MAX)
		{
			char codes[CONSOLELINE_SHORT_MAX * 5 + 1];

			ConsoleLineCodes(codes, sizeof(codes), s);
			Print(CONSOLELINE_MARK "CODES%s\n", codes);
		}
		else
		{
			Print(CONSOLELINE_MARK "LONG %u %s\n", len, ConsoleLineAllA(s, len) ? "ALL-A" : "MIXED");
		}

		Free(s);
	}

	c->Free(c);

	Print(CONSOLELINE_MARK "CHILD DONE\n");
}

// Input of the bytes of str
static BUF *ConsoleLineInput(const char *str)
{
	return MemToBuf(str, StrLen(str));
}

// Input of before, CONSOLELINE_LONG_LEN times 'A' and after
static BUF *ConsoleLineLongInput(const char *before, const char *after)
{
	BUF *b = NewBuf();
	char *a = MakeCharArray('A', CONSOLELINE_LONG_LEN);

	WriteBuf(b, before, StrLen(before));
	WriteBuf(b, a, CONSOLELINE_LONG_LEN);
	WriteBuf(b, after, StrLen(after));

	Free(a);

	return b;
}

// Open path for the child as an inheritable handle: read an existing file, or create one to write
static HANDLE ConsoleLineOpenForChild(wchar_t *path, bool for_write)
{
	SECURITY_ATTRIBUTES sa;

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	return CreateFileW(path, for_write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ, &sa,
		for_write ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

// Run this program as a child ("consoleline child") with the bytes of in as its standard input and,
// when infile is not NULL, the bytes of infile as its /IN file. Returns its standard output and
// standard error as one NUL-terminated string (Free it), or NULL when it cannot be started or does
// not end in time; its exit code goes to exit_code.
static char *ConsoleLineRunChild(BUF *in, BUF *infile, UINT *exit_code)
{
	wchar_t stdin_path[MAX_PATH], stdout_path[MAX_PATH], in_path[MAX_PATH];
	wchar_t exe[MAX_PATH];
	wchar_t cmd[MAX_PATH * 2];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD code = 1;
	bool ended = false;
	char *ret = NULL;
	BUF *out;

	*exit_code = 1;

	CombinePathW(stdin_path, sizeof(stdin_path), MsGetMyTempDirW(), CONSOLELINE_STDIN_FILE);
	CombinePathW(stdout_path, sizeof(stdout_path), MsGetMyTempDirW(), CONSOLELINE_STDOUT_FILE);
	CombinePathW(in_path, sizeof(in_path), MsGetMyTempDirW(), CONSOLELINE_IN_FILE);

	DumpBufW(in, stdin_path);
	if (infile != NULL)
	{
		DumpBufW(infile, in_path);
		SetEnvironmentVariableW(CONSOLELINE_ENV_INFILE, in_path);
	}

	HANDLE h_in = ConsoleLineOpenForChild(stdin_path, false);
	HANDLE h_out = ConsoleLineOpenForChild(stdout_path, true);

	GetExeNameW(exe, sizeof(exe));
	UniFormat(cmd, sizeof(cmd), L"\"%s\" consoleline child", exe);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = h_in;
	si.hStdOutput = h_out;
	si.hStdError = h_out;

	Zero(&pi, sizeof(pi));

	if (h_in != INVALID_HANDLE_VALUE && h_out != INVALID_HANDLE_VALUE &&
		CreateProcessW(exe, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		if (WaitForSingleObject(pi.hProcess, CONSOLELINE_CHILD_TIMEOUT) == WAIT_OBJECT_0)
		{
			ended = true;
			GetExitCodeProcess(pi.hProcess, &code);
		}
		else
		{
			TerminateProcess(pi.hProcess, 1);
			WaitForSingleObject(pi.hProcess, 10000);
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	SetEnvironmentVariableW(CONSOLELINE_ENV_INFILE, NULL);

	if (h_in != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h_in);
	}
	if (h_out != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h_out);
	}

	if (ended)
	{
		*exit_code = code;

		out = ReadDumpW(stdout_path);
		ret = ZeroMalloc((out == NULL ? 0 : out->Size) + 1);
		if (out != NULL)
		{
			Copy(ret, out->Buf, out->Size);
			FreeBuf(out);
		}
	}

	FileDeleteW(stdin_path);
	FileDeleteW(stdout_path);
	if (infile != NULL)
	{
		FileDeleteW(in_path);
	}

	return ret;
}

// The CONSOLELINE lines of the output of a child, without their prefix, joined by '|'
static void ConsoleLineResult(char *result, UINT size, const char *out)
{
	TOKEN_LIST *t = ParseToken(out, "\r\n");

	result[0] = 0;

	for (UINT i = 0;i < t->NumTokens;i++)
	{
		char *line = t->Token[i];

		if (StartWith(line, CONSOLELINE_MARK))
		{
			if (result[0] != 0)
			{
				StrCat(result, size, "|");
			}
			StrCat(result, size, line + StrLen(CONSOLELINE_MARK));
		}
	}

	FreeToken(t);
}

// Print the output of a failed child, long lines by their length only
static void ConsoleLinePrintOutput(const char *out)
{
	TOKEN_LIST *t = ParseToken(out, "\r\n");

	for (UINT i = 0;i < t->NumTokens;i++)
	{
		UINT len = StrLen(t->Token[i]);

		if (len <= CONSOLELINE_SHORT_MAX * 4)
		{
			Print("         child| %s\n", t->Token[i]);
		}
		else
		{
			Print("         child| (%u characters)\n", len);
		}
	}

	FreeToken(t);
}

// One child case: its CONSOLELINE lines must be expect, its exit code 0 and its memory without leaks.
// Frees in and infile.
static void ConsoleLineCase(CONSOLELINE_CTX *ctx, char *what, BUF *in, BUF *infile, char *expect)
{
	char result[MAX_SIZE];
	UINT exit_code = 1;
	char *out = ConsoleLineRunChild(in, infile, &exit_code);

	result[0] = 0;
	if (out != NULL)
	{
		ConsoleLineResult(result, sizeof(result), out);
	}

	bool ok = (out != NULL && exit_code == 0 && StrCmp(result, expect) == 0 && InStrEx(out, "NO MEMORY LEAKS", true));

	if (ConsoleLineCheck(ctx, ok, what) == false)
	{
		if (out == NULL)
		{
			Print("         the child did not start or did not end within %u ms\n", CONSOLELINE_CHILD_TIMEOUT);
		}
		else
		{
			Print("         got [%s], exit code %u, expected [%s] and exit code 0\n", result, exit_code, expect);
			ConsoleLinePrintOutput(out);
		}
	}

	Free(out);
	FreeBuf(in);
	FreeBuf(infile);
}

// UniToStrForSingleChars stops at its size and maps the characters as before
static void ConsoleLineSingleChars(CONSOLELINE_CTX *ctx)
{
	char dst[16];
	char map[8];
	bool untouched = true;

	for (UINT i = 0;i < sizeof(dst) - 1;i++)
	{
		dst[i] = CONSOLELINE_SENTINEL;
	}
	dst[sizeof(dst) - 1] = 0;

	UniToStrForSingleChars(dst, 8, L"abcdefghij");

	for (UINT i = 8;i < sizeof(dst) - 1;i++)
	{
		if (dst[i] != CONSOLELINE_SENTINEL)
		{
			untouched = false;
		}
	}

	ConsoleLineCheck(ctx, StrCmp(dst, "abcdefg") == 0 && untouched,
		"UniToStrForSingleChars with size 8 writes 7 characters and the terminator, nothing past them");

	Zero(map, sizeof(map));
	UniToStrForSingleChars(map, sizeof(map), L"a\x00e9\x4e2d" L"b");

	ConsoleLineCheck(ctx, map[0] == 'a' && (UCHAR)map[1] == 0xe9 && map[2] == ' ' && map[3] == 'b' && map[4] == 0,
		"UniToStrForSingleChars keeps U+0000 to U+00FF and turns other characters into spaces");
}

// UniToInt on numbers up to its buffer and on a longer string
static void ConsoleLineUniToInt(CONSOLELINE_CTX *ctx)
{
	wchar_t *s = ZeroMalloc((CONSOLELINE_INT_LEN + 1) * sizeof(wchar_t));

	ConsoleLineCheck(ctx, UniToInt(L"123456789") == 123456789, "UniToInt of 123456789");

	// 126 zeros and a 7: 127 characters and the terminator fill the 128-byte buffer of UniToInt
	for (UINT i = 0;i < 126;i++)
	{
		s[i] = L'0';
	}
	s[126] = L'7';
	s[127] = 0;

	ConsoleLineCheck(ctx, UniToInt(s) == 7, "UniToInt of a 127-character number (126 zeros and 7)");

	// 42 and 300 letters: the former copy ran 175 bytes past the buffer
	s[0] = L'4';
	s[1] = L'2';
	for (UINT i = 2;i < CONSOLELINE_INT_LEN;i++)
	{
		s[i] = L'x';
	}
	s[CONSOLELINE_INT_LEN] = 0;

	ConsoleLineCheck(ctx, UniToInt(s) == 42, "UniToInt of a 302-character string (42 and 300 letters) is 42");

	Free(s);
}

// One ParseCommandEx case: the CMD value of line is expect, or NULL when expect is NULL
static void ConsoleLineParseCmdCase(CONSOLELINE_CTX *ctx, wchar_t *line, const wchar_t *expect, char *what)
{
	wchar_t *ret = ParseCommandEx(line, L"CMD", NULL);
	bool ok;

	if (expect == NULL)
	{
		ok = (ret == NULL);
	}
	else
	{
		ok = (ret != NULL && UniStrCmp(ret, expect) == 0);
	}

	ConsoleLineCheck(ctx, ok, what);

	Free(ret);
}

// ParseCommandEx finds /CMD and -CMD with a space, a tab, ':' or '=' (FND-48)
static void ConsoleLineParseCmd(CONSOLELINE_CTX *ctx)
{
	ConsoleLineParseCmdCase(ctx, L"vpncmd /CMD HubList", L"HubList", "/CMD and a space");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /CMD\tHubList", L"HubList", "/CMD and a tab");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /CMD:HubList", L"HubList", "/CMD:");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /CMD=HubList", L"HubList", "/CMD=");
	ConsoleLineParseCmdCase(ctx, L"vpncmd -CMD HubList", L"HubList", "-CMD and a space");
	ConsoleLineParseCmdCase(ctx, L"vpncmd -CMD\tHubList", L"HubList", "-CMD and a tab");
	ConsoleLineParseCmdCase(ctx, L"vpncmd -CMD:HubList", L"HubList", "-CMD:");
	ConsoleLineParseCmdCase(ctx, L"vpncmd -CMD=HubList", L"HubList", "-CMD=");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /cmd HubList", L"HubList", "/cmd in lower case");
	// "/" "/" keeps a doubled slash out of the source, which the brace checks read as a comment
	ConsoleLineParseCmdCase(ctx, L"vpncmd /" L"/CMD HubList", NULL, "/CMD after a slash does not count");
	ConsoleLineParseCmdCase(ctx, L"vpncmd --CMD HubList", NULL, "-CMD after a dash does not count");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /" L"/CMD a /CMD b", L"", "The first /CMD and a space decides: a slash before it hides the later /CMD");
	ConsoleLineParseCmdCase(ctx, L"vpncmd -CMD:a /CMD=b", L"b", "/CMD before -CMD");
	ConsoleLineParseCmdCase(ctx, L"vpncmd /CMD=a /CMD b", L"b", "/CMD and a space before /CMD=");
}

// consoleline: console line readers and UniToInt on input longer than their buffers
void consoleline_test(UINT num, char **arg)
{
	CONSOLELINE_CTX ctx;
	char expect[MAX_SIZE];

	if (num >= 1 && StrCmpi(arg[0], "child") == 0)
	{
		ConsoleLineChild();
		return;
	}

	Zero(&ctx, sizeof(ctx));

	Print("Console input test\n");

	ConsoleLineSingleChars(&ctx);

	ConsoleLineParseCmd(&ctx);

	// Prompt, through the standard input of a child
	Format(expect, sizeof(expect), "LINE [hello world]|LONG %u ALL-A|LINE [next]|CANCEL|CHILD DONE", CONSOLELINE_PROMPT_MAX);
	ConsoleLineCase(&ctx, "A 40000-character line from a redirected standard input gives its first 32767 characters, the rest of it is dropped",
		ConsoleLineLongInput("hello world\r\n", "\r\nnext\n"), NULL, expect);

	ConsoleLineCase(&ctx, "Ctrl+D (0x04) in a line cancels the prompt",
		ConsoleLineInput("ab\x04" "cd\r\nafter\r\n"), NULL, "CANCEL|CHILD DONE");

	ConsoleLineCase(&ctx, "Ctrl+Z (0x1A) cancels the prompt",
		ConsoleLineInput("\x1a\r\nafter\r\n"), NULL, "CANCEL|CHILD DONE");

	ConsoleLineCase(&ctx, "The end of the standard input cancels the prompt",
		ConsoleLineInput(""), NULL, "CANCEL|CHILD DONE");

	// "Hub", U+00E9 and U+4E2D in UTF-8: the former fgetws read the bytes in the ANSI code page
	ConsoleLineCase(&ctx, "A UTF-8 line with a non-ASCII hub name from a redirected standard input comes back unchanged",
		ConsoleLineInput("Hub\xc3\xa9\xe4\xb8\xad\r\n"), NULL, "CODES 0048 0075 0062 00E9 4E2D|CANCEL|CHILD DONE");

	// ConsoleReadNextFromInFile, through the /IN file of a child
	Format(expect, sizeof(expect), "LINE [hello world]|LONG %u ALL-A|LINE [next]|CANCEL|CHILD DONE", CONSOLELINE_LONG_LEN);
	ConsoleLineCase(&ctx, "A 40000-character line of a /IN file is read whole",
		ConsoleLineInput(""), ConsoleLineLongInput("hello world\r\n", "\r\nnext\r\n"), expect);

	// Last: the former UniToInt overran the stack of this process here
	ConsoleLineUniToInt(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("CONSOLELINE TEST OK\n");
	}
	else
	{
		Print("CONSOLELINE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
