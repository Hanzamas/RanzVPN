// bufbounds.c
// Named BUF and binary configuration bounds test of vpntest ("bufbounds" command, SEC-3 #96)
//
// ReadBuf() clamped a read with the UINT test Current + size >= Size: a size near 2^32 wrapped
// the sum, so the read was not clamped and Current moved backwards (with a destination, Copy()
// ran for about 4 GB). ReadBufStr() skips the tail of an over-long string with
// ReadBuf(b, NULL, ...), so a string length of 0xFFFFFFFF rewound the cursor and the parser read
// its own bytes again. WriteBuf() wrapped Current + size the same way and copied past its block,
// and a write after SeekBuf() set Size to Current + size, which cut the buffer (FND-41 #114).
// CfgReadNextFolderBin() trusted the folder and item counts and the item sizes of a binary
// configuration: a count beyond the bytes left made folders with an uninitialised name, a string
// size of 0xFFFFFFFF wrapped ZeroMalloc(size + 1) to an empty block that ReadBuf() overran, and a
// byte size near 2^32 reached MallocEx(), which ends the process.
//
// This test pins the clamped reads, the WriteBuf() guard, a WriteBuf() inside the buffer that keeps
// its size, and CfgBufBinToFolder() returning NULL for each malformed input, while a valid binary
// configuration still loads unchanged. The WriteBuf() guard ends the process (AbortExitEx), so that
// case runs in a child process, "vpntest bufbounds writewrap". The cases that crashed or ended the
// old code run last. Prints "BUFBOUNDS TEST OK" only when every check passes, and frees everything
// it allocates.

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <windows.h>

// Argument of the child process that runs the WriteBuf() case, and the message of its guard
#define	BUFBOUNDS_CHILD_ARG			"writewrap"
#define	BUFBOUNDS_CHILD_MSG			"WriteBuf(): too large buffer size"
#define	BUFBOUNDS_CHILD_TIMEOUT		(120 * 1000)

// Run state of the test
typedef struct BUFBOUNDS_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} BUFBOUNDS_CTX;

// Record one check: print [PASS] or [FAIL]
static bool BufBoundsCheck(BUFBOUNDS_CTX *ctx, bool ok, char *what)
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

// A BUF holding the bytes 0, 1, 2, ... (size of them), positioned at its beginning
static BUF *BufBoundsNewBuf(UINT size)
{
	BUF *b = NewBuf();
	UINT i;

	for (i = 0;i < size;i++)
	{
		WriteBufChar(b, (UCHAR)i);
	}

	SeekBufToBegin(b);

	return b;
}

// ReadBuf: a size beyond the bytes left is clamped to them, without wrapping
static void BufBoundsTestReadBuf(BUFBOUNDS_CTX *ctx)
{
	BUF *b = BufBoundsNewBuf(100);
	UCHAR tmp[8];
	UINT ret;

	SeekBuf(b, 10, 0);
	ret = ReadBuf(b, NULL, 0xFFFFFFF8);
	BufBoundsCheck(ctx, ret == 90 && b->Current == 100,
		"ReadBuf(NULL, 0xFFFFFFF8) at offset 10 of 100 bytes skips the 90 bytes left (Current + size wrapped to 2 before)");

	SeekBuf(b, 96, 0);
	Zero(tmp, sizeof(tmp));
	tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0xEE;
	ret = ReadBuf(b, tmp, sizeof(tmp));
	BufBoundsCheck(ctx, ret == 4 && b->Current == 100 && tmp[0] == 96 && tmp[3] == 99 && IsZero(tmp + 4, 4),
		"ReadBuf of 8 bytes at offset 96 of 100 copies the 4 bytes left and zeroes the rest");

	SeekBuf(b, 92, 0);
	ret = ReadBuf(b, tmp, sizeof(tmp));
	BufBoundsCheck(ctx, ret == 8 && b->Current == 100 && tmp[0] == 92 && tmp[7] == 99,
		"ReadBuf of exactly the bytes left reads them all");

	ret = ReadBuf(b, tmp, 1);
	BufBoundsCheck(ctx, ret == 0 && b->Current == 100, "ReadBuf at the end reads nothing and stays at the end");

	BufBoundsCheck(ctx, ReadBufRemainSize(b) == 0 && ReadBufRemainSize(NULL) == 0, "ReadBufRemainSize is 0 at the end and for NULL");
	SeekBuf(b, 10, 0);
	BufBoundsCheck(ctx, ReadBufRemainSize(b) == 90, "ReadBufRemainSize at offset 10 of 100 bytes is 90");

	FreeBuf(b);
}

// ReadBufStr: the tail of an over-long string is skipped forward only, and must be there
static void BufBoundsTestReadBufStr(BUFBOUNDS_CTX *ctx)
{
	BUF *b;
	char str[64];
	char long_str[101];
	UINT i;
	bool ret;

	// 10 bytes, then a string length of 0xFFFFFFFF and 100 bytes of string
	b = NewBuf();
	for (i = 0;i < 10;i++)
	{
		WriteBufChar(b, 0);
	}
	WriteBufInt(b, 0xFFFFFFFF);
	for (i = 0;i < 100;i++)
	{
		WriteBufChar(b, 'a');
	}
	SeekBuf(b, 10, 0);
	ret = ReadBufStr(b, str, sizeof(str));
	BufBoundsCheck(ctx, ret == false && b->Current == b->Size,
		"ReadBufStr of a length 0xFFFFFFFF with 100 bytes left fails at the end (the skip wrapped back to offset 12 before)");
	FreeBuf(b);

	// An over-long string that is all there: the first size - 1 bytes, the rest skipped
	for (i = 0;i < 100;i++)
	{
		long_str[i] = 'x';
	}
	long_str[100] = 0;
	b = NewBuf();
	WriteBufStr(b, long_str);
	WriteBufInt(b, 0x12345678);
	SeekBufToBegin(b);
	ret = ReadBufStr(b, str, sizeof(str));
	BufBoundsCheck(ctx, ret && StrLen(str) == sizeof(str) - 1 && ReadBufInt(b) == 0x12345678,
		"ReadBufStr of a 100-byte string into 64 bytes keeps 63 and skips the rest");
	FreeBuf(b);

	// A short string reads back
	b = NewBuf();
	WriteBufStr(b, "hello");
	SeekBufToBegin(b);
	ret = ReadBufStr(b, str, sizeof(str));
	BufBoundsCheck(ctx, ret && StrCmp(str, "hello") == 0 && b->Current == b->Size,
		"ReadBufStr reads back what WriteBufStr wrote");
	FreeBuf(b);

	// A string cut short
	b = NewBuf();
	WriteBufInt(b, 11);
	WriteBuf(b, "abc", 3);
	SeekBufToBegin(b);
	ret = ReadBufStr(b, str, sizeof(str));
	BufBoundsCheck(ctx, ret == false, "ReadBufStr of a string cut short fails");
	FreeBuf(b);
}

// WriteBuf inside the buffer: a write after SeekBuf() overwrites the bytes there and keeps the bytes
// after them; a write past the end grows the buffer to the new end
static void BufBoundsTestWriteBufInside(BUFBOUNDS_CTX *ctx)
{
	BUF *b = BufBoundsNewBuf(100);
	UCHAR data[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	UCHAR *p;

	SeekBuf(b, 0, 0);
	WriteBuf(b, data, sizeof(data));
	p = (UCHAR *)b->Buf;
	BufBoundsCheck(ctx, b->Size == 100 && b->Current == 4 && Cmp(p, data, sizeof(data)) == 0 && p[4] == 4 && p[99] == 99,
		"WriteBuf of 4 bytes at offset 0 of 100 bytes overwrites them and keeps Size at 100 (it was cut to 4 before)");

	SeekBuf(b, 98, 0);
	WriteBuf(b, data, sizeof(data));
	p = (UCHAR *)b->Buf;
	BufBoundsCheck(ctx, b->Size == 102 && b->Current == 102 && p[97] == 97 && p[98] == 0xAA && p[101] == 0xDD,
		"WriteBuf of 4 bytes at offset 98 of 100 bytes grows the buffer to 102");

	FreeBuf(b);
}

// Child process side of the WriteBuf() case: WriteBuf() of 0xFFFFFFF8 bytes at offset 16 must end
// the process through AbortExitEx() before it copies. The old code wrapped Current + size to 8,
// kept the block as it was and copied about 4 GB into it.
static void BufBoundsWriteWrapChild(void)
{
	BUF *b = NewBuf();
	UCHAR src[16];

	Zero(src, sizeof(src));
	WriteBuf(b, src, sizeof(src));
	WriteBuf(b, src, 0xFFFFFFF8);

	// Reached only without the guard
	Print("bufbounds %s: WriteBuf returned, Size = %u\n", BUFBOUNDS_CHILD_ARG, b->Size);

	FreeBuf(b);
}

// True when the file holds text
static bool BufBoundsFileHas(wchar_t *name, char *text)
{
	BUF *b = ReadDumpW(name);
	bool ret;

	if (b == NULL)
	{
		return false;
	}

	ret = (SearchBin(b->Buf, 0, b->Size, text, StrLen(text)) != INFINITE);

	FreeBuf(b);

	return ret;
}

// WriteBuf: Current + size must not wrap. Runs "vpntest bufbounds writewrap" with its working
// directory in a directory of its own under the temporary directory of Windows (not the VPN_
// directory of this process, which a starting process may clean), and its standard output and
// error in a file there. AbortExitEx() reports the guard on standard output (flushed before
// abort() in RANZ_FUZZING builds) or in abort_error_log.txt in the working directory (other builds).
static void BufBoundsTestWriteBuf(BUFBOUNDS_CTX *ctx)
{
	wchar_t exe[MAX_PATH];
	wchar_t temp[MAX_PATH];
	wchar_t dir_name[64];
	wchar_t dir[MAX_PATH];
	wchar_t out_name[MAX_PATH];
	wchar_t log_name[MAX_PATH];
	wchar_t cmd[MAX_PATH + 64];
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE out;
	DWORD exit_code = 0;
	UINT old_mode;
	UINT err;
	bool started;
	bool ended = false;
	bool in_out, in_log;

	if (BufBoundsCheck(ctx, GetModuleFileNameW(NULL, exe, MAX_PATH) != 0 && GetTempPathW(MAX_PATH, temp) != 0,
		"path of vpntest.exe and the temporary directory of Windows") == false)
	{
		return;
	}

	UniFormat(dir_name, sizeof(dir_name), L"ranz_bufbounds_%u", (UINT)GetCurrentProcessId());
	CombinePathW(dir, sizeof(dir), temp, dir_name);
	MakeDirW(dir);
	CombinePathW(out_name, sizeof(out_name), dir, L"child_output.txt");
	CombinePathW(log_name, sizeof(log_name), dir, L"abort_error_log.txt");

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	out = CreateFileW(out_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (BufBoundsCheck(ctx, out != INVALID_HANDLE_VALUE, "output file of the child process") == false)
	{
		DeleteDirW(dir);
		return;
	}

	UniFormat(cmd, sizeof(cmd), L"\"%s\" bufbounds %S", exe, BUFBOUNDS_CHILD_ARG);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = NULL;
	si.hStdOutput = out;
	si.hStdError = out;
	Zero(&pi, sizeof(pi));

	// No error dialog when the child crashes (the old WriteBuf() did): the child inherits this mode
	old_mode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
	started = (CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, dir, &si, &pi) != FALSE);
	err = GetLastError();
	SetErrorMode(old_mode);
	CloseHandle(out);

	if (started == false)
	{
		BufBoundsCheck(ctx, false, "start the child process");
		Print("         CreateProcessW error %u\n", err);
	}
	else
	{
		if (WaitForSingleObject(pi.hProcess, BUFBOUNDS_CHILD_TIMEOUT) == WAIT_OBJECT_0)
		{
			ended = true;
		}
		else
		{
			TerminateProcess(pi.hProcess, 1);
			WaitForSingleObject(pi.hProcess, 10 * 1000);
		}
		GetExitCodeProcess(pi.hProcess, &exit_code);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		in_out = BufBoundsFileHas(out_name, BUFBOUNDS_CHILD_MSG);
		in_log = BufBoundsFileHas(log_name, BUFBOUNDS_CHILD_MSG);

		if (BufBoundsCheck(ctx, ended && exit_code != 0 && (in_out || in_log),
			"WriteBuf of 0xFFFFFFF8 bytes at offset 16 ends the process through AbortExitEx (Current + size wrapped to 8 before)") == false)
		{
			Print("         child ended %u, exit code 0x%X, guard message on its output %u, in abort_error_log.txt %u\n",
				ended, (UINT)exit_code, in_out, in_log);
		}
	}

	FileDeleteW(out_name);
	FileDeleteW(log_name);
	DeleteDirW(dir);
}

// Body of a binary configuration (what follows "SEVPN_DB" and the hash): folder "root" without
// subfolders and with one item of the given name and type; the caller writes the value
static BUF *BufBoundsCfgOneItem(char *name, UINT type)
{
	BUF *b = NewBuf();

	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0);			// Subfolders
	WriteBufInt(b, 1);			// Items
	WriteBufStr(b, name);
	WriteBufInt(b, type);

	return b;
}

// True when CfgBufBinToFolder() rejects the body in b; frees b
static bool BufBoundsCfgRejects(BUF *b)
{
	FOLDER *f;

	SeekBufToBegin(b);
	f = CfgBufBinToFolder(b);
	FreeBuf(b);

	if (f != NULL)
	{
		CfgDeleteFolder(f);
		return false;
	}

	return true;
}

// A valid binary configuration with every item type, nested folders and an empty string loads
// into the same tree: its text form is the same
static void BufBoundsTestCfgValid(BUFBOUNDS_CTX *ctx)
{
	FOLDER *f = CfgCreateFolder(NULL, TAG_ROOT);
	FOLDER *sub = CfgCreateFolder(f, "VirtualHUB");
	FOLDER *f2;
	BUF *bin, *text1, *text2 = NULL;
	UCHAR bytes[20];
	UINT i;

	for (i = 0;i < sizeof(bytes);i++)
	{
		bytes[i] = (UCHAR)i;
	}

	CfgAddInt(f, "ConfigRevision", 3);
	CfgAddInt64(f, "AutoDeleteCheckDiskFreeSpaceMin", 104857600);
	CfgAddBool(f, "IPsecMessageDisplayed", true);
	CfgAddByte(sub, "HashedPassword", bytes, sizeof(bytes));
	CfgAddUniStr(sub, "ServerName", L"Ranz VPN \x00e9\x65e5");
	CfgAddUniStr(sub, "Empty", L"");
	CfgCreateFolder(sub, "DEFAULT");

	// The same tree as a binary body, written by hand (Ranz VPN writes text only)
	bin = NewBuf();
	WriteBufStr(bin, TAG_ROOT);
	WriteBufInt(bin, 1);			// Subfolders
	WriteBufStr(bin, "VirtualHUB");
	WriteBufInt(bin, 1);			// Subfolders
	WriteBufStr(bin, "DEFAULT");
	WriteBufInt(bin, 0);			// Subfolders
	WriteBufInt(bin, 0);			// Items
	WriteBufInt(bin, 3);			// Items
	WriteBufStr(bin, "HashedPassword");
	WriteBufInt(bin, ITEM_TYPE_BYTE);
	WriteBufInt(bin, sizeof(bytes));
	WriteBuf(bin, bytes, sizeof(bytes));
	WriteBufStr(bin, "ServerName");
	WriteBufInt(bin, ITEM_TYPE_STRING);
	WriteBufInt(bin, 14);
	WriteBuf(bin, "Ranz VPN \xc3\xa9\xe6\x97\xa5", 14);
	WriteBufStr(bin, "Empty");
	WriteBufInt(bin, ITEM_TYPE_STRING);
	WriteBufInt(bin, 0);
	WriteBufInt(bin, 3);			// Items
	WriteBufStr(bin, "ConfigRevision");
	WriteBufInt(bin, ITEM_TYPE_INT);
	WriteBufInt(bin, 3);
	WriteBufStr(bin, "AutoDeleteCheckDiskFreeSpaceMin");
	WriteBufInt(bin, ITEM_TYPE_INT64);
	WriteBufInt64(bin, 104857600);
	WriteBufStr(bin, "IPsecMessageDisplayed");
	WriteBufInt(bin, ITEM_TYPE_BOOL);
	WriteBufInt(bin, 1);

	text1 = CfgFolderToBuf(f);
	SeekBufToBegin(bin);
	f2 = CfgBufBinToFolder(bin);
	if (f2 != NULL)
	{
		text2 = CfgFolderToBuf(f2);
	}

	BufBoundsCheck(ctx, f2 != NULL && CompareBuf(text1, text2),
		"a valid binary configuration (every item type, nested folders, an empty string) loads unchanged");

	FreeBuf(text1);
	FreeBuf(text2);
	FreeBuf(bin);
	CfgDeleteFolder(f2);
	CfgDeleteFolder(f);
}

// CfgBufBinToFolder: every count and size is checked against the bytes left
static void BufBoundsTestCfg(BUFBOUNDS_CTX *ctx)
{
	BUF *b;
	UINT i;

	BufBoundsTestCfgValid(ctx);

	b = NewBuf();
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 1000);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b),
		"a folder count of 1000 with no bytes left is rejected (the old reader made 1000 folders with an uninitialised name)");

	b = NewBuf();
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0);
	WriteBufInt(b, 1000);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b), "an item count of 1000 with no bytes left is rejected");

	b = BufBoundsCfgOneItem("ConfigRevision", ITEM_TYPE_INT);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b), "an INT item cut before its value is rejected (the old reader stored 0)");

	b = NewBuf();
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0);
	WriteBufInt(b, 1);
	WriteBufInt(b, 11);
	WriteBuf(b, "abc", 3);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b), "an item name cut short is rejected (the old reader went on with an uninitialised name)");

	b = BufBoundsCfgOneItem("ConfigRevision", 9);
	WriteBufInt(b, 3);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b), "an unknown item type is rejected (its value has no known size)");

	b = NewBuf();
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0);
	WriteBufInt(b, 1);
	WriteBufInt(b, 0xFFFFFFFF);
	for (i = 0;i < 600;i++)
	{
		WriteBufChar(b, 'n');
	}
	WriteBufInt(b, ITEM_TYPE_INT);
	WriteBufInt(b, 3);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b),
		"an item name of length 0xFFFFFFFF is rejected (the old ReadBufStr went back and read the name again)");

	// The old reader ended the process on these two: last
	b = BufBoundsCfgOneItem("HashedPassword", ITEM_TYPE_BYTE);
	WriteBufInt(b, 0xFFFFFFF0);
	WriteBuf(b, "abcd", 4);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b),
		"a BYTE item of size 0xFFFFFFF0 with 4 bytes left is rejected before it allocates (the old reader aborted in MallocEx)");

	b = BufBoundsCfgOneItem("ServerName", ITEM_TYPE_STRING);
	WriteBufInt(b, 0xFFFFFFFF);
	WriteBuf(b, "abcd", 4);
	BufBoundsCheck(ctx, BufBoundsCfgRejects(b),
		"a STRING item of size 0xFFFFFFFF is rejected (the old reader wrapped size + 1 to 0 and copied past the block)");
}

// Text configuration of count folders nested in each other, "root" outermost
static BUF *BufBoundsCfgNestedText(UINT count)
{
	BUF *b = NewBuf();
	UINT i;

	for (i = 0;i < count;i++)
	{
		char *line = (i == 0 ? "declare root\r\n{\r\n" : "declare x\r\n{\r\n");

		WriteBuf(b, line, StrLen(line));
	}
	for (i = 0;i < count;i++)
	{
		WriteBuf(b, "}\r\n", 3);
	}

	SeekBufToBegin(b);

	return b;
}

// Body of a binary configuration of count folders nested in each other, "root" outermost
static BUF *BufBoundsCfgNestedBin(UINT count)
{
	BUF *b = NewBuf();
	UINT i;

	for (i = 0;i < count;i++)
	{
		WriteBufStr(b, i == 0 ? TAG_ROOT : "x");
		WriteBufInt(b, (i + 1 < count) ? 1 : 0);	// Subfolders
	}
	for (i = 0;i < count;i++)
	{
		WriteBufInt(b, 0);						// Items
	}

	SeekBufToBegin(b);

	return b;
}

// True when the text configuration in b loads; frees b
static bool BufBoundsCfgTextLoads(BUF *b)
{
	FOLDER *f = CfgBufTextToFolder(b);
	bool ret = (f != NULL);

	FreeBuf(b);
	CfgDeleteFolder(f);

	return ret;
}

// Both readers stop at a nesting depth of 64 folders instead of recursing once per level
static void BufBoundsTestCfgDepth(BUFBOUNDS_CTX *ctx)
{
	BUF *b;
	FOLDER *f;

	BufBoundsCheck(ctx, BufBoundsCfgTextLoads(BufBoundsCfgNestedText(64)), "a text configuration of 64 nested folders loads");
	BufBoundsCheck(ctx, BufBoundsCfgTextLoads(BufBoundsCfgNestedText(65)) == false, "a text configuration of 65 nested folders is rejected");
	BufBoundsCheck(ctx, BufBoundsCfgTextLoads(BufBoundsCfgNestedText(10000)) == false,
		"a text configuration of 10000 nested folders is rejected (the old reader recursed once per level)");

	b = BufBoundsCfgNestedBin(64);
	f = CfgBufBinToFolder(b);
	BufBoundsCheck(ctx, f != NULL, "a binary configuration of 64 nested folders loads");
	CfgDeleteFolder(f);
	FreeBuf(b);

	BufBoundsCheck(ctx, BufBoundsCfgRejects(BufBoundsCfgNestedBin(65)), "a binary configuration of 65 nested folders is rejected");
	BufBoundsCheck(ctx, BufBoundsCfgRejects(BufBoundsCfgNestedBin(10000)),
		"a binary configuration of 10000 nested folders is rejected (the old reader recursed once per level)");
}

// True when CfgReadW() of a file holding b returns NULL; frees b
static bool BufBoundsCfgFileRejects(wchar_t *name, BUF *b)
{
	FOLDER *f;
	bool written = DumpBufW(b, name);

	FreeBuf(b);
	f = CfgReadW(name);
	FileDeleteW(name);

	if (f != NULL)
	{
		CfgDeleteFolder(f);
		return false;
	}

	return written;
}

// Binary configuration file of the body in b: "SEVPN_DB", the SHA-0 of the body, the body; frees b
static BUF *BufBoundsCfgBinFile(BUF *b)
{
	BUF *file = NewBuf();
	UCHAR hash[SHA1_SIZE];

	Sha0(hash, b->Buf, b->Size);
	WriteBuf(file, TAG_BINARY, 8);
	WriteBuf(file, hash, sizeof(hash));
	WriteBuf(file, b->Buf, b->Size);
	FreeBuf(b);

	return file;
}

// CfgReadW: a "SEVPN_DB" file too short for its SHA-0, one with a wrong SHA-0, binary files with a
// valid SHA-0 and a folder count or STRING size of 0xFFFFFFFF, and a text file of 10000 nested
// folders are rejected (the read buffer freed on every path), in a directory of its own under the
// temporary directory
static void BufBoundsTestCfgRead(BUFBOUNDS_CTX *ctx)
{
	wchar_t temp[MAX_PATH];
	wchar_t dir_name[64];
	wchar_t dir[MAX_PATH];
	wchar_t name[MAX_PATH];
	UCHAR zero[SHA1_SIZE];
	BUF *b;

	if (BufBoundsCheck(ctx, GetTempPathW(MAX_PATH, temp) != 0, "the temporary directory of Windows") == false)
	{
		return;
	}

	UniFormat(dir_name, sizeof(dir_name), L"ranz_cfgread_%u", (UINT)GetCurrentProcessId());
	CombinePathW(dir, sizeof(dir), temp, dir_name);
	MakeDirW(dir);
	CombinePathW(name, sizeof(name), dir, L"vpn_server.config");
	Zero(zero, sizeof(zero));

	b = NewBuf();
	WriteBuf(b, TAG_BINARY, 8);
	WriteBuf(b, zero, 12);
	BufBoundsCheck(ctx, BufBoundsCfgFileRejects(name, b),
		"CfgReadW of \"SEVPN_DB\" and 12 bytes is rejected (the old reader hashed b->Size - 28 bytes, past the end)");

	b = NewBuf();
	WriteBuf(b, TAG_BINARY, 8);
	WriteBuf(b, zero, sizeof(zero));
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0);
	WriteBufInt(b, 0);
	BufBoundsCheck(ctx, BufBoundsCfgFileRejects(name, b), "CfgReadW of a binary file with a wrong SHA-0 is rejected");

	b = NewBuf();
	WriteBufStr(b, TAG_ROOT);
	WriteBufInt(b, 0xFFFFFFFF);
	BufBoundsCheck(ctx, BufBoundsCfgFileRejects(name, BufBoundsCfgBinFile(b)),
		"CfgReadW of a binary file with a valid SHA-0 and a folder count of 0xFFFFFFFF is rejected");

	b = BufBoundsCfgOneItem("ServerName", ITEM_TYPE_STRING);
	WriteBufInt(b, 0xFFFFFFFF);
	WriteBuf(b, "abcd", 4);
	BufBoundsCheck(ctx, BufBoundsCfgFileRejects(name, BufBoundsCfgBinFile(b)),
		"CfgReadW of a binary file with a valid SHA-0 and a STRING item of size 0xFFFFFFFF is rejected");

	BufBoundsCheck(ctx, BufBoundsCfgFileRejects(name, BufBoundsCfgNestedText(10000)),
		"CfgReadW of a text file of 10000 nested folders is rejected (the old reader recursed once per level)");

	DeleteDirW(dir);
}

// bufbounds: BUF reads and writes near 2^32 and the binary configuration reader of SEC-3
void bufbounds_test(UINT num, char **arg)
{
	BUFBOUNDS_CTX ctx;

	if (num >= 1 && StrCmpi(arg[0], BUFBOUNDS_CHILD_ARG) == 0)
	{
		BufBoundsWriteWrapChild();
		return;
	}

	Zero(&ctx, sizeof(ctx));

	Print("BUF and binary configuration bounds test\n");

	BufBoundsTestReadBuf(&ctx);
	BufBoundsTestReadBufStr(&ctx);
	BufBoundsTestWriteBufInside(&ctx);
	BufBoundsTestWriteBuf(&ctx);
	BufBoundsTestCfg(&ctx);
	BufBoundsTestCfgDepth(&ctx);
	BufBoundsTestCfgRead(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("BUFBOUNDS TEST OK\n");
	}
	else
	{
		Print("BUFBOUNDS TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
