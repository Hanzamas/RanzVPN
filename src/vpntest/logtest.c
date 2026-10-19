// logtest.c
// Named log writer tests of vpntest (PKG-4 #108)
//
// "logwriter" (FND-15): the writer thread of a LOG kept the name of its current file with
// StrCpy(current_file_name, sizeof(current_file_name), ...) on a char * parameter, so only 7
// characters were kept and every record closed the file and opened it again. A LOG in a private
// directory takes LOGTEST_WRITER_RECORDS string records: the writer opens or creates a file at most
// LOGTEST_WRITER_MAX_OPENS times (KS_IO_OPEN_COUNT plus KS_IO_CREATE_COUNT), and every record is in
// the file in order. A second LOG on the same file with a small maximum log size (SetMaxLogSize)
// appends to it, switches once to the next file, named as before, and keeps every record in order.
//
// Each test prints "<NAME> TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"
#include "Cedar/Logging.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Tracking.h"

#include <stdarg.h>

#define	LOGTEST_WRITER_PREFIX			"lw"				// Prefix of the log files
#define	LOGTEST_WRITER_TEXT				"logwriter record %05u"	// Text of record n
#define	LOGTEST_WRITER_RECORDS			1000				// Records of the first LOG
#define	LOGTEST_WRITER_SWITCH_RECORDS	1500				// Records of the second LOG: with the first ones, more than its maximum size
#define	LOGTEST_WRITER_MAX_SIZE			100000ULL			// Maximum log size of the second LOG
#define	LOGTEST_WRITER_SWITCH_FILE		"lw~0000001.log"	// Its second file: "~%07u" for a maximum size of 100000 to 999999 bytes
#define	LOGTEST_WRITER_NEXT_FILE		"lw~0000002.log"	// A third file, never made
#define	LOGTEST_WRITER_MAX_OPENS		2					// Files one LOG may open or create
#define	LOGTEST_WRITER_SWITCH_WAIT		10000				// Milliseconds waited for the size switch

// Run state of a test
typedef struct LOGTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} LOGTEST_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool LogTestCheck(LOGTEST_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;

	return false;
}

// Print the result line of a test
static void LogTestEnd(LOGTEST_CTX *ctx, char *name)
{
	if (ctx->NumFailed == 0)
	{
		Print("%s TEST OK\n", name);
	}
	else
	{
		Print("%s TEST FAILED (%u of %u checks failed)\n", name, ctx->NumFailed, ctx->NumChecks);
	}
}

// Files opened plus files created so far in the process (counted while tracking is on)
static UINT64 LogTestNumOpens()
{
	return KS_GET64(KS_IO_OPEN_COUNT) + KS_GET64(KS_IO_CREATE_COUNT);
}

// Private directory of a test in the temporary directory of the process (not created)
static void LogTestDirName(char *dir, UINT size, char *name)
{
	Format(dir, size, "%s/%s_%u", MsGetMyTempDir(), name, Rand32());
}

// Delete a directory (it must be empty)
static void LogTestDeleteDir(char *dir)
{
	wchar_t *dir_w = CopyStrToUni(dir);

	DeleteDirW(dir_w);

	Free(dir_w);
}

// Contents of a file as a string, NULL when it cannot be read
static char *LogTestReadText(char *path)
{
	BUF *b = ReadDump(path);
	char *ret;

	if (b == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);

	FreeBuf(b);

	return ret;
}

// Next line of a text from *pos, NUL-terminated in place; a line ends at CR or LF and empty lines are
// skipped. NULL at the end of the text
static char *LogTestNextLine(char **pos)
{
	char *s = *pos;
	char *line;

	while (*s == '\r' || *s == '\n')
	{
		s++;
	}

	if (*s == 0)
	{
		*pos = s;
		return NULL;
	}

	line = s;

	while (*s != 0 && *s != '\r' && *s != '\n')
	{
		s++;
	}

	if (*s != 0)
	{
		*s = 0;
		s++;
	}

	*pos = s;

	return line;
}

////////////////////////////
// logwriter (FND-15)

// Insert the string record of number n
static void LogWriterInsert(LOG *g, UINT n)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), LOGTEST_WRITER_TEXT, n);

	InsertStringRecord(g, tmp);
}

// Number of lines of the text, and in *in_order the number of leading lines that hold the records 0, 1, ...
// in order (a line is "<date> <time> <record text>")
static UINT LogWriterCountLines(char *text, UINT *in_order)
{
	char *pos = text;
	char *line;
	char expect[MAX_SIZE];
	UINT num = 0;
	bool ordered = true;

	*in_order = 0;

	while ((line = LogTestNextLine(&pos)) != NULL)
	{
		Format(expect, sizeof(expect), " " LOGTEST_WRITER_TEXT, num);

		if (ordered && EndWith(line, expect))
		{
			(*in_order)++;
		}
		else
		{
			ordered = false;
		}

		num++;
	}

	return num;
}

// "logwriter": one file open per LOG, every record in order, one size switch named as before
void logwriter_test(UINT num, char **arg)
{
	LOGTEST_CTX ctx;
	char dir[MAX_PATH];
	char file1[MAX_PATH];
	char file2[MAX_PATH];
	char file3[MAX_PATH];
	char *text1;
	char *text2;
	LOG *g;
	UINT64 opens;
	UINT64 end;
	UINT64 size1 = 0;
	UINT total = LOGTEST_WRITER_RECORDS + LOGTEST_WRITER_SWITCH_RECORDS + 1;
	UINT lines, in_order;
	bool switched;
	UINT i;

	Zero(&ctx, sizeof(ctx));

	Print("Log writer test: %u records, then %u more with a maximum log size of %I64u bytes\n",
		LOGTEST_WRITER_RECORDS, LOGTEST_WRITER_SWITCH_RECORDS + 1, LOGTEST_WRITER_MAX_SIZE);

	LogTestCheck(&ctx, IsTrackingEnabled(), "file open and create counters are on (tracking enabled)", "IsTrackingEnabled() is false");

	LogTestDirName(dir, sizeof(dir), "logwriter");
	Format(file1, sizeof(file1), "%s/%s.log", dir, LOGTEST_WRITER_PREFIX);
	Format(file2, sizeof(file2), "%s/%s", dir, LOGTEST_WRITER_SWITCH_FILE);
	Format(file3, sizeof(file3), "%s/%s", dir, LOGTEST_WRITER_NEXT_FILE);

	// First LOG: the default maximum size, no date in the file name
	SetMaxLogSize(0);
	opens = LogTestNumOpens();

	g = NewLog(dir, LOGTEST_WRITER_PREFIX, LOG_SWITCH_NO);
	for (i = 0;i < LOGTEST_WRITER_RECORDS;i++)
	{
		LogWriterInsert(g, i);
	}
	FreeLog(g);

	opens = LogTestNumOpens() - opens;
	LogTestCheck(&ctx, opens <= LOGTEST_WRITER_MAX_OPENS,
		"1000 records: the writer opens or creates its file at most twice (it reopened the file for every record)",
		"%I64u files opened or created", opens);

	text1 = LogTestReadText(file1);
	if (LogTestCheck(&ctx, text1 != NULL, "the first LOG wrote lw.log", "%s cannot be read", file1))
	{
		lines = LogWriterCountLines(text1, &in_order);
		LogTestCheck(&ctx, lines == LOGTEST_WRITER_RECORDS && in_order == LOGTEST_WRITER_RECORDS,
			"lw.log holds the 1000 records in order",
			"%u lines, the first %u in order", lines, in_order);
		Free(text1);
	}

	// Second LOG on the same file with a small maximum size: it appends to lw.log until a write would pass the
	// maximum, then moves on to the next number; the record after that opens lw~0000001.log
	SetMaxLogSize(LOGTEST_WRITER_MAX_SIZE);
	opens = LogTestNumOpens();

	g = NewLog(dir, LOGTEST_WRITER_PREFIX, LOG_SWITCH_NO);
	for (i = LOGTEST_WRITER_RECORDS;i < (total - 1);i++)
	{
		LogWriterInsert(g, i);
	}

	end = Tick64() + LOGTEST_WRITER_SWITCH_WAIT;
	while (g->CurrentLogNumber == 0 && Tick64() < end)
	{
		SleepThread(10);
	}
	switched = (g->CurrentLogNumber == 1);

	LogWriterInsert(g, total - 1);
	FreeLog(g);

	SetMaxLogSize(0);

	opens = LogTestNumOpens() - opens;
	LogTestCheck(&ctx, opens <= LOGTEST_WRITER_MAX_OPENS,
		"1501 records with a size switch: the writer opens lw.log and creates lw~0000001.log, nothing more",
		"%I64u files opened or created", opens);

	LogTestCheck(&ctx, switched, "the writer moves to log number 1 when a write would pass the maximum size",
		"log number not 1 within %u ms", LOGTEST_WRITER_SWITCH_WAIT);

	LogTestCheck(&ctx, IsFileExists(file2) && IsFileExists(file3) == false,
		"one size switch: the second file is lw~0000001.log, there is no lw~0000002.log",
		"lw~0000001.log %s, lw~0000002.log %s", IsFileExists(file2) ? "exists" : "missing",
		IsFileExists(file3) ? "exists" : "missing");

	text1 = LogTestReadText(file1);
	text2 = LogTestReadText(file2);
	if (LogTestCheck(&ctx, text1 != NULL && text2 != NULL, "both files can be read", "%s or %s cannot be read", file1, file2))
	{
		BUF *b = NewBuf();
		char *all;

		size1 = StrLen(text1);
		LogTestCheck(&ctx, size1 <= LOGTEST_WRITER_MAX_SIZE, "lw.log stays within the maximum size",
			"%I64u bytes", size1);

		WriteBuf(b, text1, StrLen(text1));
		WriteBuf(b, text2, StrLen(text2));
		WriteBufChar(b, 0);
		all = (char *)b->Buf;

		lines = LogWriterCountLines(all, &in_order);
		LogTestCheck(&ctx, lines == total && in_order == total,
			"lw.log then lw~0000001.log hold the 2501 records in order",
			"%u lines, the first %u in order", lines, in_order);

		FreeBuf(b);
	}

	Free(text1);
	Free(text2);

	FileDelete(file1);
	FileDelete(file2);
	FileDelete(file3);
	LogTestDeleteDir(dir);

	LogTestEnd(&ctx, "LOGWRITER");
}
