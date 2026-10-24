// logretention.c
// The log retention test of vpntest (SDN-54 #247): the files of a LOG stay within an age limit and a disk limit
//
// "logretention": SetLogLimits makes the writer thread of a LOG delete the files of its own log, the oldest first.
//
// Age limit. A directory holds files of the log "lr" that were last written long ago and one that was written
// recently, and the files that are no files of that log: another prefix, another extension and a folder, all of them
// old. With an age limit of LOGRETENTION_DAYS days the old files of the log go, one line of the log tells each
// deletion, and the other files stay. The file that the log has open stays whatever its age: it is set to
// LOGRETENTION_OLD_DAYS days ago while it is open, and the limits are applied again.
//
// Disk limit. A LOG with a disk limit of LOGRETENTION_DISK_LIMIT bytes takes LOGRETENTION_RECORDS records of about
// LOGRETENTION_RECORD_SIZE bytes, far more than the limit, in batches. After each batch the files of the log take no
// more than the limit together (the file that is open counts as much as its maximum size lets it grow to, a quarter
// of the limit); at the end they hold the newest records and not the first one, and the log tells that it deleted
// files.
//
// The test prints "LOGRETENTION TEST OK" only when every check passes, and frees everything it allocates.

#include "testlist.h"

#include "Cedar/LogWriter.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#define	LOGRETENTION_DAYS			30				// The age limit
#define	LOGRETENTION_OLD_DAYS		400				// The age of the old files
#define	LOGRETENTION_DISK_LIMIT		40000ULL		// The disk limit: files of at most a quarter of it
#define	LOGRETENTION_RECORDS		2000			// Records of the disk test
#define	LOGRETENTION_BATCH			20				// Records inserted before the writer is waited for
#define	LOGRETENTION_RECORD_SIZE	100				// Bytes of a line of the log, about
#define	LOGRETENTION_WAIT			10000			// Milliseconds waited for the writer thread at most

// Run state of the test
typedef struct LOGRETENTION_CTX
{
	UINT NumChecks;		// Checks run so far
	UINT NumFailed;		// Checks failed so far
} LOGRETENTION_CTX;

// Record one check: print [PASS], or [FAIL] with the detail
static void LogRetentionCheck(LOGRETENTION_CTX *ctx, bool ok, char *what, char *detail)
{
	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;
}

// Whether text holds key
static bool LogRetentionHas(char *text, char *key)
{
	return SearchStr(text, key, 0) != INFINITE;
}

// A private directory of the test in the temporary directory of the process, made
static void LogRetentionNewDir(char *dir, UINT size, char *name)
{
	Format(dir, size, "%s/%s_%u", MsGetMyTempDir(), name, Rand32());
	MakeDirEx(dir);
}

// The path of the file name in dir
static void LogRetentionPath(char *path, UINT size, char *dir, char *name)
{
	Format(path, size, "%s/%s", dir, name);
}

// Set the time of the last write of the file or folder path to days days ago
static bool LogRetentionSetAge(char *path, UINT days)
{
	FILETIME ft;
	ULARGE_INTEGER u;
	bool ret = false;
	wchar_t *path_w = CopyStrToUni(path);

	GetSystemTimeAsFileTime(&ft);
	u.LowPart = ft.dwLowDateTime;
	u.HighPart = ft.dwHighDateTime;
	u.QuadPart -= (ULONGLONG)days * 24ULL * 60ULL * 60ULL * 10000000ULL;
	ft.dwLowDateTime = u.LowPart;
	ft.dwHighDateTime = u.HighPart;

	HANDLE h = CreateFileW(path_w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h != INVALID_HANDLE_VALUE)
	{
		ret = (SetFileTime(h, NULL, NULL, &ft) != FALSE);
		CloseHandle(h);
	}

	Free(path_w);

	return ret;
}

// Make the file name of dir with the text, or the folder name when text is NULL, last written days days ago
static void LogRetentionPlant(char *dir, char *name, char *text, UINT days)
{
	char path[MAX_SIZE];

	LogRetentionPath(path, sizeof(path), dir, name);

	if (text == NULL)
	{
		MakeDir(path);
	}
	else
	{
		IO *io = FileCreate(path);

		if (io != NULL)
		{
			FileWrite(io, text, StrLen(text));
			FileClose(io);
		}
	}

	LogRetentionSetAge(path, days);
}

// Whether the file or folder name is in dir
static bool LogRetentionExists(char *dir, char *name)
{
	char path[MAX_SIZE];

	LogRetentionPath(path, sizeof(path), dir, name);

	wchar_t *path_w = CopyStrToUni(path);
	bool ret = (GetFileAttributesW(path_w) != INVALID_FILE_ATTRIBUTES);

	Free(path_w);

	return ret;
}

// The files of dir whose names start with prefix and end with ".log", and what they take together
static UINT LogRetentionCount(char *dir, char *prefix, UINT64 *total)
{
	UINT num = 0;
	DIRLIST *d = EnumDir(dir);

	*total = 0;

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];

		if (e->Folder == false && StartWith(e->FileName, prefix) && EndWith(e->FileName, ".log"))
		{
			num++;
			*total += e->FileSize;
		}
	}

	FreeDir(d);

	return num;
}

// The text of the files of dir whose names start with prefix, in one string; the caller frees it
static char *LogRetentionRead(char *dir, char *prefix)
{
	BUF *all = NewBuf();
	DIRLIST *d = EnumDir(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];

		if (e->Folder == false && StartWith(e->FileName, prefix))
		{
			char path[MAX_SIZE];

			LogRetentionPath(path, sizeof(path), dir, e->FileName);

			BUF *b = ReadDump(path);

			if (b != NULL)
			{
				WriteBuf(all, b->Buf, b->Size);
				FreeBuf(b);
			}
		}
	}

	FreeDir(d);

	char *ret = ZeroMalloc(all->Size + 1);

	Copy(ret, all->Buf, all->Size);
	FreeBuf(all);

	return ret;
}

// The name of the file of dir with the prefix whose text holds key, "" when none does
static void LogRetentionFind(char *name, UINT size, char *dir, char *prefix, char *key)
{
	DIRLIST *d = EnumDir(dir);

	StrCpy(name, size, "");

	for (UINT i = 0;d != NULL && i < d->NumFiles && IsEmptyStr(name);i++)
	{
		DIRENT *e = d->File[i];

		if (e->Folder == false && StartWith(e->FileName, prefix))
		{
			char path[MAX_SIZE];

			LogRetentionPath(path, sizeof(path), dir, e->FileName);

			BUF *b = ReadDump(path);

			if (b != NULL)
			{
				char *text = ZeroMalloc(b->Size + 1);

				Copy(text, b->Buf, b->Size);

				if (LogRetentionHas(text, key))
				{
					StrCpy(name, size, e->FileName);
				}

				Free(text);
				FreeBuf(b);
			}
		}
	}

	FreeDir(d);
}

// Wait until the file name of dir is gone, at most LOGRETENTION_WAIT ms
static bool LogRetentionWaitGone(char *dir, char *name)
{
	UINT64 end = Tick64() + LOGRETENTION_WAIT;

	while (LogRetentionExists(dir, name))
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(10);
	}

	return true;
}

// Delete the files and the folders of dir (they hold no folder of their own), then dir
static void LogRetentionDelete(char *dir)
{
	DIRLIST *d = EnumDir(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		char path[MAX_SIZE];

		LogRetentionPath(path, sizeof(path), dir, e->FileName);

		if (e->Folder)
		{
			wchar_t *path_w = CopyStrToUni(path);

			DeleteDirW(path_w);
			Free(path_w);
		}
		else
		{
			FileDelete(path);
		}
	}

	FreeDir(d);

	wchar_t *dir_w = CopyStrToUni(dir);

	DeleteDirW(dir_w);
	Free(dir_w);
}

// The age limit
static void LogRetentionAge(LOGRETENTION_CTX *ctx)
{
	char dir[MAX_SIZE];
	char detail[MAX_SIZE];
	char open_name[MAX_SIZE];

	LogRetentionNewDir(dir, sizeof(dir), "logretention_age");

	// The files of the log that are old, one that is recent, and what is no file of the log
	LogRetentionPlant(dir, "lr_20200101.log", "an old record\r\n", LOGRETENTION_OLD_DAYS);
	LogRetentionPlant(dir, "lr_20200102~01.log", "another old record\r\n", LOGRETENTION_OLD_DAYS);
	LogRetentionPlant(dir, "lr_20991231.log", "a recent record\r\n", 1);
	LogRetentionPlant(dir, "other_20200101.log", "the log of another program\r\n", LOGRETENTION_OLD_DAYS);
	LogRetentionPlant(dir, "lr_notes.txt", "not a log file\r\n", LOGRETENTION_OLD_DAYS);
	LogRetentionPlant(dir, "lr_folder.log", NULL, LOGRETENTION_OLD_DAYS);

	LOG *g = NewLog(dir, "lr", LOG_SWITCH_DAY, 0);

	SetLogLimits(g, LOGRETENTION_DAYS, 0);

	bool gone1 = LogRetentionWaitGone(dir, "lr_20200101.log");
	bool gone2 = LogRetentionWaitGone(dir, "lr_20200102~01.log");

	Format(detail, sizeof(detail), "lr_20200101.log gone: %s, lr_20200102~01.log gone: %s", gone1 ? "yes" : "no", gone2 ? "yes" : "no");
	LogRetentionCheck(ctx, gone1 && gone2, "The files of the log that are older than the age limit are deleted", detail);

	LogRetentionCheck(ctx, LogRetentionExists(dir, "lr_20991231.log"), "A file of the log that is within the age limit stays", "lr_20991231.log is gone");

	LogRetentionCheck(ctx, LogRetentionExists(dir, "other_20200101.log") && LogRetentionExists(dir, "lr_notes.txt") && LogRetentionExists(dir, "lr_folder.log"),
		"An old file of another log, a file that is no log file and a folder stay", "one of them is gone");

	// The writer tells each deletion in the log, which opens a file of its own
	InsertStringRecord(g, "age test record");
	WaitLogFlush(g);

	char *text = LogRetentionRead(dir, "lr_2");

	LogRetentionCheck(ctx, LogRetentionHas(text, "lr_20200101.log deleted") && LogRetentionHas(text, "lr_20200102~01.log deleted") && LogRetentionHas(text, "age test record"),
		"The log says that it deleted each file, and holds the record that was inserted", "the lines of the log are not there");
	Free(text);

	// The file that is open stays when it is older than the age limit: it is aged while it is open
	LogRetentionFind(open_name, sizeof(open_name), dir, "lr_2", "age test record");
	LogRetentionCheck(ctx, IsEmptyStr(open_name) == false, "The record is in a file of the log that the test can name", "no file holds it");

	if (IsEmptyStr(open_name) == false)
	{
		char path[MAX_SIZE];

		LogRetentionPath(path, sizeof(path), dir, open_name);
		LogRetentionCheck(ctx, LogRetentionSetAge(path, LOGRETENTION_OLD_DAYS), "The file that is open can be set to an age beyond the limit", "its time cannot be set");

		SetLogLimits(g, LOGRETENTION_DAYS, 0);
		SleepThread(500);

		InsertStringRecord(g, "record after the limits");
		WaitLogFlush(g);

		text = LogRetentionRead(dir, "lr_2");
		LogRetentionCheck(ctx, LogRetentionExists(dir, open_name) && LogRetentionHas(text, "age test record") && LogRetentionHas(text, "record after the limits"),
			"The file that is open is not deleted, however old it is", "the open file is gone, or lost its records");
		Free(text);
	}

	FreeLog(g);

	LogRetentionDelete(dir);
}

// The disk limit
static void LogRetentionDisk(LOGRETENTION_CTX *ctx)
{
	char dir[MAX_SIZE];
	char detail[MAX_SIZE];
	char first[64];
	char last[64];
	UINT64 total = 0;
	UINT64 worst = 0;
	UINT num = 0;

	LogRetentionNewDir(dir, sizeof(dir), "logretention_disk");

	LOG *g = NewLog(dir, "ld", LOG_SWITCH_DAY, 0);

	SetLogLimits(g, 0, LOGRETENTION_DISK_LIMIT);

	LogRetentionCheck(ctx, GetMaxLogSize(g) == LOGRETENTION_DISK_LIMIT / 4, "A disk limit makes the maximum size of a file a quarter of it", "another maximum log size");

	for (UINT i = 0;i < LOGRETENTION_RECORDS;i++)
	{
		char line[MAX_SIZE];

		// A line of about LOGRETENTION_RECORD_SIZE bytes with the date and the time that the writer adds
		Format(line, sizeof(line), "disk test record %05u 012345678901234567890123456789012345678901234567890123456789", i);
		InsertStringRecord(g, line);

		if ((i + 1) % LOGRETENTION_BATCH == 0)
		{
			WaitLogFlush(g);
			SleepThread(1);

			num = LogRetentionCount(dir, "ld", &total);

			if (total > worst)
			{
				worst = total;
			}
		}
	}

	WaitLogFlush(g);
	SleepThread(200);

	num = LogRetentionCount(dir, "ld", &total);

	if (total > worst)
	{
		worst = total;
	}

	Format(detail, sizeof(detail), "the files took %I64u bytes at most, the limit is %I64u", worst, (UINT64)LOGRETENTION_DISK_LIMIT);
	LogRetentionCheck(ctx, worst <= LOGRETENTION_DISK_LIMIT, "The files of the log never take more than the disk limit together", detail);

	Format(detail, sizeof(detail), "%u files take %I64u bytes", num, total);
	LogRetentionCheck(ctx, num >= 2 && total >= LOGRETENTION_DISK_LIMIT / 2, "The log keeps what the limit allows, and not much less", detail);

	char *text = LogRetentionRead(dir, "ld");

	Format(first, sizeof(first), "disk test record %05u ", 0);
	Format(last, sizeof(last), "disk test record %05u ", LOGRETENTION_RECORDS - 1);
	LogRetentionCheck(ctx, LogRetentionHas(text, last) && LogRetentionHas(text, first) == false && LogRetentionHas(text, "deleted: the log files would take more than the disk limit"),
		"The log keeps the newest records, and says that it deleted the oldest files", "the newest record is gone, the first one is there, or no deletion is told");
	Free(text);

	FreeLog(g);

	LogRetentionDelete(dir);
}

RANZ_TEST("logretention", logretention_test, "Log retention: the files of a LOG stay within an age limit and a disk limit, and the open file is never deleted (SDN-54).");
void logretention_test(UINT num, char **arg)
{
	LOGRETENTION_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("Log retention test: the age limit and the disk limit of the files of a LOG\n");

	LogRetentionAge(&ctx);
	LogRetentionDisk(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("LOGRETENTION TEST OK\n");
	}
	else
	{
		Print("LOGRETENTION TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
