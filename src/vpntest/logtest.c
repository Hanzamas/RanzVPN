// logtest.c
// Named log writer tests of vpntest (PKG-4 #108)
//
// "logwriter" (FND-15): the writer thread of a LOG kept the name of its current file with
// StrCpy(current_file_name, sizeof(current_file_name), ...) on a char * parameter, so only 7
// characters were kept and every record closed the file and opened it again. A LOG in a private
// directory takes LOGTEST_WRITER_RECORDS string records: the writer opens or creates a file at most
// LOGTEST_WRITER_MAX_OPENS times (KS_IO_OPEN_COUNT plus KS_IO_CREATE_COUNT), and every record is in
// the file in order. A second LOG on the same file with a small maximum log size (NewLog, SetMaxLogSize)
// appends to it, switches once to the next file, named as before, and keeps every record in order.
//
// "logbound" (FND-16): while the log file could not be opened, the record queue grew without a limit
// and the buffer up to the maximum log size (1 GiB), and the writer slept 30 ms per record. A LOG whose
// directory has an existing file as its parent takes LOGTEST_BOUND_RECORDS string records and LOGTEST_BOUND_PACKETS
// packet log records: the queue never holds more than LOG_ENGINE_MAX_QUEUE records, every dropped
// packet log record releases its session reference and its logging record count. Once that file is a
// directory, the writer opens the log on its own retry timer: the file starts with the buffered records
// (at most LOG_ENGINE_BUFFER_NO_FILE_MAX bytes, in order), then one dropped-records line whose count
// makes up the rest, then the records inserted after the unblock.
//
// "slog" (FND-18): SetSysLog stored Tick64() + IsZeroIP(&ip) ? NG : OK, the bare interval, so the first message
// after it resolved the host again; SendSysLog resolved the host while it held the lock of the SLOG, so every other
// sender waited for the resolver. The next resolve is a tick deadline (SYSLOG_POLL_IP_INTERVAL after a resolved
// host, SYSLOG_POLL_IP_INTERVAL_NG after an empty one); while a first sender resolves an unknown single-label host
// name, a second sender returns within LOGTEST_SLOG_SECOND_LIMIT ms; a datagram holds the UTF-8 text, at most
// 1023 bytes of it.
//
// "eraser" (FND-20): EraserThread waited GetEraserCheckInterval() milliseconds, the interval in seconds, so the
// 5-minute default became 300 ms and a 1-second interval 1 ms. An eraser with a check interval of 1 s and a free
// space threshold of DISK_FREE_SPACE_MIN (nothing is deleted) makes at most LOGTEST_ERASER_MAX_CHECKS checks in
// LOGTEST_ERASER_SPAN ms; the interval keeps its seconds in the configuration (AutoDeleteCheckIntervalSecs).
//
// Each test prints "<NAME> TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"
#include "Cedar/Eraser.h"
#include "Cedar/LogWriter.h"
#include "Cedar/PacketLog.h"
#include "Cedar/Session.h"
#include "Cedar/Syslog.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
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

#define	LOGTEST_BOUND_PREFIX			"lb"				// Prefix of the log file
#define	LOGTEST_BOUND_DIR				"blocked"			// Parent of the log directory: a file while the LOG cannot write
#define	LOGTEST_BOUND_LOG_DIR			"logs"				// The log directory
#define	LOGTEST_BOUND_TEXT				"logbound record %06u "	// Start of string record n; LOGTEST_BOUND_PAD characters follow
#define	LOGTEST_BOUND_PAD				170					// With the date and the time, a line of 219 bytes
#define	LOGTEST_BOUND_RECORDS			300000				// String records inserted while the directory is blocked
#define	LOGTEST_BOUND_PACKETS			100					// Packet log records inserted after them
#define	LOGTEST_BOUND_AFTER_TEXT		"logbound after %02u"	// Text of a record inserted after the unblock
#define	LOGTEST_BOUND_AFTER				10					// Records inserted after the unblock
#define	LOGTEST_BOUND_DRAIN_WAIT		240000				// Milliseconds waited for the writer to take every queued record: about 100 s under AddressSanitizer, 6000 s at one per 30 ms
#define	LOGTEST_BOUND_OPEN_WAIT			(LOG_ENGINE_RETRY_MAX + 10000)	// Milliseconds waited for the log file after the unblock
#define	LOGTEST_BOUND_FRAME_SIZE		64					// Frame of the packet log records (EtherType 0x88B5, no IP)

#define	LOGTEST_SLOG_TEXT				L"slog datagram caf\x00e9"	// Message of the content check
#define	LOGTEST_SLOG_TEXT_UTF8			"slog datagram caf\xc3\xa9"	// Its datagram
#define	LOGTEST_SLOG_LONG				2000				// Characters of the long message
#define	LOGTEST_SLOG_DATAGRAM_MAX		1023				// Bytes of a message SendSysLog sends at most
#define	LOGTEST_SLOG_RECV_WAIT			2000				// Milliseconds waited for a datagram
#define	LOGTEST_SLOG_RESOLVE_WAIT		3000				// Milliseconds waited for the first sender to start resolving
#define	LOGTEST_SLOG_SECOND_LIMIT		100					// Milliseconds a second sender may take meanwhile

#define	LOGTEST_ERASER_INTERVAL			1					// Check interval of the eraser (seconds)
#define	LOGTEST_ERASER_SPAN				3000				// Milliseconds the eraser runs
#define	LOGTEST_ERASER_MAX_CHECKS		4					// Checks at 0, 1, 2 and 3 s at most
#define	LOGTEST_ERASER_CONFIG_SECS		7					// A check interval through the configuration getter

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

	if (b == NULL)
	{
		return NULL;
	}

	char *ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);

	FreeBuf(b);

	return ret;
}

// Next line of a text from *pos, NUL-terminated in place; a line ends at CR or LF and empty lines are
// skipped. NULL at the end of the text
static char *LogTestNextLine(char **pos)
{
	char *s = *pos;

	while (*s == '\r' || *s == '\n')
	{
		s++;
	}

	if (*s == 0)
	{
		*pos = s;
		return NULL;
	}

	char *line = s;

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

// Text of a string record line after its date and time ("<date> <time> <text>"), NULL when the line has
// no two spaces
static char *LogTestLineText(char *line)
{
	UINT num_spaces = 0;
	char *s;

	for (s = line;*s != 0;s++)
	{
		if (*s == ' ')
		{
			num_spaces++;

			if (num_spaces == 2)
			{
				return s + 1;
			}
		}
	}

	return NULL;
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
	UINT64 size1 = 0;
	UINT total = LOGTEST_WRITER_RECORDS + LOGTEST_WRITER_SWITCH_RECORDS + 1;
	UINT lines, in_order;

	Zero(&ctx, sizeof(ctx));

	Print("Log writer test: %u records, then %u more with a maximum log size of %I64u bytes\n",
		LOGTEST_WRITER_RECORDS, LOGTEST_WRITER_SWITCH_RECORDS + 1, LOGTEST_WRITER_MAX_SIZE);

	LogTestCheck(&ctx, IsTrackingEnabled(), "file open and create counters are on (tracking enabled)", "IsTrackingEnabled() is false");

	LogTestDirName(dir, sizeof(dir), "logwriter");
	Format(file1, sizeof(file1), "%s/%s.log", dir, LOGTEST_WRITER_PREFIX);
	Format(file2, sizeof(file2), "%s/%s", dir, LOGTEST_WRITER_SWITCH_FILE);
	Format(file3, sizeof(file3), "%s/%s", dir, LOGTEST_WRITER_NEXT_FILE);

	// First LOG: the default maximum size, no date in the file name
	UINT64 opens = LogTestNumOpens();

	LOG *g = NewLog(dir, LOGTEST_WRITER_PREFIX, LOG_SWITCH_NO, 0);
	for (UINT i = 0;i < LOGTEST_WRITER_RECORDS;i++)
	{
		LogWriterInsert(g, i);
	}
	FreeLog(g);

	opens = LogTestNumOpens() - opens;
	LogTestCheck(&ctx, opens <= LOGTEST_WRITER_MAX_OPENS,
		"1000 records: the writer opens or creates its file at most twice (it reopened the file for every record)",
		"%I64u files opened or created", opens);

	char *text1 = LogTestReadText(file1);
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
	opens = LogTestNumOpens();

	g = NewLog(dir, LOGTEST_WRITER_PREFIX, LOG_SWITCH_NO, LOGTEST_WRITER_MAX_SIZE);
	for (UINT i = LOGTEST_WRITER_RECORDS;i < (total - 1);i++)
	{
		LogWriterInsert(g, i);
	}

	UINT64 end = Tick64() + LOGTEST_WRITER_SWITCH_WAIT;
	while (g->CurrentLogNumber == 0 && Tick64() < end)
	{
		SleepThread(10);
	}
	bool switched = (g->CurrentLogNumber == 1);

	LogWriterInsert(g, total - 1);
	FreeLog(g);

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
	char *text2 = LogTestReadText(file2);
	if (LogTestCheck(&ctx, text1 != NULL && text2 != NULL, "both files can be read", "%s or %s cannot be read", file1, file2))
	{
		BUF *b = NewBuf();

		size1 = StrLen(text1);
		LogTestCheck(&ctx, size1 <= LOGTEST_WRITER_MAX_SIZE, "lw.log stays within the maximum size",
			"%I64u bytes", size1);

		WriteBuf(b, text1, StrLen(text1));
		WriteBuf(b, text2, StrLen(text2));
		WriteBufChar(b, 0);
		char *all = (char *)b->Buf;

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

////////////////////////////
// logbound (FND-16)

// Run state of logbound
typedef struct LOGBOUND_TEST
{
	LOG *Log;							// The LOG under test
	UINT MaxQueue;						// Most records seen in its queue
	char Pad[LOGTEST_BOUND_PAD + 1];	// Padding of a string record
} LOGBOUND_TEST;

// Records in the queue of the LOG; the most seen so far goes to t->MaxQueue
static UINT LogBoundQueued(LOGBOUND_TEST *t)
{
	UINT num;

	LockQueue(t->Log->RecordQueue);
	{
		num = t->Log->RecordQueue->num_item;
	}
	UnlockQueue(t->Log->RecordQueue);

	t->MaxQueue = MAX(t->MaxQueue, num);

	return num;
}

// Insert string record n: LOGTEST_BOUND_TEXT and the padding
static void LogBoundInsert(LOGBOUND_TEST *t, UINT n)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), LOGTEST_BOUND_TEXT, n);
	StrCat(tmp, sizeof(tmp), t->Pad);

	InsertStringRecord(t->Log, tmp);
	LogBoundQueued(t);
}

// Insert a packet log record of session s as PacketLog makes it: a clone of the frame without its data,
// the session names, a reference to the session and one more logging record of it
static void LogBoundInsertPacket(LOGBOUND_TEST *t, SESSION *s, PKT *frame)
{
	PACKET_LOG *pl = ZeroMalloc(sizeof(PACKET_LOG));

	pl->Packet = ClonePacket(frame, false);
	pl->SrcSessionName = CopyStr("logbound-session");
	pl->DestSessionName = CopyStr("");
	pl->SrcSession = s;
	AddRef(s->ref);
	Inc(s->LoggingRecordCount);

	InsertRecord(t->Log, pl, PacketLogParseProc, PacketLogFreeProc, true);
	LogBoundQueued(t);
}

// Session of the packet log records: a packet log record uses only its reference and its logging record count
static SESSION *LogBoundNewSession()
{
	SESSION *s = ZeroMalloc(sizeof(SESSION));

	s->ref = NewRef();
	s->LoggingRecordCount = NewCounter();

	return s;
}

// Release the session of the packet log records: its reference is freed only when no record holds it
static void LogBoundFreeSession(SESSION *s)
{
	Release(s->ref);
	DeleteCounter(s->LoggingRecordCount);
	Free(s);
}

// Frame of the packet log records (EtherType 0x88B5, no IP), parsed as the hub parses it
static PKT *LogBoundParseFrame(UCHAR *buf)
{
	for (UINT i = 0;i < LOGTEST_BOUND_FRAME_SIZE;i++)
	{
		buf[i] = (UCHAR)i;
	}

	buf[0] = 0x02;								// Locally administered unicast addresses
	buf[6] = 0x02;
	buf[12] = 0x88;
	buf[13] = 0xB5;

	return ParsePacket(buf, LOGTEST_BOUND_FRAME_SIZE);
}

// The log file after the unblock: the buffered records in order, one dropped-records line that makes up the
// rest of the records inserted while blocked, then the records inserted after the unblock
static void LogBoundCheckFile(LOGTEST_CTX *ctx, char *path)
{
	char *text = LogTestReadText(path);
	char expect[MAX_SIZE];
	char *line;
	UINT num_buffered = 0;
	UINT64 buffered_bytes = 0;
	UINT num_dropped_lines = 0;
	UINT64 num_dropped = 0;
	bool dropped_next = false;
	UINT num_after = 0;
	UINT num_other = 0;
	UINT64 total = (UINT64)LOGTEST_BOUND_RECORDS + (UINT64)LOGTEST_BOUND_PACKETS;

	if (LogTestCheck(ctx, text != NULL, "the log file can be read after the unblock", "%s cannot be read", path) == false)
	{
		return;
	}

	char *pos = text;

	while ((line = LogTestNextLine(&pos)) != NULL)
	{
		char *s = LogTestLineText(line);

		if (s == NULL)
		{
			num_other++;
			continue;
		}

		Format(expect, sizeof(expect), LOGTEST_BOUND_TEXT, num_buffered);
		if (num_dropped_lines == 0 && num_after == 0 && StartWith(s, expect) &&
			StrLen(s) == StrLen(expect) + LOGTEST_BOUND_PAD)
		{
			num_buffered++;
			buffered_bytes += (UINT64)StrLen(line) + 2;
			continue;
		}

		Format(expect, sizeof(expect), LOG_DROPPED_RECORDS_FORMAT, ToInt64(s));
		if (StrCmp(s, expect) == 0)
		{
			if (num_dropped_lines == 0 && num_after == 0 && num_other == 0)
			{
				dropped_next = true;
			}

			num_dropped_lines++;
			num_dropped += ToInt64(s);
			continue;
		}

		Format(expect, sizeof(expect), LOGTEST_BOUND_AFTER_TEXT, num_after);
		if (num_dropped_lines != 0 && StrCmp(s, expect) == 0)
		{
			num_after++;
			continue;
		}

		num_other++;
	}

	Free(text);

	LogTestCheck(ctx, num_buffered >= 1 && buffered_bytes <= LOG_ENGINE_BUFFER_NO_FILE_MAX,
		"the file starts with the buffered records in order, at most LOG_ENGINE_BUFFER_NO_FILE_MAX bytes of them",
		"%u records, %I64u bytes, cap %u bytes", num_buffered, buffered_bytes, LOG_ENGINE_BUFFER_NO_FILE_MAX);

	LogTestCheck(ctx, num_dropped_lines == 1 && dropped_next,
		"one dropped-records line, right after the buffered records",
		"%u dropped-records lines, %s", num_dropped_lines, dropped_next ? "the first one after the buffered records" : "none after the buffered records");

	LogTestCheck(ctx, (UINT64)num_buffered + num_dropped == total,
		"the buffered and the dropped records make up every record inserted while the file could not be opened",
		"%u buffered + %I64u dropped, %I64u inserted", num_buffered, num_dropped, total);

	LogTestCheck(ctx, num_after == LOGTEST_BOUND_AFTER && num_other == 0,
		"the records inserted after the unblock follow in order, no other line",
		"%u of %u in order, %u other lines", num_after, LOGTEST_BOUND_AFTER, num_other);
}

// "logbound": bounded record queue and buffer while the log file cannot be opened, one dropped-records line
void logbound_test(UINT num, char **arg)
{
	LOGTEST_CTX ctx;
	LOGBOUND_TEST t;
	char dir[MAX_PATH];
	char block[MAX_PATH];
	char log_dir[MAX_PATH];
	char file[MAX_PATH];
	UCHAR frame_buf[LOGTEST_BOUND_FRAME_SIZE];
	bool drained;
	bool opened;

	Zero(&ctx, sizeof(ctx));
	Zero(&t, sizeof(t));

	Print("Log bound test: %u string records and %u packet log records while the parent of the log directory is a "
		"file, %u more after it is a directory\n", LOGTEST_BOUND_RECORDS, LOGTEST_BOUND_PACKETS, LOGTEST_BOUND_AFTER);

	for (UINT i = 0;i < LOGTEST_BOUND_PAD;i++)
	{
		t.Pad[i] = 'x';
	}

	LogTestDirName(dir, sizeof(dir), "logbound");
	Format(block, sizeof(block), "%s/%s", dir, LOGTEST_BOUND_DIR);
	Format(log_dir, sizeof(log_dir), "%s/%s", block, LOGTEST_BOUND_LOG_DIR);
	Format(file, sizeof(file), "%s/%s.log", log_dir, LOGTEST_BOUND_PREFIX);

	// The parent of the log directory is an existing file: the writer can make neither the directory nor the log file
	MakeDir(dir);
	IO *io = FileCreate(block);
	bool blocked = (io != NULL);
	FileClose(io);
	LogTestCheck(&ctx, blocked, "the parent of the log directory is an existing file", "%s cannot be created", block);

	SESSION *s = LogBoundNewSession();
	PKT *frame = LogBoundParseFrame(frame_buf);
	LogTestCheck(&ctx, frame != NULL, "the frame of the packet log records parses", "ParsePacket returned NULL");

	t.Log = NewLog(log_dir, LOGTEST_BOUND_PREFIX, LOG_SWITCH_NO, 0);

	for (UINT i = 0;i < LOGTEST_BOUND_RECORDS;i++)
	{
		LogBoundInsert(&t, i);
	}

	if (frame != NULL)
	{
		for (UINT i = 0;i < LOGTEST_BOUND_PACKETS;i++)
		{
			LogBoundInsertPacket(&t, s, frame);
		}
	}

	// The writer takes every record while the file cannot be opened: the first ones into its buffer, the
	// others it drops through their release path
	UINT64 end = Tick64() + LOGTEST_BOUND_DRAIN_WAIT;
	while (true)
	{
		drained = (LogBoundQueued(&t) == 0 && Count(s->LoggingRecordCount) == 0);

		if (drained || Tick64() >= end)
		{
			break;
		}

		SleepThread(50);
	}

	LogTestCheck(&ctx, t.MaxQueue <= LOG_ENGINE_MAX_QUEUE,
		"the record queue never holds more than LOG_ENGINE_MAX_QUEUE records (it had no limit)",
		"%u records queued at most, cap %u", t.MaxQueue, LOG_ENGINE_MAX_QUEUE);

	LogTestCheck(&ctx, drained, "the writer takes every queued record while the file cannot be opened (it took one per 30 ms)",
		"%u records still queued after %u ms", LogBoundQueued(&t), LOGTEST_BOUND_DRAIN_WAIT);

	LogTestCheck(&ctx, Count(s->LoggingRecordCount) == 0 && Count(&s->ref->c) == 1,
		"dropped packet log records release their session reference and their logging record count",
		"logging record count %u, session references %u (expected 0 and 1)", Count(s->LoggingRecordCount), Count(&s->ref->c));

	// Unblock (the parent becomes a directory): with no new record, the writer makes the log directory and the
	// file on its retry timer
	FileDelete(block);
	MakeDir(block);

	end = Tick64() + LOGTEST_BOUND_OPEN_WAIT;
	while ((opened = IsFileExists(file)) == false && Tick64() < end)
	{
		SleepThread(50);
	}

	LogTestCheck(&ctx, opened, "the writer opens the log file on its own once the directory can be made",
		"%s missing after %u ms", file, LOGTEST_BOUND_OPEN_WAIT);

	for (UINT i = 0;i < LOGTEST_BOUND_AFTER;i++)
	{
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), LOGTEST_BOUND_AFTER_TEXT, i);
		InsertStringRecord(t.Log, tmp);
	}

	FreeLog(t.Log);

	LogBoundCheckFile(&ctx, file);

	FreePacket(frame);
	LogBoundFreeSession(s);

	FileDelete(file);
	LogTestDeleteDir(log_dir);
	FileDelete(block);
	LogTestDeleteDir(block);
	LogTestDeleteDir(dir);

	LogTestEnd(&ctx, "LOGBOUND");
}

////////////////////////////
// slog (FND-18)

// Next datagram on a loopback UDP socket of the test within timeout ms: its size, 0 when none arrives
static UINT LogTestRecvDatagram(SOCK *s, UCHAR *buf, UINT size, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;

	while (true)
	{
		SOCKSET set;
		IP src_ip;
		UINT src_port;
		UINT64 now = Tick64();

		// Select() also puts the socket in non-blocking mode for RecvFrom()
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, (UINT)(now < end ? MIN(end - now, 100) : 0), NULL, NULL);

		UINT ret = RecvFrom(s, &src_ip, &src_port, buf, size);
		if (ret != 0 && ret != SOCK_LATER)
		{
			return ret;
		}

		if (Tick64() >= end)
		{
			return 0;
		}
	}
}

// Tick of the next resolve of the host of an SLOG
static UINT64 SlogNextPoll(SLOG *g)
{
	UINT64 ret;

	Lock(g->lock);
	{
		ret = g->NextPollIp;
	}
	Unlock(g->lock);

	return ret;
}

// The first sender of the slow resolve case: its message is due to resolve the host again
static void SlogFirstSenderThread(THREAD *thread, void *param)
{
	SendSysLog((SLOG *)param, L"slog first sender");
}

// "slog": tick deadline of the next resolve, a second sender while the first one resolves, unchanged datagrams
void slog_test(UINT num, char **arg)
{
	LOGTEST_CTX ctx;
	IP localhost;
	UINT64 elapsed = 0;
	UCHAR buf[2048];
	char host[64];
	bool in_flight;
	bool still_in_flight = false;

	Zero(&ctx, sizeof(ctx));

	Print("Syslog test: next resolve deadline, a second sender during a slow resolve, datagram content\n");

	SetIP(&localhost, 127, 0, 0, 1);
	SOCK *s = NewUDPEx2(0, false, &localhost);
	if (LogTestCheck(&ctx, s != NULL, "loopback UDP socket of the test", "NewUDPEx2 failed") == false)
	{
		LogTestEnd(&ctx, "SLOG");
		return;
	}

	// A host that resolves: the next resolve is SYSLOG_POLL_IP_INTERVAL from now
	UINT64 before = Tick64();
	SLOG *g = NewSysLog("127.0.0.1", s->LocalPort, NULL);
	UINT64 after = Tick64();
	UINT64 next = SlogNextPoll(g);
	LogTestCheck(&ctx, next >= before + SYSLOG_POLL_IP_INTERVAL && next <= after + SYSLOG_POLL_IP_INTERVAL,
		"SetSysLog with a resolved host: the next resolve is SYSLOG_POLL_IP_INTERVAL ms from now (it was the bare interval)",
		"NextPollIp %I64u, set between ticks %I64u and %I64u", next, before, after);

	// No host: the next resolve is SYSLOG_POLL_IP_INTERVAL_NG from now
	before = Tick64();
	SetSysLog(g, "", s->LocalPort);
	after = Tick64();
	next = SlogNextPoll(g);
	LogTestCheck(&ctx, next >= before + SYSLOG_POLL_IP_INTERVAL_NG && next <= after + SYSLOG_POLL_IP_INTERVAL_NG,
		"SetSysLog without an address: the next resolve is SYSLOG_POLL_IP_INTERVAL_NG ms from now",
		"NextPollIp %I64u, set between ticks %I64u and %I64u", next, before, after);

	SetSysLog(g, "127.0.0.1", s->LocalPort);

	// A datagram holds the UTF-8 text of the message, at most LOGTEST_SLOG_DATAGRAM_MAX bytes of it
	SendSysLog(g, LOGTEST_SLOG_TEXT);
	UINT size = LogTestRecvDatagram(s, buf, sizeof(buf), LOGTEST_SLOG_RECV_WAIT);
	LogTestCheck(&ctx, size == StrLen(LOGTEST_SLOG_TEXT_UTF8) && Cmp(buf, LOGTEST_SLOG_TEXT_UTF8, size) == 0,
		"a syslog datagram holds the UTF-8 text of its message", "%u bytes received", size);

	wchar_t *long_text = ZeroMalloc(sizeof(wchar_t) * (LOGTEST_SLOG_LONG + 1));
	for (UINT i = 0;i < LOGTEST_SLOG_LONG;i++)
	{
		long_text[i] = L'a';
	}

	SendSysLog(g, long_text);
	Free(long_text);

	size = LogTestRecvDatagram(s, buf, sizeof(buf), LOGTEST_SLOG_RECV_WAIT);
	bool all_a = true;
	for (UINT i = 0;i < size;i++)
	{
		if (buf[i] != 'a')
		{
			all_a = false;
		}
	}
	LogTestCheck(&ctx, size == LOGTEST_SLOG_DATAGRAM_MAX && all_a,
		"a longer message is cut to its first 1023 bytes", "%u bytes received", size);

	// A host name that is not in DNS, single-label so that the resolver also asks LLMNR and NetBIOS: the
	// first sender resolves it, a second sender must not wait for that
	Format(host, sizeof(host), "ranzslog%08x%08x", Rand32(), Rand32());
	Lock(g->lock);
	{
		StrCpy(g->HostName, sizeof(g->HostName), host);
		g->NextPollIp = 0;
	}
	Unlock(g->lock);

	UINT base = DnsThreadNum();
	THREAD *t = NewThread(SlogFirstSenderThread, g);

	before = Tick64();
	while ((in_flight = (DnsThreadNum() > base)) == false && Tick64() < before + LOGTEST_SLOG_RESOLVE_WAIT)
	{
		SleepThread(0);
	}

	if (in_flight)
	{
		before = TickHighres64();
		SendSysLog(g, L"slog second sender");
		elapsed = TickHighres64() - before;
		still_in_flight = (DnsThreadNum() > base);
	}

	LogTestCheck(&ctx, in_flight && still_in_flight && elapsed < LOGTEST_SLOG_SECOND_LIMIT,
		"a second sender returns at once while the first one resolves the host (it waited for the resolver)",
		"first sender resolving: %s, second sender took %I64u ms, the resolve %s when it returned",
		in_flight ? "yes" : "never seen", elapsed, still_in_flight ? "was still running" : "had ended");

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	FreeSysLog(g);
	ReleaseSock(s);

	LogTestEnd(&ctx, "SLOG");
}

////////////////////////////
// eraser (FND-20)

// "eraser": the eraser thread waits its check interval in milliseconds; the configuration keeps seconds
void eraser_test(UINT num, char **arg)
{
	LOGTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("Eraser test: check interval %u s for %u ms\n", LOGTEST_ERASER_INTERVAL, LOGTEST_ERASER_SPAN);

	// AutoDeleteCheckIntervalSecs goes through NewEraser and GetEraserCheckInterval in seconds. The threshold of
	// DISK_FREE_SPACE_MIN is met on any test machine and no target is given: the eraser only checks, it deletes nothing
	ERASER *e = NewEraser(NULL, DISK_FREE_SPACE_MIN, LOGTEST_ERASER_CONFIG_SECS, NULL, 0);
	UINT secs = GetEraserCheckInterval(e);
	FreeEraser(e);
	LogTestCheck(&ctx, secs == LOGTEST_ERASER_CONFIG_SECS, "the check interval goes in and out of the configuration in seconds",
		"set %u s, got %u", LOGTEST_ERASER_CONFIG_SECS, secs);

	e = NewEraser(NULL, DISK_FREE_SPACE_MIN, LOGTEST_ERASER_INTERVAL, NULL, 0);
	SleepThread(LOGTEST_ERASER_SPAN);
	UINT checks = e->NumChecks;
	FreeEraser(e);

	LogTestCheck(&ctx, checks >= 1 && checks <= LOGTEST_ERASER_MAX_CHECKS,
		"a check interval of 1 s gives at most 4 free space checks in 3 s (it waited 1 ms)",
		"%u checks", checks);

	e = NewEraser(NULL, DISK_FREE_SPACE_MIN, 0, NULL, 0);
	secs = GetEraserCheckInterval(e);
	FreeEraser(e);
	LogTestCheck(&ctx, secs == DISK_FREE_CHECK_INTERVAL_DEFAULT / 1000, "an interval of 0 restores the default of 300 s",
		"got %u s", secs);

	LogTestEnd(&ctx, "ERASER");
}
