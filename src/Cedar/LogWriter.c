// LogWriter.c
// Log writer: a thread per LOG writes its records to log files that switch by date and size

#include "LogWriter.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

// Milliseconds in a day, the unit of the age limit of the files of a log (SetLogLimits)
#define LOG_MS_PER_DAY (24ULL * 60ULL * 60ULL * 1000ULL)

// State of the writer thread of a LOG (LogThread): the open file, the records not yet written,
// the name of the open file and the date part of the current file name
typedef struct LOG_WRITER {
	IO *Io;                  // Open log file, NULL while none is open
	BUF *Buffer;             // Records not yet written to the file
	char FileName[MAX_SIZE]; // Name of the open file (while none is open: of the file to open)
	char DateName[MAX_SIZE]; // Date part of the current file name
	UINT RetryWait;          // Milliseconds waited after the last failed open, 0 after a successful one
	UINT64 RetryTick;        // No new try to open the file before this tick
	bool Realtime;           // The thread runs at the realtime priority (false: idle priority)
	// The limits of the files of the log are applied again at this tick at the latest (LogSweep)
	UINT64 NextSweepTick;
} LOG_WRITER;

static bool LogThreadWriteGeneral(LOG *log_object, LOG_WRITER *w);
static UINT LogWriterWaitTime(const LOG_WRITER *w);

// Map the control characters of size bytes of UTF-8 text (bytes below 0x20 and 0x7F, never part of a
// multi-byte sequence) to '?': a CR or LF from untrusted input cannot start a forged log line or syslog message
void LogMapControlChars(UCHAR *s, UINT size) {
	for (UINT i = 0; i < size; i++)
		if (s[i] < 0x20 || s[i] == 0x7F)
			s[i] = '?';
}

// Format the text of the string table entry name with args into buf (size bytes): the one place HLog and ELog build
// their log line
void LogFormat(wchar_t *buf, UINT size, char *name, va_list args) {
	UniFormatArgs(buf, size, _UU(name), args);
}

void SetLogSwitchType(LOG *g, UINT switch_type) {
	if (g == NULL)
		return;

	LockLog(g);
	{
		g->SwitchType = switch_type;
	}
	UnlockLog(g);
}

static char *StringRecordParseProc(RECORD *rec) {
	if (rec == NULL)
		return NULL;

	return (char *)rec->Data;
}

void InsertUnicodeRecord(LOG *g, wchar_t *unistr) {
	if (g == NULL || unistr == NULL)
		return;

	UINT size = CalcUniToUtf8(unistr) + 32;
	char *str = ZeroMalloc(size);

	UniToUtf8((BYTE *)str, size, unistr);
	LogMapControlChars((UCHAR *)str, StrLen(str));

	// The record owns the buffer
	InsertRecord(g, str, StringRecordParseProc, Free, false);
}

void InsertStringRecord(LOG *g, char *str) {
	if (g == NULL || str == NULL)
		return;

	char *str_copy = CopyStr(str);
	LogMapControlChars((UCHAR *)str_copy, StrLen(str_copy));

	InsertRecord(g, str_copy, StringRecordParseProc, Free, false);
}

// Release a record that is not written: its free procedure releases its data without making its line (a packet
// log record also gives back its session reference and its logging record count)
static void FreeRecord(RECORD *rec) {
	rec->FreeProc(rec->Data);
	Free(rec);
}

// Queue a record of data for the writer: proc makes its line when it is written, free_proc releases data when it
// is dropped, is_csv separates the date and the time of the line with commas
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc, RECORD_FREE_PROC *free_proc, bool is_csv) {
	bool dropped = false;
	if (g == NULL || data == NULL || proc == NULL || free_proc == NULL)
		return;

	RECORD *rec = ZeroMalloc(sizeof(RECORD));
	rec->Tick = Tick64();
	rec->ParseProc = proc;
	rec->FreeProc = free_proc;
	rec->IsCsv = is_csv;
	rec->Data = data;

	LockQueue(g->RecordQueue);
	{
		if (g->RecordQueue->num_item >= LOG_ENGINE_MAX_QUEUE) {
			// The writer is too far behind: the new record is dropped and counted
			g->NumDropped++;
			dropped = true;
		} else {
			InsertQueue(g->RecordQueue, rec);
		}
	}
	UnlockQueue(g->RecordQueue);

	if (dropped)
		FreeRecord(rec);

	Set(g->Event);
}

void LockLog(LOG *g) {
	if (g == NULL)
		return;

	Lock(g->lock);
}

void UnlockLog(LOG *g) {
	if (g == NULL)
		return;

	Unlock(g->lock);
}

static void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type) {
	SYSTEMTIME st;

	if (str == NULL || g == NULL)
		return;

	if (g->CacheFlag) {
		if (g->LastTick == tick &&
		    g->LastSwitchType == switch_type) {
			StrCpy(str, size, g->LastStr);
			return;
		}
	}

	UINT64 time = Tick64ToTime64(tick);
	UINT64ToSystem(&st, SystemToLocal64(time));

	switch (switch_type) {
	case LOG_SWITCH_SECOND:
		snprintf(str, size, "_%04u%02u%02u_%02u%02u%02u",
		         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		break;

	case LOG_SWITCH_MINUTE:
		snprintf(str, size, "_%04u%02u%02u_%02u%02u",
		         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		break;

	case LOG_SWITCH_HOUR:
		snprintf(str, size, "_%04u%02u%02u_%02u", st.wYear, st.wMonth, st.wDay, st.wHour);
		break;

	case LOG_SWITCH_DAY:
		snprintf(str, size, "_%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
		break;

	case LOG_SWITCH_MONTH:
		snprintf(str, size, "_%04u%02u", st.wYear, st.wMonth);
		break;

	default:
		StrCpy(str, size, "");
		break;
	}

	g->CacheFlag = true;
	g->LastTick = tick;
	g->LastSwitchType = switch_type;
	StrCpy(g->LastStr, sizeof(g->LastStr), str);
}

// Make the name of the log file of tick with the file number num from the directory and prefix of g (g->lock held).
// True when the date part of the name differs from old_datestr, which then takes the new one
static bool MakeLogFileName(LOG *g, char *name, UINT size, UINT64 tick, UINT switch_type, UINT num,
                            char *old_datestr, UINT old_datestr_size) {
	char tmp[MAX_SIZE];
	char tmp2[64];
	bool ret = false;
	if (g == NULL || name == NULL || old_datestr == NULL)
		return false;

	MakeLogFileNameStringFromTick(g, tmp, sizeof(tmp), tick, switch_type);

	if (num == 0) {
		tmp2[0] = 0;
	} else {
		UINT64 max_log_size = GetMaxLogSize(g);
		if (max_log_size == MAX_LOG_SIZE_DEFAULT) {
			snprintf(tmp2, sizeof(tmp2), "~%02u", num);
		} else {
			char tag[32];
			char c = '2';
			if (max_log_size >= 1000000000ULL)
				c = '3';
			else if (max_log_size >= 100000000ULL)
				c = '4';
			else if (max_log_size >= 10000000ULL)
				c = '5';
			else if (max_log_size >= 1000000ULL)
				c = '6';
			else if (max_log_size >= 100000ULL)
				c = '7';
			else if (max_log_size >= 10000ULL)
				c = '8';
			else if (max_log_size >= 1000ULL)
				c = '9';

			StrCpy(tag, sizeof(tag), "~%02u");
			tag[3] = c;

			snprintf(tmp2, sizeof(tmp2), tag, num);
		}
	}

	if (StrCmp(old_datestr, tmp) != 0) {
		ret = true;
		StrCpy(old_datestr, old_datestr_size, tmp);
	}

	snprintf(name, size, "%s%s%s%s%s.log", g->DirName,
	         StrLen(g->DirName) == 0 ? "" : "/",
	         g->Prefix, tmp, tmp2);

	return ret;
}

void WaitLogFlush(LOG *g) {
	if (g == NULL)
		return;

	while (true) {
		UINT num;
		LockQueue(g->RecordQueue);
		{
			num = g->RecordQueue->num_item;
		}
		UnlockQueue(g->RecordQueue);

		if (num == 0)
			break;

		Wait(g->FlushEvent, 100);
	}
}

// Set the maximum size of a log file of g (LoggerMaxLogSize of the configuration), 0 for MAX_LOG_SIZE_DEFAULT: a
// record that would take the file over it goes to the next file number
void SetMaxLogSize(LOG *g, UINT64 size) {
	if (g == NULL)
		return;

	if (size == 0)
		size = MAX_LOG_SIZE_DEFAULT;

	g->MaxLogSize = size;
}

UINT64 GetMaxLogSize(LOG *g) {
	if (g == NULL)
		return MAX_LOG_SIZE_DEFAULT;

	UINT64 ret = g->MaxLogSize;

	if (ret == 0)
		ret = MAX_LOG_SIZE_DEFAULT;

	return ret;
}

// Set the limits of the files of g (SDN-54, #247): an age limit in days and a disk limit in bytes, 0 for none. The
// files of a log are the files of its directory whose names start with its prefix and end with ".log". The writer
// thread deletes the oldest of them that are past the age limit, and the oldest ones while the files together would
// pass the disk limit, when the limits are set, every LOG_LIMITS_SWEEP_INTERVAL and each time it opens a file. The
// file that is open counts as much as the maximum log size lets it grow to, so a disk limit makes the maximum log size
// at most a quarter of it, and the log never takes more than the limit, also not between two files.
void SetLogLimits(LOG *g, UINT max_age_days, UINT64 max_total_size) {
	if (g == NULL)
		return;

	if (max_total_size != 0)
		SetMaxLogSize(g, MIN(GetMaxLogSize(g), MAX(max_total_size / 4, 1)));

	LockLog(g);
	{
		g->MaxAgeDays = max_age_days;
		g->MaxTotalSize = max_total_size;
		g->LimitsChanged = true;
	}
	UnlockLog(g);

	Set(g->Event);
}

// A file of the directory of a log that its limits may delete
typedef struct LOG_OLD_FILE {
	char Path[MAX_SIZE];
	UINT64 Size;
	UINT64 UpdateDate;
} LOG_OLD_FILE;

// Order the files of a log by the time of their last write, the oldest first, and by name when it is the same
static int CompareLogOldFile(void *p1, void *p2) {
	LOG_OLD_FILE *f1 = *(LOG_OLD_FILE **)p1;
	LOG_OLD_FILE *f2 = *(LOG_OLD_FILE **)p2;

	if (f1->UpdateDate == f2->UpdateDate)
		return StrCmpi(f1->Path, f2->Path);

	return (f1->UpdateDate > f2->UpdateDate) ? 1 : -1;
}

// Whether name is the name of a file of g: its prefix, then "_" (a date), "~" (a file number) or "." (no date), and
// ".log" last
static bool LogIsFileOf(const LOG *g, const char *name) {
	if (StartWith(name, g->Prefix) == false || EndWith(name, ".log") == false)
		return false;

	char next = name[StrLen(g->Prefix)];

	return (next == '_' || next == '~' || next == '.');
}

// Delete the files of g that its limits take away, the oldest first: those whose last write is more than the age limit
// ago, then as many more as it takes for the files that are left, and the file that is open with the room that it may
// grow to, not to pass the disk limit. The open file open_file is never deleted. A file that cannot be deleted stays
// and is tried again later. Each deletion is a line of the log.
static void LogApplyLimits(LOG *g, const char *open_file) {
	UINT max_age_days = g->MaxAgeDays;
	UINT64 max_total_size = g->MaxTotalSize;
	UINT64 max_file_size = GetMaxLogSize(g);
	UINT64 now = SystemTime64();
	UINT64 total = 0;
	char text[MAX_SIZE];

	if (max_age_days == 0 && max_total_size == 0)
		return;

	LIST *o = NewListFast(CompareLogOldFile);
	DIRLIST *d = EnumDir(IsEmptyStr(g->DirName) ? "." : g->DirName);

	for (UINT i = 0; d != NULL && i < d->NumFiles; i++) {
		DIRENT *e = d->File[i];

		if (e->Folder == false && LogIsFileOf(g, e->FileName)) {
			LOG_OLD_FILE *f = ZeroMalloc(sizeof(LOG_OLD_FILE));

			// The name of the file as the writer makes it, so that it can tell the open file
			Format(f->Path, sizeof(f->Path), "%s%s%s", g->DirName, IsEmptyStr(g->DirName) ? "" : "/", e->FileName);
			f->Size = e->FileSize;
			f->UpdateDate = e->UpdateDate;

			if (StrCmpi(f->Path, open_file) == 0) {
				Free(f);
			} else {
				Add(o, f);
				total += f->Size;
			}
		}
	}

	FreeDir(d);
	Sort(o);

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		LOG_OLD_FILE *f = LIST_DATA(o, i);
		bool too_old = (max_age_days != 0 && f->UpdateDate + (UINT64)max_age_days * LOG_MS_PER_DAY < now);
		bool too_big = (max_total_size != 0 && total + max_file_size > max_total_size);

		// The files are in the order of their age: when this one stays, so do the newer ones
		if (too_old == false && too_big == false)
			break;

		if (FileDelete(f->Path) == false)
			continue;

		total -= f->Size;

		if (too_old)
			Format(text, sizeof(text), "Log file %s deleted: its last record is more than %u days old", f->Path, max_age_days);
		else
			Format(text, sizeof(text), "Log file %s deleted: the log files would take more than the disk limit of %I64u bytes", f->Path, max_total_size);

		InsertStringRecord(g, text);
	}

	for (UINT i = 0; i < LIST_NUM(o); i++)
		Free(LIST_DATA(o, i));

	ReleaseList(o);
}

// Apply the limits of g in the writer thread w when they were just set, or when LOG_LIMITS_SWEEP_INTERVAL has passed
// since they were applied, so that the files of a log that nothing is written to still age out
static void LogSweep(LOG *g, LOG_WRITER *w) {
	if (g->MaxAgeDays == 0 && g->MaxTotalSize == 0)
		return;

	UINT64 now = Tick64();
	if (g->LimitsChanged == false && now < w->NextSweepTick)
		return;

	g->LimitsChanged = false;
	w->NextSweepTick = now + LOG_LIMITS_SWEEP_INTERVAL;

	LogApplyLimits(g, w->FileName);
}

// Run the writer thread at the realtime priority (realtime) or the idle priority: the system call only on a change
static void LogWriterSetPriority(LOG_WRITER *w, bool realtime) {
	if (w->Realtime == realtime)
		return;

	w->Realtime = realtime;

	if (realtime)
		MsSetThreadPriorityRealtime();
	else
		MsSetThreadPriorityIdle();
}

static void LogThread(THREAD *thread, void *param) {
	LOG_WRITER w;
	bool flag = false;
	if (thread == NULL || param == NULL)
		return;

	Zero(&w, sizeof(w));

	LOG *g = (LOG *)param;

	w.Buffer = NewBuf();


	MsSetThreadPriorityIdle();


	NoticeThreadInit(thread);

	while (true) {
		while (true)
			if (!LogThreadWriteGeneral(g, &w))
				break;

		LogSweep(g, &w);

		if (g->Halt) {
			// When the stop flag is set, break only after every record is saved
			UINT num;

			if (flag == false) {
				LogWriterSetPriority(&w, true);
				flag = true;

				if (w.Io == NULL && w.Buffer->Size != 0) {
					// One more try at once to write what was buffered while no file could be opened
					w.RetryTick = 0;
					continue;
				}
			}

			LockQueue(g->RecordQueue);
			{
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

			if (num == 0 || w.Io == NULL)
				break;
		} else {
			Wait(g->Event, LogWriterWaitTime(&w));
		}
	}

	if (w.Io != NULL)
		FileCloseEx(w.Io, true);

	FreeBuf(w.Buffer);
}

// Milliseconds the writer thread waits for a new record: while records wait in the buffer for a file that
// could not be opened, only until the next try to open it
static UINT LogWriterWaitTime(const LOG_WRITER *w) {
	if (w->Io != NULL || w->Buffer->Size == 0 || IsEmptyStr(w->FileName))
		return 9821;

	UINT64 now = Tick64();
	if (w->RetryTick <= now)
		return 1;

	return (UINT)MIN(w->RetryTick - now, 9821);
}

// Open the log file file_name to append to it, or create it (and its directory). After a failed try the next
// one waits LOG_ENGINE_RETRY_MIN ms, then twice the last wait after each further failure, at most
// LOG_ENGINE_RETRY_MAX ms
static void LogOpenFile(LOG *g, LOG_WRITER *w, char *file_name) {
	StrCpy(w->FileName, sizeof(w->FileName), file_name);

	w->Io = FileOpen(file_name, true);
	if (w->Io == NULL) {
		LockLog(g);
		{
			// MakeDir also fails on an existing directory: the create tells whether the file can be written
			MakeDir(g->DirName);

			Win32SetFolderCompress(g->DirName, true);
		}
		UnlockLog(g);
		w->Io = FileCreate(file_name);
		g->CurrentFilePointer = 0;
	} else {
		g->CurrentFilePointer = FileSize64(w->Io);
		FileSeek(w->Io, SEEK_END, 0);
	}

	if (w->Io != NULL) {
		w->RetryWait = 0;

		// A new file takes the log up to its limits again: the oldest files go before anything is written to it
		LogApplyLimits(g, w->FileName);
	} else {
		w->RetryWait = (w->RetryWait == 0 ? LOG_ENGINE_RETRY_MIN : MIN(w->RetryWait * 2, LOG_ENGINE_RETRY_MAX));
		w->RetryTick = Tick64() + (UINT64)w->RetryWait;
	}
}

// Put the line that reports the dropped records into the buffer, in front of the next record (a file is open)
static void LogWriterAddDropped(LOG *g, LOG_WRITER *w) {
	UINT64 num;
	RECORD r;
	char tmp[MAX_SIZE];

	LockQueue(g->RecordQueue);
	{
		num = g->NumDropped;
		g->NumDropped = 0;
	}
	UnlockQueue(g->RecordQueue);

	if (num == 0)
		return;

	Format(tmp, sizeof(tmp), LOG_DROPPED_RECORDS_FORMAT, num);

	Zero(&r, sizeof(r));
	r.Tick = Tick64();
	r.ParseProc = StringRecordParseProc;
	r.FreeProc = Free;
	r.Data = CopyStr(tmp);

	WriteRecordToBuffer(w->Buffer, &r);
}

// No file is open: keep the record in the buffer while the buffer stays within the smaller of
// LOG_ENGINE_BUFFER_NO_FILE_MAX and the maximum log size, drop and count it otherwise. Either way its data is released
static void LogWriterKeep(LOG *g, LOG_WRITER *w, RECORD *rec) {
	BUF *b = NewBuf();

	WriteRecordToBuffer(b, rec);

	if ((UINT64)w->Buffer->Size + (UINT64)b->Size <= MIN((UINT64)LOG_ENGINE_BUFFER_NO_FILE_MAX, GetMaxLogSize(g))) {
		WriteBuf(w->Buffer, b->Buf, b->Size);
	} else {
		LockQueue(g->RecordQueue);
		{
			g->NumDropped++;
		}
		UnlockQueue(g->RecordQueue);
	}

	FreeBuf(b);
}

// Write the buffer to the open file and empty it. A buffer that would take the file over the maximum log size
// is not written: with next_number set that moves on, once, to the next log file number. A failed write closes
// the file and drops the buffer
static void LogFlushBuffer(LOG *g, LOG_WRITER *w, bool next_number) {
	BUF *buffer = w->Buffer;

	if (w->Io == NULL || buffer->Size == 0)
		return;

	if ((g->CurrentFilePointer + (UINT64)buffer->Size) > GetMaxLogSize(g)) {
		if (next_number && g->log_number_incremented == false) {
			g->CurrentLogNumber++;
			g->log_number_incremented = true;
		}

		return;
	}

	if (FileWrite(w->Io, buffer->Buf, buffer->Size) == false) {
		FileCloseEx(w->Io, true);
		ClearBuf(buffer);
		w->Io = NULL;
	} else {
		g->CurrentFilePointer += (UINT64)buffer->Size;
		ClearBuf(buffer);
	}
}

static bool LogThreadWriteGeneral(LOG *log_object, LOG_WRITER *w) {
	RECORD *rec;
	char file_name[MAX_SIZE];
	UINT num;
	bool log_date_changed;
	BUF *buffer = w->Buffer;

	LockQueue(log_object->RecordQueue);
	{
		rec = GetNext(log_object->RecordQueue);
		num = log_object->RecordQueue->num_item;
	}
	UnlockQueue(log_object->RecordQueue);

	if (num >= LOG_ENGINE_SAVE_START_CACHE_COUNT)
		LogWriterSetPriority(w, true);

	if (num < (LOG_ENGINE_SAVE_START_CACHE_COUNT / 2))
		LogWriterSetPriority(w, false);

	if (buffer->Size > GetMaxLogSize(log_object))
		ClearBuf(buffer);

	if (rec == NULL && w->Io == NULL && buffer->Size != 0 && IsEmptyStr(w->FileName) == false &&
	    Tick64() >= w->RetryTick) {
		// No new record, but buffered records wait for a file that could not be opened: try it again
		char last_name[MAX_SIZE];

		StrCpy(last_name, sizeof(last_name), w->FileName);
		LogOpenFile(log_object, w, last_name);
		log_object->log_number_incremented = false;

		if (w->Io != NULL)
			LogWriterAddDropped(log_object, w);
	}

	if (buffer->Size >= LOG_ENGINE_BUFFER_CACHE_SIZE_MAX)
		LogFlushBuffer(log_object, w, true);

	if (rec == NULL) {
		LogFlushBuffer(log_object, w, true);

		Set(log_object->FlushEvent);
		return false;
	}

	LockLog(log_object);
	{
		log_date_changed = MakeLogFileName(log_object, file_name, sizeof(file_name),
		                                   rec->Tick, log_object->SwitchType, log_object->CurrentLogNumber,
		                                   w->DateName, sizeof(w->DateName));

		if (log_date_changed) {
			log_object->CurrentLogNumber = 0;
			MakeLogFileName(log_object, file_name, sizeof(file_name),
			                rec->Tick, log_object->SwitchType, 0, w->DateName, sizeof(w->DateName));
			for (UINT i = 0;; i++) {
				char tmp[MAX_SIZE];
				MakeLogFileName(log_object, tmp, sizeof(tmp),
				                rec->Tick, log_object->SwitchType, i, w->DateName, sizeof(w->DateName));

				if (IsFileExists(tmp) == false)
					break;
				StrCpy(file_name, sizeof(file_name), tmp);
				log_object->CurrentLogNumber = i;
			}
		}
	}
	UnlockLog(log_object);

	if (w->Io != NULL) {
		if (StrCmp(w->FileName, file_name) != 0) {
			// Switching to another log file: flush the buffer and close the current file first
			if (log_date_changed)
				LogFlushBuffer(log_object, w, false);
			FileCloseEx(w->Io, true);

			log_object->log_number_incremented = false;

			LogOpenFile(log_object, w, file_name);
		}
	} else {
		if (Tick64() >= w->RetryTick) {
			LogOpenFile(log_object, w, file_name);
		} else {
			// Before the next try: a later record, or the writer thread once the wait is over, opens this file
			StrCpy(w->FileName, sizeof(w->FileName), file_name);
		}

		log_object->log_number_incremented = false;
	}

	if (w->Io != NULL) {
		LogWriterAddDropped(log_object, w);
		WriteRecordToBuffer(buffer, rec);
	} else {
		LogWriterKeep(log_object, w, rec);
	}

	Free(rec);

	return true;
}

void WriteRecordToBuffer(BUF *b, RECORD *r) {
	char time_str[MAX_SIZE];
	char date_str[MAX_SIZE];
	if (b == NULL || r == NULL)
		return;

	UINT64 time = SystemToLocal64(Tick64ToTime64(r->Tick));

	GetDateStr64(date_str, sizeof(date_str), time);
	GetTimeStrMilli64(time_str, sizeof(time_str), time);

	if (r->IsCsv == false) {
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, " ", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, " ", 1);
	} else {
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, ",", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, ",", 1);
	}

	char *s = r->ParseProc(r);
	WriteBuf(b, s, StrLen(s));
	Free(s);

	WriteBuf(b, "\r\n", 2);
}

void FreeLog(LOG *g) {
	RECORD *rec;
	if (g == NULL)
		return;

	g->Halt = true;
	Set(g->Event);

	WaitThread(g->Thread, INFINITE);
	ReleaseThread(g->Thread);

	DeleteLock(g->lock);
	Free(g->DirName);
	Free(g->Prefix);

	// Release any leftover records (there should be none) without making their lines
	while (rec = GetNext(g->RecordQueue))
		FreeRecord(rec);
	ReleaseQueue(g->RecordQueue);

	ReleaseEvent(g->Event);
	ReleaseEvent(g->FlushEvent);

	Free(g);
}

// A log writing to files with prefix in dir that switch by switch_type, each at most max_size bytes (0 for
// MAX_LOG_SIZE_DEFAULT, see SetMaxLogSize)
LOG *NewLog(char *dir, char *prefix, UINT switch_type, UINT64 max_size) {
	LOG *g = ZeroMalloc(sizeof(LOG));
	g->lock = NewLock();
	g->DirName = CopyStr(dir == NULL ? "" : dir);
	g->Prefix = CopyStr(prefix == NULL ? "log" : prefix);
	g->SwitchType = switch_type;
	SetMaxLogSize(g, max_size);
	g->RecordQueue = NewQueue();
	g->Event = NewEvent();
	g->FlushEvent = NewEvent();

	g->Thread = NewThread(LogThread, g);

	WaitThreadInit(g->Thread);

	return g;
}
