// LogWriter.h
// Header of LogWriter.c

#ifndef LOGWRITER_H
#define LOGWRITER_H

#include "Mayaqua/MayaType.h"

typedef struct RECORD RECORD;
typedef struct LOG LOG;

#define MAX_LOG_SIZE_DEFAULT 1073741823ULL

#define LOG_ENGINE_SAVE_START_CACHE_COUNT 100000
#define LOG_ENGINE_BUFFER_CACHE_SIZE_MAX  (10 * 1024 * 1024)

// Bounds of the log writer while it cannot write its file (FND-16). A record past a bound is dropped
// through its normal release path and counted; the count is written as one line once a file is open.
#define LOG_ENGINE_MAX_QUEUE          200000                                 // Records queued in one LOG: above LOG_ENGINE_SAVE_START_CACHE_COUNT and the 30000-record back-pressure of PacketLog
#define LOG_ENGINE_BUFFER_NO_FILE_MAX (2 * LOG_ENGINE_BUFFER_CACHE_SIZE_MAX) // Bytes buffered while no log file is open
#define LOG_ENGINE_RETRY_MIN          30                                     // Milliseconds before the first new try to open a log file
#define LOG_ENGINE_RETRY_MAX          5000                                   // The wait doubles after each failed try, up to this
#define LOG_DROPPED_RECORDS_FORMAT    "%I64u log records dropped: the log file could not be written or the record queue was full"

// The files of a log within an age limit and a disk limit (SetLogLimits, SDN-54 #247): the writer thread applies them
// at least this often, besides when they are set and each time it opens a file
#define LOG_LIMITS_SWEEP_INTERVAL (60 * 60 * 1000)

#define LOG_SWITCH_NO     0
#define LOG_SWITCH_SECOND 1
#define LOG_SWITCH_MINUTE 2
#define LOG_SWITCH_HOUR   3
#define LOG_SWITCH_DAY    4
#define LOG_SWITCH_MONTH  5

// The line of a record, which the writer frees; it also releases the data of the record
typedef char *(RECORD_PARSE_PROC)(RECORD * rec);
// Release the data of a record that is not written, without making its line
typedef void(RECORD_FREE_PROC)(void *data);

struct RECORD {
	UINT64 Tick;
	RECORD_PARSE_PROC *ParseProc; // Makes the line of a written record and releases Data
	RECORD_FREE_PROC *FreeProc;   // Releases Data of a dropped record, or of one left at FreeLog
	bool IsCsv;                   // The date and the time in front of the line end with a comma, not a space
	void *Data;
};

struct LOG {
	LOCK *lock;
	THREAD *Thread;
	char *DirName;
	char *Prefix;
	UINT SwitchType;
	QUEUE *RecordQueue;
	volatile bool Halt;
	EVENT *Event;
	EVENT *FlushEvent;
	bool CacheFlag;
	UINT64 LastTick;
	UINT LastSwitchType;
	char LastStr[MAX_SIZE];
	UINT64 CurrentFilePointer;
	UINT CurrentLogNumber;
	bool log_number_incremented;
	UINT64 NumDropped;          // Records dropped and not yet reported in the file (under the RecordQueue lock)
	volatile UINT64 MaxLogSize; // Maximum size of a log file (SetMaxLogSize), never 0
	// The limits of the files of this log (SetLogLimits), 0 for none, and whether the writer thread has yet to apply them
	volatile UINT MaxAgeDays;
	volatile UINT64 MaxTotalSize;
	volatile bool LimitsChanged;
};

LOG *NewLog(char *dir, char *prefix, UINT switch_type, UINT64 max_size);
void FreeLog(LOG *g);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc, RECORD_FREE_PROC *free_proc, bool is_csv);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
void LogMapControlChars(UCHAR *s, UINT size);
void LogFormat(wchar_t *buf, UINT size, char *name, va_list args);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogSwitchType(LOG *g, UINT switch_type);
void SetMaxLogSize(LOG *g, UINT64 size);
UINT64 GetMaxLogSize(LOG *g);
void SetLogLimits(LOG *g, UINT max_age_days, UINT64 max_total_size);

#endif
