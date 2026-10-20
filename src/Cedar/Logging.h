// Logging.h
// Header of Logging.c

#ifndef	LOGGING_H
#define	LOGGING_H

#include "Cedar.h"

#include "Mayaqua/Network.h"

#define	MAX_LOG_SIZE_DEFAULT				1073741823ULL

// Bounds of the log writer while it cannot write its file (FND-16). A record past a bound is dropped
// through its normal release path and counted; the count is written as one line once a file is open.
#define	LOG_ENGINE_MAX_QUEUE				200000		// Records queued in one LOG: above LOG_ENGINE_SAVE_START_CACHE_COUNT and the 30000-record back-pressure of PacketLog
#define	LOG_ENGINE_BUFFER_NO_FILE_MAX		(2 * LOG_ENGINE_BUFFER_CACHE_SIZE_MAX)	// Bytes buffered while no log file is open
#define	LOG_ENGINE_RETRY_MIN				30			// Milliseconds before the first new try to open a log file
#define	LOG_ENGINE_RETRY_MAX				5000		// The wait doubles after each failed try, up to this
#define	LOG_DROPPED_RECORDS_FORMAT			"%I64u log records dropped: the log file could not be written or the record queue was full"

typedef char *(RECORD_PARSE_PROC)(RECORD *rec);

struct PACKET_LOG
{
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool WritePhysicalIP;
	char SrcPhysicalIP[64];
	char DestPhysicalIP[64];
	SESSION *SrcSession;
	bool NoLog;
};

struct HUB_LOG
{
	bool SaveSecurityLog;
	UINT SecurityLogSwitchType;
	bool SavePacketLog;
	UINT PacketLogSwitchType;
	UINT PacketLogConfig[NUM_PACKET_LOG];
};

struct RECORD
{
	UINT64 Tick;
	RECORD_PARSE_PROC *ParseProc;
	void *Data;
};

struct LOG
{
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
	UINT64 NumDropped;					// Records dropped and not yet reported in the file (under the RecordQueue lock)
};


struct ERASER
{
	LOG *Log;
	UINT64 MinFreeSpace;
	char *DirName;
	volatile bool Halt;
	THREAD *Thread;
	bool LastFailed;
	EVENT *HaltEvent;
	volatile UINT NumChecks;			// Free space checks made so far (EraserMain passes)
};

typedef struct ERASE_FILE
{
	char *FullPath;
	UINT64 UpdateTime;
} ERASE_FILE;

struct SLOG
{
	LOCK *lock;
	SOCK *Udp;
	IP DestIp;
	UINT DestPort;
	char HostName[MAX_HOST_NAME_LEN + 1];
	UINT64 NextPollIp;
};

LOG *NewLog(char *dir, char *prefix, UINT switch_type);
void FreeLog(LOG *g);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogSwitchType(LOG *g, UINT switch_type);
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now);
char *PacketLogParseProc(RECORD *rec);
UINT CalcPacketLoggingLevel(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void SiSetDefaultLogSetting(HUB_LOG *g);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
ERASER *NewEraser(LOG *log, UINT64 min_size);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
int CompareEraseFile(void *p1, void *p2);
SLOG *NewSysLog(char *hostname, UINT port, IP *ip);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);
void MakeSafeLogStr(char *str);
void AddLogBufToStr(BUF *b, char *name, char *value);
void SetEraserCheckInterval(UINT interval);
UINT GetEraserCheckInterval();
void SetMaxLogSize(UINT64 size);
UINT64 GetMaxLogSize();

#endif

