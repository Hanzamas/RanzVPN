// Command.h
// Header of Command.c

#ifndef COMMAND_H
#define COMMAND_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

#include <stddef.h>

#define TRAFFIC_DEFAULT_PORT   9821
#define TRAFFIC_NUMTCP_MAX     32
#define TRAFFIC_NUMTCP_DEFAULT 32
#define TRAFFIC_SPAN_DEFAULT   15
#define TRAFFIC_TYPE_DOWNLOAD  1
#define TRAFFIC_TYPE_UPLOAD    2
#define TRAFFIC_TYPE_FULL      0
#define TRAFFIC_BUF_SIZE       65535
#define TRAFFIC_VER_STR_SIZE   16
#define TRAFFIC_VER_STR        "TrafficServer\r\n"

struct TT_RESULT {
	bool Raw;
	bool Double;
	UINT64 NumBytesUpload;
	UINT64 NumBytesDownload;
	UINT64 NumBytesTotal;
	UINT64 Span;
	UINT64 BpsUpload;
	UINT64 BpsDownload;
	UINT64 BpsTotal;
};

typedef void(TT_PRINT_PROC)(void *param, wchar_t *str);

struct TTC_SOCK {
	SOCK *Sock;
	UINT State;
	UINT64 NumBytes;
	bool Download;
	bool ServerUploadReportReceived;
	UINT64 NextSendRequestReportTick;
	UINT Id;
	bool HideErrMsg;
};

struct TTC {
	TT_PRINT_PROC *Print;
	void *Param;
	bool Double;
	bool Raw;
	UINT Port;
	char Host[MAX_HOST_NAME_LEN + 1];
	UINT NumTcp;
	UINT Type;
	UINT64 Span;
	UINT64 RealSpan;
	THREAD *Thread;
	LIST *ItcSockList;
	TT_RESULT Result;
	UINT ErrorCode;
	bool AbnormalTerminated;
	EVENT *InitedEvent;
	LIST *WorkerThreadList;

	UINT flag2;

	UINT64 session_id;
	UINT64 end_tick;
	UINT64 start_tick;
};

struct TTC_WORKER {
	THREAD *WorkerThread;
	TTC *Ttc;
	LIST *SockList;
	SOCK_EVENT *SockEvent;
	EVENT *StartEvent;
	bool Ok;
};

struct TTS_SOCK {
	SOCK *Sock;
	UINT State;
	UINT64 NumBytes;
	bool SockJoined;
	UINT Id;
	UINT64 LastWaitTick;
	UINT64 SessionId;
	bool NoMoreSendData;
	UINT64 FirstRecvTick;
	UINT64 FirstSendTick;
	UINT64 Span;
	UINT64 GiveupSpan;
	UINT64 LastCommTime;
};

struct TTS {
	TT_PRINT_PROC *Print;
	void *Param;
	volatile bool Halt; // Only through FlagRead and FlagWrite (Native.h)
	UINT Port;
	THREAD *Thread;
	SOCK *ListenSocket;
	UINT ErrorCode;
	UINT IdSeed;
	LIST *WorkerList;
};

struct TTS_WORKER {
	TTS *Tts;
	THREAD *WorkThread;
	SOCK_EVENT *SockEvent;
	LIST *TtsSockList;
	bool NewSocketArrived;
};

struct PT {
	CONSOLE *Console;
	UINT LastError;
	wchar_t *CmdLine;
};

struct PS {
	CONSOLE *Console;
	RPC *Rpc;
	char *ServerName;
	UINT ServerPort;
	char *HubName;
	UINT LastError;
	char *AdminHub;
	wchar_t *CmdLine;
	CAPSLIST *CapsList;
};

struct CTC {
	wchar_t *String;
	bool Right;
};

struct CTR {
	wchar_t **Strings;
};

struct CT {
	LIST *Columns;
	LIST *Rows;
};

UINT CommandMain(wchar_t *command_line);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);




#endif


