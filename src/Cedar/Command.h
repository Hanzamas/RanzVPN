// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Command.h
// Header of Command.c

#ifndef	COMMAND_H
#define	COMMAND_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

#include <stddef.h>

// Constants
#define	TRAFFIC_DEFAULT_PORT		9821
#define	TRAFFIC_NUMTCP_MAX			32
#define	TRAFFIC_NUMTCP_DEFAULT		32
#define	TRAFFIC_SPAN_DEFAULT		15
#define	TRAFFIC_TYPE_DOWNLOAD		1
#define	TRAFFIC_TYPE_UPLOAD			2
#define	TRAFFIC_TYPE_FULL			0
#define	TRAFFIC_BUF_SIZE			65535
#define	TRAFFIC_VER_STR_SIZE		16
#define	TRAFFIC_VER_STR				"TrafficServer\r\n"

// Constants for Win32
#define	VPNCMD_BOOTSTRAP_REG_KEYNAME	"Software\\" GC_REG_COMPANY_NAME "\\VPN Command Line Utility"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_VER	"InstalledVersion"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH	"InstalledPath"
#define	VPNCMD_BOOTSTRAP_FILENAME		"|vpncmdsys.exe"


// Traffic test results
struct TT_RESULT
{
	bool Raw;					// Whether raw data
	bool Double;				// Whether it is doubled
	UINT64 NumBytesUpload;		// Uploaded size
	UINT64 NumBytesDownload;	// Downloaded size
	UINT64 NumBytesTotal;		// Total size
	UINT64 Span;				// Period (in milliseconds)
	UINT64 BpsUpload;			// Upload throughput
	UINT64 BpsDownload;			// Download throughput
	UINT64 BpsTotal;			// Total throughput
};

// Text display function
typedef void (TT_PRINT_PROC)(void *param, wchar_t *str);

// Client side socket
struct TTC_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool Download;			// Download socket
	bool ServerUploadReportReceived;	// Complete to receive the report of upload amount from the server
	UINT64 NextSendRequestReportTick;	// Time to request a next report
	UINT Id;
	bool HideErrMsg;
};

// Traffic test Client
struct TTC
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	bool Double;			// Double mode
	bool Raw;				// Raw data mode
	UINT Port;				// Port number
	char Host[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT NumTcp;			// Number of TCP connections
	UINT Type;				// Type
	UINT64 Span;			// Period
	UINT64 RealSpan;		// The actual span
	THREAD *Thread;			// Thread
	volatile bool Halt;		// Halting flag
	bool *Cancel;			// Halting flag 2
	LIST *ItcSockList;		// Client socket list
	TT_RESULT Result;		// Result
	UINT ErrorCode;			// Error code
	bool AbnormalTerminated;	// Abnormal termination
	EVENT *StartEvent;		// Start event
	EVENT *InitedEvent;		// Initialize completion notification event
	LIST *WorkerThreadList;	// List of worker threads

	UINT flag1, flag2;

	UINT64 session_id;
	UINT64 end_tick;
	UINT64 start_tick;
};

// Traffic test worker thread
struct TTC_WORKER
{
	THREAD *WorkerThread;
	TTC *Ttc;
	LIST *SockList;			// Client socket list
	SOCK_EVENT *SockEvent;	// Socket event
	EVENT *StartEvent;		// Start event
	bool Ok;				// The result
};

// Server side socket
struct TTS_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool SockJoined;		// Whether it has been added to the event
	UINT Id;				// ID
	UINT64 LastWaitTick;	// Retry waiting time to notify the size information to the client
	UINT64 SessionId;		// Session ID
	bool NoMoreSendData;	// Flag not to send more data
	UINT64 FirstRecvTick;	// Time which the data has been received last
	UINT64 FirstSendTick;	// Time which the data has been sent last
	UINT64 Span;			// Period
	UINT64 GiveupSpan;
	UINT64 LastCommTime;
};

// Traffic test server
struct TTS
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	volatile bool Halt;		// Halting flag
	UINT Port;				// Port number
	THREAD *Thread;			// Thread
	THREAD *IPv6AcceptThread;	// IPv6 Accept thread
	SOCK *ListenSocket;		// Socket to wait
	SOCK *ListenSocketV6;	// Socket to wait (IPv6)
	UINT ErrorCode;			// Error code
	UINT IdSeed;			// ID value
	LIST *WorkerList;		// Worker threads list
};

// Traffic test worker thread
struct TTS_WORKER
{
	TTS *Tts;				// TTS
	THREAD *WorkThread;		// Worker thread
	SOCK_EVENT *SockEvent;	// Socket event
	LIST *TtsSockList;		// Server socket list
	bool NewSocketArrived;	// New socket has arrived
};

// VPN Tools context
struct PT
{
	CONSOLE *Console;	// Console
	UINT LastError;		// Last error
	wchar_t *CmdLine;	// Command line to execute
};

// Server management context
struct PS
{
	bool ConsoleForServer;	// Console for the server (always true)
	CONSOLE *Console;	// Console
	RPC *Rpc;			// RPC
	char *ServerName;	// Server name
	UINT ServerPort;	// Port number
	char *HubName;		// Virtual HUB name in the currently managed
	UINT LastError;		// Last error
	char *AdminHub;		// Virtual HUB to be managed by default
	wchar_t *CmdLine;	// Command line to execute
	CAPSLIST *CapsList;	// Caps list
};

// A column of the table
struct CTC
{
	wchar_t *String;	// String
	bool Right;			// Right justification
};

// A row of the table
struct CTR
{
	wchar_t **Strings;	// String list
};

// Table for console
struct CT
{
	LIST *Columns;		// Column list
	LIST *Rows;			// Row list
};

UINT CommandMain(wchar_t *command_line);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);

bool CmdEvalPassOrDiscard(CONSOLE *c, wchar_t *str, void *param);






UINT PsCascadePolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


#endif	// COMMAND_H


