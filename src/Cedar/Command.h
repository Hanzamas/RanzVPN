// Command.h
// Header of Command.c

#ifndef	COMMAND_H
#define	COMMAND_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

#include <stddef.h>

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

struct TT_RESULT
{
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

typedef void (TT_PRINT_PROC)(void *param, wchar_t *str);

struct TTC_SOCK
{
	SOCK *Sock;
	UINT State;
	UINT64 NumBytes;
	bool Download;
	bool ServerUploadReportReceived;
	UINT64 NextSendRequestReportTick;
	UINT Id;
	bool HideErrMsg;
};

struct TTC
{
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

struct TTC_WORKER
{
	THREAD *WorkerThread;
	TTC *Ttc;
	LIST *SockList;
	SOCK_EVENT *SockEvent;
	EVENT *StartEvent;
	bool Ok;
};

struct TTS_SOCK
{
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

struct TTS
{
	TT_PRINT_PROC *Print;
	void *Param;
	volatile bool Halt;
	UINT Port;
	THREAD *Thread;
	THREAD *IPv6AcceptThread;
	SOCK *ListenSocket;
	SOCK *ListenSocketV6;
	UINT ErrorCode;
	UINT IdSeed;
	LIST *WorkerList;
};

struct TTS_WORKER
{
	TTS *Tts;
	THREAD *WorkThread;
	SOCK_EVENT *SockEvent;
	LIST *TtsSockList;
	bool NewSocketArrived;
};

struct PT
{
	CONSOLE *Console;
	UINT LastError;
	wchar_t *CmdLine;
};

struct PS
{
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

struct CTC
{
	wchar_t *String;
	bool Right;
};

struct CTR
{
	wchar_t **Strings;
};

struct CT
{
	LIST *Columns;
	LIST *Rows;
};

UINT CommandMain(wchar_t *command_line);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);
CT *CtNew();
void CtFree(CT *ct, CONSOLE *c);
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view);
void CtInsertColumn(CT *ct, wchar_t *str, bool right);
CT *CtNewStandard();
CT *CtNewStandardEx();
void CtInsert(CT *ct, ...);

void CmdPrintError(CONSOLE *c, UINT err);
void CmdPrintAbout(CONSOLE *c);
wchar_t *CmdPromptPort(CONSOLE *c, void *param);
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param);
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param);
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t);
char *CmdPasswordPrompt(CONSOLE *c);
wchar_t *GetAuthTypeStr(UINT id);






UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


#endif


