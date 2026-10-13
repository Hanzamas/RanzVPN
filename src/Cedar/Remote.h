// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Remote.h
// Header of Remote.c

#ifndef	REMOTE_H
#define	REMOTE_H

#include "Connection.h"

typedef PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p);

struct RPC
{
	SOCK *Sock;
	bool ServerMode;
	RPC_DISPATCHER *Dispatch;
	void *Param;
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_SIZE];
	LOCK *Lock;
	bool IsVpnServer;
	CLIENT_OPTION VpnServerClientOption;
	char VpnServerHubName[MAX_HUBNAME_LEN + 1];
	UCHAR VpnServerHashedPassword[SHA1_SIZE];
	char VpnServerClientName[MAX_PATH];
};

RPC *StartRpcClient(SOCK *s, void *param);
RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param);
PACK *RpcCallInternal(RPC *r, PACK *p);
PACK *RpcCall(RPC *r, char *function_name, PACK *p);
void RpcServer(RPC *r);
bool RpcRecvNextCall(RPC *r);
PACK *CallRpcDispatcher(RPC *r, PACK *p);
void EndRpc(RPC *rpc);
void RpcFree(RPC *rpc);
void RpcFreeEx(RPC *rpc, bool no_disconnect);

#endif	// REMOTE_H

