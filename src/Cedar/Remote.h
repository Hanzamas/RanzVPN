// Remote.h
// Header of Remote.c

#ifndef REMOTE_H
#define REMOTE_H

#include "Connection.h"

typedef PACK *(RPC_DISPATCHER)(RPC * r, char *function_name, PACK *p);

struct RPC {
	SOCK *Sock;
	RPC_DISPATCHER *Dispatch;
	void *Param;
	char Name[MAX_SIZE];
	LOCK *Lock;
	CLIENT_OPTION VpnServerClientOption;
	char VpnServerHubName[MAX_HUBNAME_LEN + 1];
	UCHAR VpnServerHashedPassword[SHA1_SIZE];
	char VpnServerClientName[MAX_PATH];
};

RPC *NewRpc(SOCK *s, RPC_DISPATCHER *dispatch, void *param);
PACK *RpcCallInternal(RPC *r, PACK *p);
PACK *RpcCall(RPC *r, char *function_name, PACK *p);
void RpcServer(RPC *r);
void RpcFree(RPC *rpc);

#endif // REMOTE_H

