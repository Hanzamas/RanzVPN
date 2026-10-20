// Remote.c
// Remote Procedure Call

#include "Remote.h"

#include "Admin.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"

// The body of a frame is read in pieces of this size, so a frame that declares more than it sends costs only what it sent
#define	RPC_RECV_CHUNK_SIZE		(64 * 1024U)

void RpcFree(RPC *rpc)
{
	if (rpc == NULL)
	{
		return;
	}

	Disconnect(rpc->Sock);

	ReleaseSock(rpc->Sock);

	DeleteLock(rpc->Lock);

	Free(rpc);
}

static PACK *CallRpcDispatcher(RPC *r, PACK *p)
{
	char func_name[MAX_SIZE];
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (PackGetStr(p, "function_name", func_name, sizeof(func_name)) == false)
	{
		return NULL;
	}

	return r->Dispatch(r, func_name, p);
}

// One frame is a 32-bit big-endian size and the serialised PACK
static bool RpcSendPack(SOCK *s, PACK *p)
{
	BUF *b;
	UINT size;

	b = PackToBuf(p);

	size = Endian32(b->Size);
	SendAdd(s, &size, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);
	FreeBuf(b);

	return SendNow(s, s->SecureMode);
}

static PACK *RpcRecvPack(SOCK *s)
{
	BUF *b;
	PACK *p;
	UINT size;
	if (RecvAll(s, &size, sizeof(UINT), s->SecureMode) == false)
	{
		return NULL;
	}

	size = Endian32(size);

	if (size > MAX_PACK_SIZE)
	{
		return NULL;
	}

	b = NewBuf();

	while (b->Size < size)
	{
		UINT chunk = MIN(size - b->Size, RPC_RECV_CHUNK_SIZE);

		AdjustBufSize(b, b->Size + chunk);

		if (RecvAll(s, (UCHAR *)b->Buf + b->Size, chunk, s->SecureMode) == false)
		{
			FreeBuf(b);
			return NULL;
		}

		b->Size += chunk;
	}

	p = BufToPack(b);
	FreeBuf(b);

	return p;
}

static bool RpcRecvNextCall(RPC *r)
{
	PACK *p;
	PACK *ret;
	bool ok;
	if (r == NULL)
	{
		return false;
	}

	p = RpcRecvPack(r->Sock);
	if (p == NULL)
	{
		return false;
	}

	ret = CallRpcDispatcher(r, p);
	FreePack(p);

	if (ret == NULL)
	{
		ret = PackError(ERR_NOT_SUPPORTED);
	}

	ok = RpcSendPack(r->Sock, ret);
	FreePack(ret);

	return ok;
}

void RpcServer(RPC *r)
{
	if (r == NULL)
	{
		return;
	}

	while (true)
	{
		if (RpcRecvNextCall(r) == false)
		{
			break;
		}
	}
}

PACK *RpcCall(RPC *r, char *function_name, PACK *p)
{
	PACK *ret;
	UINT num_retry = 0;
	UINT err = 0;
	if (r == NULL || function_name == NULL)
	{
		return NULL;
	}


	Lock(r->Lock);
	{
		if (p == NULL)
		{
			p = NewPack();
		}

		PackAddStr(p, "function_name", function_name);

RETRY:
		err = 0;
		ret = RpcCallInternal(r, p);

		if (ret == NULL)
		{
			if (r->Sock != NULL)
			{
				if (num_retry < 1)
				{
					num_retry++;

					err = AdminReconnect(r);

					if (err == ERR_NO_ERROR)
					{
						goto RETRY;
					}
				}
			}
		}

		FreePack(p);

		if (ret == NULL)
		{
			if (err == 0)
			{
				err = ERR_DISCONNECTED;
			}

			ret = PackError(err);
			PackAddInt(ret, "error_code", err);
		}
	}
	Unlock(r->Lock);

	return ret;
}

PACK *RpcCallInternal(RPC *r, PACK *p)
{
	if (r == NULL || p == NULL)
	{
		return NULL;
	}

	if (r->Sock == NULL)
	{
		return NULL;
	}

	if (RpcSendPack(r->Sock, p) == false)
	{
		return NULL;
	}

	return RpcRecvPack(r->Sock);
}

// dispatch is the function a server-side RPC runs for each call, NULL for the calling side
RPC *NewRpc(SOCK *s, RPC_DISPATCHER *dispatch, void *param)
{
	RPC *r;
	if (s == NULL)
	{
		return NULL;
	}

	r = ZeroMallocEx(sizeof(RPC), true);
	r->Sock = s;
	r->Param = param;
	r->Lock = NewLock();
	AddRef(s->ref);

	r->Dispatch = dispatch;

	Format(r->Name, sizeof(r->Name), "RPC-%u", (UINT)s->socket);

	return r;
}

