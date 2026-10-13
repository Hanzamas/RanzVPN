// NetworkDns.c
// DNS wrappers and wait threads: host and NetBIOS names, the machine name, and the wait-thread list

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "HTTP.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Pack.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

static LIST *WaitThreadList = NULL;

void AddWaitThread(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	AddRef(t->ref);

	LockList(WaitThreadList);
	{
		Add(WaitThreadList, t);
	}
	UnlockList(WaitThreadList);
}

void DelWaitThread(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	LockList(WaitThreadList);
	{
		if (Delete(WaitThreadList, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(WaitThreadList);
}

void InitWaitThread()
{
	WaitThreadList = NewList(NULL);
}

void FreeWaitThread()
{
	UINT i, num;
	THREAD **threads;

	LockList(WaitThreadList);
	{
		num = LIST_NUM(WaitThreadList);
		threads = ToArray(WaitThreadList);
		DeleteAll(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	for (i = 0; i < num; i++)
	{
		THREAD *t = threads[i];
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);

	ReleaseList(WaitThreadList);
	WaitThreadList = NULL;
}

void GetMachineHostName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	UINT i, len;
	if (name == NULL)
	{
		return;
	}

	GetMachineName(tmp, sizeof(tmp));

	len = StrLen(tmp);
	for (i = 0; i < len; i++)
	{
		if (tmp[i] == '.')
		{
			tmp[i] = 0;
		}
	}

	ConvertSafeFileName(name, size, tmp);
}

bool GetHostName(char *hostname, UINT size, IP *ip)
{
	if (hostname == NULL || size == 0 || ip == NULL)
	{
		return false;
	}

	if (DnsResolveReverse(hostname, size, ip, 0, NULL))
	{
		return true;
	}

	if (IsIP4(ip) && GetNetBiosName(hostname, size, ip))
	{
		DnsCacheReverseUpdate(ip, hostname);
		return true;
	}

	return false;
}

#define	NUM_NBT_QUERYS_SEND			3

bool GetNetBiosName(char *name, UINT size, IP *ip)
{
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	if (name == NULL || ip == NULL)
	{
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
	{
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL)
	{
		return false;
	}

	for (j = 0; j < NUM_NBT_QUERYS_SEND; j++)
	{
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3; i <= 32; i++)
		{
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0)
		{
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick64() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1)
	{
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick64() >= timeout_tick)
		{
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false)
		{
			flag = true;
		}
		else
		{
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER)
		{
			continue;
		}
		else if (ret == 0)
		{
			break;
		}
		else
		{
			if (ret >= sizeof(NBTRESPONSE))
			{
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
				{
					if (id == tran_id[i])
					{
						b = true;
						break;
					}
				}
				if (b)
				{
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1)
					{
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
						        r->Response[2] == 0x4b)
						{
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
							        r->Response[36] == 0x00 && r->Response[37] == 0x01)
							{
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15))
								{
									if (IsEmptyStr(a) == false)
									{
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									}
									else
									{
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
}
