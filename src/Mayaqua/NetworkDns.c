// NetworkDns.c
// DNS wrappers: the machine name, the reverse host name lookup and the NetBIOS name query

#include "Network.h"

#include "DNS.h"
#include "Memory.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

void GetMachineName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	DWORD tmp_size = sizeof(tmp);
	if (name == NULL)
	{
		return;
	}

	if (GetComputerNameExA(ComputerNameDnsHostname, tmp, &tmp_size) == false)
	{
		StrCpy(name, size, "Unknown");
		return;
	}

	StrCpy(name, size, tmp);
}

bool GetHostName(char *hostname, UINT size, const IP *ip)
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

bool GetNetBiosName(char *name, UINT size, const IP *ip)
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
			// Only a reply from the queried host's NetBIOS port counts; anything else may be spoofed
			if (ret >= sizeof(NBTRESPONSE) && src_port == 137 && CmpIpAddr(&src_ip, ip) == 0)
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
