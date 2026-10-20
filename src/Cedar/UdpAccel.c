// UdpAccel.c
// UDP acceleration function

#include "UdpAccel.h"

#include "Connection.h"
#include "Logging.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Stun.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>

void UdpAccelPoll(UDP_ACCEL *a)
{
	UINT num_ignore_errors = 0;
	UINT num_recv = 0;
	UCHAR *tmp;
	if (a == NULL)
	{
		return;
	}

	tmp = a->TmpBuf;

	// The per-tick budget starts over on a new tick
	if (a->RecvTick != a->Now)
	{
		a->RecvTick = a->Now;
		a->RecvNumInTick = 0;
	}

	while (true)
	{
		IP src_ip;
		UINT src_port;
		UINT ret;

		// A flood must not hold the session thread: past the budget, the datagrams stay in the
		// socket for the next call. After a full poll the last read has re-armed the socket event,
		// so the session loop comes back at once; after a full tick ConnectionReceive() waits at most
		// 1 ms (UdpAccelIsRecvBudgetSpent), so it reads on at the next tick.
		if (num_recv >= UDP_ACCELERATION_MAX_RECV_PER_POLL || a->RecvNumInTick >= UDP_ACCELERATION_MAX_RECV_PER_TICK)
		{
			// Only a poll that read something counts, not one that finds the tick's budget already spent
			if (num_recv > 0)
			{
				a->NumRecvLimit++;
			}
			break;
		}

		ret = RecvFrom(a->UdpSock, &src_ip, &src_port, tmp, UDP_ACCELERATION_TMP_BUF_SIZE);

		if (ret != 0 && ret != SOCK_LATER)
		{
			BLOCK *b;

			num_recv++;
			a->RecvNumInTick++;

			b = UdpAccelProcessRecvPacket(a, tmp, ret, &src_ip, src_port);

			if (b != NULL)
			{
				InsertQueue(a->RecvBlockQueue, b);
			}
		}
		else
		{
			if (ret == 0)
			{
				if (a->UdpSock->IgnoreRecvErr == false)
				{
					a->FatalError = true;
					break;
				}

				if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
				{
					a->FatalError = true;
					break;
				}
			}
			else
			{
				break;
			}
		}
	}

	if (a->NextSendKeepAlive == 0 || (a->NextSendKeepAlive <= a->Now))
	{
		if (UdpAccelIsSendReady(a, false))
		{
			UINT rand_interval;

			if (a->FastDetect == false)
			{
				rand_interval = rand() % (UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX - UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN) + UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN;
			}
			else
			{
				rand_interval = rand() % (UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST - UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST) + UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST;
			}

			a->NextSendKeepAlive = a->Now + (UINT64)rand_interval;

			UdpAccelSend(a, NULL, 0, false, 1000);
		}
	}
}

void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b)
{
	if (a == NULL || b == NULL)
	{
		return;
	}

	UdpAccelSend(a, b->Buf, b->Size, b->Compressed ? 1 : 0, a->MaxUdpPacketSize);
}

UINT UdpAccelCalcMss(UDP_ACCEL *a)
{
	UINT ret;

	if (a == NULL)
	{
		return 0;
	}

	ret = MTU_FOR_PPPOE;

	if (a->IsIPv6)
	{
		ret -= 40;
	}
	else
	{
		ret -= 20;
	}

	ret -= 8;

	if (a->PlainTextMode == false)
	{
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;
	}

	ret -= sizeof(UINT);

	ret -= sizeof(UINT64);

	ret -= sizeof(UINT64);

	ret -= sizeof(USHORT);

	ret -= sizeof(UCHAR);

	if (a->PlainTextMode == false)
	{
		ret -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;
	}

	ret -= 14;

	ret -= 20;

	ret -= 20;

	return ret;
}

void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size)
{
	UCHAR buffer[UDP_ACCELERATION_TMP_BUF_SIZE];
	UCHAR *buf = buffer;
	UINT size = 0;
	UINT64 tmp;
	UINT ret;
	UINT u32;
	USHORT u16;
	if (a == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}
	if (max_size == 0)
	{
		max_size = INFINITE;
	}

	if (a->PlainTextMode == false)
	{
		if (a->Version > 1)
		{
			Copy(buf, a->NextIv_V2, UDP_ACCELERATION_PACKET_IV_SIZE_V2);

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
		}
		else
		{
			Copy(buf, a->NextIv, UDP_ACCELERATION_PACKET_IV_SIZE_V1);

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
		}
	}

	u32 = Endian32(a->YourCookie);
	Copy(buf, &u32, sizeof(UINT));
	buf += sizeof(UINT);
	size += sizeof(UINT);

	tmp = Endian64(a->Now == 0 ? 1ULL : a->Now);
	Copy(buf, &tmp, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	tmp = Endian64(a->LastRecvYourTick);
	Copy(buf, &tmp, sizeof(UINT64));
	buf += sizeof(UINT64);
	size += sizeof(UINT64);

	u16 = Endian16(data_size);
	Copy(buf, &u16, sizeof(USHORT));
	buf += sizeof(USHORT);
	size += sizeof(USHORT);

	Copy(buf, &flag, sizeof(UCHAR));
	buf += sizeof(UCHAR);
	size += sizeof(UCHAR);

	Copy(buf, data, data_size);
	buf += data_size;
	size += data_size;

	if (a->PlainTextMode == false)
	{
		// Add padding to make protocol identification harder to accomplish
		const UINT current_total_size = size + (a->Version > 1 ? UDP_ACCELERATION_PACKET_MAC_SIZE_V2 : UDP_ACCELERATION_PACKET_IV_SIZE_V1);
		if (current_total_size < max_size)
		{
			UCHAR pad[UDP_ACCELERATION_MAX_PADDING_SIZE];
			UINT pad_size = MIN(max_size - current_total_size, UDP_ACCELERATION_MAX_PADDING_SIZE);
			pad_size = rand() % pad_size;
			Zero(pad, sizeof(pad));
			Copy(buf, pad, pad_size);
			buf += pad_size;
			size += pad_size;
		}

		if (a->Version > 1)
		{
			const UINT inner_size = size - UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			UCHAR *inner = buffer + UDP_ACCELERATION_PACKET_IV_SIZE_V2;

			ret = CipherProcessAead(a->CipherEncrypt, a->NextIv_V2, inner + inner_size, UDP_ACCELERATION_PACKET_MAC_SIZE_V2, inner, inner, inner_size, NULL, 0);
			if (ret == 0)
			{
				return;
			}

			Copy(a->NextIv_V2, inner, UDP_ACCELERATION_PACKET_IV_SIZE_V2);

			// Tag (appended to the buffer by CipherProcessAead())
			size += UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
		}
		else
		{
			UCHAR *inner = buffer + UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE_V1];
			const UINT inner_size = size; // We don't have to subtract because we add below
			CRYPT *c;

			// Integrity check: some bytes are filled with zeroes,
			// and the remote host checks that all of them are still zero.
			Zero(buf, UDP_ACCELERATION_PACKET_IV_SIZE_V1);
			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size += UDP_ACCELERATION_PACKET_IV_SIZE_V1;

			UdpAccelCalcKeyV1(key, a->MyKey, a->NextIv);

			c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE_V1);
			Encrypt(c, inner, inner, inner_size);
			FreeCrypt(c);

			Copy(a->NextIv, buf - UDP_ACCELERATION_PACKET_IV_SIZE_V1, UDP_ACCELERATION_PACKET_IV_SIZE_V1);
		}
	}

	if (SendTo(a->UdpSock, &a->YourIp, a->YourPort, buffer, size) == 0)
	{
		if (a->UdpSock->IgnoreSendErr == false)
		{
			a->FatalError = true;
			return;
		}
	}

	if (data_size > 0 || UdpAccelIsSendReady(a, true))
	{
		return;
	}

	IP *ips[2];
	ips[0] = &a->YourIp;
	ips[1] = CmpIpAddr(&a->YourIpReported, &a->YourIp) == 0 ? NULL : &a->YourIpReported;

	USHORT ports[2];
	ports[0] = a->YourPort;
	ports[1] = a->YourPortReported == a->YourPort ? 0 : a->YourPortReported;

	for (BYTE i = 0; i < sizeof(ips) / sizeof(ips[0]); ++i)
	{
		if (IsZeroIP(ips[i]))
		{
			continue;
		}

		for (BYTE j = 0; j < sizeof(ports) / sizeof(ports[0]); ++j)
		{
			if (ports[j] == 0)
			{
				continue;
			}

			if (CmpIpAddr(ips[i], &a->YourIp) == 0 && ports[j] == a->YourPort)
			{
				continue;
			}

			if (SendTo(a->UdpSock, ips[i], ports[j], buffer, size) == 0)
			{
				if (a->UdpSock->IgnoreSendErr == false)
				{
					a->FatalError = true;
					return;
				}
			}

			if (UdpAccelIsSendReady(a, true))
			{
				break;
			}
		}
	}
}

bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive)
{
	UINT64 timeout_value;
	if (a == NULL)
	{
		return false;
	}

	if (a->Inited == false)
	{
		return false;
	}

	if (a->YourPort == 0)
	{
		return false;
	}

	if (IsZeroIp(&a->YourIp))
	{
		return false;
	}

	timeout_value = UDP_ACCELERATION_KEEPALIVE_TIMEOUT;

	if (a->FastDetect)
	{
		timeout_value = UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST;
	}

	if (check_keepalive)
	{
		if (a->LastRecvTick == 0 || ((a->LastRecvTick + timeout_value) < a->Now))
		{
			a->FirstStableReceiveTick = 0;
			return false;
		}
		else
		{
			if ((a->FirstStableReceiveTick + (UINT64)UDP_ACCELERATION_REQUIRE_CONTINUOUS) <= a->Now)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

// Size of the smallest packet of the format in use: the header with no data and no padding,
// plus the IV and the tag (version 2) or the IV and the zero trailer (version 1)
static UINT UdpAccelMinPacketSize(UDP_ACCEL *a)
{
	UINT ret = (UINT)UDP_ACCELERATION_PACKET_HEADER_SIZE;

	if (a->PlainTextMode == false)
	{
		if (a->Version > 1)
		{
			ret += UDP_ACCELERATION_PACKET_IV_SIZE_V2 + UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
		}
		else
		{
			ret += UDP_ACCELERATION_PACKET_IV_SIZE_V1 + UDP_ACCELERATION_PACKET_IV_SIZE_V1;
		}
	}

	return ret;
}

BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port)
{
	UINT64 my_tick, your_tick;
	UINT inner_size;
	UCHAR *inner_data = NULL;
	bool compress_flag;
	UCHAR raw_flag;
	BLOCK *b = NULL;
	UINT cookie;
	if (a == NULL || buf == NULL || size == 0 || src_ip == NULL)
	{
		return NULL;
	}

	// Header check before any decryption: a datagram shorter than the smallest packet of the
	// format (header, no data, no padding) cannot be one, so it costs no cipher work
	if (size < UdpAccelMinPacketSize(a))
	{
		a->NumDropShort++;
		return NULL;
	}

	if (a->PlainTextMode == false)
	{
		UCHAR *iv = buf;

		if (a->Version > 1)
		{
			UINT data_size;

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V2;
			size -= UDP_ACCELERATION_PACKET_IV_SIZE_V2;

			data_size = size - UDP_ACCELERATION_PACKET_MAC_SIZE_V2;

			if (CipherProcessAead(a->CipherDecrypt, iv, buf + data_size, UDP_ACCELERATION_PACKET_MAC_SIZE_V2, buf, buf, data_size, NULL, 0) == 0)
			{
				goto DROP;
			}

			size -= UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
		}
		else
		{
			UCHAR key[UDP_ACCELERATION_PACKET_KEY_SIZE_V1];
			CRYPT *c;

			buf += UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			size -= UDP_ACCELERATION_PACKET_IV_SIZE_V1;

			UdpAccelCalcKeyV1(key, a->YourKey, iv);

			// The cookie first: RC4 keeps its keystream position from one Encrypt() to the next,
			// so a datagram with a wrong cookie is dropped without decrypting the rest of it
			c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE_V1);
			Encrypt(c, buf, buf, sizeof(UINT));
			if (READ_UINT(buf) != a->MyCookie)
			{
				FreeCrypt(c);
				goto DROP;
			}
			Encrypt(c, buf + sizeof(UINT), buf + sizeof(UINT), size - sizeof(UINT));
			FreeCrypt(c);
		}
	}

	if (size < sizeof(UINT))
	{
		goto DROP;
	}
	cookie = READ_UINT(buf);
	buf += sizeof(UINT);
	size -= sizeof(UINT);

	if (cookie != a->MyCookie)
	{
		goto DROP;
	}

	if (size < sizeof(UINT64))
	{
		goto DROP;
	}
	my_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	if (size < sizeof(UINT64))
	{
		goto DROP;
	}
	your_tick = READ_UINT64(buf);
	buf += sizeof(UINT64);
	size -= sizeof(UINT64);

	if (size < sizeof(USHORT))
	{
		goto DROP;
	}
	inner_size = READ_USHORT(buf);
	buf += sizeof(USHORT);
	size -= sizeof(USHORT);

	if (size < sizeof(UCHAR))
	{
		goto DROP;
	}
	if (a->ReadRawFlagMode == false)
	{
		compress_flag = *((UCHAR *)buf);
	}
	else
	{
		raw_flag = *((UCHAR *)buf);
	}

	buf += sizeof(UCHAR);
	size -= sizeof(UCHAR);

	if (size < inner_size)
	{
		goto DROP;
	}

	if (inner_size >= 1)
	{
		inner_data = buf;
		buf += inner_size;
		size -= inner_size;
	}

	if (a->PlainTextMode == false)
	{
		if (a->Version == 1)
		{
			UINT pad_size;

			if (size < UDP_ACCELERATION_PACKET_IV_SIZE_V1)
			{
				goto DROP;
			}

			pad_size = size - UDP_ACCELERATION_PACKET_IV_SIZE_V1;
			buf += pad_size;
			size -= pad_size;

			if (size != UDP_ACCELERATION_PACKET_IV_SIZE_V1)
			{
				goto DROP;
			}

			if (IsZero(buf, UDP_ACCELERATION_PACKET_IV_SIZE_V1) == false)
			{
				goto DROP;
			}
		}
	}

	if (my_tick < a->LastRecvYourTick)
	{
		if ((a->LastRecvYourTick - my_tick) >= ((UINT64)UDP_ACCELERATION_WINDOW_SIZE_MSEC))
		{
			goto DROP;
		}
	}

	a->LastRecvMyTick = MAX(a->LastRecvMyTick, your_tick);
	a->LastRecvYourTick = MAX(a->LastRecvYourTick, my_tick);

	if (inner_size >= 1)
	{
		b = NewBlock(Clone(inner_data, inner_size), inner_size, a->ReadRawFlagMode == false ? (compress_flag ? -1 : 0) : 0);
	}

	if (a->LastSetSrcIpAndPortTick < a->LastRecvYourTick)
	{
		a->LastSetSrcIpAndPortTick = a->LastRecvYourTick;

		Copy(&a->YourIp, src_ip, sizeof(IP));
		a->YourPort = src_port;
	}

	if (a->LastRecvMyTick != 0)
	{
		if ((a->LastRecvMyTick + (UINT64)(UDP_ACCELERATION_WINDOW_SIZE_MSEC)) >= a->Now)
		{
			a->LastRecvTick = a->Now;

			if (a->FirstStableReceiveTick == 0)
			{
				a->FirstStableReceiveTick = a->Now;
			}
		}
	}

	return b;

DROP:
	// Failed decryption, the cookie, the format or the window: not a packet of this session
	a->NumDropInvalid++;
	return NULL;
}

void UdpAccelCalcKeyV1(UCHAR *key, UCHAR *common_key, UCHAR *iv)
{
	UCHAR tmp[UDP_ACCELERATION_COMMON_KEY_SIZE_V1 + UDP_ACCELERATION_PACKET_IV_SIZE_V1];
	if (key == NULL || common_key == NULL || iv == NULL)
	{
		return;
	}

	Copy(tmp, common_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
	Copy(tmp + UDP_ACCELERATION_COMMON_KEY_SIZE_V1, iv, UDP_ACCELERATION_PACKET_IV_SIZE_V1);

	Sha1(key, tmp, sizeof(tmp));
}

void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64)
{
	if (a == NULL)
	{
		return;
	}

	a->Now = tick64;
}

bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port)
{
	if (a == NULL || key == NULL || detected_ip == NULL || port == 0)
	{
		return false;
	}

	if (IsIP6(detected_ip) != a->IsIPv6)
	{
		return false;
	}

	if (a->Version > 1)
	{
		a->CipherEncrypt = NewCipher("ChaCha20-Poly1305");
		a->CipherDecrypt = NewCipher("ChaCha20-Poly1305");

		SetCipherKey(a->CipherEncrypt, a->MyKey_V2, true);
		SetCipherKey(a->CipherDecrypt, key, false);
	}
	else
	{
		Copy(a->YourKey, key, sizeof(a->YourKey));
	}

	Copy(&a->YourIp, detected_ip, sizeof(a->YourIp));
	Copy(&a->YourIpReported, reported_ip, sizeof(a->YourIpReported));

	a->YourPort = a->YourPortReported = port;

	a->Now = Tick64();

	a->Inited = true;

	return true;
}

bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *key, IP *detected_ip, IP *reported_ip, USHORT port, UINT cookie, UINT my_cookie)
{
	if (a == NULL || key == NULL || detected_ip == NULL || port == 0)
	{
		return false;
	}

	if (IsIP6(detected_ip) != a->IsIPv6)
	{
		return false;
	}

	if (a->Version > 1)
	{
		a->CipherEncrypt = NewCipher("ChaCha20-Poly1305");
		a->CipherDecrypt = NewCipher("ChaCha20-Poly1305");

		SetCipherKey(a->CipherEncrypt, a->MyKey_V2, true);
		SetCipherKey(a->CipherDecrypt, key, false);
	}
	else
	{
		Copy(a->YourKey, key, sizeof(a->YourKey));
	}

	Copy(&a->YourIp, detected_ip, sizeof(a->YourIp));
	Copy(&a->YourIpReported, reported_ip, sizeof(a->YourIpReported));

	a->YourPort = a->YourPortReported = port;

	a->Now = Tick64();

	a->MyCookie = my_cookie;
	a->YourCookie = cookie;

	a->Inited = true;

	return true;
}

// Learn the public endpoint of the UDP socket by STUN if a STUN server is configured.
// On success the STUN-derived address and port are reported to the peer instead of
// MyIp and MyPort. With no STUN server configured, nothing is sent. STUN is also
// skipped when the peer (peer_ip) is on a private, loopback, IPv6 link-local or IPv6
// unique local address, because such a peer does not reach this host through the
// public endpoint.
void UdpAccelQueryStun(UDP_ACCEL *a, IP *peer_ip)
{
	char server[MAX_HOST_NAME_LEN + 1];
	IP ip;
	UINT port;
	if (a == NULL || a->UdpSock == NULL || peer_ip == NULL)
	{
		return;
	}

	Lock(a->Cedar->lock);
	{
		StrCpy(server, sizeof(server), a->Cedar->StunServer);
	}
	Unlock(a->Cedar->lock);

	if (IsEmptyStr(server))
	{
		return;
	}

	if (IsIPPrivate(peer_ip) || IsLocalHostIP(peer_ip) ||
		(IsIP6(peer_ip) && ((GetIPAddrType6(peer_ip) & IPV6_ADDR_LOCAL_UNICAST) || (peer_ip->address[0] & 0xfe) == 0xfc)))
	{
		// The peer is on the local side of the NAT: report the local endpoint
		return;
	}

	if (StunGetMappedAddress(a->UdpSock, server, &ip, &port) == false)
	{
		return;
	}

	// The result must be a unicast address of the socket's family (not zero, loopback,
	// multicast or broadcast), because STUN has no integrity protection here
	if (IsIP6(&ip) != a->IsIPv6 || port == 0 || port > 65535 || IsLocalHostIP(&ip) ||
		(IsIP6(&ip) ? IsValidUnicastIPAddress6(&ip) : IsValidUnicastIPAddress4(&ip)) == false)
	{
		return;
	}

	Copy(&a->StunIp, &ip, sizeof(a->StunIp));
	a->StunPort = (USHORT)port;
	a->UseStun = true;

}

// True when the polls of the current tick have read UDP_ACCELERATION_MAX_RECV_PER_TICK datagrams
bool UdpAccelIsRecvBudgetSpent(UDP_ACCEL *a)
{
	if (a == NULL)
	{
		return false;
	}

	return a->RecvNumInTick >= UDP_ACCELERATION_MAX_RECV_PER_TICK;
}

// Write the drop counters to the log of hub h (its security log and the server log) when
// datagrams were dropped since the last entry: at most once per UDP_ACCELERATION_DROP_LOG_INTERVAL
// while the session runs, and at once when final is set (the session ends). The first drops of a
// session are written at once. Returns true when an entry was written.
bool UdpAccelLogDrops(UDP_ACCEL *a, HUB *h, char *session_name, bool final)
{
	UINT64 num_drop;
	if (a == NULL)
	{
		return false;
	}

	num_drop = a->NumDropShort + a->NumDropInvalid;
	if (num_drop == a->LogDropNum)
	{
		return false;
	}

	if (final == false && a->LogDropTick != 0 && (a->LogDropTick + (UINT64)UDP_ACCELERATION_DROP_LOG_INTERVAL) > a->Now)
	{
		return false;
	}

	a->LogDropTick = a->Now;
	a->LogDropNum = num_drop;

	HLog(h, "LH_UDP_ACCEL_DROP", session_name, a->NumDropShort, a->NumDropInvalid, a->NumRecvLimit);

	return true;
}

// Draw the cookie pair of a new UDP_ACCEL from rand32: both are non-zero and differ from each other
void UdpAccelNewCookies(UINT *my_cookie, UINT *your_cookie, UINT (*rand32)(void))
{
	do
	{
		*my_cookie = rand32();
	}
	while (*my_cookie == 0);

	do
	{
		*your_cookie = rand32();
	}
	while (*your_cookie == 0 || *my_cookie == *your_cookie);
}

UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port)
{
	UDP_ACCEL *a;
	SOCK *s;
	UINT max_udp_size;
	bool is_in_cedar_port_list = false;

	if (IsZeroIP(ip))
	{
		ip = NULL;
	}

	if (client_mode || random_port)
	{
		s = NewUDPEx3(0, ip);
	}
	else
	{
		UINT i;
		s = NULL;

		LockList(cedar->UdpPortList);
		{
			for (i = UDP_SERVER_PORT_LOWER;i <= UDP_SERVER_PORT_HIGHER;i++)
			{
				if (IsIntInList(cedar->UdpPortList, i) == false)
				{
					s = NewUDPEx3(i, ip);

					if (s != NULL)
					{
						is_in_cedar_port_list = true;
						break;
					}
				}
			}

			if (s == NULL)
			{
				// No free port in the range: let the OS pick one
				s = NewUDPEx3(0, ip);
			}

			if (s != NULL && is_in_cedar_port_list)
			{
				AddIntDistinct(cedar->UdpPortList, i);
			}
		}
		UnlockList(cedar->UdpPortList);
	}

	if (s == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(UDP_ACCEL));

	a->Cedar = cedar;
	AddRef(a->Cedar->ref);

	a->Version = 1;

	a->CreatedTick = Tick64();

	a->IsInCedarPortList = is_in_cedar_port_list;

	a->Now = Tick64();
	a->UdpSock = s;

	Rand(a->MyKey, sizeof(a->MyKey));
	Rand(a->MyKey_V2, sizeof(a->MyKey_V2));

	Copy(&a->MyIp, ip, sizeof(a->MyIp));
	a->MyPort = s->LocalPort;

	a->IsIPv6 = IsIP6(ip);

	a->RecvBlockQueue = NewQueue();

	Rand(a->NextIv, sizeof(a->NextIv));
	Rand(a->NextIv_V2, sizeof(a->NextIv_V2));

	UdpAccelNewCookies(&a->MyCookie, &a->YourCookie, Rand32);

	max_udp_size = MTU_FOR_PPPOE;

	if (a->IsIPv6 == false)
	{
		max_udp_size -= 20;
	}
	else
	{
		max_udp_size -= 40;
	}

	max_udp_size -= 8;

	a->MaxUdpPacketSize = max_udp_size;

	return a;
}

void FreeUdpAccel(UDP_ACCEL *a)
{
	if (a == NULL)
	{
		return;
	}

	while (true)
	{
		BLOCK *b = GetNext(a->RecvBlockQueue);

		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(a->RecvBlockQueue);

	ReleaseSock(a->UdpSock);

	if (a->IsInCedarPortList)
	{
		LockList(a->Cedar->UdpPortList);
		{
			DelInt(a->Cedar->UdpPortList, a->MyPort);
		}
		UnlockList(a->Cedar->UdpPortList);
	}

	ReleaseCedar(a->Cedar);

	FreeCipher(a->CipherEncrypt);
	FreeCipher(a->CipherDecrypt);

	Free(a);
}
