// Logging.c
// Log storaging module

#include "Logging.h"

#include "Admin.h"
#include "Remote.h"
#include "Server.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Win32.h"

static char *delete_targets[] =
{
	"backup.ranz_server.config",
	HUB_PACKET_LOG_DIR,
	HUB_SECURITY_LOG_DIR,
	SERVER_LOG_DIR,
};

static UINT eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;
static UINT64 logger_max_log_size = MAX_LOG_SIZE_DEFAULT;

// State of the writer thread of a LOG (LogThread): the open file, the records not yet written,
// the name of the open file and the date part of the current file name
typedef struct LOG_WRITER
{
	IO *Io;								// Open log file, NULL while none is open
	BUF *Buffer;						// Records not yet written to the file
	char FileName[MAX_SIZE];			// Name of the open file (while none is open: of the file to open)
	char DateName[MAX_SIZE];			// Date part of the current file name
	UINT RetryWait;						// Milliseconds waited after the last failed open, 0 after a successful one
	UINT64 RetryTick;					// No new try to open the file before this tick
	bool Realtime;						// The thread runs at the realtime priority (false: idle priority)
} LOG_WRITER;

static bool LogThreadWriteGeneral(LOG *log_object, LOG_WRITER *w);
static UINT LogWriterWaitTime(LOG_WRITER *w);

// Map the control characters of size bytes of UTF-8 text (bytes below 0x20 and 0x7F, never part of a
// multi-byte sequence) to '?': a CR or LF from untrusted input cannot start a forged log line or syslog message
static void LogMapControlChars(UCHAR *s, UINT size)
{
	UINT i;

	for (i = 0;i < size;i++)
	{
		if (s[i] < 0x20 || s[i] == 0x7F)
		{
			s[i] = '?';
		}
	}
}

// Send one syslog datagram to the current address (g->lock held)
static void SendSysLogLocked(SLOG *g, UCHAR *buf, UINT size)
{
	if (g->DestPort != 0 && IsZeroIp(&g->DestIp) == false)
	{
		SendTo(g->Udp, &g->DestIp, g->DestPort, buf, size);
	}
}

void SendSysLog(SLOG *g, wchar_t *str)
{
	UCHAR *buf;
	UINT buf_size;
	char hostname[MAX_HOST_NAME_LEN + 1];
	bool poll = false;
	if (g == NULL || str == NULL)
	{
		return;
	}

	buf_size = CalcUniToUtf8(str);
	buf = ZeroMalloc(buf_size);
	UniToUtf8(buf, buf_size, str);
	LogMapControlChars(buf, buf_size);

	if (buf_size >= 1024)
	{
		buf_size = 1023;
	}

	Lock(g->lock);
	{
		if (Tick64() >= g->NextPollIp)
		{
			// This sender resolves the host again; the others use the current address meanwhile
			g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
			StrCpy(hostname, sizeof(hostname), g->HostName);
			poll = true;
		}
		else
		{
			SendSysLogLocked(g, buf, buf_size);
		}
	}
	Unlock(g->lock);

	if (poll)
	{
		// The resolve can take seconds: it runs outside the lock, which every logging thread takes
		IP ip;
		bool resolved = GetIP(&ip, hostname);

		Lock(g->lock);
		{
			// A SetSysLog with another host meanwhile has resolved that host already
			if (StrCmp(g->HostName, hostname) == 0)
			{
				if (resolved)
				{
					g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL;
					Copy(&g->DestIp, &ip, sizeof(IP));
				}
				else
				{
					g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
				}
			}

			SendSysLogLocked(g, buf, buf_size);
		}
		Unlock(g->lock);
	}

	Free(buf);
}

void FreeSysLog(SLOG *g)
{
	if (g == NULL)
	{
		return;
	}

	DeleteLock(g->lock);
	ReleaseSock(g->Udp);
	Free(g);
}

void SetSysLog(SLOG *g, char *hostname, UINT port)
{
	IP ip;
	if (g == NULL)
	{
		return;
	}
	if (port == 0)
	{
		port = SYSLOG_PORT;
	}

	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&ip, sizeof(IP));
	GetIP(&ip, hostname);

	Lock(g->lock);
	{
		Copy(&g->DestIp, &ip, sizeof(IP));
		g->DestPort = port;
		StrCpy(g->HostName, sizeof(g->HostName), hostname);
		g->NextPollIp = Tick64() + (IsZeroIp(&ip) ? SYSLOG_POLL_IP_INTERVAL_NG : SYSLOG_POLL_IP_INTERVAL);
	}
	Unlock(g->lock);
}

SLOG *NewSysLog(char *hostname, UINT port, IP *ip)
{
	SLOG *g = ZeroMalloc(sizeof(SLOG));

	g->lock = NewLock();
	// The socket is IPv4: NewUDP4 refuses an address that is not IPv4, and an unset ListenIP is the all-zero
	// IPv6 address, so only an IPv4 address is bound; otherwise the socket binds to any address
	g->Udp = NewUDPEx2(0, false, (ip != NULL && IsIP4(ip)) ? ip : NULL);

	SetSysLog(g, hostname, port);

	return g;
}

static bool CheckEraserDiskFreeSpace(ERASER *e)
{
	UINT64 s;
	if (e == NULL)
	{
		return true;
	}

	if (GetDiskFree(e->DirName, &s, NULL, NULL) == false)
	{
		return true;
	}

	if (e->MinFreeSpace > s)
	{
		return false;
	}

	return true;
}

static void FreeEraseFileList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Free(f->FullPath);
		Free(f);
	}

	ReleaseList(o);
}

static void EnumEraseFile(LIST *o, char *dirname)
{
	DIRLIST *dir;
	UINT i;
	char tmp[MAX_PATH];
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	dir = EnumDir(dirname);

	for (i = 0; i < dir->NumFiles; i++)
	{
		DIRENT *e = dir->File[i];
		Format(tmp, sizeof(tmp), "%s/%s", dirname, e->FileName);
		NormalizePath(tmp, sizeof(tmp), tmp);

		if (e->Folder == false)
		{
			ERASE_FILE *f;

			if (EndWith(tmp, ".log") || EndWith(tmp, ".config") || EndWith(tmp, ".old"))
			{
				f = ZeroMalloc(sizeof(ERASE_FILE));
				f->FullPath = CopyStr(tmp);
				f->UpdateTime = e->UpdateDate;

				Add(o, f);
			}
		}
		else
		{
			EnumEraseFile(o, tmp);
		}
	}

	FreeDir(dir);
}

static LIST *GenerateEraseFileList(ERASER *e)
{
	LIST *o;
	UINT i;
	if (e == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareEraseFile);

	for (i = 0; i < sizeof(delete_targets) / sizeof(delete_targets[0]); i++)
	{
		char dirname[MAX_PATH];
		Format(dirname, sizeof(dirname), "%s/%s", e->DirName, delete_targets[i]);

		EnumEraseFile(o, dirname);
	}

	Sort(o);

	return o;
}

static void EraserMain(ERASER *e)
{
	LIST *o;
	UINT i;
	bool ok = false;
	char bs[64];
	if (e == NULL)
	{
		return;
	}

	if (CheckEraserDiskFreeSpace(e))
	{
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);

	o = GenerateEraseFileList(e);

	for (i = 0; i < LIST_NUM(o); i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);

		if (FileDelete(f->FullPath))
		{
			ELog(e, "LE_DELETE", bs, f->FullPath);
		}

		if (CheckEraserDiskFreeSpace(e))
		{
			ok = true;
			break;
		}
	}

	FreeEraseFileList(o);

	if (e->LastFailed == false && ok == false)
	{
		ELog(e, "LE_NOT_ENOUGH_FREE", bs);
	}

	e->LastFailed = ok ? false : true;
}

int CompareEraseFile(void *p1, void *p2)
{
	ERASE_FILE *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ERASE_FILE **)p1;
	f2 = *(ERASE_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	if (f1->UpdateTime > f2->UpdateTime)
	{
		return 1;
	}
	else if (f1->UpdateTime == f2->UpdateTime)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static void EraserThread(THREAD *t, void *p)
{
	ERASER *e = (ERASER *)p;
	char bs[64];
	if (t == NULL || e == NULL)
	{
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);
	ELog(e, "LE_START", e->DirName, bs);

	while (e->Halt == false)
	{
		EraserMain(e);
		e->NumChecks++;

		// The interval in milliseconds (at least 1 s, as the seconds of GetEraserCheckInterval for the configuration)
		Wait(e->HaltEvent, MAX(eraser_check_interval, 1000));
	}
}

void SetEraserCheckInterval(UINT interval)
{
	if (interval == 0)
	{
		eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;
	}
	else
	{
		eraser_check_interval = interval * 1000;
	}
}

UINT GetEraserCheckInterval()
{
	UINT ret = eraser_check_interval / 1000;

	if (ret == 0)
	{
		ret = 1;
	}

	return ret;
}

ERASER *NewEraser(LOG *log, UINT64 min_size)
{
	ERASER *e;
	char dir[MAX_PATH];

	if (min_size == 0)
	{
		if (OS_IS_WINDOWS(GetOsInfo()->OsType))
		{
			min_size = DISK_FREE_SPACE_DEFAULT_WINDOWS;
		}
		else
		{
			min_size = DISK_FREE_SPACE_DEFAULT;
		}
	}

	if (min_size < DISK_FREE_SPACE_MIN)
	{
		min_size = DISK_FREE_SPACE_MIN;
	}

	e = ZeroMalloc(sizeof(ERASER));

	GetExeDir(dir, sizeof(dir));

	e->Log = log;
	e->MinFreeSpace = min_size;
	e->DirName = CopyStr(dir);
	e->HaltEvent = NewEvent();

	e->Thread = NewThread(EraserThread, e);

	return e;
}

void FreeEraser(ERASER *e)
{
	if (e == NULL)
	{
		return;
	}

	e->Halt = true;
	Set(e->HaltEvent);
	WaitThread(e->Thread, INFINITE);
	ReleaseThread(e->Thread);
	ReleaseEvent(e->HaltEvent);

	Free(e->DirName);
	Free(e);
}

// Format the text of the string table entry name with args into buf (size bytes): the one place SLog, HLog, ALog
// and ELog build their log line
static void LogFormat(wchar_t *buf, UINT size, char *name, va_list args)
{
	UniFormatArgs(buf, size, _UU(name), args);
}

void ELog(ERASER *e, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	InsertUnicodeRecord(e->Log, buf);

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", buf);
	}
	va_end(args);
}

void SLog(CEDAR *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteServerLog(c, buf);
	va_end(args);
}

void ALog(ADMIN *a, HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t tmp[MAX_SIZE * 2];
	va_list args;
	RPC *r;
	if (a == NULL || name == NULL)
	{
		return;
	}

	r = a->Rpc;

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	if (h == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_1"), r->Name);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_2"), r->Name, h->Name);
	}

	UniStrCat(tmp, sizeof(tmp), buf);

	if (h == NULL)
	{
		WriteServerLog(((ADMIN *)r->Param)->Server->Cedar, tmp);
	}
	else
	{
		WriteHubLog(h, tmp);
	}
	va_end(args);
}
void HLog(HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	WriteHubLog(h, buf);
	va_end(args);
}

void WriteHubLog(HUB *h, wchar_t *str)
{
	wchar_t buf[MAX_SIZE * 2];
	UINT syslog_status;
	SERVER *s;
	if (h == NULL || str == NULL)
	{
		return;
	}

	s = h->Cedar->Server;
	syslog_status = SiGetSysLogSaveStatus(s);

	UniFormat(buf, sizeof(buf), L"[HUB \"%S\"] %s", h->Name, str);

	if (syslog_status == SYSLOG_NONE)
	{
		WriteServerLog(h->Cedar, buf);
	}

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	if (syslog_status == SYSLOG_SERVER_AND_HUB_SECURITY_LOG
	        || syslog_status == SYSLOG_SERVER_AND_HUB_ALL_LOG)
	{
		SiWriteSysLog(s, "SECURITY_LOG", h->Name, str);
	}
	else
	{
		InsertUnicodeRecord(h->SecurityLogger, str);
	}
}

void WriteServerLog(CEDAR *c, wchar_t *str)
{
	SERVER *s;
	if (c == NULL || str == NULL)
	{
		return;
	}

	s = c->Server;
	if (s == NULL)
	{
		return;
	}

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", str);
	}

	if (SiGetSysLogSaveStatus(s) != SYSLOG_NONE)
	{
		SiWriteSysLog(s, "SERVER_LOG", NULL, str);
	}
	else
	{
		InsertUnicodeRecord(s->Logger, str);
	}
}

bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now)
{
	UINT level;
	PKT *p;
	PACKET_LOG *pl;
	SERVER *s;
	UINT syslog_setting;
	bool no_log = false;
	if (hub == NULL || src_session == NULL || packet == NULL)
	{
		return true;
	}

	s = hub->Cedar->Server;

	if (hub->LogSetting.SavePacketLog == false)
	{
		return true;
	}

	if (Cmp(hub->HubMacAddr, packet->MacAddressSrc, 6) == 0 ||
		Cmp(hub->HubMacAddr, packet->MacAddressDest, 6) == 0)
	{
		return true;
	}

	level = CalcPacketLoggingLevel(&hub->LogSetting, packet);
	if (level == PACKET_LOG_NONE)
	{
		return true;
	}

	if (hub->Option != NULL)
	{
		if (hub->Option->NoIPv4PacketLog && (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4))
		{
			return true;
		}

		if (hub->Option->NoIPv6PacketLog && packet->TypeL3 == L3_IPV6)
		{
			return true;
		}

		if (hub->Option->MaxLoggedPacketsPerMinute != 0 &&
			CheckMaxLoggedPacketsPerMinute(src_session, hub->Option->MaxLoggedPacketsPerMinute, now) == false)
		{
			return false;
		}
	}

	if (GetGlobalServerFlag(GSF_DISABLE_DEEP_LOGGING) != 0)
	{
		no_log = true;
	}

	syslog_setting = SiGetSysLogSaveStatus(s);

	p = ClonePacket(packet, level == PACKET_LOG_ALL ? true : false);

	pl = ZeroMalloc(sizeof(PACKET_LOG));

	pl->Cedar = hub->Cedar;
	pl->Packet = p;
	pl->NoLog = no_log;
	pl->SrcSessionName = CopyStr(src_session->Name);
	if (dest_session != NULL)
	{
		pl->DestSessionName = CopyStr(dest_session->Name);
	}
	else
	{
		pl->DestSessionName = CopyStr("");
	}

	if (hub->Option == NULL || hub->Option->NoPhysicalIPOnPacketLog == false)
	{
		if (src_session->NormalClient)
		{
			StrCpy(pl->SrcPhysicalIP, sizeof(pl->SrcPhysicalIP), src_session->ClientIP);
		}

		if (dest_session != NULL && dest_session->NormalClient)
		{
			StrCpy(pl->DestPhysicalIP, sizeof(pl->DestPhysicalIP), dest_session->ClientIP);
		}

		pl->WritePhysicalIP = true;
	}

	if (src_session->LoggingRecordCount != NULL)
	{
		UINT n = 0;
		while (src_session->LoggingRecordCount->c >= 30000)
		{
			SleepThread(50);
			n++;
			if (n >= 5)
			{
				break;
			}
		}
	}

	pl->SrcSession = src_session;
	AddRef(src_session->ref);

	Inc(src_session->LoggingRecordCount);

	if (syslog_setting == SYSLOG_SERVER_AND_HUB_ALL_LOG)
	{
		RECORD rec;
		char *buf;
		wchar_t tmp[1024];
		bool self_syslog_packet = false;

		if (packet->TypeL3 == L3_IPV4 && packet->TypeL4 == L4_UDP)
		{
			if (s->Syslog != NULL)
			{
				Lock(s->Syslog->lock);
				{
					if (IsZeroIp(&s->Syslog->DestIp) == false && s->Syslog->DestPort != 0)
					{
						if (IPToUINT(&s->Syslog->DestIp) == packet->L3.IPv4Header->DstIP)
						{
							// DstPort is a 16-bit field in network order, DestPort a port in host order
							if (Endian16(packet->L4.UDPHeader->DstPort) == (USHORT)s->Syslog->DestPort)
							{
								self_syslog_packet = true;
							}
						}
					}
				}
				Unlock(s->Syslog->lock);
			}
		}

		Zero(&rec, sizeof(rec));
		rec.Data = pl;

		buf = PacketLogParseProc(&rec);
		StrToUni(tmp, sizeof(tmp), buf);

		if (self_syslog_packet == false)
		{
			SiWriteSysLog(s, "PACKET_LOG", hub->Name, tmp);
		}

		Free(buf);
	}
	else
	{
		InsertRecord(hub->PacketLogger, pl, PacketLogParseProc);
	}

	return true;
}

// A TCP segment that opens or closes a connection
static bool IsTcpConnectionFlag(UCHAR flag)
{
	return ((flag & (TCP_SYN | TCP_RST | TCP_FIN)) != 0);
}

UINT CalcPacketLoggingLevel(HUB_LOG *g, PKT *packet)
{
	UINT ret = 0;
	if (g == NULL || packet == NULL)
	{
		return PACKET_LOG_NONE;
	}

	ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ETHERNET]);

	switch (packet->TypeL3)
	{
	case L3_ARPV4:
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ARP]);
		break;

	case L3_IPV4:
	case L3_IPV6:
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4)
		{
		case L4_ICMPV4:
		case L4_ICMPV6:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (IsTcpConnectionFlag(packet->L4.TCPHeader->Flag))
			{
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
			}

			break;

		case L4_UDP:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			switch (packet->TypeL7)
			{
			case L7_DHCPV4:
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_DHCP]);
				break;

			case L7_IKECONN:
			case L7_DNS:
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;
			}

			break;
		}

		break;
	}

	if (packet->HttpLog != NULL)
	{
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
	}

	return ret;
}

static char *BuildHttpLogStr(HTTPLOG *h)
{
	BUF *b;
	char url[MAX_SIZE];
	char nullchar = 0;
	char *ret;
	if (h == NULL)
	{
		return CopyStr("");
	}

	b = NewBuf();

	if (StartWith(h->Path, "http://") || StartWith(h->Path, "https://"))
	{
		StrCpy(url, sizeof(url), h->Path);
	}
	else
	{
		if (h->IsSsl == false)
		{
			if (h->Port == 80)
			{
				Format(url, sizeof(url), "http://%s%s",
				       h->Hostname, h->Path);
			}
			else
			{
				Format(url, sizeof(url), "http://%s:%u%s",
				       h->Hostname, h->Port, h->Path);
			}
		}
		else
		{
			if (h->Port == 443)
			{
				Format(url, sizeof(url), "https://%s/",
				       h->Hostname);
			}
			else
			{
				Format(url, sizeof(url), "https://%s:%u/",
				       h->Hostname, h->Port);
			}
		}
	}

	AddLogBufToStr(b, "HttpMethod", h->Method);
	AddLogBufToStr(b, "HttpUrl", url);
	AddLogBufToStr(b, "HttpProtocol", h->Protocol);
	AddLogBufToStr(b, "HttpReferer", h->Referer);
	AddLogBufToStr(b, "HttpUserAgent", h->UserAgent);

	WriteBuf(b, &nullchar, 1);

	ret = CopyStr(b->Buf);

	FreeBuf(b);

	return ret;
}

void AddLogBufToStr(BUF *b, char *name, char *value)
{
	char tmp[MAX_SIZE * 2];
	char *p = NULL;
	if (b == NULL || value == NULL)
	{
		return;
	}

	if (IsEmptyStr(value))
	{
		return;
	}

	tmp[0] = 0;

	if (IsEmptyStr(name) == false)
	{
		p = &tmp[StrLen(tmp)];
		StrCat(tmp, sizeof(tmp), name);
		MakeSafeLogStr(p);
		StrCat(tmp, sizeof(tmp), "=");
	}

	p = &tmp[StrLen(tmp)];
	StrCat(tmp, sizeof(tmp), value);
	MakeSafeLogStr(p);
	StrCat(tmp, sizeof(tmp), " ");

	WriteBuf(b, tmp, StrLen(tmp));
}

void MakeSafeLogStr(char *str)
{
	UINT i, len;
	bool is_http = false;
	if (str == NULL)
	{
		return;
	}

	if (str[0] == 'h' && str[1] == 't' && str[2] == 't' && str[3] == 'p' &&
	        ((str[4] == 's' && str[5] == ':') || (str[4] == ':')))
	{
		is_http = true;
	}

	EnPrintableAsciiStr(str, '?');

	len = StrLen(str);
	for (i = 0; i < len; i++)
	{
		if (str[i] == ',')
		{
			str[i] = '.';
		}
		else if (str[i] == ' ')
		{
			if (is_http == false)
			{
				str[i] = '_';
			}
		}
	}
}

// The packet log tokens of a TCP segment. suffix is "v4" or "v6"
static void PacketLogTcp(TOKEN_LIST *t, PACKET_LOG *pl, PKT *p, char *suffix)
{
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "%s%s", (IsTcpConnectionFlag(p->L4.TCPHeader->Flag) ? "TCP_CONNECT" : "TCP_DATA"), suffix);
	t->Token[6] = CopyStr(tmp);
	t->Token[7] = TcpFlagStr(p->L4.TCPHeader->Flag);

	t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->SrcPort), false);
	t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->DstPort), false);

	ToStr(tmp, Endian32(p->L4.TCPHeader->SeqNumber));
	t->Token[12] = CopyStr(tmp);

	ToStr(tmp, Endian32(p->L4.TCPHeader->AckNumber));
	t->Token[13] = CopyStr(tmp);

	snprintf(tmp, sizeof(tmp), "WindowSize=%u", Endian16(p->L4.TCPHeader->WindowSize));

	if (p->HttpLog != NULL)
	{
		char *tmp2;
		UINT tmp2_size;
		char *http_str = BuildHttpLogStr(p->HttpLog);

		tmp2_size = StrLen(http_str) + 16 + StrLen(tmp);
		tmp2 = Malloc(tmp2_size);

		StrCpy(tmp2, tmp2_size, tmp);

		if (IsEmptyStr(http_str) == false)
		{
			StrCat(tmp2, tmp2_size, " ");
			StrCat(tmp2, tmp2_size, http_str);
		}

		Free(http_str);

		t->Token[14] = tmp2;
	}
	else
	{
		t->Token[14] = CopyStr(tmp);
	}
}

// The packet log tokens of an IKE connection packet. suffix is "v4" or "v6"
static void PacketLogIke(TOKEN_LIST *t, PKT *p, char *suffix)
{
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "IKE_CONNECT%s", suffix);
	t->Token[6] = CopyStr(tmp);

	if (p->L7.IkeHeader != NULL)
	{
		if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
		{
			t->Token[7] = CopyStr("MainMode");
		}
		else if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_AGGRESSIVE)
		{
			t->Token[7] = CopyStr("AggressiveMode");
		}

		Format(tmp, sizeof(tmp), "InitiatorCookie=%I64u ResponderCookie=%I64u "
		       "Version=0x%x ExchangeType=0x%x Flag=0x%x MessageId=%u MessageSize=%u",
		       Endian64(p->L7.IkeHeader->InitiatorCookie),
		       Endian64(p->L7.IkeHeader->ResponderCookie),
		       p->L7.IkeHeader->Version,
		       p->L7.IkeHeader->ExchangeType,
		       p->L7.IkeHeader->Flag,
		       Endian32(p->L7.IkeHeader->MessageId),
		       Endian32(p->L7.IkeHeader->MessageSize));

		t->Token[14] = CopyStr(tmp);
	}
}

// The packet log tokens of a DNS query. suffix is "v4" or "v6"
static void PacketLogDns(TOKEN_LIST *t, PKT *p, char *suffix)
{
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "DNS%s", suffix);
	t->Token[6] = CopyStr(tmp);
	t->Token[7] = CopyStr("DNS_Query");
	// The query name holds raw label bytes from the wire
	t->Token[14] = CopyStr(p->DnsQueryHost);
	MakeSafeLogStr(t->Token[14]);
}

// The packet log tokens of a UDP datagram. suffix is "v4" or "v6"
static void PacketLogUdp(TOKEN_LIST *t, PACKET_LOG *pl, PKT *p, char *suffix)
{
	char tmp[MAX_SIZE];

	t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->SrcPort), true);
	t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->DstPort), true);

	switch (p->TypeL7)
	{
	case L7_DHCPV4:
		t->Token[6] = CopyStr("DHCPv4");
		if (p->L7.DHCPv4Header->OpCode == 1)
		{
			t->Token[7] = CopyStr("Request");
		}
		else
		{
			t->Token[7] = CopyStr("Response");
		}

		{
			char ip1[64], ip2[64], ip3[64], ip4[64];
			IPToStr32(ip1, sizeof(ip1), p->L7.DHCPv4Header->ClientIP);
			IPToStr32(ip2, sizeof(ip2), p->L7.DHCPv4Header->YourIP);
			IPToStr32(ip3, sizeof(ip3), p->L7.DHCPv4Header->ServerIP);
			IPToStr32(ip4, sizeof(ip4), p->L7.DHCPv4Header->RelayIP);

			snprintf(tmp, sizeof(tmp),
			         "TransactionId=%u ClientIP=%s YourIP=%s ServerIP=%s RelayIP=%s",
			         Endian32(p->L7.DHCPv4Header->TransactionId),
			         ip1, ip2, ip3, ip4);

			t->Token[14] = CopyStr(tmp);
		}

		break;

	case L7_IKECONN:
		PacketLogIke(t, p, suffix);
		break;

	case L7_DNS:
		PacketLogDns(t, p, suffix);
		break;

	default:
		snprintf(tmp, sizeof(tmp), "UDP%s", suffix);
		t->Token[6] = CopyStr(tmp);
		break;
	}
}

// The packet log tokens of an ARP packet: the request and the response differ only in the text
static void PacketLogArp(TOKEN_LIST *t, PKT *p)
{
	ARPV4_HEADER *a = p->L3.ARPv4Header;
	char tmp[MAX_SIZE];
	bool request;

	t->Token[6] = CopyStr("ARPv4");

	switch (Endian16(a->Operation))
	{
	case ARP_OPERATION_REQUEST:
		t->Token[7] = CopyStr("Request");
		request = true;
		break;

	case ARP_OPERATION_RESPONSE:
		t->Token[7] = CopyStr("Response");
		request = false;
		break;

	default:
		return;
	}

	if (Endian16(a->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
	        a->HardwareSize == 6 &&
	        Endian16(a->ProtocolType) == MAC_PROTO_IPV4 &&
	        a->ProtocolSize == 4)
	{
		char src_mac[16];
		char src_ip[16];
		IP src_ip_st;
		BinToStr(src_mac, sizeof(src_mac), a->SrcAddress, 6);
		UINTToIP(&src_ip_st, a->SrcIP);
		IPToStr(src_ip, sizeof(src_ip), &src_ip_st);

		if (request)
		{
			char dst_ip[16];
			IP dst_ip_st;
			UINTToIP(&dst_ip_st, a->TargetIP);
			IPToStr(dst_ip, sizeof(dst_ip), &dst_ip_st);
			snprintf(tmp, sizeof(tmp), "Who has %s? Please Tell %s(%s)",
			         dst_ip, src_mac, src_ip);
		}
		else
		{
			snprintf(tmp, sizeof(tmp), "%s has %s",
			         src_mac, src_ip);
		}

		t->Token[14] = CopyStr(tmp);
	}
}

char *PacketLogParseProc(RECORD *rec)
{
	PACKET_LOG *pl;
	PKT *p;
	char *s;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	UINT i;
	if (rec == NULL)
	{
		return NULL;
	}

	pl = (PACKET_LOG *)rec->Data;
	p = pl->Packet;

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = 16;
	if (pl->WritePhysicalIP)
	{
		t->NumTokens += 2;
	}
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	t->Token[0] = pl->SrcSessionName;

	t->Token[1] = pl->DestSessionName;

	BinToStr(tmp, sizeof(tmp), p->MacAddressSrc, 6);

	t->Token[2] = CopyStr(tmp);
	BinToStr(tmp, sizeof(tmp), p->MacAddressDest, 6);

	t->Token[3] = CopyStr(tmp);

	snprintf(tmp, sizeof(tmp), "0x%04X", Endian16(p->MacHeader->Protocol));
	t->Token[4] = CopyStr(tmp);

	ToStr(tmp, p->PacketSize);
	t->Token[5] = CopyStr(tmp);

	if (pl->NoLog == false)
	{
		switch (p->TypeL3)
		{
		case L3_ARPV4:
			PacketLogArp(t, p);
			break;

		case L3_IPV4:
			switch (p->TypeL4)
			{
			case L4_ICMPV4:
				t->Token[6] = CopyStr("ICMPv4");

				switch (p->L4.ICMPHeader->Type)
				{
				case ICMP_TYPE_ECHO_REQUEST:
					t->Token[7] = CopyStr("Echo Request");
					break;

				case ICMP_TYPE_ECHO_RESPONSE:
					t->Token[7] = CopyStr("Echo Reply");
					break;
				}
				break;

			case L4_TCP:
				PacketLogTcp(t, pl, p, "v4");
				break;

			case L4_UDP:
				PacketLogUdp(t, pl, p, "v4");
				break;

			case L4_FRAGMENT:
				snprintf(tmp, sizeof(tmp), "IPv4_Fragment(0x%02X)", p->L3.IPv4Header->Protocol);
				t->Token[6] = CopyStr(tmp);
				break;

			case L4_UNKNOWN:
				snprintf(tmp, sizeof(tmp), "IPv4(0x%02X)", p->L3.IPv4Header->Protocol);
				t->Token[6] = CopyStr(tmp);
				break;
			}

			IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->SrcIP);
			t->Token[8] = CopyStr(tmp);

			IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->DstIP);
			t->Token[10] = CopyStr(tmp);

			break;

		case L3_IPV6:
			switch (p->TypeL4)
			{
			case L4_ICMPV6:
			{
				char info[MAX_SIZE];
				ICMPV6_HEADER_INFO *icmp = &p->ICMPv6HeaderPacketInfo;
				ICMPV6_OPTION_LIST *ol = &icmp->OptionList;

				Zero(info, sizeof(info));

				t->Token[6] = CopyStr("ICMPv6");

				switch (icmp->Type)
				{
				case ICMPV6_TYPE_ECHO_REQUEST:
					t->Token[7] = CopyStr("Echo Request");
					snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
					StrCat(info, sizeof(info), tmp);
					break;

				case ICMPV6_TYPE_ECHO_RESPONSE:
					t->Token[7] = CopyStr("Echo Reply");
					snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
					StrCat(info, sizeof(info), tmp);
					break;

				case ICMPV6_TYPE_ROUTER_SOLICIATION:
					t->Token[7] = CopyStr("Router Soliciation");
					break;

				case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
				{
					ICMPV6_ROUTER_ADVERTISEMENT_HEADER *h = icmp->Headers.RouterAdvertisementHeader;
					t->Token[7] = CopyStr("Router Advertisement");

					if (h != NULL)
					{
						snprintf(tmp, sizeof(tmp), "CurHopLimit=%u "
						         "Flags=0x%02X Lifetime=%u ",
						         h->CurHopLimit, h->Flags, Endian16(h->Lifetime));
						StrCat(info, sizeof(info), tmp);
					}
				}
				break;

				case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
				{
					ICMPV6_NEIGHBOR_SOLICIATION_HEADER *h = icmp->Headers.NeighborSoliciationHeader;
					t->Token[7] = CopyStr("Neighbor Soliciation");

					if (h != NULL)
					{
						char tmp2[MAX_SIZE];

						IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

						snprintf(tmp, sizeof(tmp), "TargetAddress=%s ",
						         tmp2);
						StrCat(info, sizeof(info), tmp);
					}
				}
				break;

				case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
				{
					ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *h = icmp->Headers.NeighborAdvertisementHeader;
					t->Token[7] = CopyStr("Neighbor Advertisement");

					if (h != NULL)
					{
						char tmp2[MAX_SIZE];

						IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

						snprintf(tmp, sizeof(tmp), "TargetAddress=%s Flags=0x%02X ",
						         tmp2, h->Flags);
						StrCat(info, sizeof(info), tmp);
					}
				}
				break;

				default:
				{
					snprintf(tmp, sizeof(tmp), "Type=%u", icmp->Type);
					t->Token[7] = CopyStr(tmp);
				}
				break;
				}

				if (ol->SourceLinkLayer != NULL)
				{
					char tmp2[MAX_SIZE];
					BinToStr(tmp2, sizeof(tmp2), ol->SourceLinkLayer->Address, 6);
					snprintf(tmp, sizeof(tmp), "SourceLinkLayer=%s ", tmp2);
					StrCat(info, sizeof(info), tmp);
				}
				if (ol->TargetLinkLayer != NULL)
				{
					char tmp2[MAX_SIZE];
					BinToStr(tmp2, sizeof(tmp2), ol->TargetLinkLayer->Address, 6);
					snprintf(tmp, sizeof(tmp), "TargetLinkLayer=%s ", tmp2);
					StrCat(info, sizeof(info), tmp);
				}
				for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
				{
					if (ol->Prefix[i] != NULL)
					{
						char tmp2[MAX_SIZE];
						IP6AddrToStr(tmp2, sizeof(tmp2), &ol->Prefix[i]->Prefix);
						snprintf(tmp, sizeof(tmp), "Prefix=%s/%u PrefixFlag=0x%02X ", tmp2,
						         ol->Prefix[i]->SubnetLength, ol->Prefix[i]->Flags);
						StrCat(info, sizeof(info), tmp);
					}
					else
					{
						break;
					}
				}
				if (ol->Mtu != NULL)
				{
					snprintf(tmp, sizeof(tmp), "Mtu=%u ", Endian32(ol->Mtu->Mtu));
					StrCat(info, sizeof(info), tmp);
				}

				Trim(info);

				if (IsEmptyStr(info) == false)
				{
					t->Token[14] = CopyStr(info);
				}
			}
			break;

			case L4_TCP:
				PacketLogTcp(t, pl, p, "v6");
				break;

			case L4_UDP:
				PacketLogUdp(t, pl, p, "v6");
				break;

			case L4_FRAGMENT:
				snprintf(tmp, sizeof(tmp), "IPv6_Fragment(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
				t->Token[6] = CopyStr(tmp);
				break;

			case L4_UNKNOWN:
				snprintf(tmp, sizeof(tmp), "IPv6(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
				t->Token[6] = CopyStr(tmp);
				break;
			}

			IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->SrcAddress);
			t->Token[8] = CopyStr(tmp);

			IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->DestAddress);
			t->Token[10] = CopyStr(tmp);

			break;

		case L3_UNKNOWN:
			snprintf(tmp, sizeof(tmp), "Proto=0x%04X", Endian16(p->MacHeader->Protocol));
			t->Token[6] = CopyStr(tmp);
			break;
		}

		if (p->PacketData != NULL)
		{
			char *data = Malloc(p->PacketSize * 2 + 1);
			BinToStr(data, p->PacketSize * 2 + 1, p->PacketData, p->PacketSize);
			t->Token[15] = data;
		}

		if (StrLen(pl->SrcPhysicalIP) != 0)
		{
			t->Token[16] = CopyStr(pl->SrcPhysicalIP);
		}
		if (StrLen(pl->DestPhysicalIP) != 0)
		{
			t->Token[17] = CopyStr(pl->DestPhysicalIP);
		}
	}
	else
	{
		t->Token[6] = CopyUniToUtf(_UU("LH_PACKET_LOG_NO_LOG_OSS"));
	}

	s = GenCsvLine(t);
	FreeToken(t);

	FreeClonePacket(p);

	if (pl->SrcSession != NULL)
	{
		Dec(pl->SrcSession->LoggingRecordCount);
		ReleaseSession(pl->SrcSession);
	}
	Free(pl);

	return s;
}

char *TcpFlagStr(UCHAR flag)
{
	char tmp[MAX_SIZE];
	StrCpy(tmp, sizeof(tmp), "");

	if (flag & TCP_FIN)
	{
		StrCat(tmp, sizeof(tmp), "FIN+");
	}

	if (flag & TCP_SYN)
	{
		StrCat(tmp, sizeof(tmp), "SYN+");
	}

	if (flag & TCP_RST)
	{
		StrCat(tmp, sizeof(tmp), "RST+");
	}

	if (flag & TCP_PSH)
	{
		StrCat(tmp, sizeof(tmp), "PSH+");
	}

	if (flag & TCP_ACK)
	{
		StrCat(tmp, sizeof(tmp), "ACK+");
	}

	if (flag & TCP_URG)
	{
		StrCat(tmp, sizeof(tmp), "URG+");
	}

	if (StrLen(tmp) >= 1)
	{
		if (tmp[StrLen(tmp) - 1] == '+')
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	return CopyStr(tmp);
}

char *PortStr(CEDAR *cedar, UINT port, bool udp)
{
	char tmp[MAX_SIZE];
	char *name;
	if (cedar == NULL)
	{
		return NULL;
	}

	name = GetSvcName(cedar, udp, port);

	if (name == NULL)
	{
		snprintf(tmp, sizeof(tmp), "%u", port);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "%s(%u)", name, port);
	}

	return CopyStr(tmp);
}

char *GenCsvLine(TOKEN_LIST *t)
{
	UINT i;
	BUF *b;
	char *ret;
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0; i < t->NumTokens; i++)
	{
		if (t->Token[i] != NULL)
		{
			ReplaceForCsv(t->Token[i]);
			if (StrLen(t->Token[i]) == 0)
			{
				WriteBuf(b, "-", 1);
			}
			else
			{
				WriteBuf(b, t->Token[i], StrLen(t->Token[i]));
			}
		}
		else
		{
			WriteBuf(b, "-", 1);
		}
		if (i != (t->NumTokens - 1))
		{
			WriteBuf(b, ",", 1);
		}
	}
	WriteBuf(b, "\0", 1);

	ret = (char *)b->Buf;

	Free(b);

	return ret;
}

void ReplaceForCsv(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	// A comma, a CR, an LF or another control character would split the record (a NUL ends the token)
	for (i = 0; i < len; i++)
	{
		if (str[i] == ',' || (UCHAR)str[i] < 0x20 || (UCHAR)str[i] == 0x7F)
		{
			str[i] = '_';
		}
	}
}

void SetLogSwitchType(LOG *g, UINT switch_type)
{
	if (g == NULL)
	{
		return;
	}

	LockLog(g);
	{
		g->SwitchType = switch_type;
	}
	UnlockLog(g);
}

static char *StringRecordParseProc(RECORD *rec)
{
	if (rec == NULL)
	{
		return NULL;
	}

	return (char *)rec->Data;
}

void InsertUnicodeRecord(LOG *g, wchar_t *unistr)
{
	char *str;
	UINT size;
	if (g == NULL || unistr == NULL)
	{
		return;
	}

	size = CalcUniToUtf8(unistr) + 32;
	str = ZeroMalloc(size);

	UniToUtf8((BYTE *)str, size, unistr);
	LogMapControlChars((UCHAR *)str, StrLen(str));

	// The record owns the buffer
	InsertRecord(g, str, StringRecordParseProc);
}

void InsertStringRecord(LOG *g, char *str)
{
	char *str_copy;
	if (g == NULL || str == NULL)
	{
		return;
	}

	str_copy = CopyStr(str);
	LogMapControlChars((UCHAR *)str_copy, StrLen(str_copy));

	InsertRecord(g, str_copy, StringRecordParseProc);
}

// Release a record that is not written: its parse procedure frees its data (a packet log record also
// gives back its session reference and its logging record count)
static void FreeRecord(RECORD *rec)
{
	Free(rec->ParseProc(rec));
	Free(rec);
}

void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc)
{
	RECORD *rec;
	bool dropped = false;
	if (g == NULL || data == NULL || proc == NULL)
	{
		return;
	}

	rec = ZeroMalloc(sizeof(RECORD));
	rec->Tick = Tick64();
	rec->ParseProc = proc;
	rec->Data = data;

	LockQueue(g->RecordQueue);
	{
		if (g->RecordQueue->num_item >= LOG_ENGINE_MAX_QUEUE)
		{
			// The writer is too far behind: the new record is dropped and counted
			g->NumDropped++;
			dropped = true;
		}
		else
		{
			InsertQueue(g->RecordQueue, rec);
		}
	}
	UnlockQueue(g->RecordQueue);

	if (dropped)
	{
		FreeRecord(rec);
	}

	Set(g->Event);
}

void LockLog(LOG *g)
{
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
}

void UnlockLog(LOG *g)
{
	if (g == NULL)
	{
		return;
	}

	Unlock(g->lock);
}

static void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type)
{
	UINT64 time;
	SYSTEMTIME st;

	if (str == NULL || g == NULL)
	{
		return;
	}

	if (g->CacheFlag)
	{
		if (g->LastTick == tick &&
		        g->LastSwitchType == switch_type)
		{
			StrCpy(str, size, g->LastStr);
			return;
		}
	}

	time = Tick64ToTime64(tick);
	UINT64ToSystem(&st, SystemToLocal64(time));

	switch (switch_type)
	{
	case LOG_SWITCH_SECOND:
		snprintf(str, size, "_%04u%02u%02u_%02u%02u%02u",
		         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		break;

	case LOG_SWITCH_MINUTE:
		snprintf(str, size, "_%04u%02u%02u_%02u%02u",
		         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		break;

	case LOG_SWITCH_HOUR:
		snprintf(str, size, "_%04u%02u%02u_%02u", st.wYear, st.wMonth, st.wDay, st.wHour);
		break;

	case LOG_SWITCH_DAY:
		snprintf(str, size, "_%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
		break;

	case LOG_SWITCH_MONTH:
		snprintf(str, size, "_%04u%02u", st.wYear, st.wMonth);
		break;

	default:
		StrCpy(str, size, "");
		break;
	}

	g->CacheFlag = true;
	g->LastTick = tick;
	g->LastSwitchType = switch_type;
	StrCpy(g->LastStr, sizeof(g->LastStr), str);
}

// Make the name of the log file of tick with the file number num from the directory and prefix of g (g->lock held).
// True when the date part of the name differs from old_datestr, which then takes the new one
static bool MakeLogFileName(LOG *g, char *name, UINT size, UINT64 tick, UINT switch_type, UINT num,
	char *old_datestr, UINT old_datestr_size)
{
	char tmp[MAX_SIZE];
	char tmp2[64];
	bool ret = false;
	if (g == NULL || name == NULL || old_datestr == NULL)
	{
		return false;
	}

	MakeLogFileNameStringFromTick(g, tmp, sizeof(tmp), tick, switch_type);

	if (num == 0)
	{
		tmp2[0] = 0;
	}
	else
	{
		UINT64 max_log_size = GetMaxLogSize();
		if (max_log_size == MAX_LOG_SIZE_DEFAULT)
		{
			snprintf(tmp2, sizeof(tmp2), "~%02u", num);
		}
		else
		{
			char tag[32];
			char c = '2';
			if (max_log_size >= 1000000000ULL)
			{
				c = '3';
			}
			else if (max_log_size >= 100000000ULL)
			{
				c = '4';
			}
			else if (max_log_size >= 10000000ULL)
			{
				c = '5';
			}
			else if (max_log_size >= 1000000ULL)
			{
				c = '6';
			}
			else if (max_log_size >= 100000ULL)
			{
				c = '7';
			}
			else if (max_log_size >= 10000ULL)
			{
				c = '8';
			}
			else if (max_log_size >= 1000ULL)
			{
				c = '9';
			}

			StrCpy(tag, sizeof(tag), "~%02u");
			tag[3] = c;

			snprintf(tmp2, sizeof(tmp2), tag, num);
		}
	}

	if (StrCmp(old_datestr, tmp) != 0)
	{
		ret = true;
		StrCpy(old_datestr, old_datestr_size, tmp);
	}

	snprintf(name, size, "%s%s%s%s%s.log", g->DirName,
	         StrLen(g->DirName) == 0 ? "" : "/",
	         g->Prefix, tmp, tmp2
	        );

	return ret;
}

void WaitLogFlush(LOG *g)
{
	if (g == NULL)
	{
		return;
	}

	while (true)
	{
		UINT num;
		LockQueue(g->RecordQueue);
		{
			num = g->RecordQueue->num_item;
		}
		UnlockQueue(g->RecordQueue);

		if (num == 0)
		{
			break;
		}

		Wait(g->FlushEvent, 100);
	}
}

void SetMaxLogSize(UINT64 size)
{
	if (size == 0)
	{
		size = MAX_LOG_SIZE_DEFAULT;
	}

	logger_max_log_size = size;
}

UINT64 GetMaxLogSize()
{
	UINT64 ret = logger_max_log_size;

	if (ret == 0)
	{
		ret = MAX_LOG_SIZE_DEFAULT;
	}

	return ret;
}

// Run the writer thread at the realtime priority (realtime) or the idle priority: the system call only on a change
static void LogWriterSetPriority(LOG_WRITER *w, bool realtime)
{
	if (w->Realtime == realtime)
	{
		return;
	}

	w->Realtime = realtime;

	if (realtime)
	{
		MsSetThreadPriorityRealtime();
	}
	else
	{
		MsSetThreadPriorityIdle();
	}
}

static void LogThread(THREAD *thread, void *param)
{
	LOG *g;
	LOG_WRITER w;
	bool flag = false;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	Zero(&w, sizeof(w));

	g = (LOG *)param;

	w.Buffer = NewBuf();


	MsSetThreadPriorityIdle();


	NoticeThreadInit(thread);

	while (true)
	{
		while (true)
		{
			if (! LogThreadWriteGeneral(g, &w))
			{
				break;
			}
		}

		if (g->Halt)
		{
			// When the stop flag is set, break only after every record is saved
			UINT num;

			if (flag == false)
			{
				LogWriterSetPriority(&w, true);
				flag = true;

				if (w.Io == NULL && w.Buffer->Size != 0)
				{
					// One more try at once to write what was buffered while no file could be opened
					w.RetryTick = 0;
					continue;
				}
			}

			LockQueue(g->RecordQueue);
			{
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

			if (num == 0 || w.Io == NULL)
			{
				break;
			}
		}
		else
		{
			Wait(g->Event, LogWriterWaitTime(&w));
		}
	}

	if (w.Io != NULL)
	{
		FileCloseEx(w.Io, true);
	}

	FreeBuf(w.Buffer);
}

// Milliseconds the writer thread waits for a new record: while records wait in the buffer for a file that
// could not be opened, only until the next try to open it
static UINT LogWriterWaitTime(LOG_WRITER *w)
{
	UINT64 now;

	if (w->Io != NULL || w->Buffer->Size == 0 || IsEmptyStr(w->FileName))
	{
		return 9821;
	}

	now = Tick64();
	if (w->RetryTick <= now)
	{
		return 1;
	}

	return (UINT)MIN(w->RetryTick - now, 9821);
}

// Open the log file file_name to append to it, or create it (and its directory). After a failed try the next
// one waits LOG_ENGINE_RETRY_MIN ms, then twice the last wait after each further failure, at most
// LOG_ENGINE_RETRY_MAX ms
static void LogOpenFile(LOG *g, LOG_WRITER *w, char *file_name)
{
	StrCpy(w->FileName, sizeof(w->FileName), file_name);

	w->Io = FileOpen(file_name, true);
	if (w->Io == NULL)
	{
		LockLog(g);
		{
			// MakeDir also fails on an existing directory: the create tells whether the file can be written
			MakeDir(g->DirName);

			Win32SetFolderCompress(g->DirName, true);
		}
		UnlockLog(g);
		w->Io = FileCreate(file_name);
		g->CurrentFilePointer = 0;
	}
	else
	{
		g->CurrentFilePointer = FileSize64(w->Io);
		FileSeek(w->Io, SEEK_END, 0);
	}

	if (w->Io != NULL)
	{
		w->RetryWait = 0;
	}
	else
	{
		w->RetryWait = (w->RetryWait == 0 ? LOG_ENGINE_RETRY_MIN : MIN(w->RetryWait * 2, LOG_ENGINE_RETRY_MAX));
		w->RetryTick = Tick64() + (UINT64)w->RetryWait;
	}
}

// Put the line that reports the dropped records into the buffer, in front of the next record (a file is open)
static void LogWriterAddDropped(LOG *g, LOG_WRITER *w)
{
	UINT64 num;
	RECORD r;
	char tmp[MAX_SIZE];

	LockQueue(g->RecordQueue);
	{
		num = g->NumDropped;
		g->NumDropped = 0;
	}
	UnlockQueue(g->RecordQueue);

	if (num == 0)
	{
		return;
	}

	Format(tmp, sizeof(tmp), LOG_DROPPED_RECORDS_FORMAT, num);

	Zero(&r, sizeof(r));
	r.Tick = Tick64();
	r.ParseProc = StringRecordParseProc;
	r.Data = CopyStr(tmp);

	WriteRecordToBuffer(w->Buffer, &r);
}

// No file is open: keep the record in the buffer while the buffer stays within the smaller of
// LOG_ENGINE_BUFFER_NO_FILE_MAX and the maximum log size, drop and count it otherwise. Either way its data is released
static void LogWriterKeep(LOG *g, LOG_WRITER *w, RECORD *rec)
{
	BUF *b = NewBuf();

	WriteRecordToBuffer(b, rec);

	if ((UINT64)w->Buffer->Size + (UINT64)b->Size <= MIN((UINT64)LOG_ENGINE_BUFFER_NO_FILE_MAX, GetMaxLogSize()))
	{
		WriteBuf(w->Buffer, b->Buf, b->Size);
	}
	else
	{
		LockQueue(g->RecordQueue);
		{
			g->NumDropped++;
		}
		UnlockQueue(g->RecordQueue);
	}

	FreeBuf(b);
}

// Write the buffer to the open file and empty it. A buffer that would take the file over the maximum log size
// is not written: with next_number set that moves on, once, to the next log file number. A failed write closes
// the file and drops the buffer
static void LogFlushBuffer(LOG *g, LOG_WRITER *w, bool next_number)
{
	BUF *buffer = w->Buffer;

	if (w->Io == NULL || buffer->Size == 0)
	{
		return;
	}

	if ((g->CurrentFilePointer + (UINT64)buffer->Size) > GetMaxLogSize())
	{
		if (next_number && g->log_number_incremented == false)
		{
			g->CurrentLogNumber++;
			g->log_number_incremented = true;
		}

		return;
	}

	if (FileWrite(w->Io, buffer->Buf, buffer->Size) == false)
	{
		FileCloseEx(w->Io, true);
		ClearBuf(buffer);
		w->Io = NULL;
	}
	else
	{
		g->CurrentFilePointer += (UINT64)buffer->Size;
		ClearBuf(buffer);
	}
}

static bool LogThreadWriteGeneral(LOG *log_object, LOG_WRITER *w)
{
	RECORD *rec;
	char file_name[MAX_SIZE];
	UINT num;
	bool log_date_changed;
	BUF *buffer = w->Buffer;

	LockQueue(log_object->RecordQueue);
	{
		rec = GetNext(log_object->RecordQueue);
		num = log_object->RecordQueue->num_item;
	}
	UnlockQueue(log_object->RecordQueue);

	if (num >= LOG_ENGINE_SAVE_START_CACHE_COUNT)
	{
		LogWriterSetPriority(w, true);
	}

	if (num < (LOG_ENGINE_SAVE_START_CACHE_COUNT / 2))
	{
		LogWriterSetPriority(w, false);
	}

	if (buffer->Size > GetMaxLogSize())
	{
		ClearBuf(buffer);
	}

	if (rec == NULL && w->Io == NULL && buffer->Size != 0 && IsEmptyStr(w->FileName) == false &&
		Tick64() >= w->RetryTick)
	{
		// No new record, but buffered records wait for a file that could not be opened: try it again
		char last_name[MAX_SIZE];

		StrCpy(last_name, sizeof(last_name), w->FileName);
		LogOpenFile(log_object, w, last_name);
		log_object->log_number_incremented = false;

		if (w->Io != NULL)
		{
			LogWriterAddDropped(log_object, w);
		}
	}

	if (buffer->Size >= LOG_ENGINE_BUFFER_CACHE_SIZE_MAX)
	{
		LogFlushBuffer(log_object, w, true);
	}

	if (rec == NULL)
	{
		LogFlushBuffer(log_object, w, true);

		Set(log_object->FlushEvent);
		return false;
	}

	LockLog(log_object);
	{
		log_date_changed = MakeLogFileName(log_object, file_name, sizeof(file_name),
		                                   rec->Tick, log_object->SwitchType, log_object->CurrentLogNumber,
		                                   w->DateName, sizeof(w->DateName));

		if (log_date_changed)
		{
			UINT i;

			log_object->CurrentLogNumber = 0;
			MakeLogFileName(log_object, file_name, sizeof(file_name),
			                rec->Tick, log_object->SwitchType, 0, w->DateName, sizeof(w->DateName));
			for (i = 0;; i++)
			{
				char tmp[MAX_SIZE];
				MakeLogFileName(log_object, tmp, sizeof(tmp),
				                rec->Tick, log_object->SwitchType, i, w->DateName, sizeof(w->DateName));

				if (IsFileExists(tmp) == false)
				{
					break;
				}
				StrCpy(file_name, sizeof(file_name), tmp);
				log_object->CurrentLogNumber = i;
			}
		}
	}
	UnlockLog(log_object);

	if (w->Io != NULL)
	{
		if (StrCmp(w->FileName, file_name) != 0)
		{
			// Switching to another log file: flush the buffer and close the current file first
			if (log_date_changed)
			{
				LogFlushBuffer(log_object, w, false);
			}
			FileCloseEx(w->Io, true);

			log_object->log_number_incremented = false;

			LogOpenFile(log_object, w, file_name);
		}
	}
	else
	{
		if (Tick64() >= w->RetryTick)
		{
			LogOpenFile(log_object, w, file_name);
		}
		else
		{
			// Before the next try: a later record, or the writer thread once the wait is over, opens this file
			StrCpy(w->FileName, sizeof(w->FileName), file_name);
		}

		log_object->log_number_incremented = false;
	}

	if (w->Io != NULL)
	{
		LogWriterAddDropped(log_object, w);
		WriteRecordToBuffer(buffer, rec);
	}
	else
	{
		LogWriterKeep(log_object, w, rec);
	}

	Free(rec);

	return true;
}

void WriteRecordToBuffer(BUF *b, RECORD *r)
{
	UINT64 time;
	char time_str[MAX_SIZE];
	char date_str[MAX_SIZE];
	char *s;
	if (b == NULL || r == NULL)
	{
		return;
	}

	time = SystemToLocal64(Tick64ToTime64(r->Tick));

	GetDateStr64(date_str, sizeof(date_str), time);
	GetTimeStrMilli64(time_str, sizeof(time_str), time);

	if (r->ParseProc != PacketLogParseProc)
	{
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, " ", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, " ", 1);
	}
	else
	{
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, ",", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, ",", 1);
	}

	s = r->ParseProc(r);
	WriteBuf(b, s, StrLen(s));
	Free(s);

	WriteBuf(b, "\r\n", 2);
}

void FreeLog(LOG *g)
{
	RECORD *rec;
	if (g == NULL)
	{
		return;
	}

	g->Halt = true;
	Set(g->Event);

	WaitThread(g->Thread, INFINITE);
	ReleaseThread(g->Thread);

	DeleteLock(g->lock);
	Free(g->DirName);
	Free(g->Prefix);

	// Free any leftover records (there should be none)
	while (rec = GetNext(g->RecordQueue))
	{
		FreeRecord(rec);
	}
	ReleaseQueue(g->RecordQueue);

	ReleaseEvent(g->Event);
	ReleaseEvent(g->FlushEvent);

	Free(g);
}

LOG *NewLog(char *dir, char *prefix, UINT switch_type)
{
	LOG *g;

	g = ZeroMalloc(sizeof(LOG));
	g->lock = NewLock();
	g->DirName = CopyStr(dir == NULL ? "" : dir);
	g->Prefix = CopyStr(prefix == NULL ? "log" : prefix);
	g->SwitchType = switch_type;
	g->RecordQueue = NewQueue();
	g->Event = NewEvent();
	g->FlushEvent = NewEvent();

	g->Thread = NewThread(LogThread, g);

	WaitThreadInit(g->Thread);

	return g;
}

