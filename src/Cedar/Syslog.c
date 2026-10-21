// Syslog.c
// Syslog sender: each log line as one UDP datagram to the syslog server

#include "Syslog.h"

#include "LogWriter.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Str.h"

// Send one syslog datagram to the current address (g->lock held)
static void SendSysLogLocked(SLOG *g, const UCHAR *buf, UINT size) {
	if (g->DestPort != 0 && IsZeroIP(&g->DestIp) == false) {
		SendTo(g->Udp, &g->DestIp, g->DestPort, buf, size);
	}
}

void SendSysLog(SLOG *g, wchar_t *str) {
	char hostname[MAX_HOST_NAME_LEN + 1];
	bool poll = false;
	if (g == NULL || str == NULL) {
		return;
	}

	UINT buf_size = CalcUniToUtf8(str);
	UCHAR *buf = ZeroMalloc(buf_size);
	UniToUtf8(buf, buf_size, str);
	LogMapControlChars(buf, buf_size);

	if (buf_size >= 1024) {
		buf_size = 1023;
	}

	Lock(g->lock);
	{
		if (Tick64() >= g->NextPollIp) {
			// This sender resolves the host again; the others use the current address meanwhile
			g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
			StrCpy(hostname, sizeof(hostname), g->HostName);
			poll = true;
		} else {
			SendSysLogLocked(g, buf, buf_size);
		}
	}
	Unlock(g->lock);

	if (poll) {
		// The resolve can take seconds: it runs outside the lock, which every logging thread takes
		IP ip;
		bool resolved = GetIP(&ip, hostname);

		Lock(g->lock);
		{
			// A SetSysLog with another host meanwhile has resolved that host already
			if (StrCmp(g->HostName, hostname) == 0) {
				if (resolved) {
					g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL;
					Copy(&g->DestIp, &ip, sizeof(IP));
				} else {
					g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
				}
			}

			SendSysLogLocked(g, buf, buf_size);
		}
		Unlock(g->lock);
	}

	Free(buf);
}

void FreeSysLog(SLOG *g) {
	if (g == NULL) {
		return;
	}

	DeleteLock(g->lock);
	ReleaseSock(g->Udp);
	Free(g);
}

void SetSysLog(SLOG *g, char *hostname, UINT port) {
	IP ip;
	if (g == NULL) {
		return;
	}
	if (port == 0) {
		port = SYSLOG_PORT;
	}

	if (hostname == NULL) {
		hostname = "";
	}

	Zero(&ip, sizeof(IP));
	GetIP(&ip, hostname);

	Lock(g->lock);
	{
		Copy(&g->DestIp, &ip, sizeof(IP));
		g->DestPort = port;
		StrCpy(g->HostName, sizeof(g->HostName), hostname);
		g->NextPollIp = Tick64() + (IsZeroIP(&ip) ? SYSLOG_POLL_IP_INTERVAL_NG : SYSLOG_POLL_IP_INTERVAL);
	}
	Unlock(g->lock);
}

SLOG *NewSysLog(char *hostname, UINT port, IP *ip) {
	SLOG *g = ZeroMalloc(sizeof(SLOG));

	g->lock = NewLock();
	// The socket is IPv4: NewUDPEx2 refuses an address that is not IPv4, and an unset ListenIP is the all-zero
	// IPv6 address, so only an IPv4 address is bound; otherwise the socket binds to any address
	g->Udp = NewUDPEx2(0, false, (ip != NULL && IsIP4(ip)) ? ip : NULL);

	SetSysLog(g, hostname, port);

	return g;
}
