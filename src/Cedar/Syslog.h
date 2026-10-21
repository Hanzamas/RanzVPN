// Syslog.h
// Header of Syslog.c

#ifndef SYSLOG_H
#define SYSLOG_H

#include "Mayaqua/Network.h"

typedef struct SLOG SLOG;

#define SYSLOG_PORT                514
#define SYSLOG_POLL_IP_INTERVAL    (UINT64)(3600 * 1000)
#define SYSLOG_POLL_IP_INTERVAL_NG (UINT64)(60 * 1000)

struct SLOG {
	LOCK *lock;
	SOCK *Udp;
	IP DestIp;
	UINT DestPort;
	char HostName[MAX_HOST_NAME_LEN + 1];
	UINT64 NextPollIp;
};

SLOG *NewSysLog(char *hostname, UINT port, IP *ip);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);

#endif
