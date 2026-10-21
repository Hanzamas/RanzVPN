// PacketLog.h
// Header of PacketLog.c

#ifndef PACKETLOG_H
#define PACKETLOG_H

#include "Cedar.h"
#include "LogWriter.h"

// Queued packet log records of one source session from which its thread waits for the log writer (PacketLogWait)
#define PACKET_LOG_WAIT_RECORDS 30000

struct PACKET_LOG {
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool WritePhysicalIP;
	char SrcPhysicalIP[64];
	char DestPhysicalIP[64];
	SESSION *SrcSession;
};

bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now, bool *wait);
void PacketLogWait(SESSION *src_session);
char *PacketLogParseProc(RECORD *rec);
void PacketLogFreeProc(void *data);
UINT CalcPacketLoggingLevel(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void MakeSafeLogStr(char *str);
void AddLogBufToStr(BUF *b, char *name, char *value);

#endif
