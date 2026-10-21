// PktSniff.c
// Layer 7 sniffing for the packet log: the HTTP request and the HTTPS server name (SNI) of the first data segment of a TCP connection

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"
#include "TcpIpInternal.h"

HTTPLOG *ParseHttpsAccessLog(PKT *pkt) {
	HTTPLOG h;
	char sni[MAX_PATH];
	if (pkt == NULL)
		return NULL;

	if (GetSniNameFromSslPacket(pkt->Payload, pkt->PayloadSize, sni, sizeof(sni)) == false)
		return NULL;

	Zero(&h, sizeof(h));

	StrCpy(h.Method, sizeof(h.Method), "SSL_Connect");
	StrCpy(h.Hostname, sizeof(h.Hostname), sni);
	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);
	StrCpy(h.Path, sizeof(h.Path), "/");
	h.IsSsl = true;

	return Clone(&h, sizeof(h));
}

HTTPLOG *ParseHttpAccessLog(PKT *pkt) {
	HTTPLOG h;
	bool ok = false;
	if (pkt == NULL)
		return NULL;

	UCHAR *buf = pkt->Payload;
	UINT size = pkt->PayloadSize;

	if (size <= 5)
		return NULL;

	if (CmpCaseIgnore(buf, "GET ", 4) != 0 &&
	    CmpCaseIgnore(buf, "HEAD ", 5) != 0 &&
	    CmpCaseIgnore(buf, "POST ", 5) != 0)
		return NULL;

	Zero(&h, sizeof(h));

	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);

	BUF *b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	char *line1 = CfgReadNextLine(b);

	if (line1 != NULL) {
		TOKEN_LIST *tokens = ParseToken(line1, " \t");
		if (tokens != NULL) {
			if (tokens->NumTokens == 3) {
				StrCpy(h.Method, sizeof(h.Method), tokens->Token[0]);
				Trim(h.Method);

				StrCpy(h.Path, sizeof(h.Path), tokens->Token[1]);
				Trim(h.Path);

				StrCpy(h.Protocol, sizeof(h.Protocol), tokens->Token[2]);
				Trim(h.Protocol);

				StrUpper(h.Method);

				while (true) {
					char *line = CfgReadNextLine(b);

					if (line == NULL)
						break;

					UINT i = SearchStr(line, ":", 0);
					if (i != INFINITE && i < (MAX_SIZE / 2)) {
						char name[MAX_SIZE];
						char value[MAX_SIZE];

						StrCpy(name, sizeof(name), line);
						name[i] = 0;
						Trim(name);

						StrCpy(value, sizeof(value), line + i + 1);
						Trim(value);

						if (StrCmpi(name, "host") == 0)
							StrCpy(h.Hostname, sizeof(h.Hostname), value);
						else if (StrCmpi(name, "referer") == 0)
							StrCpy(h.Referer, sizeof(h.Referer), value);
						else if (StrCmpi(name, "user-agent") == 0)
							StrCpy(h.UserAgent, sizeof(h.UserAgent), value);
					}

					Free(line);
				}

				if (IsEmptyStr(h.Hostname) == false)
					ok = true;
			}
			FreeToken(tokens);
		}
	}

	Free(line1);
	FreeBuf(b);

	if (ok)
		return Clone(&h, sizeof(h));
	else
		return NULL;
}
