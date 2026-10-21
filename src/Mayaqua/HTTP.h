#ifndef HTTP_H
#define HTTP_H

#include "MayaType.h"

#define DEFAULT_USER_AGENT              "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
#define HTTP_CONTENT_TYPE               "text/html; charset=iso-8859-1"
#define HTTP_CONTENT_TYPE2              "application/octet-stream"
#define HTTP_CONTENT_TYPE3              "image/jpeg"
#define HTTP_KEEP_ALIVE                 "timeout=15; max=19"
#define HTTP_VPN_TARGET                 "/vpnsvc/vpn.cgi"
#define HTTP_VPN_TARGET2                "/vpnsvc/connect.cgi"
#define HTTP_VPN_TARGET_POSTDATA        "VPNCONNECT"
#define HTTP_CUSTOM_HEADER_MAX_SIZE     1024
#define HTTP_HEADER_LINE_MAX_SIZE       4096
#define HTTP_HEADER_MAX_LINES           128
#define HTTP_HEADER_USER_AGENT_MAX_SIZE 512
#define HTTP_PACK_MAX_SIZE              65536

struct HTTP_VALUE {
	char *Name;
	char *Data;
};

struct HTTP_HEADER {
	char *Method;
	char *Target;
	char *Version;
	LIST *ValueList;
};

// One header line for HttpParseHeaderLines(), as RecvLine() returns it; NULL when no line can be read
typedef char *(HTTP_LINE_SOURCE)(void *param, UINT max_size);

HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version);
void FreeHttpHeader(HTTP_HEADER *header);
HTTP_VALUE *NewHttpValue(char *name, char *data);
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name);
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value);
bool AddHttpValueStr(HTTP_HEADER *header, char *string);
UINT GetContentLength(HTTP_HEADER *header);
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size);
char *HttpHeaderToStr(HTTP_HEADER *header);
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header);
char *HttpBufLineSource(void *param, UINT max_size);
HTTP_HEADER *HttpParseHeaderLines(HTTP_LINE_SOURCE *source, void *param);
HTTP_HEADER *RecvHttpHeader(SOCK *s);
bool HttpClientSend(SOCK *s, PACK *p);
PACK *HttpClientRecv(SOCK *s);
PACK *HttpClientRecvEx(SOCK *s, UINT max_data_size);
bool HttpServerSend(SOCK *s, PACK *p);
PACK *HttpServerRecv(SOCK *s);
bool HttpSendDecoyPage(SOCK *s, UINT code, HTTP_HEADER *request);

#endif
