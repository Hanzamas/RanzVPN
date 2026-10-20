#ifndef PROXY_H
#define PROXY_H

#include "HTTP.h"
#include "Network.h"

// Proxy types (the ProxyType of a client option)
#define	PROXY_DIRECT			0
#define	PROXY_HTTP				1
#define	PROXY_SOCKS				2
#define	PROXY_SOCKS5			3

#define PROXY_CONNECTION_TIMEOUT	(4 * 1000)

#define PROXY_MAX_USERNAME_LEN		255
#define PROXY_MAX_PASSWORD_LEN		255

#define PROXY_ERROR_SUCCESS			0
#define PROXY_ERROR_GENERIC			1
#define PROXY_ERROR_PARAMETER		2
#define PROXY_ERROR_CANCELED		3
#define PROXY_ERROR_CONNECTION		4
#define PROXY_ERROR_DISCONNECTED	5
#define PROXY_ERROR_VERSION			6
#define PROXY_ERROR_AUTHENTICATION	7
#define PROXY_ERROR_TARGET			8

struct PROXY_PARAM_IN
{
	char Hostname[MAX_HOST_NAME_LEN + 1];
	USHORT Port;
	char TargetHostname[MAX_HOST_NAME_LEN + 1];
	USHORT TargetPort;
	char Username[PROXY_MAX_USERNAME_LEN + 1];
	char Password[PROXY_MAX_PASSWORD_LEN + 1];
	UINT Timeout;
	char HttpCustomHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];
	char HttpUserAgent[HTTP_HEADER_USER_AGENT_MAX_SIZE + 1];
	IP   *BindLocalIP;
	UINT BindLocalPort;
};

struct PROXY_PARAM_OUT
{
	SOCK *Sock;
	IP ResolvedIp;
};

// Connects to the proxy in->Hostname:in->Port and through it to in->TargetHostname:in->TargetPort.
// proxy_type is PROXY_HTTP, PROXY_SOCKS or PROXY_SOCKS5. Returns PROXY_ERROR_SUCCESS with the
// socket in out->Sock, or a PROXY_ERROR_* code (PROXY_ERROR_PARAMETER for any other proxy_type).
UINT ProxyConnect(UINT proxy_type, PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);

#endif
