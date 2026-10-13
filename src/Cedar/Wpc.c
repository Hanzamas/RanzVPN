// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Wpc.c
// RPC over HTTP

#include "Wpc.h"

#include "Command.h"
#include "Protocol.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Encoding.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Proxy.h"
#include "Mayaqua/Str.h"

#include <winhttp.h>

// Generate a entry name
void WpcFillEntryName(char *dst, char *name)
{
	UINT i, len;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), name);
	StrUpper(tmp);
	len = StrLen(tmp);

	for (i = 0;i < WPC_DATA_ENTRY_SIZE;i++)
	{
		dst[i] = ' ';
	}

	if (len <= WPC_DATA_ENTRY_SIZE)
	{
		Copy(dst, tmp, len);
	}
	else
	{
		Copy(dst, tmp, WPC_DATA_ENTRY_SIZE);
	}
}


// Add the data entry
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size)
{
	char entry_name[WPC_DATA_ENTRY_SIZE];
	char size_str[11];
	// Validate arguments
	if (b == NULL || name == NULL || (data == NULL && size != 0))
	{
		return;
	}

	WpcFillEntryName(entry_name, name);
	WriteBuf(b, entry_name, WPC_DATA_ENTRY_SIZE);

	Format(size_str, sizeof(size_str), "%010u", size);
	WriteBuf(b, size_str, 10);

	WriteBuf(b, data, size);
}

// Socket connection
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout)
{
	return WpcSockConnectEx(param, error_code, timeout, NULL);
}
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel)
{
	SOCK *sock;
	UINT ret;
	// Validate arguments
	if (param == NULL)
	{
		return NULL;
	}

	if (error_code == NULL)
	{
		error_code = &ret;
	}

	if (param->ProxyType == PROXY_DIRECT)
	{
		sock = TcpConnectEx3(param->HostName, param->Port, timeout, cancel, NULL, NULL);
		*error_code = (sock != NULL ? ERR_NO_ERROR : ERR_CONNECT_FAILED);
		return sock;
	}
	else
	{
		PROXY_PARAM_OUT out;
		PROXY_PARAM_IN in;
		UINT ret;

		Zero(&in, sizeof(in));

		in.Timeout = timeout;

		StrCpy(in.TargetHostname, sizeof(in.TargetHostname), param->HostName);
		in.TargetPort = param->Port;

		StrCpy(in.Hostname, sizeof(in.Hostname), param->ProxyHostName);
		in.Port = param->ProxyPort;

		StrCpy(in.Username, sizeof(in.Username), param->ProxyUsername);
		StrCpy(in.Password, sizeof(in.Password), param->ProxyPassword);

		StrCpy(in.HttpCustomHeader, sizeof(in.HttpCustomHeader), param->CustomHttpHeader);

		switch (param->ProxyType)
		{
		case PROXY_HTTP:
			ret = ProxyHttpConnect(&out, &in, cancel);
			break;
		case PROXY_SOCKS:
			ret = ProxySocks4Connect(&out, &in, cancel);
			break;
		case PROXY_SOCKS5:
			ret = ProxySocks5Connect(&out, &in, cancel);
			break;
		default:
			*error_code = ERR_INTERNAL_ERROR;
			Debug("WpcSockConnect(): Unknown proxy type: %u!\n", param->ProxyType);
			return NULL;
		}

		*error_code = ProxyCodeToCedar(ret);

		if (*error_code != ERR_NO_ERROR)
		{
			Debug("ClientConnectGetSocket(): Connection via proxy server failed with error %u\n", ret);
			return NULL;
		}

		return out.Sock;
	}
}

// Set a DWORD option of a WinHTTP handle
static bool WpcWinHttpSetDword(HINTERNET h, DWORD option, DWORD value)
{
	return (WinHttpSetOption(h, option, &value, sizeof(value)) != FALSE);
}

// Error code of a failed WinHttpSendRequest: the code the socket client gave for the same failure
static UINT WpcWinHttpSendError(DWORD err)
{
	switch (err)
	{
	case ERROR_WINHTTP_NAME_NOT_RESOLVED:
	case ERROR_WINHTTP_CANNOT_CONNECT:
	case ERROR_WINHTTP_TIMEOUT:
		// Name not resolved, or no connection within the timeout
		return ERR_CONNECT_FAILED;

	case ERROR_WINHTTP_SECURE_FAILURE:
		// TLS handshake failed
		return ERR_PROTOCOL_ERROR;

	default:
		// The request could not be sent
		return ERR_DISCONNECTED;
	}
}

// Send a GET request on a WinHTTP request handle and receive the body, as the socket client did
static BUF *WpcWinHttpGet(HINTERNET request, bool secure, UINT timeout_connect, UINT timeout_comm, UINT *error_code,
						  UINT max_recv_size)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	wchar_t *headers;
	DWORD size;
	DWORD http_error_code = 0;
	UINT content_len = 0;
	void *socket_buffer;
	UINT socket_buffer_size = WPC_RECV_BUF_SIZE;
	BUF *recv_buf;
	bool ok;

	// No redirect, cookie, authentication or default credentials; no total time limit on the response header
	ok = WpcWinHttpSetDword(request, WINHTTP_OPTION_DISABLE_FEATURE,
		WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION) &&
		WpcWinHttpSetDword(request, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) &&
		WpcWinHttpSetDword(request, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, INFINITE);

	if (ok && secure)
	{
		// No check of the server certificate and no client certificate, as StartSSLEx(s, NULL, NULL, 0, NULL)
		ok = WpcWinHttpSetDword(request, WINHTTP_OPTION_SECURITY_FLAGS,
			SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
			SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE) &&
			(WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0) != FALSE);
	}

	if (ok)
	{
		// Request headers of the socket client that WinHTTP does not add itself (it sends Host, User-Agent and
		// Connection: Keep-Alive)
		Format(str, sizeof(str), "Keep-Alive: %s\r\nAccept-Language: ja\r\nPragma: no-cache\r\nCache-Control: no-cache",
			HTTP_KEEP_ALIVE);
		headers = CopyStrToUni(str);
		ok = (WinHttpAddRequestHeaders(request, headers, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD) != FALSE);
		Free(headers);
	}

	if (ok == false)
	{
		*error_code = ERR_INTERNAL_ERROR;
		return NULL;
	}

	// Send
	if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE)
	{
		*error_code = WpcWinHttpSendError(GetLastError());
		return NULL;
	}

	// From here on timeout_comm applies to each send and receive, as SetTimeout set it on the socket. Should
	// WinHTTP refuse the change, an https request keeps the TLS handshake timeout.
	WinHttpSetTimeouts(request, (int)DNS_RESOLVE_DEFAULT_TIMEOUT, (int)timeout_connect, (int)timeout_comm,
		(int)timeout_comm);

	// Receive
	if (WinHttpReceiveResponse(request, NULL) == FALSE)
	{
		*error_code = ERR_DISCONNECTED;
		return NULL;
	}

	// Only an HTTP/1.x status line counts. WinHTTP has already skipped interim 1xx responses.
	size = sizeof(tmp);
	if (WinHttpQueryHeaders(request, WINHTTP_QUERY_VERSION, WINHTTP_HEADER_NAME_BY_INDEX, tmp, &size,
		WINHTTP_NO_HEADER_INDEX))
	{
		UniToStr(str, sizeof(str), tmp);

		if (StrLen(str) == 8 && Cmp(str, "HTTP/1.", 7) == 0)
		{
			size = sizeof(http_error_code);
			if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX, &http_error_code, &size, WINHTTP_NO_HEADER_INDEX) == FALSE)
			{
				http_error_code = 0;
			}
		}
	}

	*error_code = ERR_NO_ERROR;

	switch (http_error_code)
	{
	case 401:
	case 407:
		// Proxy authentication error
		*error_code = ERR_PROXY_AUTH_FAILED;
		break;

	case 404:
		// 404 File Not Found
		*error_code = ERR_OBJECT_NOT_FOUND;
		break;

	case 200:
		// Success
		break;

	default:
		// Protocol error
		*error_code = ERR_PROTOCOL_ERROR;
		break;
	}

	if (*error_code != ERR_NO_ERROR)
	{
		// An error has occured
		return NULL;
	}

	// Get the length of the content as GetContentLength does: ToInt of the first Content-Length value, 0 without
	// one. Without it no body is read, chunked or not.
	size = sizeof(tmp);
	if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, tmp, &size,
		WINHTTP_NO_HEADER_INDEX))
	{
		UniToStr(str, sizeof(str), tmp);
		content_len = ToInt(str);
	}
	if (max_recv_size != 0)
	{
		content_len = MIN(content_len, max_recv_size);
	}

	socket_buffer = Malloc(socket_buffer_size);

	// Receive the content
	recv_buf = NewBuf();

	while (true)
	{
		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);

		if (recvsize == 0)
		{
			break;
		}

		size = 0;
		if (WinHttpReadData(request, socket_buffer, recvsize, &size) == FALSE || size == 0)
		{
			// Disconnected
			*error_code = ERR_DISCONNECTED;
			FreeBuf(recv_buf);
			recv_buf = NULL;
			break;
		}

		WriteBuf(recv_buf, socket_buffer, size);
	}

	Free(socket_buffer);

	if (recv_buf != NULL)
	{
		SeekBuf(recv_buf, 0, 0);
	}

	return recv_buf;
}

// Handle the HTTP request
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size)
{
	return HttpRequestEx2(data, setting, timeout_connect, timeout_comm, error_code,
		check_ssl_trust, post_data, recv_callback, recv_callback_param, sha1_cert_hash,
		cancel, max_recv_size, NULL, NULL);
}
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	return HttpRequestEx3(data, setting, timeout_connect, timeout_comm, error_code, check_ssl_trust,
		post_data, recv_callback, recv_callback_param, sha1_cert_hash, (sha1_cert_hash == NULL ? 0 : 1),
		cancel, max_recv_size, header_name, header_value);
}
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value)
{
	HINTERNET session;
	HINTERNET connect = NULL;
	HINTERNET request = NULL;
	wchar_t *str;
	UINT io_timeout;
	BUF *recv_buf = NULL;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}
	if (error_code == NULL)
	{
		static UINT ret = 0;
		error_code = &ret;
	}
	if (timeout_connect == 0)
	{
		timeout_connect = TIMEOUT_TCP_PORT_CHECK;
	}
	if (timeout_comm == 0)
	{
		timeout_comm = WPC_TIMEOUT;
	}

	// WinHTTP serves the request of DownloadCert, the only caller: a GET without proxy, extra header, referer,
	// SNI string, certificate hash, receive callback or cancel flag
	if ((setting != NULL && setting->ProxyType != PROXY_DIRECT) || StrCmpi(data->Method, WPC_HTTP_GET_NAME) != 0 ||
		(IsEmptyStr(header_name) == false && IsEmptyStr(header_value) == false) ||
		IsEmptyStr(data->Referer) == false ||
		(IsEmptyStr(data->AdditionalHeaderName) == false && IsEmptyStr(data->AdditionalHeaderValue) == false) ||
		(data->Secure && IsEmptyStr(data->SniString) == false) ||
		(sha1_cert_hash != NULL && num_hashes != 0) || recv_callback != NULL || cancel != NULL)
	{
		*error_code = ERR_NOT_SUPPORTED;
		return NULL;
	}

	// TcpConnectEx3 refused a port outside 1 to 65535; INTERNET_PORT would truncate it
	if (data->Port == 0 || data->Port >= 65536)
	{
		*error_code = ERR_CONNECT_FAILED;
		return NULL;
	}

	// No proxy: WinHTTP does not read the system or WPAD proxy settings either
	str = CopyStrToUni(WPC_USER_AGENT);
	session = WinHttpOpen(str, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	Free(str);

	if (session == NULL)
	{
		*error_code = ERR_INTERNAL_ERROR;
		return NULL;
	}

	// Timeouts of the socket client until the request is sent: the DnsResolveEx default, the TCP connect timeout,
	// and on each send and receive the TLS handshake timeout of StartSSLEx for https
	io_timeout = (data->Secure ? TIMEOUT_SSL_CONNECT : timeout_comm);

	if (WinHttpSetTimeouts(session, (int)DNS_RESOLVE_DEFAULT_TIMEOUT, (int)timeout_connect, (int)io_timeout,
		(int)io_timeout))
	{
		str = CopyStrToUni(data->HostName);
		connect = WinHttpConnect(session, str, (INTERNET_PORT)data->Port, 0);
		Free(str);
	}

	if (connect != NULL)
	{
		// The target goes out as written in the URL, unescaped like the socket client sent it
		str = CopyStrToUni(data->Target);
		request = WinHttpOpenRequest(connect, L"GET", str, L"HTTP/1.1", WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_ESCAPE_DISABLE_QUERY | (data->Secure ? WINHTTP_FLAG_SECURE : 0));
		Free(str);
	}

	if (request != NULL)
	{
		recv_buf = WpcWinHttpGet(request, data->Secure, timeout_connect, timeout_comm, error_code, max_recv_size);
		WinHttpCloseHandle(request);
	}
	else
	{
		*error_code = ERR_INTERNAL_ERROR;
	}

	if (connect != NULL)
	{
		WinHttpCloseHandle(connect);
	}
	WinHttpCloseHandle(session);

	// Transmission
	return recv_buf;
}

// Generate the URL
void CreateUrl(char *url, UINT url_size, URL_DATA *data)
{
	char *protocol;
	// Validate arguments
	if (url == NULL || data == NULL)
	{
		return;
	}

	if (data->Secure == false)
	{
		protocol = "http://";
	}
	else
	{
		protocol = "https://";
	}

	Format(url, url_size, "%s%s%s", protocol, data->HeaderHostName, data->Target);
}


// Parse the URL
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer)
{
	char tmp[MAX_SIZE * 3];
	char server_port[MAX_HOST_NAME_LEN + 16];
	char *s = NULL;
	char *host;
	UINT port;
	UINT i;
	// Validate arguments
	if (data == NULL || str == NULL)
	{
		return false;
	}

	Zero(data, sizeof(URL_DATA));

	if (is_post)
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_POST_NAME);
	}
	else
	{
		StrCpy(data->Method, sizeof(data->Method), WPC_HTTP_GET_NAME);
	}

	if (referrer != NULL)
	{
		StrCpy(data->Referer, sizeof(data->Referer), referrer);
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	// Determine the protocol
	if (StartWith(tmp, "http://"))
	{
		data->Secure = false;
		s = &tmp[7];
	}
	else if (StartWith(tmp, "https://"))
	{
		data->Secure = true;
		s = &tmp[8];
	}
	else
	{
		if (SearchStrEx(tmp, "://", 0, false) != INFINITE)
		{
			return false;
		}
		data->Secure = false;
		s = &tmp[0];
	}

	// Get the "server name:port number"
	StrCpy(server_port, sizeof(server_port), s);
	i = SearchStrEx(server_port, "/", 0, false);
	if (i != INFINITE)
	{
		server_port[i] = 0;
		s += StrLen(server_port);
		StrCpy(data->Target, sizeof(data->Target), s);
	}
	else
	{
		StrCpy(data->Target, sizeof(data->Target), "/");
	}

	if (ParseHostPort(server_port, &host, &port, data->Secure ? 443 : 80) == false)
	{
		return false;
	}

	StrCpy(data->HostName, sizeof(data->HostName), host);
	data->Port = port;

	Free(host);

	if ((data->Secure && data->Port == 443) || (data->Secure == false && data->Port == 80))
	{
		StrCpy(data->HeaderHostName, sizeof(data->HeaderHostName), data->HostName);
	}
	else
	{
		Format(data->HeaderHostName, sizeof(data->HeaderHostName),
			"%s:%u", data->HostName, data->Port);
	}

	return true;
}

// String replacement
void Base64ToSafe64(char *str, const UINT size)
{
	if (str == NULL || size == 0)
	{
		return;
	}

	for (UINT i = 0; i < size; ++i)
	{
		switch (str[i])
		{
		case '=':
			str[i] = '(';
			break;

		case '+':
			str[i] = ')';
			break;

		case '/':
			str[i] = '_';
			break;
		}
	}
}
void Safe64ToBase64(char *str, const UINT size)
{
	if (str == NULL || size == 0)
	{
		return;
	}

	for (UINT i = 0; i < size; ++i)
	{
		switch (str[i])
		{
		case '(':
			str[i] = '=';
			break;

		case ')':
			str[i] = '+';
			break;

		case '_':
			str[i] = '/';
			break;
		}
	}
}

// Decode from escaped Base64
UINT DecodeSafe64(void *dst, const char *src, UINT size)
{
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	if (size == 0)
	{
		size = StrLen(src);
	}

	char *tmp = Malloc(size + 1);
	Copy(tmp, src, size);
	tmp[size] = '\0';

	Safe64ToBase64(tmp, size);
	const UINT ret = Base64Decode(dst, tmp, size);
	Free(tmp);

	return ret;
}

// Encode to escaped Base64
void EncodeSafe64(char *dst, const void *src, const UINT size)
{
	if (dst == NULL || src == NULL)
	{
		return;
	}

	const UINT ret = Base64Encode(dst, src, size);

	Base64ToSafe64(dst, ret);
}
