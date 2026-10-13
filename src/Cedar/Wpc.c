// Wpc.c
// RPC over HTTP

#include "Wpc.h"

#include "Command.h"
#include "Protocol.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Encoding.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Proxy.h"
#include "Mayaqua/Str.h"

SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel)
{
	SOCK *sock;
	UINT ret;
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
		sock = BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, param->HostName, param->Port, timeout, cancel, true, NULL);
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
			return NULL;
		}

		*error_code = ProxyCodeToCedar(ret);

		if (*error_code != ERR_NO_ERROR)
		{
			return NULL;
		}

		return out.Sock;
	}
}

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
	WPC_CONNECT con;
	SOCK *s;
	HTTP_HEADER *h;
	bool use_http_proxy = false;
	char target[MAX_SIZE * 4];
	char *send_str;
	BUF *send_buf;
	BUF *recv_buf;
	UINT http_error_code;
	char len_str[100];
	UINT content_len;
	void *socket_buffer;
	UINT socket_buffer_size = WPC_RECV_BUF_SIZE;
	UINT num_continue = 0;
	INTERNET_SETTING wt_setting;
	if (data == NULL)
	{
		return NULL;
	}
	if (setting == NULL)
	{
		Zero(&wt_setting, sizeof(wt_setting));
		setting = &wt_setting;
	}
	if (error_code == NULL)
	{
		static UINT ret = 0;
		error_code = &ret;
	}
	if (timeout_comm == 0)
	{
		timeout_comm = WPC_TIMEOUT;
	}
	if (sha1_cert_hash == NULL)
	{
		num_hashes = 0;
	}
	if (num_hashes == 0)
	{
		sha1_cert_hash = NULL;
	}

	Zero(&con, sizeof(con));
	StrCpy(con.HostName, sizeof(con.HostName), data->HostName);
	con.Port = data->Port;
	con.ProxyType = setting->ProxyType;
	StrCpy(con.ProxyHostName, sizeof(con.ProxyHostName), setting->ProxyHostName);
	con.ProxyPort = setting->ProxyPort;
	StrCpy(con.ProxyUsername, sizeof(con.ProxyUsername), setting->ProxyUsername);
	StrCpy(con.ProxyPassword, sizeof(con.ProxyPassword), setting->ProxyPassword);
	StrCpy(con.CustomHttpHeader, sizeof(con.CustomHttpHeader), setting->CustomHttpHeader);

	if (setting->ProxyType != PROXY_HTTP || data->Secure)
	{
		use_http_proxy = false;
		StrCpy(target, sizeof(target), data->Target);
	}
	else
	{
		use_http_proxy = true;
		CreateUrl(target, sizeof(target), data);
	}

	if (use_http_proxy == false)
	{
		s = WpcSockConnectEx(&con, error_code, timeout_connect, cancel);
	}
	else
	{
		s = BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, con.ProxyHostName, con.ProxyPort, timeout_connect, cancel, true, NULL);
		if (s == NULL)
		{
			*error_code = ERR_PROXY_CONNECT_FAILED;
		}
	}

	if (s == NULL)
	{
		return NULL;
	}

	if (data->Secure)
	{
		if (StartSSLEx(s, NULL, NULL, 0, (IsEmptyStr(data->SniString) ? NULL : data->SniString)) == false)
		{
			*error_code = ERR_PROTOCOL_ERROR;
			Disconnect(s);
			ReleaseSock(s);
			return NULL;
		}

		if (sha1_cert_hash != NULL && num_hashes >= 1)
		{
			UCHAR hash[SHA1_SIZE];
			UINT i;
			bool ok = false;

			Zero(hash, sizeof(hash));
			GetXDigest(s->RemoteX, hash, true);

			for (i = 0;i < num_hashes;i++)
			{
				UCHAR *a = (UCHAR *)sha1_cert_hash;
				a += (SHA1_SIZE * i);

				if (Cmp(hash, a, SHA1_SIZE) == 0)
				{
					ok = true;
					break;
				}
			}

			if (ok == false)
			{
				*error_code = ERR_CERT_NOT_TRUSTED;
				Disconnect(s);
				ReleaseSock(s);
				return NULL;
			}
		}
	}

	SetTimeout(s, timeout_comm);

	h = NewHttpHeader(data->Method, target, use_http_proxy ? "HTTP/1.0" : "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Accept-Language", "ja"));
	AddHttpValue(h, NewHttpValue("User-Agent", WPC_USER_AGENT));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));
	AddHttpValue(h, NewHttpValue("Host", data->HeaderHostName));

	if (IsEmptyStr(header_name) == false && IsEmptyStr(header_value) == false)
	{
		AddHttpValue(h, NewHttpValue(header_name, header_value));
	}

	if (IsEmptyStr(data->Referer) == false)
	{
		AddHttpValue(h, NewHttpValue("Referer", data->Referer));
	}

	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		ToStr(len_str, StrLen(post_data));
		AddHttpValue(h, NewHttpValue("Content-Type", "application/x-www-form-urlencoded"));
		AddHttpValue(h, NewHttpValue("Content-Length", len_str));
	}

	if (IsEmptyStr(data->AdditionalHeaderName) == false && IsEmptyStr(data->AdditionalHeaderValue) == false)
	{
		AddHttpValue(h, NewHttpValue(data->AdditionalHeaderName, data->AdditionalHeaderValue));
	}

	if (use_http_proxy)
	{
		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));

		if (IsEmptyStr(setting->ProxyUsername) == false || IsEmptyStr(setting->ProxyPassword) == false)
		{
			char auth_str[MAX_SIZE * 2];
			Format(auth_str, sizeof(auth_str), "%s:%s", setting->ProxyUsername, setting->ProxyPassword);

			char *base64 = Base64FromBin(NULL, auth_str, StrLen(auth_str));
			Format(auth_str, sizeof(auth_str), "Basic %s", base64);
			Free(base64);

			AddHttpValue(h, NewHttpValue("Proxy-Authorization", auth_str));
		}
	}

	send_str = HttpHeaderToStr(h);
	FreeHttpHeader(h);

	send_buf = NewBuf();
	WriteBuf(send_buf, send_str, StrLen(send_str));
	Free(send_str);

	if (StrCmpi(data->Method, WPC_HTTP_POST_NAME) == 0)
	{
		WriteBuf(send_buf, post_data, StrLen(post_data));
	}

	if (SendAll(s, send_buf->Buf, send_buf->Size, s->SecureMode) == false)
	{
		Disconnect(s);
		ReleaseSock(s);
		FreeBuf(send_buf);

		*error_code = ERR_DISCONNECTED;

		return NULL;
	}

	FreeBuf(send_buf);

CONT:
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);

		*error_code = ERR_DISCONNECTED;

		return NULL;
	}

	http_error_code = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			http_error_code = ToInt(h->Target);
		}
	}

	*error_code = ERR_NO_ERROR;

	switch (http_error_code)
	{
	case 401:
	case 407:
		*error_code = ERR_PROXY_AUTH_FAILED;
		break;

	case 404:
		*error_code = ERR_OBJECT_NOT_FOUND;
		break;

	case 100:
		num_continue++;
		if (num_continue >= 10)
		{
			goto DEF;
		}
		FreeHttpHeader(h);
		goto CONT;

	case 200:
		break;

	default:
DEF:
		*error_code = ERR_PROTOCOL_ERROR;
		break;
	}

	if (*error_code != ERR_NO_ERROR)
	{
		Disconnect(s);
		ReleaseSock(s);
		FreeHttpHeader(h);
		return NULL;
	}

	content_len = GetContentLength(h);
	if (max_recv_size != 0)
	{
		content_len = MIN(content_len, max_recv_size);
	}

	FreeHttpHeader(h);

	socket_buffer = Malloc(socket_buffer_size);

	recv_buf = NewBuf();

	while (true)
	{
		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);
		UINT size;

		if (recv_callback != NULL)
		{
			if (recv_callback(recv_callback_param,
				content_len, recv_buf->Size, recv_buf) == false)
			{
				*error_code = ERR_USER_CANCEL;
				goto RECV_CANCEL;
			}
		}

		if (recvsize == 0)
		{
			break;
		}

		size = Recv(s, socket_buffer, recvsize, s->SecureMode);
		if (size == 0)
		{
			*error_code = ERR_DISCONNECTED;

RECV_CANCEL:
			FreeBuf(recv_buf);
			Free(socket_buffer);
			Disconnect(s);
			ReleaseSock(s);

			return NULL;
		}

		WriteBuf(recv_buf, socket_buffer, size);
	}

	SeekBuf(recv_buf, 0, 0);
	Free(socket_buffer);

	Disconnect(s);
	ReleaseSock(s);

	return recv_buf;
}

void CreateUrl(char *url, UINT url_size, URL_DATA *data)
{
	char *protocol;
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


bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer)
{
	char tmp[MAX_SIZE * 3];
	char server_port[MAX_HOST_NAME_LEN + 16];
	char *s = NULL;
	char *host;
	UINT port;
	UINT i;
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
