// Protocol.c
// SoftEther protocol related routines

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Hub.h"
#include "HubLog.h"
#include "Link.h"
#include "Sam.h"
#include "Server.h"
#include "UdpAccel.h"
#include "WaterMark.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <winhttp.h>

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x)
{
	LIST *o;
	bool ret = false;
	if (x == NULL)
	{
		return false;
	}

	if (x->root_cert)
	{
		return true;
	}

	o = NewCertList(true);

	ret = TryGetRootCertChain(o, x, true, NULL);

	FreeCertList(o);

	return ret;
}

bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x)
{
	bool ret = false;
	LIST *chain = NULL;
	LIST *current_chain_dir = NULL;
	if (o == NULL || x == NULL)
	{
		return false;
	}

	chain = NewCertList(false);

	ret = TryGetParentCertFromCertList(o, x, chain);

	if (ret)
	{
		UINT i;
		DIRLIST *dir;
		wchar_t dirname[MAX_SIZE];
		wchar_t exedir[MAX_SIZE];

		GetExeDirW(exedir, sizeof(exedir));
		CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");
		MakeDirExW(dirname);

		if (auto_save)
		{
			dir = EnumDirW(dirname);
			if (dir != NULL)
			{
				for (i = 0;i < dir->NumFiles;i++)
				{
					DIRENT *e = dir->File[i];

					if (e->Folder == false)
					{
						if (UniStartWith(e->FileNameW, AUTO_DOWNLOAD_CERTS_PREFIX))
						{
							wchar_t tmp[MAX_SIZE];

							CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

							FileDeleteW(tmp);
						}
					}
				}

				FreeDir(dir);
			}
		}

		current_chain_dir = NewCertList(false);
		AddAllChainCertsToCertList(current_chain_dir);

		for (i = 0;i < LIST_NUM(chain);i++)
		{
			wchar_t tmp[MAX_SIZE];
			X *xx = LIST_DATA(chain, i);

			GetAllNameFromName(tmp, sizeof(tmp), xx->subject_name);


			if (auto_save && CompareX(x, xx) == false && IsXInCertList(current_chain_dir, xx) == false)
			{
				wchar_t fn[MAX_PATH];
				char hex_a[128];
				wchar_t hex[128];
				UCHAR hash[SHA1_SIZE];
				wchar_t tmp[MAX_SIZE];
				BUF *b;

				GetXDigest(xx, hash, true);
				BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
				StrToUni(hex, sizeof(hex), hex_a);

				UniStrCpy(fn, sizeof(fn), AUTO_DOWNLOAD_CERTS_PREFIX);
				UniStrCat(fn, sizeof(fn), hex);
				UniStrCat(fn, sizeof(fn), L".cer");

				CombinePathW(tmp, sizeof(tmp), dirname, fn);

				b = XToBuf(xx, true);

				DumpBufW(b, tmp);

				FreeBuf(b);
			}

			if (xx->root_cert)
			{
				if (found_root_x != NULL)
				{
					*found_root_x = CloneX(xx);
				}
			}
		}
	}

	FreeCertList(chain);

	FreeCertList(current_chain_dir);

	if (ret && auto_save)
	{
		// The folder was changed: the next connection of the server scans it again
		InvalidateChainCertCache();
	}

	return ret;
}

bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain)
{
	bool ret = false;
	X *r;
	bool do_free = false;
	if (o == NULL || x == NULL || found_chain == NULL)
	{
		return false;
	}

	if (LIST_NUM(found_chain) >= FIND_CERT_CHAIN_MAX_DEPTH)
	{
		return false;
	}

	Add(found_chain, CloneX(x));

	if (x->root_cert)
	{
		return true;
	}

	r = FindCertIssuerFromCertList(o, x);

	if (r == NULL)
	{
		if (IsEmptyStr(x->issuer_url) == false)
		{
			r = DownloadCert(x->issuer_url);

			if (CheckXEx(x, r, true, true) && CompareX(x, r) == false)
			{
				do_free = true;
			}
			else
			{
				FreeX(r);
				r = NULL;
			}
		}
	}

	if (r != NULL)
	{
		ret = TryGetParentCertFromCertList(o, r, found_chain);
	}

	if (do_free)
	{
		FreeX(r);
	}

	return ret;
}

X *FindCertIssuerFromCertList(LIST *o, X *x)
{
	UINT i;
	if (o == NULL || x == NULL)
	{
		return NULL;
	}

	if (x->root_cert)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CheckXEx(x, xx, true, true))
		{
			if (CompareX(x, xx) == false)
			{
				return xx;
			}
		}
	}

	return NULL;
}

// Receive buffer size of HttpGet
#define	HTTP_GET_RECV_BUF_SIZE		64000

// Set a DWORD option of a WinHTTP handle
static bool HttpSetDword(HINTERNET h, DWORD option, DWORD value)
{
	return (WinHttpSetOption(h, option, &value, sizeof(value)) != FALSE);
}

// GET an http or https URL with WinHTTP and return the body (the only HTTP request of the product: DownloadCert)
// No proxy (WinHTTP does not read the system or WPAD proxy settings either), no redirect, cookie, authentication
// or default credentials, no check of the server certificate and no client certificate. Only a 200 answer counts.
// The body is read as far as Content-Length says, up to max_size bytes (0: no limit); without Content-Length no
// body is read, chunked or not. timeout_ms is the TCP connect timeout and the time of each send and receive, the
// TLS handshake of an https URL gets TIMEOUT_SSL_CONNECT instead. error_code may be NULL.
static BUF *HttpGet(char *url, UINT timeout_ms, UINT max_size, UINT *error_code)
{
	char str[MAX_SIZE * 3];
	wchar_t tmp[MAX_SIZE];
	wchar_t host[MAX_HOST_NAME_LEN + 1];
	wchar_t *wide_url;
	wchar_t *target;
	void *buffer;
	URL_COMPONENTS uc;
	HINTERNET session = NULL;
	HINTERNET connect = NULL;
	HINTERNET request = NULL;
	BUF *ret = NULL;
	UINT err = ERR_INTERNAL_ERROR;
	UINT io_timeout;
	UINT content_len = 0;
	DWORD size;
	DWORD http_status = 0;
	bool secure;
	bool ok;

	// The URL, cut to a bounded length and trimmed
	StrCpy(str, sizeof(str), url);
	Trim(str);

	if (SearchStrEx(str, "://", 0, false) == INFINITE)
	{
		// Without a scheme the URL is http
		char *copy = CopyStr(str);

		Format(str, sizeof(str), "http://%s", copy);
		Free(copy);
	}

	wide_url = CopyStrToUni(str);

	// Host into a buffer, the path and what follows it (query, fragment) stay in the URL string, which ends
	// with them: that tail is the target and goes out as written, unescaped
	Zero(&uc, sizeof(uc));
	uc.dwStructSize = sizeof(uc);
	uc.lpszHostName = host;
	uc.dwHostNameLength = sizeof(host) / sizeof(host[0]);
	uc.dwUserNameLength = (DWORD)-1;
	uc.dwUrlPathLength = (DWORD)-1;
	uc.dwExtraInfoLength = (DWORD)-1;

	if (WinHttpCrackUrl(wide_url, 0, 0, &uc) == FALSE ||
		(uc.nScheme != INTERNET_SCHEME_HTTP && uc.nScheme != INTERNET_SCHEME_HTTPS) ||
		uc.dwHostNameLength == 0 || uc.dwUserNameLength != 0 || uc.nPort == 0 || (uc.dwUrlPathLength == 0 && uc.dwExtraInfoLength != 0))
	{
		err = ERR_INVALID_PARAMETER;
		goto FINAL;
	}

	secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
	target = (uc.dwUrlPathLength == 0 ? L"/" : uc.lpszUrlPath);

	session = WinHttpOpen(L"" DEFAULT_USER_AGENT, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (session == NULL)
	{
		goto FINAL;
	}

	// Timeouts until the request is sent: the DnsResolveEx default, the TCP connect timeout, and on each send
	// and receive the TLS handshake timeout for https
	io_timeout = (secure ? TIMEOUT_SSL_CONNECT : timeout_ms);

	if (WinHttpSetTimeouts(session, (int)DNS_RESOLVE_DEFAULT_TIMEOUT, (int)timeout_ms, (int)io_timeout,
		(int)io_timeout) == FALSE)
	{
		goto FINAL;
	}

	connect = WinHttpConnect(session, host, uc.nPort, 0);
	if (connect == NULL)
	{
		goto FINAL;
	}

	request = WinHttpOpenRequest(connect, L"GET", target, L"HTTP/1.1", WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_ESCAPE_DISABLE_QUERY | (secure ? WINHTTP_FLAG_SECURE : 0));
	if (request == NULL)
	{
		goto FINAL;
	}

	// No redirect, cookie, authentication or default credentials, and no keep-alive. DownloadCert makes
	// one request per connection: a pooled keep-alive connection would outlive the request and let a later
	// request reach a server that already answered the first one
	ok = HttpSetDword(request, WINHTTP_OPTION_DISABLE_FEATURE,
		WINHTTP_DISABLE_KEEP_ALIVE | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION) &&
		HttpSetDword(request, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH);

	// No total time limit on the response header. Should WinHTTP refuse the value, the request keeps
	// WinHTTP's default limit instead of failing.
	HttpSetDword(request, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, INFINITE);

	if (ok && secure)
	{
		// No check of the server certificate, and no client certificate
		ok = HttpSetDword(request, WINHTTP_OPTION_SECURITY_FLAGS,
			SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
			SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE) &&
			(WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0) != FALSE);
	}

	if (ok)
	{
		// Request headers that WinHTTP does not add itself (it sends Host, User-Agent and Connection: Keep-Alive)
		ok = (WinHttpAddRequestHeaders(request,
			L"Keep-Alive: " HTTP_KEEP_ALIVE "\r\nAccept-Language: ja\r\nPragma: no-cache\r\nCache-Control: no-cache",
			(DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD) != FALSE);
	}

	if (ok == false)
	{
		goto FINAL;
	}

	// Send
	if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE)
	{
		switch (GetLastError())
		{
		case ERROR_WINHTTP_NAME_NOT_RESOLVED:
		case ERROR_WINHTTP_CANNOT_CONNECT:
		case ERROR_WINHTTP_TIMEOUT:
			// Name not resolved, or no connection within the timeout
			err = ERR_CONNECT_FAILED;
			break;

		case ERROR_WINHTTP_SECURE_FAILURE:
			// TLS handshake failed
			err = ERR_PROTOCOL_ERROR;
			break;

		default:
			// The request could not be sent
			err = ERR_DISCONNECTED;
			break;
		}

		goto FINAL;
	}

	// From here on timeout_ms applies to each send and receive. Should WinHTTP refuse the change, an https
	// request keeps the TLS handshake timeout.
	WinHttpSetTimeouts(request, (int)DNS_RESOLVE_DEFAULT_TIMEOUT, (int)timeout_ms, (int)timeout_ms, (int)timeout_ms);

	// Receive
	if (WinHttpReceiveResponse(request, NULL) == FALSE)
	{
		err = ERR_DISCONNECTED;
		goto FINAL;
	}

	// Only an HTTP/1.x status line counts. WinHTTP has already skipped interim 1xx responses.
	size = sizeof(tmp);
	if (WinHttpQueryHeaders(request, WINHTTP_QUERY_VERSION, WINHTTP_HEADER_NAME_BY_INDEX, tmp, &size,
		WINHTTP_NO_HEADER_INDEX))
	{
		UniToStr(str, sizeof(str), tmp);

		if (StrLen(str) == 8 && Cmp(str, "HTTP/1.", 7) == 0)
		{
			size = sizeof(http_status);
			if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX, &http_status, &size, WINHTTP_NO_HEADER_INDEX) == FALSE)
			{
				http_status = 0;
			}
		}
	}

	switch (http_status)
	{
	case 401:
	case 407:
		// Proxy authentication error
		err = ERR_PROXY_AUTH_FAILED;
		break;

	case 404:
		// 404 File Not Found
		err = ERR_OBJECT_NOT_FOUND;
		break;

	case 200:
		// Success
		err = ERR_NO_ERROR;
		break;

	default:
		// Protocol error
		err = ERR_PROTOCOL_ERROR;
		break;
	}

	if (err != ERR_NO_ERROR)
	{
		goto FINAL;
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
	if (max_size != 0)
	{
		content_len = MIN(content_len, max_size);
	}

	// Receive the content
	buffer = Malloc(HTTP_GET_RECV_BUF_SIZE);
	ret = NewBuf();

	while (true)
	{
		UINT recv_size = MIN(HTTP_GET_RECV_BUF_SIZE, content_len - ret->Size);

		if (recv_size == 0)
		{
			break;
		}

		size = 0;
		if (WinHttpReadData(request, buffer, recv_size, &size) == FALSE || size == 0)
		{
			// Disconnected
			err = ERR_DISCONNECTED;
			FreeBuf(ret);
			ret = NULL;
			break;
		}

		WriteBuf(ret, buffer, size);
	}

	Free(buffer);

	if (ret != NULL)
	{
		SeekBuf(ret, 0, 0);
	}

FINAL:
	if (request != NULL)
	{
		WinHttpCloseHandle(request);
	}
	if (connect != NULL)
	{
		WinHttpCloseHandle(connect);
	}
	if (session != NULL)
	{
		WinHttpCloseHandle(session);
	}
	Free(wide_url);

	if (error_code != NULL)
	{
		*error_code = err;
	}

	return ret;
}

X *DownloadCert(char *url)
{
	BUF *b;
	X *ret = NULL;
	if (IsEmptyStr(url))
	{
		return NULL;
	}

	b = HttpGet(url, CERT_HTTP_DOWNLOAD_TIMEOUT, CERT_HTTP_DOWNLOAD_MAXSIZE, NULL);

	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToX(b, IsBase64(b));

	FreeBuf(b);

	return ret;
}

LIST *NewCertList(bool load_root_and_chain)
{
	LIST *o;

	o = NewList(NULL);

	if (load_root_and_chain)
	{
		AddAllRootCertsToCertList(o);
		AddAllChainCertsToCertList(o);
	}

	return o;
}

void FreeCertList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

bool IsXInCertList(LIST *o, X *x)
{
	UINT i;
	if (o == NULL || x == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CompareX(x, xx))
		{
			return true;
		}
	}

	return false;
}

static void AddXToCertList(LIST *o, X *x)
{
	if (o == NULL || x == NULL)
	{
		return;
	}

	if (IsXInCertList(o, x))
	{
		return;
	}

	if (CheckXDateNow(x) == false)
	{
		return;
	}

	Add(o, CloneX(x));
}

void AddAllChainCertsToCertList(LIST *o)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	DIRLIST *dir;
	if (o == NULL)
	{
		return;
	}

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		UINT i;

		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder == false)
			{
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}
}

void AddAllRootCertsToCertList(LIST *o)
{
	BUF *buf;
	PACK *p;
	UINT num_ok = 0, num_error = 0;
	if (o == NULL)
	{
		return;
	}

	buf = ReadDump(ROOT_CERTS_FILENAME);
	if (buf == NULL)
	{
		return;
	}

	p = BufToPack(buf);

	if (p != NULL)
	{
		UINT num = PackGetIndexCount(p, "cert");
		UINT i;

		for (i = 0;i < num;i++)
		{
			bool ok = false;
			BUF *b = PackGetBufEx(p, "cert", i);

			if (b != NULL)
			{
				X *x = BufToX(b, false);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					ok = true;

					FreeX(x);
				}

				FreeBuf(b);
			}

			if (ok)
			{
				num_ok++;
			}
			else
			{
				num_error++;
			}
		}

		FreePack(p);
	}

	FreeBuf(buf);

}

// Machine identity (FIX-5, #101): the first SHA1_SIZE bytes of SHA-256 over MACHINE_ID_LABEL with its
// terminator, the MachineGuid of Windows (trimmed, lower case) with its terminator, and the salt. Host
// name, IP addresses and OS version are no input. An unreadable MachineGuid is the empty string, so the
// salt alone still tells two servers apart.
void ComputeMachineUniqueHash(void *data, char *machine_guid, void *salt, UINT salt_size)
{
	BUF *b;
	char guid[MAX_SIZE];
	UCHAR hash[SHA256_SIZE];
	if (data == NULL || (salt == NULL && salt_size != 0))
	{
		return;
	}

	StrCpy(guid, sizeof(guid), machine_guid);
	Trim(guid);
	StrLower(guid);

	b = NewBuf();
	WriteBuf(b, MACHINE_ID_LABEL, StrSize(MACHINE_ID_LABEL));
	WriteBuf(b, guid, StrSize(guid));
	WriteBuf(b, salt, salt_size);

	Sha2_256(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(data, hash, SHA1_SIZE);
}

// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid in the 64-bit registry view, or "" when it cannot be read
static void GetMachineGuid(char *guid, UINT size)
{
	char *s;
	if (guid == NULL)
	{
		return;
	}

	s = MsRegReadStrEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", false);

	StrCpy(guid, size, s);

	Free(s);
}

// Set the machine identity salt of a CEDAR (NewCedar: a random one; SiLoadMachineIdCfg: the one of the
// config file) and derive its machine identity. Called before the hubs and listeners exist, so readers
// of the identity need no lock.
void SetCedarMachineIdSalt(CEDAR *c, void *salt)
{
	char guid[MAX_SIZE];
	if (c == NULL || salt == NULL)
	{
		return;
	}

	Copy(c->MachineIdSalt, salt, sizeof(c->MachineIdSalt));

	GetMachineGuid(guid, sizeof(guid));

	ComputeMachineUniqueHash(c->MachineUniqueHash, guid, c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// The machine identity of a server (SHA1_SIZE bytes): virtual hub MAC address and address, Cascade unique_id
void GenerateMachineUniqueHash(CEDAR *c, void *data)
{
	if (c == NULL || data == NULL)
	{
		return;
	}

	Copy(data, c->MachineUniqueHash, SHA1_SIZE);
}

// Reads the fields of the client's "login" PACK that the hub-side login steps and the new session use.
// Reads the PACK only. False when the PACK has no user name or no hub name.
bool ParseLoginRequest(PACK *p, LOGIN_REQ *req)
{
	if (p == NULL || req == NULL)
	{
		return false;
	}

	Zero(req, sizeof(LOGIN_REQ));

	InRpcNodeInfo(&req->NodeInfo, p);

	req->AuthType = GetAuthTypeFromPack(p);
	if (GetHubnameAndUsernameFromPack(p, req->Username, sizeof(req->Username), req->HubName, sizeof(req->HubName)) == false)
	{
		return false;
	}

	req->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
	req->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
	req->MaxConnection = PackGetInt(p, "max_connection");
	req->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
	req->QoS = PackGetInt(p, "qos") ? true : false;
	req->ClientId = PackGetInt(p, "client_id");
	req->AdjustMss = PackGetInt(p, "adjust_mss");
	req->UseUdpAcceleration = PackGetBool(p, "use_udp_acceleration");
	req->UdpAccelMaxVersion = PackGetInt(p, "udp_acceleration_max_version");
	if (req->UdpAccelMaxVersion == 0)
	{
		req->UdpAccelMaxVersion = 1;
	}
	req->UseHMacOnUdpAcceleration = PackGetBool(p, "support_hmac_on_udp_acceleration");
	req->UdpAccelFastDisconnectDetect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

	if (req->UseUdpAcceleration)
	{
		PackGetData2(p, "udp_acceleration_client_key", req->UdpAccelClientKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackGetData2(p, "udp_acceleration_client_key_v2", req->UdpAccelClientKeyV2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

		if (PackGetIp(p, "udp_acceleration_client_ip", &req->UdpAccelClientIp) == false)
		{
			req->UseUdpAcceleration = false;
		}
		else
		{
			req->UdpAccelClientPort = PackGetInt(p, "udp_acceleration_client_port");
			if (req->UdpAccelClientPort == 0)
			{
				req->UseUdpAcceleration = false;
			}
		}
	}

	req->RequireBridgeRoutingMode = PackGetBool(p, "require_bridge_routing_mode");
	req->RequireMonitorMode = PackGetBool(p, "require_monitor_mode");
	if (req->RequireMonitorMode)
	{
		req->QoS = false;
	}

	if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
	{
		PackGetData(p, "unique_id", req->UniqueId);
	}

	return true;
}

// Looks up the user object of an authenticated login and builds the policy of its session from the user's or
// group's policy, the hub's admin options and the request. Runs under hub->lock and leaves it held.
// Returns ERR_NO_ERROR with login->Policy set, or the error of a refused login (logged to the hub log) with
// login->Policy NULL. login->User holds a reference in both cases; the caller releases it.
UINT HubResolveSessionPolicy(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login)
{
	POLICY *policy = NULL;
	USER *user;
	USERGROUP *group;
	UINT64 user_expires = 0;
	UCHAR unique2[SHA1_SIZE];
	bool qos;
	bool local_host_session = false;

	if (hub == NULL || c == NULL || req == NULL || login == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	qos = req->QoS;

	if (StrCmpi(req->Username, ADMINISTRATOR_USERNAME) != 0)
	{
		user = AcGetUser(hub, req->Username);
		if (user == NULL)
		{
			user = AcGetUser(hub, "*");
			if (user == NULL)
			{
				return ERR_ACCESS_DENIED;
			}
		}

		policy = NULL;

		Lock(user->lock);
		{
			user_expires = user->ExpireTime;

			StrCpy(login->UserNameReal, sizeof(login->UserNameReal), user->Name);
			group = user->Group;
			if (group != NULL)
			{
				AddRef(group->ref);

				Lock(group->lock);
				{
					StrCpy(login->GroupName, sizeof(login->GroupName), group->Name);
				}
				Unlock(group->lock);
			}

			if (user->Policy != NULL)
			{
				policy = ClonePolicy(user->Policy);
			}
			else
			{
				if (group)
				{
					Lock(group->lock);
					{
						if (group->Policy != NULL)
						{
							policy = ClonePolicy(group->Policy);
						}
					}
					Unlock(group->lock);
				}
			}

			if (group != NULL)
			{
				ReleaseGroup(group);
			}
		}
		Unlock(user->lock);
		login->User = user;
	}
	else
	{
		login->AdminMode = true;
		StrCpy(login->UserNameReal, sizeof(login->UserNameReal), ADMINISTRATOR_USERNAME);

		policy = ClonePolicy(GetDefaultPolicy());
		policy->NoBroadcastLimiter = true;
		policy->MonitorPort = true;
	}

	if (policy == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}

	if (policy->MaxConnection == 0)
	{
		policy->MaxConnection = MAX_TCP_CONNECTION;
	}

	if (policy->TimeOut == 0)
	{
		policy->TimeOut = 20;
	}

	if (qos)
	{
		if (policy->NoQoS)
		{
			qos = false;
		}
		if (GetHubAdminOption(hub, "deny_qos") != 0)
		{
			qos = false;
			policy->NoQoS = true;
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_download") != 0)
	{
		if (policy->MaxDownload == 0)
		{
			policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
		}
		else
		{
			UINT r = GetHubAdminOption(hub, "max_bitrates_download");
			policy->MaxDownload = MIN(policy->MaxDownload, r);
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_upload") != 0)
	{
		if (policy->MaxUpload == 0)
		{
			policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
		}
		else
		{
			UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
			policy->MaxUpload = MIN(policy->MaxUpload, r);
		}
	}

	if (GetHubAdminOption(hub, "deny_bridge") != 0)
	{
		policy->NoBridge = true;
	}

	if (GetHubAdminOption(hub, "deny_routing") != 0)
	{
		policy->NoRouting = true;
	}

	if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
		 InStrEx(c->ClientStr, "client", false))
	{
		HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

		Free(policy);
		return ERR_VERSION_INVALID;
	}

	if (hub->Option->RequiredClientId != 0 &&
		hub->Option->RequiredClientId != req->ClientId &&
		InStrEx(c->ClientStr, "client", false))
	{
		HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, req->ClientId, hub->Option->RequiredClientId);

		Free(policy);
		return ERR_CLIENT_ID_REQUIRED;
	}

	if (user_expires != 0 && user_expires <= SystemTime64())
	{
		HLog(hub, "LH_USER_EXPIRES", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (policy->Access == false)
	{
		HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (req->RequireMonitorMode && policy->MonitorPort == false)
	{
		HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

		Free(policy);
		return ERR_MONITOR_MODE_DENIED;
	}

	if (policy->MonitorPort)
	{
		if (req->RequireMonitorMode == false)
		{
			policy->MonitorPort = false;
		}
	}

	if (policy->MonitorPort)
	{
		qos = false;
	}

	if (req->RequireBridgeRoutingMode &&
		(policy->NoBridge && policy->NoRouting))
	{
		HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

		Free(policy);
		return ERR_BRIDGE_MODE_DENIED;
	}

	if (req->RequireBridgeRoutingMode == false)
	{
		policy->NoBridge = true;
		policy->NoRouting = true;
	}

	GenerateMachineUniqueHash(c->Cedar, unique2);
	if (Cmp(req->UniqueId, unique2, SHA1_SIZE) == 0)
	{
		local_host_session = true;
	}

	if (local_host_session == false)
	{
		SOCK *s = c->FirstSock;

		if (s != NULL)
		{
			if (IsIPMyHost(&s->RemoteIP))
			{
				local_host_session = true;
			}
		}
	}

	if (local_host_session)
	{
		policy->NoBridge = false;
		policy->NoRouting = false;
	}

	login->Policy = policy;
	login->QoS = qos;
	login->LocalHostSession = local_host_session;

	return ERR_NO_ERROR;
}

// Admits a login whose policy HubResolveSessionPolicy built: the user's multiple-login limit and the session limits
// of the hub and the server. Runs under hub->lock. On ERR_NO_ERROR hub->lock is still held and the slot holds the
// hub's and Cedar's session counters (HubReleaseSessionSlot gives them back). A refused login is logged to the hub
// log after hub->lock is released, so on an error hub->lock is no longer held and login->Policy is freed.
UINT HubAdmitSession(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login, HUB_SESSION_SLOT *slot)
{
	POLICY *policy;
	bool use_client_license = false, use_bridge_license = false;

	if (hub == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (c == NULL || req == NULL || login == NULL || login->Policy == NULL || slot == NULL)
	{
		Unlock(hub->lock);
		return ERR_INTERNAL_ERROR;
	}

	Zero(slot, sizeof(HUB_SESSION_SLOT));

	policy = login->Policy;

	if (login->LocalHostSession == false)
	{

		if (policy->NoBridge == false || policy->NoRouting == false)
		{
			use_bridge_license = true;
		}
		else
		{
			use_client_license = true;
		}
	}


	{
		UINT num;
		UINT max_logins = policy->MultiLogins;
		UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

		if (ao != 0)
		{
			if (max_logins != 0)
			{
				max_logins = MIN(max_logins, ao);
			}
			else
			{
				max_logins = ao;
			}
		}

		if (max_logins != 0)
		{
			// Lock order is hub->lock, SessionList, s->lock: release hub->lock
			// while the session list is walked, as before
			Unlock(hub->lock);

			num = HubCountUserSessions(hub, req->Username, req->NodeInfo.UniqueId);

			Lock(hub->lock);

			if (num >= max_logins)
			{
				Unlock(hub->lock);

				HLog(hub, "LH_TOO_MANY_MULTILOGINS",
					c->Name,
					req->Username, max_logins, num);

				Free(policy);
				login->Policy = NULL;
				return ERR_TOO_MANY_USER_SESSION;
			}
		}
	}

	if (login->User != NULL)
	{
		Lock(login->User->lock);
		{
			login->User->LastLoginTime = SystemTime64();
		}
		Unlock(login->User->lock);
	}

	hub->LastCommTime = hub->LastLoginTime = SystemTime64();

	if (login->AdminMode == false)
	{
		if (hub->Option->MaxSession != 0 &&
			hub->Option->MaxSession <= Count(hub->NumSessions))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license || use_bridge_license)
	{
		if (
			(GetHubAdminOption(hub, "max_sessions") != 0 &&
			(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions"))
			||
			(hub->Option->MaxSession != 0 &&
			(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license)
	{
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
			Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client"))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_bridge_license)
	{
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
			Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge"))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (Count(hub->Cedar->CurrentSessions) >= SERVER_MAX_SESSIONS)
	{
		Unlock(hub->lock);

		HLog(hub, "LH_MAX_SESSION_2", c->Name, SERVER_MAX_SESSIONS);

		Free(policy);
		login->Policy = NULL;
		return ERR_HUB_IS_BUSY;
	}

	Inc(hub->NumSessions);
	if (use_bridge_license)
	{
		Inc(hub->NumSessionsBridge);
	}

	if (use_client_license)
	{
		Inc(hub->NumSessionsClient);
	}
	Inc(hub->Cedar->CurrentSessions);

	slot->Hub = hub;
	slot->UseClientLicense = use_client_license;
	slot->UseBridgeLicense = use_bridge_license;

	return ERR_NO_ERROR;
}

// Takes the licence counters of an admitted session's slot on Cedar
void HubAssignSessionLicense(HUB_SESSION_SLOT *slot)
{
	CEDAR *cedar;

	if (slot == NULL || slot->Hub == NULL)
	{
		return;
	}

	cedar = slot->Hub->Cedar;

	if (slot->UseBridgeLicense)
	{
		Inc(cedar->AssignedBridgeLicense);
	}

	if (slot->UseClientLicense)
	{
		Inc(cedar->AssignedClientLicense);
	}

	slot->LicenseAssigned = true;
}

// Gives back every counter a slot holds (HubAdmitSession, HubAssignSessionLicense), under hub->lock, and empties the
// slot. Does nothing for an empty slot.
void HubReleaseSessionSlot(HUB_SESSION_SLOT *slot)
{
	HUB *hub;
	CEDAR *cedar;

	if (slot == NULL || slot->Hub == NULL)
	{
		return;
	}

	hub = slot->Hub;
	cedar = hub->Cedar;

	Lock(hub->lock);
	{
		if (slot->UseBridgeLicense)
		{
			Dec(hub->NumSessionsBridge);
		}

		if (slot->UseClientLicense)
		{
			Dec(hub->NumSessionsClient);
		}

		Dec(hub->NumSessions);
		Dec(cedar->CurrentSessions);

		if (slot->LicenseAssigned)
		{
			if (slot->UseBridgeLicense)
			{
				Dec(cedar->AssignedBridgeLicense);
			}

			if (slot->UseClientLicense)
			{
				Dec(cedar->AssignedClientLicense);
			}
		}
	}
	Unlock(hub->lock);

	Zero(slot, sizeof(HUB_SESSION_SLOT));
}

// Creates the session of an admitted login (NewServerSession) and applies the login's settings to it, assigns the
// slot's licence (HubAssignSessionLicense) and sets c->Session. Runs under hub->lock, so the UDP acceleration
// socket (NewUdpAccel) is created under it.
SESSION *NewLoginSession(CONNECTION *c, HUB *hub, SERVER_SESSION_PARAMS *prm, HUB_SESSION_SLOT *slot)
{
	SESSION *s;
	SERVER *server;
	POLICY *policy;

	if (c == NULL || hub == NULL || prm == NULL || prm->Policy == NULL || slot == NULL)
	{
		return NULL;
	}

	server = c->Cedar->Server;
	policy = prm->Policy;

	s = NewServerSession(c->Cedar, c, hub, prm->Username, policy);

	s->LocalHostSession = prm->LocalHostSession;
	s->NormalClient = true;

	IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

	StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

	AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

	s->NoSendSignature = server->NoSendSignature;

	if (prm->UseUdpAcceleration)
	{
		s->UseUdpAcceleration = true;

		s->UdpAccelFastDisconnectDetect = prm->UdpAccelFastDisconnectDetect;
	}

	if (hub->Option->DisableUdpAcceleration)
	{
		s->UseUdpAcceleration = false;
	}

	if (s->UseUdpAcceleration)
	{
		s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false);
		if (s->UdpAccel == NULL)
		{
			s->UseUdpAcceleration = false;
		}
		else
		{
			s->UdpAccel->Version = prm->UdpAccelVersion;

			if (UdpAccelInitServer(s->UdpAccel, prm->UdpAccelClientKey,
				&c->FirstSock->RemoteIP, &prm->UdpAccelClientIp, prm->UdpAccelClientPort) == false)
			{
				s->UseUdpAcceleration = false;
			}

			s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

			if (prm->UseEncrypt == false)
			{
				s->UdpAccel->PlainTextMode = true;
			}

			s->UdpAccel->UseHMac = prm->UseHMacOnUdpAcceleration;

			UdpAccelAddProtocolDetails(s->UdpAccel, s->ProtocolDetails, sizeof(s->ProtocolDetails));
		}
	}

	s->AdjustMss = prm->AdjustMss;
	if (s->AdjustMss != 0)
	{
		AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);
	}

	s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
	s->IsMonitorMode = policy->MonitorPort;

	s->IPv6Session = prm->IPv6Session;

	HubAssignSessionLicense(slot);

	{
		char ip[128];
		IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort, c->FirstSock->UnderlayProtocol, c->FirstSock->ProtocolDetails);
	}

	c->Session = s;
	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), prm->UserNameReal);
	StrCpy(s->GroupName, sizeof(s->GroupName), prm->GroupName);

	s->MaxConnection = prm->MaxConnection;
	s->UseEncrypt = prm->UseEncrypt;
	s->UseCompress = prm->UseCompress;
	s->HalfConnection = prm->HalfConnection;
	s->Timeout = prm->Timeout;
	s->QoS = prm->QoS;
	s->VLanId = policy->VLanId;

	s->Username = CopyStr(prm->Username);

	HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
		s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
		s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
		s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
		s->Timeout / 1000);

	return s;
}


PACK *PackWelcome(SESSION *s)
{
	PACK *p;
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();

	PackAddStr(p, "session_name", s->Name);

	PackAddStr(p, "connection_name", s->Connection->Name);

	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);

	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	PackAddPolicy(p, s->Policy);

	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->NoSendSignature)
	{
		PackAddBool(p, "no_send_signature", true);
	}

	if (s->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		if (s->UdpAccel->UseStun)
		{
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->StunIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->StunPort);
		}
		else
		{
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->MyIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->MyPort);
		}
		PackAddData(p, "udp_acceleration_server_key", s->UdpAccel->MyKey, sizeof(s->UdpAccel->MyKey));
		PackAddData(p, "udp_acceleration_server_key_v2", s->UdpAccel->MyKey_V2, sizeof(s->UdpAccel->MyKey_V2));
		PackAddInt(p, "udp_acceleration_server_cookie", s->UdpAccel->MyCookie);
		PackAddInt(p, "udp_acceleration_client_cookie", s->UdpAccel->YourCookie);
		PackAddBool(p, "udp_acceleration_use_encryption", !s->UdpAccel->PlainTextMode);
		PackAddBool(p, "use_hmac_on_udp_acceleration", s->UdpAccel->UseHMac);
		PackAddBool(p, "udp_accel_fast_disconnect_detect", s->UdpAccelFastDisconnectDetect);
	}

	return p;
}

bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32)
{
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return false;
	}

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "session_key", session_key) == false)
	{
		return false;
	}
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}

void PackAddPolicy(PACK *p, POLICY *y)
{
	UINT i;
	if (p == NULL || y == NULL)
	{
		return;
	}

	for (i = 0;i < NUM_POLICY_ITEM;i++)
	{
		POLICY_ITEM *item = &policy_item[i];
		char name[MAX_SIZE];

		Format(name, sizeof(name), "policy:%s", item->Name);

		if (item->TypeInt)
		{
			PackAddInt(p, name, GetPolicyValue(y, i));
		}
		else
		{
			PackAddBool(p, name, GetPolicyValue(y, i) != 0);
		}
	}

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

bool ServerUploadHello(CONNECTION *c)
{
	PACK *p;
	if (c == NULL)
	{
		return false;
	}

	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false)
	{
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

bool ServerDownloadSignature(CONNECTION *c)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	if (c == NULL)
	{
		return false;
	}

	s = c->FirstSock;

	while (true)
	{
		num++;
		if (num > max)
		{
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			return false;
		}
		h = RecvHttpHeader(s);
		if (h == NULL)
		{
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		if (StrCmpi(h->Method, "POST") == 0)
		{
			bool signature_ok = false;

			data_size = GetContentLength(h);

			if ((data_size > MAX_WATERMARK_SIZE || data_size < WaterMarkSize) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA)))
			{
				HttpSendDecoyPage(s, 403, h);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				return false;
			}
			if (StrCmpi(h->Target, vpn_http_target) != 0)
			{
				HttpSendDecoyPage(s, 404, h);
			}
			else
			{
				if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0))
					|| ((data_size >= WaterMarkSize) && Cmp(data, WaterMark, WaterMarkSize) == 0))
				{
					signature_ok = true;
				}
				else
				{
					HttpSendDecoyPage(s, 403, h);
				}
			}

			// The one release of the body of a received POST, whatever the comparison found
			Free(data);
			FreeHttpHeader(h);

			if (signature_ok)
			{
				return true;
			}
		}
		else
		{
			// Not a VPN client, but still answer plain HTTP.
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0
				 && StrCmpi(h->Method, "POST") != 0)
			{
				HttpSendDecoyPage(s, 501, h);
			}
			else
			{
				if (StrCmpi(h->Target, "/") == 0)
				{
					HttpSendDecoyPage(s, 403, h);
				}
				else
				{
					HttpSendDecoyPage(s, 404, h);
				}
			}
			FreeHttpHeader(h);
		}
	}
}

PACK *PackHello(void *random, UINT ver, UINT build, char *server_str)
{
	PACK *p;
	if (random == NULL || server_str == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

UINT GetAuthTypeFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "authtype");
}

bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size)
{
	if (p == NULL || username == NULL || hubname == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "username", username, username_size) == false)
	{
		return false;
	}
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
	{
		return false;
	}
	return true;
}

UINT GetProtocolFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	// Only TCP is supported.
	return CONNECTION_TCP;
}

bool GetMethodFromPack(PACK *p, char *method, UINT size)
{
	if (p == NULL || method == NULL || size == 0)
	{
		return false;
	}

	return PackGetStr(p, "method", method, size);
}
