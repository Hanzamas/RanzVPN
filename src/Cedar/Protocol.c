// Protocol.c
// SoftEther protocol related routines

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Hub.h"
#include "Link.h"
#include "Logging.h"
#include "MsChapV2.h"
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
#include "Mayaqua/OS.h"
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

static void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info)
{
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	if (str == NULL || info == NULL)
	{
		return;
	}

	IPToStr4or6(client_ip, sizeof(client_ip), info->ClientIpAddress, info->ClientIpAddress6);
	IPToStr4or6(server_ip, sizeof(server_ip), info->ServerIpAddress, info->ServerIpAddress6);
	IPToStr4or6(proxy_ip, sizeof(proxy_ip), info->ProxyIpAddress, info->ProxyIpAddress6);
	BinToStr(unique_id, sizeof(unique_id), info->UniqueId, sizeof(info->UniqueId));

	UniFormat(str, size, _UU("LS_NODE_INFO_TAG"), info->ClientProductName,
		Endian32(info->ClientProductVer), Endian32(info->ClientProductBuild),
		info->ServerProductName, Endian32(info->ServerProductVer), Endian32(info->ServerProductBuild),
		info->ClientOsName, info->ClientOsVer, info->ClientOsProductId,
		info->ClientHostname, client_ip, Endian32(info->ClientPort),
		info->ServerHostname, server_ip, Endian32(info->ServerPort),
		info->ProxyHostname, proxy_ip, Endian32(info->ProxyPort),
		info->HubName, unique_id);
}

// Whether the access list of hub (source IP address limit) admits the client of c. A denied client is logged
// (LS_IP_DENIED); the caller refuses the request with ERR_IP_ADDRESS_DENIED before any credential check.
static bool ServerCheckHubAccess(CONNECTION *c, HUB *hub)
{
	IP ip;
	char ip_str[64];

	if (hub->HubDb == NULL || c->FirstSock == NULL)
	{
		return true;
	}

	Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

	if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList) == false)
	{
		return true;
	}

	IPToStr(ip_str, sizeof(ip_str), &ip);
	SLog(c->Cedar, "LS_IP_DENIED", c->Name, ip_str);

	return false;
}

static UINT ChangePasswordAccept(CONNECTION *c, PACK *p)
{
	CEDAR *cedar;
	UCHAR random[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	char username[MAX_USERNAME_LEN + 1];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR new_password_ntlm[SHA1_SIZE];
	UCHAR check_secure_old_password[SHA1_SIZE];
	UINT ret = ERR_NO_ERROR;
	HUB *hub;
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
		PackGetStr(p, "username", username, sizeof(username)) == false ||
		PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
		PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
	{
		Zero(new_password_ntlm, sizeof(new_password_ntlm));
	}

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		char tmp[MAX_SIZE];

		if (ServerCheckHubAccess(c, hub) == false)
		{
			ReleaseHub(hub);
			return ERR_IP_ADDRESS_DENIED;
		}

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0)
		{
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL)
			{
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			}
			else
			{
				Lock(u->lock);
				{
					if (u->AuthType	!= AUTHTYPE_PASSWORD)
					{
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					}
					else
					{
						bool fix_password = false;
						if (u->Policy != NULL)
						{
							fix_password = u->Policy->FixPassword;
						}
						else
						{
							if (u->Group != NULL)
							{
								if (u->Group->Policy != NULL)
								{
									fix_password = u->Group->Policy->FixPassword;
								}
							}
						}
						if (fix_password == false)
						{
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0)
							{
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							}
							else
							{
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE))
								{
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						}
						else
						{
							ret = ERR_NOT_ENOUGH_RIGHT;
						}
					}
				}
				Unlock(u->lock);

				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
		ReleaseHub(hub);
	}

	return ret;
}

// Adds the login message to the Welcome pack: the OS support warning for the client, then msg
static void PackAddWelcomeMsg(PACK *p, RPC_WINVER *client_winver, wchar_t *msg)
{
	char *utf;
	wchar_t winver_msg_client[3800];
	UINT tmpsize;
	wchar_t *tmp;

	FormatUnsupportedWinVerMsg(winver_msg_client, sizeof(winver_msg_client), client_winver);

	tmpsize = UniStrSize(winver_msg_client) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

	tmp = ZeroMalloc(tmpsize);

	if (IsURLMsg(msg, NULL, 0) == false)
	{
		UniStrCat(tmp, tmpsize, winver_msg_client);
	}
	UniStrCat(tmp, tmpsize, msg);

	utf = CopyUniToUtf(tmp);

	PackAddData(p, "Msg", utf, StrLen(utf));

	Free(tmp);
	Free(utf);
}

bool ServerAccept(CONNECTION *c)
{
	bool ret = false;
	UINT err;
	PACK *p;
	char ip1[64], verstr[64];
	wchar_t *authtype_str;
	char username_real[MAX_SIZE];
	char method[MAX_SIZE];
	char hubname[MAX_SIZE];
	char username[MAX_SIZE];
	char groupname[MAX_SIZE];
	UCHAR session_key[SHA1_SIZE];
	UINT authtype;
	POLICY *policy;
	HUB *hub;
	SESSION *s = NULL;
	UINT64 user_expires = 0;
	bool use_encrypt;
	bool use_compress;
	bool half_connection;
	UINT adjust_mss;
	bool use_udp_acceleration_client;
	UINT client_udp_acceleration_max_version = 1;
	UINT udp_acceleration_version = 1;
	bool support_hmac_on_udp_acceleration_client = false;
	bool support_udp_accel_fast_disconnect_detect;
	bool use_hmac_on_udp_acceleration = false;
	bool supress_return_pack_error = false;
	IP udp_acceleration_client_ip;
	UCHAR udp_acceleration_client_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
	UCHAR udp_acceleration_client_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
	UINT udp_acceleration_client_port;
	bool admin_mode = false;
	UINT direction;
	UINT max_connection;
	UINT timeout;
	bool require_bridge_routing_mode;
	bool require_monitor_mode;
	bool use_client_license = false, use_bridge_license = false;
	bool local_host_session = false;
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	bool is_server_or_bridge = false;
	bool qos = false;
	bool no_save_password = false;
	NODE_INFO node;
	wchar_t *msg = NULL;
	bool suppress_client_update_notification = false;
	USER *loggedin_user_object = NULL;
	UCHAR unique[SHA1_SIZE], unique2[SHA1_SIZE];
	RPC_WINVER winver;
	UINT client_id;
	UCHAR mschap_v2_server_response_20[20];
	UINT ms_chap_error = 0;
	bool is_empty_password = false;

	if (c == NULL)
	{
		return false;
	}

	GenerateMachineUniqueHash(c->Cedar, unique2);

	Zero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));

	Zero(&udp_acceleration_client_ip, sizeof(udp_acceleration_client_ip));
	udp_acceleration_client_port = 0;
	Zero(udp_acceleration_client_key, sizeof(udp_acceleration_client_key));
	Zero(udp_acceleration_client_key_v2, sizeof(udp_acceleration_client_key_v2));

	Zero(&winver, sizeof(winver));

	StrCpy(groupname, sizeof(groupname), "");
	StrCpy(sessionname, sizeof(sessionname), "");

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (ServerDownloadSignature(c) == false)
	{
		supress_return_pack_error = true;

		goto CLEANUP;
	}

	if (ServerUploadHello(c) == false)
	{
		goto CLEANUP;
	}


	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		FreePack(p);
		c->Err = err;
		goto CLEANUP;
	}

	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
		SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
	{
		is_server_or_bridge = true;
	}

	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0)
	{
		bool auth_ret = false;

		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}

		Zero(&node, sizeof(node));
		InRpcNodeInfo(&node, p);

		c->Protocol = GetProtocolFromPack(p);

		authtype = GetAuthTypeFromPack(p);
		if (GetHubnameAndUsernameFromPack(p, username, sizeof(username), hubname, sizeof(hubname)) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, hubname);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL)
		{
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, hubname);
			goto CLEANUP;
		}

		if (hub->ForceDisableComm)
		{
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (ServerCheckHubAccess(c, hub) == false)
		{
			ReleaseHub(hub);
			hub = NULL;
			FreePack(p);
			c->Err = ERR_IP_ADDRESS_DENIED;
			goto CLEANUP;
		}

		Lock(hub->lock);
		{
			UINT cert_size = 0;
			void *cert_buf = NULL;
			USER *user;
			USERGROUP *group;
			char plain_password[MAX_PASSWORD_LEN + 1];

			if (hub->Halt || hub->Offline)
			{
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			use_encrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
			use_compress = PackGetInt(p, "use_compress") == 0 ? false : true;
			max_connection = PackGetInt(p, "max_connection");
			half_connection = PackGetInt(p, "half_connection") == 0 ? false : true;
			qos = PackGetInt(p, "qos") ? true : false;
			client_id = PackGetInt(p, "client_id");
			adjust_mss = PackGetInt(p, "adjust_mss");
			use_udp_acceleration_client = PackGetBool(p, "use_udp_acceleration");
			client_udp_acceleration_max_version = PackGetInt(p, "udp_acceleration_max_version");
			if (client_udp_acceleration_max_version == 0)
			{
				client_udp_acceleration_max_version = 1;
			}
			support_hmac_on_udp_acceleration_client = PackGetBool(p, "support_hmac_on_udp_acceleration");
			support_udp_accel_fast_disconnect_detect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

			if (c->CipherName != NULL)
			{
				Free(c->CipherName);
			}
			c->CipherName = NULL;

			if (c->SslVersion != NULL)
			{
				Free(c->SslVersion);
			}
			c->SslVersion = NULL;

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
			{
				c->CipherName = CopyStr(c->FirstSock->CipherName);
			}

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->SslVersion) == false)
			{
				c->SslVersion = CopyStr(c->FirstSock->SslVersion);
			}

			if (use_udp_acceleration_client)
			{
				PackGetData2(p, "udp_acceleration_client_key", udp_acceleration_client_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
				PackGetData2(p, "udp_acceleration_client_key_v2", udp_acceleration_client_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

				if (PackGetIp(p, "udp_acceleration_client_ip", &udp_acceleration_client_ip) == false)
				{
					use_udp_acceleration_client = false;
				}
				else
				{
					if (IsZeroIp(&udp_acceleration_client_ip))
					{
						Copy(&udp_acceleration_client_ip, &c->FirstSock->RemoteIP, sizeof(IP));
					}
					udp_acceleration_client_port = PackGetInt(p, "udp_acceleration_client_port");
					if (udp_acceleration_client_port == 0)
					{
						use_udp_acceleration_client = false;
					}
				}

				use_hmac_on_udp_acceleration = support_hmac_on_udp_acceleration_client;
			}


			require_bridge_routing_mode = PackGetBool(p, "require_bridge_routing_mode");
			require_monitor_mode = PackGetBool(p, "require_monitor_mode");
			if (require_monitor_mode)
			{
				qos = false;
			}

			if (is_server_or_bridge)
			{
				require_bridge_routing_mode = true;
			}

			Zero(unique, sizeof(unique));
			if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
			{
				PackGetData(p, "unique_id", unique);
			}

			authtype_str = _UU("LH_AUTH_UNKNOWN");
			switch (authtype)
			{
			case CLIENT_AUTHTYPE_ANONYMOUS:
				authtype_str = _UU("LH_AUTH_ANONYMOUS");
				break;
			case CLIENT_AUTHTYPE_PASSWORD:
				authtype_str = _UU("LH_AUTH_PASSWORD");
				break;
			case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
				authtype_str = _UU("LH_AUTH_PLAIN_PASSWORD");
				break;
			case CLIENT_AUTHTYPE_CERT:
				authtype_str = _UU("LH_AUTH_CERT");
				break;
			}
			IPToStr(ip1, sizeof(ip1), &c->FirstSock->RemoteIP);

			Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

			HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
				c->ClientStr, verstr, c->ClientBuild, authtype_str, username);

			auth_ret = SamAuthUserByAnonymous(hub, username);
			if (auth_ret)
			{
				is_empty_password = true;
			}

			if (auth_ret == false)
			{
				switch (authtype)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						PackGetData(p, "secure_password", secure_password);
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							UCHAR hashed_empty_password[SHA1_SIZE];
							UCHAR secure_empty_password[SHA1_SIZE];
							HashPassword(hashed_empty_password, username, "");
							SecurePassword(secure_empty_password, hashed_empty_password, c->Random);
							if(Cmp(secure_password, secure_empty_password, SHA1_SIZE)==0){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					{
						POLICY *pol = NULL;

						Zero(plain_password, sizeof(plain_password));
						PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
						if (StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG))
						{
							// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
							Zero(plain_password, sizeof(plain_password));
						}

						if (auth_ret == false)
						{
							UCHAR secure_password[SHA1_SIZE];
							UCHAR hash_password[SHA1_SIZE];
							bool is_mschap = StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG);

							HashPassword(hash_password, username, plain_password);
							SecurePassword(secure_password, hash_password, c->Random);

							if (is_mschap == false)
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);
							}
							else
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password,
									plain_password, mschap_v2_server_response_20, &ms_chap_error);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (auth_ret == false)
						{
							auth_ret = SamAuthUserByPlainPassword(hub, username, plain_password);

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							if(IsEmptyStr(plain_password)){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_CERT:
					cert_size = PackGetDataSize(p, "cert");
					if (cert_size >= 1 && cert_size <= 100000)
					{
						cert_buf = ZeroMalloc(cert_size);
						if (PackGetData(p, "cert", cert_buf))
						{
							UCHAR sign[4096 / 8];
							UINT sign_size = PackGetDataSize(p, "sign");
							if (sign_size <= sizeof(sign) && sign_size >= 1)
							{
								if (PackGetData(p, "sign", sign))
								{
									BUF *b = NewBuf();
									X *x;
									WriteBuf(b, cert_buf, cert_size);
									x = BufToX(b, false);
									if (x != NULL && x->is_compatible_bit &&
										sign_size == (x->bits / 8))
									{
										K *k = GetKFromX(x);
										if (RsaVerifyEx(c->Random, SHA1_SIZE, sign, sign_size, k))
										{
											// A matching signature proves the client holds this certificate.
											auth_ret = SamAuthUserByCert(hub, username, x);
											if (auth_ret)
											{
												c->ClientX = CloneX(x);
											}
										}
										FreeK(k);
									}
									FreeX(x);
									FreeBuf(b);
								}
							}
						}
						Free(cert_buf);
					}
					break;

				default:
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					goto CLEANUP;
				}
			}

			if (auth_ret == false)
			{
				char ip[64];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_AUTH_NG", c->Name, username, ip);

				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				if (ms_chap_error != 0)
				{
					c->Err = ms_chap_error;
				}
				goto CLEANUP;
			}
			else
			{
				if (is_empty_password)
				{
					const SOCK *s = c->FirstSock;
					if (s != NULL && IsLocalHostIP(&s->RemoteIP) == false)
					{
						if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || GetHubAdminOption(hub, "deny_empty_password") != 0)
						{
							// Reject remote logins with an empty password.
							HLog(hub, "LH_LOCAL_ONLY", c->Name, username);

							Unlock(hub->lock);
							ReleaseHub(hub);
							FreePack(p);
							c->Err = ERR_NULL_PASSWORD_LOCAL_ONLY;
							goto CLEANUP;
						}
					}
				}

				HLog(hub, "LH_AUTH_OK", c->Name, username);
			}

			policy = NULL;

			FreePack(p);

			if (StrCmpi(username, ADMINISTRATOR_USERNAME) != 0)
			{
				user = AcGetUser(hub, username);
				if (user == NULL)
				{
					user = AcGetUser(hub, "*");
					if (user == NULL)
					{
						Unlock(hub->lock);
						ReleaseHub(hub);
						c->Err = ERR_ACCESS_DENIED;
						goto CLEANUP;
					}
				}

				policy = NULL;

				Lock(user->lock);
				{
					user_expires = user->ExpireTime;

					StrCpy(username_real, sizeof(username_real), user->Name);
					group = user->Group;
					if (group != NULL)
					{
						AddRef(group->ref);

						Lock(group->lock);
						{
							StrCpy(groupname, sizeof(groupname), group->Name);
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
				loggedin_user_object = user;
			}
			else
			{
				admin_mode = true;
				StrCpy(username_real, sizeof(username_real), ADMINISTRATOR_USERNAME);

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

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_VERSION_INVALID;
				Free(policy);
				goto CLEANUP;
			}

			if (hub->Option->RequiredClientId != 0 &&
				hub->Option->RequiredClientId != client_id && 
				InStrEx(c->ClientStr, "client", false))
			{
				HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, client_id, hub->Option->RequiredClientId);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_CLIENT_ID_REQUIRED;
				Free(policy);
				goto CLEANUP;
			}

			if (user_expires != 0 && user_expires <= SystemTime64())
			{
				HLog(hub, "LH_USER_EXPIRES", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (policy->Access == false)
			{
				HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, username);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_ACCESS_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (require_monitor_mode && policy->MonitorPort == false)
			{
				HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_MONITOR_MODE_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (policy->MonitorPort)
			{
				if (require_monitor_mode == false)
				{
					policy->MonitorPort = false;
				}
			}

			if (policy->MonitorPort)
			{
				qos = false;
			}

			if (require_bridge_routing_mode &&
				(policy->NoBridge && policy->NoRouting))
			{
				HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_BRIDGE_MODE_DENIED;
				Free(policy);
				goto CLEANUP;
			}

			if (require_bridge_routing_mode == false)
			{
				policy->NoBridge = true;
				policy->NoRouting = true;
			}

			if (Cmp(unique, unique2, SHA1_SIZE) == 0)
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

			if (local_host_session == false)
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

					num = HubCountUserSessions(hub, username, node.UniqueId);

					Lock(hub->lock);

					if (num >= max_logins)
					{
						Unlock(hub->lock);

						HLog(hub, "LH_TOO_MANY_MULTILOGINS",
							c->Name,
							username, max_logins, num);

						ReleaseHub(hub);
						c->Err = ERR_TOO_MANY_USER_SESSION;
						Free(policy);
						goto CLEANUP;
					}
				}
			}

			if (loggedin_user_object != NULL)
			{
				Lock(loggedin_user_object->lock);
				{
					loggedin_user_object->LastLoginTime = SystemTime64();
				}
				Unlock(loggedin_user_object->lock);
			}

			hub->LastCommTime = hub->LastLoginTime = SystemTime64();

			if (admin_mode == false)
			{
				if (hub->Option->MaxSession != 0 &&
					hub->Option->MaxSession <= Count(hub->NumSessions))
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
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

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_client_license)
			{
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
					Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client"))
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (use_bridge_license)
			{
				if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
					Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge"))
				{
					Unlock(hub->lock);

					HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

					ReleaseHub(hub);
					c->Err = ERR_HUB_IS_BUSY;
					Free(policy);
					goto CLEANUP;
				}
			}

			if (Count(hub->Cedar->CurrentSessions) >= SERVER_MAX_SESSIONS)
			{
				Unlock(hub->lock);

				HLog(hub, "LH_MAX_SESSION_2", c->Name, SERVER_MAX_SESSIONS);

				ReleaseHub(hub);
				c->Err = ERR_HUB_IS_BUSY;
				Free(policy);
				goto CLEANUP;
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

			timeout = policy->TimeOut * 1000;
			if (timeout == 0)
			{
				timeout = TIMEOUT_DEFAULT;
			}
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			max_connection = MIN(max_connection, policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (half_connection)
			{
				// Half connection needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
			}

			if (qos)
			{
				// VoIP / QoS needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
				if (half_connection)
				{
					max_connection = MAX(max_connection, 4);
				}
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			DelConnection(c->Cedar, c);

			StrLower(username);
			s = NewServerSession(c->Cedar, c, hub, username, policy);

			s->LocalHostSession = local_host_session;
			s->NormalClient = true;

			IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

			StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

			AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

			s->NoSendSignature = c->Cedar->Server->NoSendSignature;

			if (use_udp_acceleration_client)
			{
				s->UseUdpAcceleration = true;

				s->UdpAccelFastDisconnectDetect = support_udp_accel_fast_disconnect_detect;

				udp_acceleration_version = 1;
				if (client_udp_acceleration_max_version >= 2)
				{
					udp_acceleration_version = 2;
				}
			}

			if (hub->Option->DisableUdpAcceleration)
			{
				s->UseUdpAcceleration = false;
			}

			if (s->UseUdpAcceleration)
			{
				s->UseHMacOnUdpAcceleration = use_hmac_on_udp_acceleration;
			}


			if (s->UseUdpAcceleration)
			{
				s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false, false);
				if (s->UdpAccel == NULL)
				{
					s->UseUdpAcceleration = false;
				}
				else
				{
					s->UdpAccel->Version = udp_acceleration_version;

					if (UdpAccelInitServer(s->UdpAccel,
						s->UdpAccel->Version == 2 ? udp_acceleration_client_key_v2 : udp_acceleration_client_key,
						&c->FirstSock->RemoteIP, &udp_acceleration_client_ip, udp_acceleration_client_port) == false)
					{
						s->UseUdpAcceleration = false;
					}

					s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

					if (use_encrypt == false)
					{
						s->UdpAccel->PlainTextMode = true;
					}

					s->UdpAccel->UseHMac = s->UseHMacOnUdpAcceleration;

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_Ver", s->UdpAccel->Version);

					AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), s->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

					AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(s->UdpAccel));
				}
			}

			s->AdjustMss = adjust_mss;
			if (s->AdjustMss != 0)
			{
				AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);
			}

			s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
			s->IsMonitorMode = policy->MonitorPort;

			s->IPv6Session = false;

			if (node.ClientIpAddress == 0)
			{
				s->IPv6Session = true;
			}

			if (use_bridge_license)
			{
				Inc(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Inc(s->Cedar->AssignedClientLicense);
			}

			if (StrLen(sessionname) != 0)
			{
				Free(s->Name);
				s->Name = CopyStr(sessionname);
			}

			{
				char ip[128];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort, c->FirstSock->UnderlayProtocol, c->FirstSock->ProtocolDetails);
			}

			c->Session = s;
			StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username_real);
			StrCpy(s->GroupName, sizeof(s->GroupName), groupname);

			Copy(session_key, s->SessionKey, SHA1_SIZE);

			s->MaxConnection = max_connection;
			s->UseEncrypt = use_encrypt;
			s->UseCompress = use_compress;
			s->HalfConnection = half_connection;
			s->Timeout = timeout;
			s->QoS = qos;
			s->VLanId = policy->VLanId;

			s->Username = CopyStr(username);

			HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
				s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
				s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
				s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
				s->Timeout / 1000);

			msg = GetHubMsg(hub);

			suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
		}
		Unlock(hub->lock);

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local).
			// This is done after releasing the hub lock because the query may block for a while.
			UdpAccelQueryStun(s->UdpAccel, &c->FirstSock->RemoteIP);
		}

		p = PackWelcome(s);

		PackAddBool(p, "suppress_client_update_notification", suppress_client_update_notification);

		PackAddWelcomeMsg(p, &winver, msg);

		Free(msg);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		Copy(&c->Session->NodeInfo, &node, sizeof(NODE_INFO));


		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);

			if (s->VLanId != 0)
			{
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
			}
		}

		StartTunnelingMode(c);

		if (s->HalfConnection)
		{
			// The first socket's direction is client to server.
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->LocalHostSession)
		{
			RefreshLocalMacAddressList();
		}

		DeleteAllUserListCache(hub->UserList);


		s->NumLoginIncrementUserObject = loggedin_user_object;
		s->NumLoginIncrementHubObject = s->Hub;
		s->NumLoginIncrementTick = Tick64() + (UINT64)NUM_LOGIN_INCREMENT_INTERVAL;
		SessionMain(s);


		DeleteAllUserListCache(hub->UserList);

		Lock(s->Hub->lock);
		{
			if (use_bridge_license)
			{
				Dec(hub->NumSessionsBridge);
			}

			if (use_client_license)
			{
				Dec(hub->NumSessionsClient);
			}

			Dec(s->Hub->NumSessions);
			Dec(s->Hub->Cedar->CurrentSessions);

			if (use_bridge_license)
			{
				Dec(s->Cedar->AssignedBridgeLicense);
			}

			if (use_client_license)
			{
				Dec(s->Cedar->AssignedClientLicense);
			}
		}
		Unlock(s->Hub->lock);

		HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

		if (s->UdpAccel != NULL)
		{
			FreeUdpAccel(s->UdpAccel);
			s->UdpAccel = NULL;
		}

		ReleaseSession(s);

		ret = true;
		c->Err = ERR_SESSION_REMOVED;

		ReleaseHub(hub);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "additional_connect") == 0)
	{
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		if (GetSessionKeyFromPack(p, session_key, &dummy) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt)
		{
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
			{
				c->Err = ERR_INVALID_PROTOCOL;
			}
		}
		Unlock(s->lock);
		Lock(s->Connection->lock);
		if (c->Err == 0)
		{
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
			{
				c->Err = ERR_TOO_MANY_CONNECTION;
			}
		}
		if (c->Err != 0)
		{
			Unlock(s->Connection->lock);
			ReleaseSession(s);
			goto CLEANUP;
		}

		sock = c->FirstSock;

		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection)
			{
				// In half-connection mode, set this socket's direction from the directions of the existing TCP connections.
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0;i < LIST_NUM(s->Connection->Tcp->TcpSockList);i++)
				{
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
					{
						s2c++;
					}
					else
					{
						c2s++;
					}
				}
				if (s2c > c2s)
				{
					direction = TCP_CLIENT_TO_SERVER;
				}
				else
				{
					direction = TCP_SERVER_TO_CLIENT;
				}
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		p = PackError(ERR_NO_ERROR);
		PackAddInt(p, "direction", direction);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		SetTimeout(sock, INFINITE);

		LockList(s->Connection->Tcp->TcpSockList);
		{
			Add(s->Connection->Tcp->TcpSockList, ts);
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		Inc(s->Connection->CurrentNumConnection);

		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	}
	else if (StrCmpi(method, "enum_hub") == 0)
	{
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0;i < num;i++)
			{
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option->NoEnum == false)
				{
					Insert(o, CopyStr(h->Name));
				}
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0;i < num;i++)
		{
			char *name = LIST_DATA(o, i);
			PackAddStrEx(p, "HubName", name, i, num);
			Free(name);
		}
		ReleaseList(o);
		PackAddInt(p, "NumHub", num);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		FreePack(HttpServerRecv(c->FirstSock));
		c->Err = 0;

		SLog(c->Cedar, "LS_ENUM_HUB", c->Name, num);

		goto CLEANUP;
	}
	else if (StrCmpi(method, "admin") == 0)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR)
		{
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		goto CLEANUP;
	}
	else if (StrCmpi(method, "password") == 0)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		goto CLEANUP;
	}
	else
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		goto CLEANUP;
	}

CLEANUP:
	if (loggedin_user_object != NULL)
	{
		ReleaseUser(loggedin_user_object);
	}


	if (supress_return_pack_error == false)
	{
		p = PackError(c->Err);
		PackAddBool(p, "no_save_password", no_save_password);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
	}

	FreePack(HttpServerRecv(c->FirstSock));

	SleepThread(25);

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);

	return ret;
}


static void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	wchar_t namew[256];
	char namea[256];
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();


	Zero(info, sizeof(NODE_INFO));

	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	info->ClientProductVer = Endian32(c->ClientVer);
	info->ClientProductBuild = Endian32(c->ClientBuild);

	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	info->ServerProductVer = Endian32(c->ServerVer);
	info->ServerProductBuild = Endian32(c->ServerBuild);

	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	Zero(namew, sizeof(namew));
	MsGetComputerNameFullEx(namew, sizeof(namew), true);

	Zero(namea, sizeof(namea));
	UniToStr(namea, sizeof(namea), namew);

	if (IsEmptyStr(namea))
	{
		GetMachineName(namea, sizeof(namea));
	}

	StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);

	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.address, sizeof(info->ClientIpAddress6));
	}
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	if (s->ClientOption->ProxyType == PROXY_DIRECT)
	{
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ServerIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(info->ServerIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ServerIpAddress6));
		}
	}
	else if (GetIP(&ip, info->ServerHostname))
	{
		if (IsIP6(&ip) == false)
		{
			info->ServerIpAddress = IPToUINT(&ip);
		}
		else
		{
			Copy(info->ServerIpAddress6, ip.address, sizeof(info->ServerIpAddress6));
		}
	}
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ProxyIpAddress6));
		}

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

static SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	if (c == NULL)
	{
		return NULL;
	}

	s = ClientConnectGetSocket(c, true);
	if (s == NULL)
	{
		return NULL;
	}

	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	if (StartSSLEx(s, NULL, NULL, c->ServerName) == false)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		// The server of an additional connection presents another certificate than the
		// first one: drop the socket and fail, like the other failures above
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	return s;
}

bool ClientAdditionalConnect(CONNECTION *c)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	if (c == NULL)
	{
		return false;
	}

	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadAuth2(c, s) == false)
	{
		goto CLEANUP;
	}

	p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
	{
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}


	ts = NewTcpSock(s);

	if (c->ServerMode == false)
	{
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
		{
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);

	Cancel(c->Session->Cancel1);

	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return true;

CLEANUP:
	Disconnect(s);
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);

		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

static void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(thread);

	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Expired);
	p->UserSelected = true;
}

static bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	bool ret;
	UINT64 start;
	if (c == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	auth = c->Session->ClientAuth;

	if (auth->CheckCertProc == NULL)
	{
		return false;
	}

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL)
	{
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			start = Tick64();
			// No NOOP here: the user is asked before the signature is sent.
		}
		if (p->UserSelected)
		{
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
	{
		*expired = p->Expired;
	}

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

bool ClientConnect(CONNECTION *c)
{
	bool ret = false;
	bool ok = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	POLICY *policy;
	bool expired = false;
	IP server_ip;
	UINT utf_size;
	char *utf;
	wchar_t *msg;
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL)
	{
		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}
		PrintStatus(sess, L"free");
		return false;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Prompt user whether to continue on verification errors
	if ((c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH || c->Err == ERR_SERVER_CERT_EXPIRES) && ClientCheckServerCert(c, &expired) == false)
	{
		if (expired)
		{
			c->Err = ERR_SERVER_CERT_EXPIRES;
		}

		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}

		goto CLEANUP;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false)
	{
		if (sess->ClientOption->ProxyType == PROXY_DIRECT)
		{
			if (s->Type == SOCK_TCP)
			{
				if (sess->UdpAccel == NULL)
				{
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true);

					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}


	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	PrintStatus(sess, _UU("STATUS_6"));

	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	p = HttpClientRecvEx(s, CLIENT_WELCOME_PACK_MAX_SIZE);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	if (err != 0)
	{
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	utf_size = PackGetDataSize(p, "Msg");
	utf = ZeroMalloc(utf_size + 8);
	PackGetData(p, "Msg", utf);

	msg = CopyUtfToUni(utf);

	if (IsEmptyUniStr(msg) == false)
	{
		if (c->Session->Client_Message != NULL)
		{
			Free(c->Session->Client_Message);
		}

		c->Session->Client_Message = msg;
	}
	else
	{
		Free(msg);
	}

	Free(utf);

	PrintStatus(sess, _UU("STATUS_7"));

	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;


	Lock(c->Session->lock);
	{
		c->Session->MaxConnection = PackGetInt(p, "max_connection");
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, c->Session->ClientOption->MaxConnection);
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, MAX_TCP_CONNECTION);
		c->Session->MaxConnection = MAX(c->Session->MaxConnection, 1);
		c->Session->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
		c->Session->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
		c->Session->NoSendSignature = PackGetBool(p, "no_send_signature");
		c->Session->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
		c->Session->Timeout = PackGetInt(p, "timeout");
		// Clamped to the bounds of ServerAccept: the server chooses it, and GenNextKeepAliveSpan divides it by 2
		c->Session->Timeout = MIN(c->Session->Timeout, TIMEOUT_MAX);
		c->Session->Timeout = MAX(c->Session->Timeout, TIMEOUT_MIN);
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
		{
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		}
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;
		sess->UseHMacOnUdpAcceleration = false;

		if (sess->UdpAccel != NULL)
		{
			sess->UdpAccel->UseHMac = false;

			sess->UdpAccelFastDisconnectDetect = false;

			if (PackGetBool(p, "use_udp_acceleration"))
			{
				UINT udp_acceleration_version = PackGetInt(p, "udp_acceleration_version");
				IP udp_acceleration_server_ip;

				if (udp_acceleration_version == 0)
				{
					udp_acceleration_version = 1;
				}

				sess->UdpAccelFastDisconnectDetect = PackGetBool(p, "udp_accel_fast_disconnect_detect");

				if (PackGetIp(p, "udp_acceleration_server_ip", &udp_acceleration_server_ip))
				{
					UINT udp_acceleration_server_port = PackGetInt(p, "udp_acceleration_server_port");

					if (IsZeroIp(&udp_acceleration_server_ip))
					{
						Copy(&udp_acceleration_server_ip, &s->RemoteIP, sizeof(IP));
					}

					if (udp_acceleration_server_port != 0)
					{
						UCHAR udp_acceleration_server_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
						UCHAR udp_acceleration_server_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
						UINT server_cookie = PackGetInt(p, "udp_acceleration_server_cookie");
						UINT client_cookie = PackGetInt(p, "udp_acceleration_client_cookie");
						bool encryption = PackGetBool(p, "udp_acceleration_use_encryption");

						Zero(udp_acceleration_server_key, sizeof(udp_acceleration_server_key));
						Zero(udp_acceleration_server_key_v2, sizeof(udp_acceleration_server_key_v2));

						PackGetData2(p, "udp_acceleration_server_key", udp_acceleration_server_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
						PackGetData2(p, "udp_acceleration_server_key_v2", udp_acceleration_server_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

						if (server_cookie != 0 && client_cookie != 0)
						{
							IP remote_ip;

							Copy(&remote_ip, &s->RemoteIP, sizeof(IP));

							sess->UdpAccel->Version = 1;
							if (udp_acceleration_version == 2)
							{
								sess->UdpAccel->Version = 2;
							}

							if (UdpAccelInitClient(sess->UdpAccel,
								sess->UdpAccel->Version == 2 ? udp_acceleration_server_key_v2 : udp_acceleration_server_key,
								&remote_ip, &udp_acceleration_server_ip, udp_acceleration_server_port,
								server_cookie, client_cookie))
							{
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UseHMacOnUdpAcceleration = PackGetBool(p, "use_hmac_on_udp_acceleration");

								if (sess->UseHMacOnUdpAcceleration)
								{
									sess->UdpAccel->UseHMac = true;
								}

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_Ver", sess->UdpAccel->Version);

								AddProtocolDetailsStr(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), sess->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(sess->UdpAccel));
							}
						}
					}
				}
			}
		}
	}
	Unlock(c->Session->lock);


	if (sess->UseUdpAcceleration == false)
	{
		if (sess->UdpAccel != NULL)
		{
			FreeUdpAccel(sess->UdpAccel);
			sess->UdpAccel = NULL;
		}
	}

	Lock(c->lock);
	{
		if (c->Name != NULL)
		{
			Free(c->Name);
		}
		c->Name = CopyStr(connection_name);

		if (c->CipherName != NULL)
		{
			Free(c->CipherName);
		}

		c->CipherName = CopyStr(c->FirstSock->CipherName);

		if (c->SslVersion != NULL)
		{
			Free(c->SslVersion);
		}

		c->SslVersion = CopyStr(c->FirstSock->SslVersion);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
		{
			Free(c->Session->Name);
		}
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	FreePack(p);
	p = NULL;


	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	PrintStatus(sess, L"free");

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
	{
		ret = true;
	}

CLEANUP:
	// StopConnection reads c->FirstSock and takes its ref under c->lock
	Lock(c->lock);
	{
		c->FirstSock = NULL;
	}
	Unlock(c->lock);

	if (sess->UdpAccel != NULL)
	{
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
	{
		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);


	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	*policy = PackGetPolicy(p);
	if (*policy == NULL)
	{
		return false;
	}

	return true;
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

#define	PACK_ADD_POLICY_BOOL(name, value)	\
	PackAddBool(p, "policy:" name, y->value == false ? 0 : 1)
#define	PACK_ADD_POLICY_UINT(name, value)	\
	PackAddInt(p, "policy:" name, y->value)
#define	PACK_GET_POLICY_BOOL(name, value)	\
	y->value = (PackGetBool(p, "policy:" name))
#define	PACK_GET_POLICY_UINT(name, value)	\
	y->value = PackGetInt(p, "policy:" name)

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

POLICY *PackGetPolicy(PACK *p)
{
	POLICY *y;
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// Ver 2
	PACK_GET_POLICY_BOOL("Access", Access);
	PACK_GET_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_GET_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_GET_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_GET_POLICY_BOOL("NoBridge", NoBridge);
	PACK_GET_POLICY_BOOL("NoRouting", NoRouting);
	PACK_GET_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_GET_POLICY_BOOL("NoServer", NoServer);
	PACK_GET_POLICY_BOOL("CheckMac", CheckMac);
	PACK_GET_POLICY_BOOL("CheckIP", CheckIP);
	PACK_GET_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_GET_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_GET_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_GET_POLICY_BOOL("FixPassword", FixPassword);
	PACK_GET_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_GET_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_GET_POLICY_BOOL("RAFilter", RAFilter);
	PACK_GET_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_GET_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_GET_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_GET_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_GET_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_GET_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_GET_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_GET_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_GET_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_GET_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_GET_POLICY_UINT("TimeOut", TimeOut);
	PACK_GET_POLICY_UINT("MaxMac", MaxMac);
	PACK_GET_POLICY_UINT("MaxIP", MaxIP);
	PACK_GET_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_GET_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_GET_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_GET_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_GET_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_GET_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PACK_GET_POLICY_BOOL("Ver3", Ver3);

	return y;
}

void PackAddPolicy(PACK *p, POLICY *y)
{
	if (p == NULL || y == NULL)
	{
		return;
	}

	// Ver 2
	PACK_ADD_POLICY_BOOL("Access", Access);
	PACK_ADD_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_ADD_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_ADD_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_ADD_POLICY_BOOL("NoBridge", NoBridge);
	PACK_ADD_POLICY_BOOL("NoRouting", NoRouting);
	PACK_ADD_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_ADD_POLICY_BOOL("NoServer", NoServer);
	PACK_ADD_POLICY_BOOL("CheckMac", CheckMac);
	PACK_ADD_POLICY_BOOL("CheckIP", CheckIP);
	PACK_ADD_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_ADD_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_ADD_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_ADD_POLICY_BOOL("FixPassword", FixPassword);
	PACK_ADD_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_ADD_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_ADD_POLICY_BOOL("RAFilter", RAFilter);
	PACK_ADD_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_ADD_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_ADD_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_ADD_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_ADD_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_ADD_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_ADD_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_ADD_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_ADD_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_ADD_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_ADD_POLICY_UINT("TimeOut", TimeOut);
	PACK_ADD_POLICY_UINT("MaxMac", MaxMac);
	PACK_ADD_POLICY_UINT("MaxIP", MaxIP);
	PACK_ADD_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_ADD_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_ADD_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_ADD_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_ADD_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_ADD_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	if (c == NULL)
	{
		return false;
	}

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

bool ClientUploadAuth(CONNECTION *c)
{
	PACK *p = NULL;
	CLIENT_AUTH *a;
	CLIENT_OPTION *o;
	bool ret;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	if (c == NULL)
	{
		return false;
	}

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		p = PackLoginWithAnonymous(o->HubName, a->Username);
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		SecurePassword(secure_password, a->HashedPassword, c->Random);
		p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
			a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
		{
			if (RsaSignEx(sign, sizeof(sign), c->Random, SHA1_SIZE, a->ClientK))
			{
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;
	}

	if (p == NULL)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		return false;
	}

	PackAddClientVersion(p, c);

	PackAddInt(p, "protocol", c->Protocol);

	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", 0);

	PackAddInt(p, "max_connection", o->MaxConnection);
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	GenerateMachineUniqueHash(c->Cedar, unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun)
		{
			Copy(&my_ip, &c->Session->UdpAccel->StunIp, sizeof(my_ip));
			my_port = c->Session->UdpAccel->StunPort;
		}
		else if (IsLocalHostIP(&c->Session->UdpAccel->MyIp) == false)
		{
			Copy(&my_ip, &c->Session->UdpAccel->MyIp, sizeof(my_ip));
		}
		else
		{
			Zero(&my_ip, sizeof(my_ip));
		}

		PackAddIp(p, "udp_acceleration_client_ip", &my_ip);
		PackAddInt(p, "udp_acceleration_client_port", my_port);
		PackAddData(p, "udp_acceleration_client_key", c->Session->UdpAccel->MyKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackAddData(p, "udp_acceleration_client_key_v2", c->Session->UdpAccel->MyKey_V2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);
		PackAddBool(p, "support_hmac_on_udp_acceleration", true);
		PackAddBool(p, "support_udp_accel_fast_disconnect_detect", true);
		PackAddInt(p, "udp_acceleration_max_version", 2);
	}

	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreePack(p);

	return ret;
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

bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	if (c == NULL)
	{
		return false;
	}

	p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		c->Err = err;
		FreePack(p);
		return false;
	}

	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
	{
		Copy(c->Random, random, SHA1_SIZE);
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

bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));


	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = WaterMarkSize + rand_size;
	water = Malloc(water_size);
	Copy(water, WaterMark, WaterMarkSize);
	Rand(&water[WaterMarkSize], rand_size);

	if (PostHttp(s, h, water, water_size) == false)
	{
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

// Set c->FirstSock under c->lock, where StopConnection reads it and takes its ref
static void ClientSetFirstSock(CONNECTION *c, SOCK *s)
{
	Lock(c->lock);
	{
		c->FirstSock = s;
	}
	Unlock(c->lock);
}

SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
	{
		return NULL;
	}

	// StopConnection reads c->FirstSock and takes its ref under c->lock
	ClientSetFirstSock(c, s);

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	UINT err = 0;
	if (StartSSLEx3(s, x, k, NULL, c->ServerName, c->Session->SslOption, &err) == false)
	{
		Disconnect(s);
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		if (err != 0)
		{
			c->Err = err;
		}
		else
		{
			c->Err = ERR_SERVER_IS_NOT_VPN;
		}
		return NULL;
	}

	if (err != 0)
	{
		c->Err = err;
	}

	if (s->RemoteX == NULL)
	{
		Disconnect(s);
		ClientSetFirstSock(c, NULL);
		ReleaseSock(s);
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect)
{
	volatile bool *cancel_flag = NULL;
	char hostname[MAX_HOST_NAME_LEN];

	bool save_resolved_ip = false;
	CLIENT_OPTION *o;
	SESSION *sess;
	SOCK *sock = NULL;
	IP resolved_ip;
	if (c == NULL || c->Session == NULL || c->Session->ClientOption == NULL)
	{
		return NULL;
	}

	cancel_flag = &c->Halt;
	sess = c->Session;
	o = c->Session->ClientOption;

	Zero(&resolved_ip, sizeof(resolved_ip));

	if (additional_connect == false && c->RestoreServerNameAndPort)
	{
		// RestoreServerNameAndPort is currently never true.
		c->RestoreServerNameAndPort = false;

		if (StrCmpi(c->ServerName, o->Hostname) != 0)
		{
			StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);
		}

		c->ServerPort = o->Port;
	}

	if (additional_connect && IsZeroIP(&sess->ServerIP_CacheForNextConnect) == false)
	{
		IPToStr(hostname, sizeof(hostname), &sess->ServerIP_CacheForNextConnect);
	}
	else
	{
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false)
		{
			save_resolved_ip = true;
		}
	}

	if (o->ProxyType == PROXY_DIRECT)
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), hostname);
		PrintStatus(sess, tmp);

		{
			IP		*localIP;
			UINT	localport;


			if (additional_connect == false) {
				if (sess->ClientOption->NoRoutingTracking == false) {
					localIP = BIND_LOCALIP_NULL;
				}
				else {
					// Nonzero address is for source IP address to bind. Zero address is for dummy not to bind.
					if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
						localIP = BIND_LOCALIP_NULL;
					}
					else {
						localIP = &sess->ClientOption->BindLocalIP;
					}
				}
			}
			else {
				// Bind to the local IP address of the first TCP/IP connection.
				localIP = &sess->LocalIP_CacheForNextConnect;
			}
			if (sess->ClientOption->BindLocalPort == 0) {
				localport = BIND_LOCALPORT_NULL;
			}
			else {
				localport = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
			}

			sock = BindTcpIpConnectEx(localIP, localport, hostname, c->ServerPort,
				(bool *)cancel_flag, c->hWndForUI, &resolved_ip);
		}

		if (sock == NULL)
		{
			c->Err = ERR_CONNECT_FAILED;

			return NULL;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		PROXY_PARAM_OUT out;
		PROXY_PARAM_IN in;
		UINT ret;

		Zero(&in, sizeof(in));

		in.Timeout = 0;

		StrCpy(in.TargetHostname, sizeof(in.TargetHostname), c->ServerName);
		in.TargetPort = c->ServerPort;

		StrCpy(in.Hostname, sizeof(in.Hostname), IsEmptyStr(hostname) ? o->ProxyName : hostname);
		in.Port = o->ProxyPort;

		StrCpy(in.Username, sizeof(in.Username), o->ProxyUsername);
		StrCpy(in.Password, sizeof(in.Password), o->ProxyPassword);

		StrCpy(in.HttpCustomHeader, sizeof(in.HttpCustomHeader), o->CustomHttpHeader);
		StrCpy(in.HttpUserAgent, sizeof(in.HttpUserAgent), c->Cedar->HttpUserAgent);

		if (additional_connect == false) {
			if (sess->ClientOption->NoRoutingTracking == false) {
				in.BindLocalIP = BIND_LOCALIP_NULL;
			}
			else {
				if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
					in.BindLocalIP = BIND_LOCALIP_NULL;
				}
				else {
					in.BindLocalIP = &sess->ClientOption->BindLocalIP;
				}
			}
		}
		else {
			in.BindLocalIP = &sess->LocalIP_CacheForNextConnect;
		}
		if (sess->ClientOption->BindLocalPort == 0) {
			in.BindLocalPort = BIND_LOCALPORT_NULL;
		}
		else {
			in.BindLocalPort = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
		}

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), in.TargetHostname, in.Hostname);
		PrintStatus(sess, tmp);

		// An unknown proxy type gives PROXY_ERROR_PARAMETER, which is ERR_INTERNAL_ERROR
		ret = ProxyConnect(o->ProxyType, &out, &in, cancel_flag);

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR)
		{
			return NULL;
		}

		sock = out.Sock;

		CopyIP(&resolved_ip, &out.ResolvedIp);
	}

	if (additional_connect == false || IsZeroIP(&sock->RemoteIP))
	{
		if (IsZeroIP(&sock->RemoteIP) == false || (sock->IPv6 && GetIP6(&c->Session->ServerIP, hostname) == false) || (sock->IPv6 == false && GetIP4(&c->Session->ServerIP, hostname) == false))
		{
			Copy(&c->Session->ServerIP, &sock->RemoteIP, sizeof(c->Session->ServerIP));
		}
	}

	if (save_resolved_ip && IsZeroIP(&resolved_ip) == false)
	{
		Copy(&c->Session->ServerIP_CacheForNextConnect, &resolved_ip, sizeof(c->Session->ServerIP_CacheForNextConnect));
	}

	if (additional_connect == false) {
		c->Session->LocalIP_CacheForNextConnect = sock->LocalIP;
	}

	return sock;
}

UINT ProxyCodeToCedar(UINT code)
{
	switch (code)
	{
	case PROXY_ERROR_SUCCESS:
		return ERR_NO_ERROR;
	case PROXY_ERROR_GENERIC:
	case PROXY_ERROR_VERSION:
		return ERR_PROXY_ERROR;
	case PROXY_ERROR_CANCELED:
		return ERR_USER_CANCEL;
	case PROXY_ERROR_CONNECTION:
		return ERR_PROXY_CONNECT_FAILED;
	case PROXY_ERROR_TARGET:
		return ERR_CONNECT_FAILED;
	case PROXY_ERROR_DISCONNECTED:
		return ERR_DISCONNECTED;
	case PROXY_ERROR_AUTHENTICATION:
		return ERR_PROXY_AUTH_FAILED;
	default:
		return ERR_INTERNAL_ERROR;
	}
}

SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
	SOCK *s = NULL;
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	s = BindConnectEx4(localIP, localport, hostname, port, 0, cancel_flag, true, ret_ip);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
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

bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
	{
		return false;
	}
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "random", random) == false)
	{
		return false;
	}

	return true;
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

PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	PackAddData(p, "sign", sign, sign_size);

	return p;
}

PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}
