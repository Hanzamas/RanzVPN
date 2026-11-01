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
#include "ProtocolInternal.h"

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x) {
	bool ret = false;
	if (x == NULL)
		return false;

	if (x->root_cert)
		return true;

	LIST *o = NewCertList(true);

	ret = TryGetRootCertChain(o, x, true, NULL);

	FreeCertList(o);

	return ret;
}

bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x) {
	bool ret = false;
	LIST *chain = NULL;
	LIST *current_chain_dir = NULL;
	if (o == NULL || x == NULL)
		return false;

	chain = NewCertList(false);

	ret = TryGetParentCertFromCertList(o, x, chain);

	if (ret) {
		DIRLIST *dir;
		wchar_t dirname[MAX_SIZE];
		wchar_t exedir[MAX_SIZE];

		GetExeDirW(exedir, sizeof(exedir));
		CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");
		MakeDirExW(dirname);

		if (auto_save) {
			dir = EnumDirW(dirname);
			if (dir != NULL) {
				for (UINT i = 0; i < dir->NumFiles; i++) {
					DIRENT *e = dir->File[i];

					if (e->Folder == false) {
						if (UniStartWith(e->FileNameW, AUTO_DOWNLOAD_CERTS_PREFIX)) {
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

		for (UINT i = 0; i < LIST_NUM(chain); i++) {
			wchar_t tmp[MAX_SIZE];
			X *xx = LIST_DATA(chain, i);

			GetAllNameFromName(tmp, sizeof(tmp), xx->subject_name);


			if (auto_save && CompareX(x, xx) == false && IsXInCertList(current_chain_dir, xx) == false) {
				wchar_t fn[MAX_PATH];
				char hex_a[128];
				wchar_t hex[128];
				UCHAR hash[SHA1_SIZE];
				wchar_t tmp[MAX_SIZE];

				GetXDigest(xx, hash, true);
				BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
				StrToUni(hex, sizeof(hex), hex_a);

				UniStrCpy(fn, sizeof(fn), AUTO_DOWNLOAD_CERTS_PREFIX);
				UniStrCat(fn, sizeof(fn), hex);
				UniStrCat(fn, sizeof(fn), L".cer");

				CombinePathW(tmp, sizeof(tmp), dirname, fn);

				BUF *b = XToBuf(xx, true);

				DumpBufW(b, tmp);

				FreeBuf(b);
			}

			if (xx->root_cert) {
				if (found_root_x != NULL)
					*found_root_x = CloneX(xx);
			}
		}
	}

	FreeCertList(chain);

	FreeCertList(current_chain_dir);

	if (ret && auto_save) {
		// The folder was changed: the next connection of the server scans it again
		InvalidateChainCertCache();
	}

	return ret;
}

bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain) {
	bool ret = false;
	bool do_free = false;
	if (o == NULL || x == NULL || found_chain == NULL)
		return false;

	if (LIST_NUM(found_chain) >= FIND_CERT_CHAIN_MAX_DEPTH)
		return false;

	Add(found_chain, CloneX(x));

	if (x->root_cert)
		return true;

	X *r = FindCertIssuerFromCertList(o, x);

	if (r == NULL) {
		if (IsEmptyStr(x->issuer_url) == false) {
			r = DownloadCert(x->issuer_url);

			if (CheckXEx(x, r, true, true) && CompareX(x, r) == false) {
				do_free = true;
			} else {
				FreeX(r);
				r = NULL;
			}
		}
	}

	if (r != NULL)
		ret = TryGetParentCertFromCertList(o, r, found_chain);

	if (do_free)
		FreeX(r);

	return ret;
}

X *FindCertIssuerFromCertList(LIST *o, X *x) {
	if (o == NULL || x == NULL)
		return NULL;

	if (x->root_cert)
		return NULL;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		X *xx = LIST_DATA(o, i);

		if (CheckXEx(x, xx, true, true)) {
			if (CompareX(x, xx) == false)
				return xx;
		}
	}

	return NULL;
}

// Receive buffer size of HttpGet
#define HTTP_GET_RECV_BUF_SIZE 64000

// Set a DWORD option of a WinHTTP handle
static bool HttpSetDword(HINTERNET h, DWORD option, DWORD value) {
	return (WinHttpSetOption(h, option, &value, sizeof(value)) != FALSE);
}

// GET an http or https URL with WinHTTP and return the body (the only HTTP request of the product: DownloadCert)
// No proxy (WinHTTP does not read the system or WPAD proxy settings either), no redirect, cookie, authentication
// or default credentials, no check of the server certificate and no client certificate. Only a 200 answer counts.
// The body is read as far as Content-Length says, up to max_size bytes (0: no limit); without Content-Length no
// body is read, chunked or not. timeout_ms is the TCP connect timeout and the time of each send and receive, the
// TLS handshake of an https URL gets TIMEOUT_SSL_CONNECT instead. error_code may be NULL.
static BUF *HttpGet(const char *url, UINT timeout_ms, UINT max_size, UINT *error_code) {
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

	if (SearchStrEx(str, "://", 0, false) == INFINITE) {
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
	    uc.dwHostNameLength == 0 || uc.dwUserNameLength != 0 || uc.nPort == 0 || (uc.dwUrlPathLength == 0 && uc.dwExtraInfoLength != 0)) {
		err = ERR_INVALID_PARAMETER;
		goto FINAL;
	}

	secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
	target = (uc.dwUrlPathLength == 0 ? L"/" : uc.lpszUrlPath);

	session = WinHttpOpen(L"" DEFAULT_USER_AGENT, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
	                      WINHTTP_NO_PROXY_BYPASS, 0);
	if (session == NULL)
		goto FINAL;

	// Timeouts until the request is sent: the DnsResolveEx default, the TCP connect timeout, and on each send
	// and receive the TLS handshake timeout for https
	io_timeout = (secure ? TIMEOUT_SSL_CONNECT : timeout_ms);

	if (WinHttpSetTimeouts(session, (int)DNS_RESOLVE_DEFAULT_TIMEOUT, (int)timeout_ms, (int)io_timeout,
	                       (int)io_timeout) == FALSE)
		goto FINAL;

	connect = WinHttpConnect(session, host, uc.nPort, 0);
	if (connect == NULL)
		goto FINAL;

	request = WinHttpOpenRequest(connect, L"GET", target, L"HTTP/1.1", WINHTTP_NO_REFERER,
	                             WINHTTP_DEFAULT_ACCEPT_TYPES,
	                             WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_ESCAPE_DISABLE_QUERY | (secure ? WINHTTP_FLAG_SECURE : 0));
	if (request == NULL)
		goto FINAL;

	// No redirect, cookie, authentication or default credentials, and no keep-alive. DownloadCert makes
	// one request per connection: a pooled keep-alive connection would outlive the request and let a later
	// request reach a server that already answered the first one
	ok = HttpSetDword(request, WINHTTP_OPTION_DISABLE_FEATURE,
	                  WINHTTP_DISABLE_KEEP_ALIVE | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION) &&
	     HttpSetDword(request, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH);

	// No total time limit on the response header. Should WinHTTP refuse the value, the request keeps
	// WinHTTP's default limit instead of failing.
	HttpSetDword(request, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, INFINITE);

	if (ok && secure) {
		// No check of the server certificate, and no client certificate
		ok = HttpSetDword(request, WINHTTP_OPTION_SECURITY_FLAGS,
		                  SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE) &&
		     (WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0) != FALSE);
	}

	if (ok) {
		// Request headers that WinHTTP does not add itself (it sends Host, User-Agent and Connection: Keep-Alive)
		ok = (WinHttpAddRequestHeaders(request,
		                               L"Keep-Alive: " HTTP_KEEP_ALIVE "\r\nAccept-Language: ja\r\nPragma: no-cache\r\nCache-Control: no-cache",
		                               (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD) != FALSE);
	}

	if (ok == false)
		goto FINAL;

	// Send
	if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE) {
		switch (GetLastError()) {
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
	if (WinHttpReceiveResponse(request, NULL) == FALSE) {
		err = ERR_DISCONNECTED;
		goto FINAL;
	}

	// Only an HTTP/1.x status line counts. WinHTTP has already skipped interim 1xx responses.
	size = sizeof(tmp);
	if (WinHttpQueryHeaders(request, WINHTTP_QUERY_VERSION, WINHTTP_HEADER_NAME_BY_INDEX, tmp, &size,
	                        WINHTTP_NO_HEADER_INDEX)) {
		UniToStr(str, sizeof(str), tmp);

		if (StrLen(str) == 8 && Cmp(str, "HTTP/1.", 7) == 0) {
			size = sizeof(http_status);
			if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			                        WINHTTP_HEADER_NAME_BY_INDEX, &http_status, &size, WINHTTP_NO_HEADER_INDEX) == FALSE)
				http_status = 0;
		}
	}

	switch (http_status) {
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
		goto FINAL;

	// Get the length of the content as GetContentLength does: ToInt of the first Content-Length value, 0 without
	// one. Without it no body is read, chunked or not.
	size = sizeof(tmp);
	if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, tmp, &size,
	                        WINHTTP_NO_HEADER_INDEX)) {
		UniToStr(str, sizeof(str), tmp);
		content_len = ToInt(str);
	}
	if (max_size != 0)
		content_len = MIN(content_len, max_size);

	// Receive the content
	buffer = Malloc(HTTP_GET_RECV_BUF_SIZE);
	ret = NewBuf();

	while (true) {
		UINT recv_size = MIN(HTTP_GET_RECV_BUF_SIZE, content_len - ret->Size);

		if (recv_size == 0)
			break;

		size = 0;
		if (WinHttpReadData(request, buffer, recv_size, &size) == FALSE || size == 0) {
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
		SeekBuf(ret, 0, 0);

FINAL:
	if (request != NULL)
		WinHttpCloseHandle(request);
	if (connect != NULL)
		WinHttpCloseHandle(connect);
	if (session != NULL)
		WinHttpCloseHandle(session);
	Free(wide_url);

	if (error_code != NULL)
		*error_code = err;

	return ret;
}

X *DownloadCert(char *url) {
	X *ret = NULL;
	if (IsEmptyStr(url))
		return NULL;

	BUF *b = HttpGet(url, CERT_HTTP_DOWNLOAD_TIMEOUT, CERT_HTTP_DOWNLOAD_MAXSIZE, NULL);

	if (b == NULL)
		return NULL;

	ret = BufToX(b, IsBase64(b));

	FreeBuf(b);

	return ret;
}

LIST *NewCertList(bool load_root_and_chain) {
	LIST *o = NewList(NULL);

	if (load_root_and_chain) {
		AddAllRootCertsToCertList(o);
		AddAllChainCertsToCertList(o);
	}

	return o;
}

void FreeCertList(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		X *x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

bool IsXInCertList(LIST *o, X *x) {
	if (o == NULL || x == NULL)
		return false;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		X *xx = LIST_DATA(o, i);

		if (CompareX(x, xx))
			return true;
	}

	return false;
}

static void AddXToCertList(LIST *o, X *x) {
	if (o == NULL || x == NULL)
		return;

	if (IsXInCertList(o, x))
		return;

	if (CheckXDateNow(x) == false)
		return;

	Add(o, CloneX(x));
}

void AddAllChainCertsToCertList(LIST *o) {
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	if (o == NULL)
		return;

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	DIRLIST *dir = EnumDirW(dirname);

	if (dir != NULL) {
		for (UINT i = 0; i < dir->NumFiles; i++) {
			DIRENT *e = dir->File[i];

			if (e->Folder == false) {
				wchar_t tmp[MAX_SIZE];

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				X *x = FileToXW(tmp);

				if (x != NULL) {
					AddXToCertList(o, x);

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}
}

void AddAllRootCertsToCertList(LIST *o) {
	UINT num_ok = 0, num_error = 0;
	if (o == NULL)
		return;

	BUF *buf = ReadDump(ROOT_CERTS_FILENAME);
	if (buf == NULL)
		return;

	PACK *p = BufToPack(buf);

	if (p != NULL) {
		UINT num = PackGetIndexCount(p, "cert");

		for (UINT i = 0; i < num; i++) {
			bool ok = false;
			BUF *b = PackGetBufEx(p, "cert", i);

			if (b != NULL) {
				X *x = BufToX(b, false);

				if (x != NULL) {
					AddXToCertList(o, x);

					ok = true;

					FreeX(x);
				}

				FreeBuf(b);
			}

			if (ok)
				num_ok++;
			else
				num_error++;
		}

		FreePack(p);
	}

	FreeBuf(buf);
}

bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32) {
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
		return false;

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
		return false;
	if (PackGetData(p, "session_key", session_key) == false)
		return false;
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}
