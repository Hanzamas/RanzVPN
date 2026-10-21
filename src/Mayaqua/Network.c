// Network.c
// Network communication module

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "Internat.h"
#include "IpAddr.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

static COUNTER *num_tcp_connections = NULL;
static LOCK *host_ip_address_list_cache_lock = NULL;
static UINT64 host_ip_address_list_cache_last = 0;
static LIST *host_ip_address_cache = NULL;
static bool disable_gethostname_by_accept = false;


static LIST *ip_clients = NULL;
static bool ip_clients_full_logged = false; // EvictOldestIpClient has logged that ip_clients is full

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;


static DH_CTX *dh_param = NULL;

// Decoded copy of the Windows ROOT store, for the client's peer verification
#define SSL_ROOT_CERTS_REFRESH_SPAN (10 * 60 * 1000ULL)
static STACK_OF(X509) *ssl_root_certs = NULL;
static UINT64 ssl_root_certs_tick = 0;

typedef struct PRIVATE_IP_SUBNET {
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


bool IsMacAddressLocalFast(void *addr) {
	bool ret = false;
	if (addr == NULL) {
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL) {
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

void RefreshLocalMacAddressList() {
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL) {
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

bool IsMacAddressLocalInner(LIST *o, void *addr) {
	bool ret = false;
	if (o == NULL || addr == NULL) {
		return false;
	}

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0) {
			ret = true;
			break;
		}
	}

	return ret;
}

LIST *GetNicList() {
	LIST *o = NULL;

	o = Win32GetNicList();

	if (o != NULL) {
		return o;
	}


	return NewListFast(NULL);
}

LIST *Win32GetNicList() {
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL) {
		return NULL;
	}

	for (UINT i = 0; i < al->Num; i++) {
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6) {
			// Skip interfaces whose state is unknown: the device is not plugged in.
			if (a->MediaConnectState == MediaConnectStateUnknown) {
				continue;
			}

			NIC_ENTRY *e = ZeroMalloc(sizeof(NIC_ENTRY));

			Copy(e->MacAddress, a->Address, 6);

			Add(o, e);
		}
	}

	MsFreeAdapterList(al);

	return o;
}

void FreeNicList(LIST *o) {
	if (o == NULL) {
		return;
	}

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

UINT GetNumIpClient(const IP *ip) {
	IP_CLIENT *c;
	UINT ret = 0;
	if (ip == NULL) {
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL) {
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Map a source address to its per-source rate-limit key: an IPv4 address keeps all 32 bits,
// an IPv6 address keeps only its /64 prefix, since one host can pick any address inside its /64
void GetRateLimitKey(IP *key, const IP *ip) {
	if (key == NULL) {
		return;
	}

	Zero(key, sizeof(IP));

	if (ip == NULL) {
		return;
	}

	Copy(key->address, ip->address, sizeof(key->address));

	if (IsIP4(ip) == false) {
		Zero(&key->address[8], 8);
	}
}

// ip_clients is full: drop the key with the oldest last connection (ip_clients has no
// expired entries, a key leaves when its last connection closes), log the first time
static void EvictOldestIpClient() {
	IP_CLIENT *oldest = NULL;

	for (UINT i = 0; i < LIST_NUM(ip_clients); i++) {
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		if (oldest == NULL || c->LastTick < oldest->LastTick) {
			oldest = c;
		}
	}

	if (oldest != NULL) {
		Delete(ip_clients, oldest);
		Free(oldest);
	}

	if (ip_clients_full_logged == false) {
		ip_clients_full_logged = true;
		Debug("ip_clients reached %u source keys, the least recently seen keys are dropped\n", RATE_LIMIT_TABLE_MAX);
	}
}

static void AddIpClient(const IP *ip) {
	IP_CLIENT *c;
	if (ip == NULL) {
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL) {
			if (LIST_NUM(ip_clients) >= RATE_LIMIT_TABLE_MAX) {
				EvictOldestIpClient();
			}

			c = ZeroMalloc(sizeof(IP_CLIENT));
			GetRateLimitKey(&c->IpAddress, ip);
			c->NumConnections = 0;

			Insert(ip_clients, c);
		}

		c->NumConnections++;
		c->LastTick = Tick64();
	}
	UnlockList(ip_clients);
}

static void DelIpClient(const IP *ip) {
	IP_CLIENT *c;
	if (ip == NULL) {
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL) {
			c->NumConnections--;

			if (c->NumConnections == 0) {
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);
}

IP_CLIENT *SearchIpClient(const IP *ip) {
	IP_CLIENT t;
	if (ip == NULL) {
		return NULL;
	}

	Zero(&t, sizeof(t));
	GetRateLimitKey(&t.IpAddress, ip);

	return Search(ip_clients, &t);
}

static void InitIpClientList() {
	ip_clients = NewList(CompareIpClientList);
	ip_clients_full_logged = false;
}

static void FreeIpClientList() {
	for (UINT i = 0; i < LIST_NUM(ip_clients); i++) {
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

int CompareIpClientList(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	IP_CLIENT *c1 = *(IP_CLIENT **)p1;
	IP_CLIENT *c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL) {
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}


static void Win32InitSocketLibrary() {
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);
}

static void Win32FreeAsyncSocket(SOCK *sock) {
	if (sock == NULL) {
		return;
	}

	if (sock->hEvent != NULL) {
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	if (sock->SockEvent != NULL) {
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}


bool IsIPv6Supported() {
	SOCKET s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		return false;
	}

	closesocket(s);

	return true;
}

bool HasIPv6Address() {
	bool ret = false;

	LIST *o = GetHostIPAddressList();

	ret = false;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p)) {
			UINT type = GetIPAddrType6(p);
			if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0)) {
				ret = true;
				break;
			}
		}
	}

	FreeHostIPAddressList(o);

	return ret;
}

// Certificates of the chain_certs folder next to the exe, deduplicated by SHA-1 digest. The cache is scanned
// once and again only after the folder changed (a change notification) or InvalidateChainCertCache() was called
static LOCK *chain_cert_lock = NULL;
static LIST *chain_cert_list = NULL;                    // X of the folder, each digest once
static HANDLE chain_cert_notify = INVALID_HANDLE_VALUE; // Change notification of the folder
static bool chain_cert_valid = false;                   // chain_cert_list is current
static UINT chain_cert_scans = 0;                       // Scans of the folder so far

// Get the folder of the chain certificates
static void GetChainCertDirW(wchar_t *dirname, UINT size) {
	wchar_t exedir[MAX_SIZE];

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, size, exedir, L"chain_certs");
}

// Create the folder of the chain certificates (once, at server start)
void PrepareChainCertDir() {
	wchar_t dirname[MAX_SIZE];

	GetChainCertDirW(dirname, sizeof(dirname));

	MakeDirExW(dirname);
}

// Mark the cached chain certificates as out of date: the next connection scans the folder again
void InvalidateChainCertCache() {
	if (chain_cert_lock == NULL) {
		return;
	}

	Lock(chain_cert_lock);
	{
		chain_cert_valid = false;
	}
	Unlock(chain_cert_lock);
}

// Number of scans of the chain_certs folder so far
UINT GetChainCertScanCount() {
	UINT ret;

	if (chain_cert_lock == NULL) {
		return 0;
	}

	Lock(chain_cert_lock);
	{
		ret = chain_cert_scans;
	}
	Unlock(chain_cert_lock);

	return ret;
}

// Release the cache and the change notification
static void FreeChainCertCache() {
	if (chain_cert_list != NULL) {
		FreeXList(chain_cert_list);
		chain_cert_list = NULL;
	}

	if (chain_cert_notify != INVALID_HANDLE_VALUE) {
		FindCloseChangeNotification(chain_cert_notify);
		chain_cert_notify = INVALID_HANDLE_VALUE;
	}

	chain_cert_valid = false;
}

// Read the folder into the cache. chain_cert_lock is held
static void ScanChainCertDir(wchar_t *dirname) {
	LIST *o = NewListFast(NULL);
	LIST *hashes = NewListFast(NULL);

	DIRLIST *dir = EnumDirW(dirname);

	if (dir != NULL) {
		for (UINT i = 0; i < dir->NumFiles; i++) {
			DIRENT *e = dir->File[i];

			if (e->Folder == false) {
				wchar_t tmp[MAX_SIZE];

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				X *x = FileToXW(tmp);

				if (x != NULL) {
					bool exists = false;
					UCHAR hash[SHA1_SIZE];

					GetXDigest(x, hash, true);

					for (UINT j = 0; j < LIST_NUM(hashes); j++) {
						UCHAR *hash2 = LIST_DATA(hashes, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0) {
							exists = true;
							break;
						}
					}

					if (exists == false) {
						Add(hashes, Clone(hash, SHA1_SIZE));
						Add(o, x);
					} else {
						FreeX(x);
					}
				}
			}
		}

		FreeDir(dir);
	}

	for (UINT i = 0; i < LIST_NUM(hashes); i++) {
		Free(LIST_DATA(hashes, i));
	}

	ReleaseList(hashes);

	chain_cert_list = o;
	chain_cert_scans++;
}

// Bring the cache up to date: read the folder again when it changed or was invalidated. chain_cert_lock is held
static void RefreshChainCertCache() {
	if (chain_cert_valid && chain_cert_notify != INVALID_HANDLE_VALUE &&
	    WaitForSingleObject(chain_cert_notify, 0) == WAIT_OBJECT_0) {
		// The folder changed: arm the notification again before the scan so that a change during it is seen
		if (FindNextChangeNotification(chain_cert_notify) == false) {
			FindCloseChangeNotification(chain_cert_notify);
			chain_cert_notify = INVALID_HANDLE_VALUE;
		}

		chain_cert_valid = false;
	}

	if (chain_cert_valid == false) {
		wchar_t dirname[MAX_SIZE];

		GetChainCertDirW(dirname, sizeof(dirname));

		if (chain_cert_list != NULL) {
			FreeXList(chain_cert_list);
			chain_cert_list = NULL;
		}

		// The notification is opened before the scan so that no change between them is lost
		if (chain_cert_notify == INVALID_HANDLE_VALUE) {
			chain_cert_notify = FindFirstChangeNotificationW(dirname, FALSE,
			                                                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE);
		}

		ScanChainCertDir(dirname);

		// Without a notification (no folder) every call scans
		chain_cert_valid = (chain_cert_notify != INVALID_HANDLE_VALUE);
	}
}

// Generation of the chain certificates: it changes each time the cached list is read again. The cache is brought
// up to date first, so a context built after this call has the certificates of this generation (or newer ones)
UINT GetChainCertGeneration() {
	UINT ret;

	if (chain_cert_lock == NULL) {
		return 0;
	}

	Lock(chain_cert_lock);
	{
		RefreshChainCertCache();

		ret = chain_cert_scans;
	}
	Unlock(chain_cert_lock);

	return ret;
}

// Add the certificates of the chain_certs folder to the chain of ctx. Returns the number added
UINT AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx) {
	UINT ret = 0;

	if (ctx == NULL || chain_cert_lock == NULL) {
		return 0;
	}

	Lock(chain_cert_lock);
	{
		RefreshChainCertCache();

		for (UINT i = 0; i < LIST_NUM(chain_cert_list); i++) {
			if (AddChainSslCert(ctx, LIST_DATA(chain_cert_list, i))) {
				ret++;
			}
		}
	}
	Unlock(chain_cert_lock);

	return ret;
}

// Drain the OpenSSL error queue of a failed SSL_accept or SSL_connect into the ssl_err code
static void SslHandshakeError(bool server_mode, UINT *ssl_err) {
	unsigned long err;
	while ((err = ERR_get_error()) != 0) {
		Debug("%s error %X: %s\n", server_mode ? "SSL_accept" : "SSL_connect", (UINT)err, ERR_reason_error_string(err));
		if (ERR_GET_LIB(err) != ERR_LIB_SSL) {
			continue;
		}
		switch (ERR_GET_REASON(err)) {
		case SSL_R_UNSUPPORTED_PROTOCOL:
		case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
		case SSL_R_VERSION_TOO_HIGH:
#endif
			*ssl_err = TLS_ERR_PROTOCOL_VERSION;
			break;
		// The two reasons the accept and connect mappings disagree on
		case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
			*ssl_err = (server_mode ? TLS_ERR_HANDSHAKE : TLS_ERR_PROTOCOL_VERSION);
			break;
		case SSL_R_NO_SHARED_CIPHER:
			*ssl_err = (server_mode ? TLS_ERR_SHARED_CIPHER : TLS_ERR_HANDSHAKE);
			break;
		default:
			*ssl_err = TLS_ERR_HANDSHAKE;
		}
	}
}

// Add the Windows ROOT store's certificates to a client's verification store
static void AddSslRootCerts(X509_STORE *store) {
	UINT64 now = Tick64();

	if (ssl_root_certs == NULL || now >= ssl_root_certs_tick + SSL_ROOT_CERTS_REFRESH_SPAN) {
		STACK_OF(X509) *certs = sk_X509_new_null();

		if (certs != NULL) {
			HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
			if (hStore != NULL) {
				PCCERT_CONTEXT pContext = NULL;
				while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
					// d2i_X509 advances the pointer it is given: decode from a local copy, never the store's own context
					const unsigned char *der = pContext->pbCertEncoded;
					X509 *x509 = d2i_X509(NULL, &der, (long)pContext->cbCertEncoded);
					if (x509 != NULL && sk_X509_push(certs, x509) == 0) {
						X509_free(x509);
					}
				}
				CertCloseStore(hStore, 0);
			}

			sk_X509_pop_free(ssl_root_certs, X509_free);
			ssl_root_certs = certs;
			ssl_root_certs_tick = now;
		}
	}

	if (ssl_root_certs != NULL) {
		for (int i = 0; i < sk_X509_num(ssl_root_certs); i++) {
			X509_STORE_add_cert(store, sk_X509_value(ssl_root_certs, i));
		}
	}
}

// A TLS start needs a connected socket that does not listen, a key with a certificate, and a server socket for a shared server context
static bool TlsCanStart(const SOCK *sock, const SSL_CTX *server_ctx, const X *x, const K *priv) {
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
	    sock->ListenMode != false) {
		return false;
	}
	if (x != NULL && priv == NULL) {
		return false;
	}
	if (server_ctx != NULL && sock->ServerMode == false) {
		return false;
	}

	return true;
}

// The context of this TLS start: the shared server context (a reference of this call), a server context built from x, priv
// and chain, or a client context. NULL when it cannot be built
static SSL_CTX *TlsGetCtx(const SOCK *sock, SSL_CTX *server_ctx, X *x, K *priv, LIST *chain) {
	if (server_ctx != NULL) {
		ShareSSLCtx(server_ctx);
		return server_ctx;
	}
	if (sock->ServerMode) {
		return NewServerSSLCtx(x, priv, chain, NULL, NULL);
	}

	return NewSSLCtx(false);
}

// A client that verifies its peer: the certificates it trusts and the hostname the peer certificate must match
static void TlsSetClientVerify(SSL_CTX *ssl_ctx, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option) {
	X509_STORE *store;
	X509_VERIFY_PARAM *vpm;

	if (ssl_option == NULL || ssl_option->VerifyPeer == false) {
		return;
	}

	store = SSL_CTX_get_cert_store(ssl_ctx);
	if (ssl_option->AddDefaultCA) {
		AddSslRootCerts(store);
	}

	for (UINT i = 0; i < LIST_NUM(ssl_option->CaList); ++i) {
		X *ca = LIST_DATA(ssl_option->CaList, i);
		X509_STORE_add_cert(store, ca->x509);
	}

	vpm = SSL_CTX_get0_param(ssl_ctx);
	X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);

	// Enable hostname verification (by default CN is only checked if SAN is not available)
	if (ssl_option->VerifyHostname && IsEmptyStr(sni_hostname) == false) {
		X509_VERIFY_PARAM_set1_host(vpm, sni_hostname, StrLen(sni_hostname));
	}
}

// The SSL object of the connection on ssl_ctx
static bool TlsNewSsl(SOCK *sock, SSL_CTX *ssl_ctx, X *x, K *priv, char *sni_hostname) {
	sock->ssl = SSL_new(ssl_ctx);
	if (sock->ssl == NULL) {
		return false;
	}

	SSL_set_fd(sock->ssl, (int)sock->socket);

	if (sock->ServerMode) {
		return true;
	}

	if (IsEmptyStr(sni_hostname) == false) {
		SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
	}

	// A client: certificate and groups of this connection (a server has them in its context)
	if (x != NULL && CheckXandK(x, priv)) {
		SSL_use_certificate(sock->ssl, x->x509);
		SSL_use_PrivateKey(sock->ssl, priv->pkey);
	}

	SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);

	return true;
}

// The handshake: SSL_accept for a server, SSL_connect within TIMEOUT_SSL_CONNECT for a client.
// A failure sets ssl_err from the OpenSSL error queue
static bool TlsHandshake(SOCK *sock, UINT *ssl_err) {
	UINT prev_timeout;
	int ret;

	if (sock->ServerMode) {
		ret = SSL_accept(sock->ssl);
	} else {
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, TIMEOUT_SSL_CONNECT);
		ret = SSL_connect(sock->ssl);
		SetTimeout(sock, prev_timeout);
	}

	if (ret <= 0) {
		SslHandshakeError(sock->ServerMode, ssl_err);
		return false;
	}

	return true;
}

// The peer certificate (sock->RemoteX) and the TLS version of the finished handshake; returns the verify result
static long TlsReadPeer(SOCK *sock) {
	X509 *x509 = SSL_get_peer_certificate(sock->ssl);
	long ssl_verify_err = SSL_get_verify_result(sock->ssl);

	sock->SslVersion = SSL_get_version(sock->ssl);

	if (x509 == NULL) {
		sock->RemoteX = NULL;
	} else {
		sock->RemoteX = X509ToX(x509);
		if (sock->RemoteX == NULL) {
			// X509ToX leaves a certificate it refuses to the caller: our reference
			FreeX509(x509);
		}
	}

	return ssl_verify_err;
}

// The peer check that ssl_option asks for (VerifyPeer): false, with ssl_err set, when the peer certificate fails it
static bool TlsCheckPeer(SOCK *sock, long ssl_verify_err, const char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err) {
	if (ssl_option == NULL || ssl_option->VerifyPeer == false) {
		return true;
	}

	// OpenSSL checks no name when none is given: hostname verification without a hostname is a mismatch
	if (ssl_verify_err == X509_V_OK && sock->ServerMode == false && ssl_option->VerifyHostname && IsEmptyStr(sni_hostname)) {
		ssl_verify_err = X509_V_ERR_HOSTNAME_MISMATCH;
	}

	if (ssl_verify_err == X509_V_OK) {
		return true;
	}

	// Clear any error if matching saved certificate and not expired
	if (ssl_option->SavedCert != NULL && sock->RemoteX != NULL && CheckXDateNow(sock->RemoteX) && CompareX(ssl_option->SavedCert, sock->RemoteX)) {
		return true;
	}

	switch (ssl_verify_err) {
	case X509_V_ERR_CERT_HAS_EXPIRED:
		*ssl_err = TLS_ERR_CERT_EXPIRED;
		break;
	case X509_V_ERR_HOSTNAME_MISMATCH:
		*ssl_err = TLS_ERR_HOSTNAME_MISMATCH;
		break;
	default:
		*ssl_err = TLS_ERR_CERT_NOT_TRUSTED;
	}

	return false;
}

static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err);

bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err) {
	return StartSSLMain(sock, NULL, x, priv, chain, sni_hostname, ssl_option, ssl_err);
}
// Start TLS on an accepted connection with a server context that is shared by many connections (NewServerSSLCtx).
// The caller keeps its own reference of ctx
bool StartSSLServer(SOCK *sock, struct ssl_ctx_st *ctx, UINT *ssl_err) {
	if (ctx == NULL) {
		return false;
	}

	return StartSSLMain(sock, ctx, NULL, NULL, NULL, NULL, NULL, ssl_err);
}
// server_ctx NULL: a context of this call (a client context, or a server one built from x, priv and chain)
static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err) {
	SSL_CTX *ssl_ctx;
	UINT dummy_err = 0;
	long ssl_verify_err;

	if (sock == NULL) {
		return false;
	}
	if (ssl_err == NULL) {
		ssl_err = &dummy_err;
	}
	if (TlsCanStart(sock, server_ctx, x, priv) == false) {
		return false;
	}

	if (sock->SecureMode) {
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode) {
		Unlock(sock->ssl_lock);
		return true;
	}

	ssl_ctx = TlsGetCtx(sock, server_ctx, x, priv, chain);
	if (ssl_ctx == NULL) {
		goto FAIL;
	}

	if (sock->ServerMode == false) {
		TlsSetClientVerify(ssl_ctx, sni_hostname, ssl_option);
	}

	if (TlsNewSsl(sock, ssl_ctx, x, priv, sni_hostname) == false || TlsHandshake(sock, ssl_err) == false) {
		goto FAIL;
	}

	ssl_verify_err = TlsReadPeer(sock);
	if (TlsCheckPeer(sock, ssl_verify_err, sni_hostname, ssl_option, ssl_err) == false) {
		goto FAIL;
	}

	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));

	// The only success point: Recv/Send(secure) and Disconnect see SecureMode with a live ssl and ssl_ctx
	sock->SecureMode = true;

	Unlock(sock->ssl_lock);

	return true;

FAIL:
	// The one failure exit: no SSL object, no context, no lock held, not secure
	if (sock->ssl != NULL) {
		SSL_free(sock->ssl);
		sock->ssl = NULL;
	}
	FreeSSLCtx(ssl_ctx);
	sock->SecureMode = false;

	Unlock(sock->ssl_lock);

	return false;
}

void DisableGetHostNameWhenAcceptInit() {
	disable_gethostname_by_accept = true;
}

void AcceptInitEx(SOCK *s, bool no_lookup_hostname) {
	char tmp[MAX_SIZE];
	if (s == NULL) {
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false) {
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		    IsEmptyStr(tmp)) {
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	} else {
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL) {
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

SOCK *Accept(SOCK *sock) {
	struct sockaddr_storage addr;
	UINT true_flag = 1;
	if (sock == NULL) {
		return NULL;
	}
	sock->AcceptError = 0;
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false) {
		return NULL;
	}
	if (sock->CancelAccept) {
		return NULL;
	}

	SOCKET s = sock->socket;
	if (s == INVALID_SOCKET) {
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	int size = sizeof(addr);

	SOCKET new_socket = accept(s, (struct sockaddr *)&addr, &size);
	if (new_socket == INVALID_SOCKET) {
		sock->AcceptError = WSAGetLastError();
		return NULL;
	}
	if (sock->CancelAccept) {
		closesocket(new_socket);
		return NULL;
	}

	SOCK *ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(ret, TIMEOUT_INFINITE);

	QuerySocketInformation(ret);

	// An IPv4 peer of the dual-stack listener arrives as ::ffff:a.b.c.d, which decodes to an IPv4 address
	bool is_ipv6 = IsIP6(&ret->RemoteIP);

	if (IsLocalHostIP(&ret->RemoteIP) == false) {
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	return ret;
}

void Disconnect(SOCK *sock) {
	SOCKET s;
	if (sock == NULL) {
		return;
	}

	if (sock->Type == SOCK_TCP && sock->ListenMode) {
		sock->CancelAccept = true;
	}

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP) {
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET) {
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected) {
				shutdown(s, SD_BOTH);
			}

			closesocket(s);

			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode) {
					if (sock->ssl != NULL) {
						SSL_free(sock->ssl);
						FreeSSLCtx(sock->ssl_ctx);
						sock->ssl = NULL;
						sock->ssl_ctx = NULL;
					}
					sock->Connected = false;
					sock->SecureMode = false;
				}
			}
			Unlock(sock->ssl_lock);

			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;

			if (sock->IpClientAdded) {
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);
	} else if (sock->Type == SOCK_UDP) {
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET) {
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				return;
			}

			s = sock->socket;

			closesocket(s);

			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
		Unlock(sock->lock);
	}
	Unlock(sock->disconnect_lock);
}


void CleanupSock(SOCK *s) {
	if (s == NULL) {
		return;
	}

	Disconnect(s);

	Win32FreeAsyncSocket(s);

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET) {
		closesocket(s->socket);
	}
	Free(s->RemoteHostname);

	if (s->RemoteX != NULL) {
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}

	if (s->CipherName != NULL) {
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

SOCK *NewSock() {
	SOCK *s = ZeroMalloc(sizeof(SOCK));

	s->ref = NewRef();
	s->lock = NewLock();
	s->SendBuf = NewBuf();
	s->socket = INVALID_SOCKET;
	s->ssl_lock = NewLock();
	s->disconnect_lock = NewLock();

	Inc(num_tcp_connections);

	return s;
}

static DH *TmpDhCallback(SSL *ssl, int is_export, int keylength) {
	DH *ret = NULL;

	if (dh_param != NULL) {
		ret = dh_param->dh;
	}

	return ret;
}

struct ssl_ctx_st *NewSSLCtx(bool server_mode) {
	struct ssl_ctx_st *ctx = SSL_CTX_new(server_mode ? TLS_server_method() : TLS_client_method());
	if (ctx == NULL) {
		return NULL;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

	if (server_mode) {
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

	return ctx;
}

void InitNetwork() {
	disable_gethostname_by_accept = false;


	host_ip_address_list_cache_lock = NewLock();
	host_ip_address_list_cache_last = 0;

	num_tcp_connections = NewCounter();

	InitIpClientList();

	InitWaitThread();

	Win32InitSocketLibrary();

	DnsInit();

	local_mac_list_lock = NewLock();

	chain_cert_lock = NewLock();
}

COUNTER *GetNumTcpConnectionsCounter() {
	return num_tcp_connections;
}

bool IsIPMyHost(const IP *ip) {
	bool ret = false;
	if (ip == NULL) {
		return false;
	}

	if (IsZeroIP(ip)) {
		return false;
	}

	LIST *o = GetHostIPAddressList();

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0) {
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false) {
		if (IsLocalHostIP(ip)) {
			ret = true;
		}
	}

	return ret;
}

bool IsIPPrivate(const IP *ip) {
	if (IsIP4(ip) == false) {
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	// RFC 1918 defines 10.0.0.0/8
	if (ipv4[0] == 10) {
		return true;
	}

	// RFC 1918 defines 172.16.0.0/12
	if (ipv4[0] == 172) {
		if (ipv4[1] >= 16 && ipv4[1] <= 31) {
			return true;
		}
	}

	// RFC 1918 defines 192.168.0.0/16
	if (ipv4[0] == 192 && ipv4[1] == 168) {
		return true;
	}

	// RFC 3927 defines 169.254.0.0/16
	if (ipv4[0] == 169 && ipv4[1] == 254) {
		return true;
	}

	// RFC 6598 defines 100.64.0.0/10
	if (ipv4[0] == 100) {
		if (ipv4[1] >= 64 && ipv4[1] <= 127) {
			return true;
		}
	}

	if (g_private_ip_list != NULL) {
		return IsOnPrivateIPFile(IPToUINT(ip));
	}

	return false;
}

void LoadPrivateIPFile() {
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	if (b == NULL) {
		return;
	}

	LIST *o = NewList(NULL);

	while (true) {
		char *line = CfgReadNextLine(b);
		if (line == NULL) {
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false) {
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask)) {
				PRIVATE_IP_SUBNET *p = ZeroMalloc(sizeof(PRIVATE_IP_SUBNET));

				p->Ip = ip;
				p->Mask = mask;
				p->Ip2 = ip & mask;

				Add(o, p);
			}
		}

		Free(line);
	}

	g_private_ip_list = o;

	FreeBuf(b);
}

bool IsOnPrivateIPFile(UINT ip) {
	bool ret = false;

	if (g_private_ip_list != NULL) {
		LIST *o = g_private_ip_list;

		for (UINT i = 0; i < LIST_NUM(o); i++) {
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2) {
				ret = true;
			}
		}
	}

	return ret;
}

void FreePrivateIPFile() {
	if (g_private_ip_list != NULL) {
		LIST *o = g_private_ip_list;

		g_private_ip_list = NULL;

		for (UINT i = 0; i < LIST_NUM(o); i++) {
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}
}

void FreeNetwork() {

	if (dh_param != NULL) {
		DhFree(dh_param);
		dh_param = NULL;
	}

	sk_X509_pop_free(ssl_root_certs, X509_free);
	ssl_root_certs = NULL;

	FreeWaitThread();

	FreeChainCertCache();
	DeleteLock(chain_cert_lock);
	chain_cert_lock = NULL;

	DnsFree();

	WSACleanup();

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	FreeIpClientList();

	if (local_mac_list != NULL) {
		FreeNicList(local_mac_list);
		local_mac_list = NULL;
	}

	DeleteLock(local_mac_list_lock);
	local_mac_list_lock = NULL;

	DeleteLock(host_ip_address_list_cache_lock);
	host_ip_address_list_cache_lock = NULL;

	FreeHostIPAddressList(host_ip_address_cache);
	host_ip_address_cache = NULL;
}



static int CmpIpAddressList(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	IP *ip1 = *(IP **)p1;
	IP *ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL) {
		return 0;
	}

	// IPv4 < IPv6
	UINT r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0) {
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false) {
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2)) {
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false) {
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2)) {
		return -1;
	}

	r = CmpIpAddr(ip1, ip2);
	if (r != 0) {
		return r;
	}

	if (IsIP6(ip1)) {
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	} else {
		r = 0;
	}

	return r;
}

LIST *GetHostIPAddressList() {
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL) {
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
		    ((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
		    host_ip_address_cache == NULL) {
			if (host_ip_address_cache != NULL) {
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL) {
		o = GetHostIPAddressListInternal();
	}

	return o;
}

LIST *GetHostIPAddressListInternal() {
	char hostname[MAX_SIZE];
	IP any6, any4;
	IP local6, local4;
	struct addrinfo hint;
	bool is_v6_supported = IsIPv6Supported();

	GetLocalHostIP4(&local4);
	GetLocalHostIP6(&local6);

	ZeroIP4(&any4);
	Zero(&any6, sizeof(any6));

	Zero(hostname, sizeof(hostname));

	gethostname(hostname, sizeof(hostname));

	LIST *o = NewListFast(CmpIpAddressList);

	AddHostIPAddressToList(o, &any4);
	if (is_v6_supported) {
		AddHostIPAddressToList(o, &any6);
	}

	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported) {
		AddHostIPAddressToList(o, &local6);
	}

	Zero(&hint, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;
	struct addrinfo *info = NULL;

	if (getaddrinfo(hostname, NULL, &hint, &info) == 0) {
		struct addrinfo *current;

		for (current = info; current != NULL; current = current->ai_next) {
			IP ip;

			if (current->ai_family == AF_INET) {
				struct sockaddr_in in;

				Copy(&in, current->ai_addr, sizeof(in));

				InAddrToIP(&ip, &in.sin_addr);
				AddHostIPAddressToList(o, &ip);
			} else if (current->ai_family == AF_INET6 && is_v6_supported) {
				struct sockaddr_in6 in;

				Copy(&in, current->ai_addr, sizeof(in));

				InAddrToIP6(&ip, &in.sin6_addr);
				ip.ipv6_scope_id = in.sin6_scope_id;

				AddHostIPAddressToList(o, &ip);
			}
		}

		freeaddrinfo(info);
	}

	return o;
}

void SetDhParam(DH_CTX *dh) {
	if (dh_param) {
		DhFree(dh_param);
	}

	dh_param = dh;
}
