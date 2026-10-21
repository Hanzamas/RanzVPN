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
static bool ip_clients_full_logged = false;	// EvictOldestIpClient has logged that ip_clients is full

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;


static DH_CTX *dh_param = NULL;

// Decoded copy of the Windows ROOT store, for the client's peer verification
#define	SSL_ROOT_CERTS_REFRESH_SPAN		(10 * 60 * 1000ULL)
static STACK_OF(X509) *ssl_root_certs = NULL;
static UINT64 ssl_root_certs_tick = 0;

typedef struct PRIVATE_IP_SUBNET
{
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


bool IsMacAddressLocalFast(void *addr)
{
	bool ret = false;
	if (addr == NULL)
	{
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL)
		{
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

void RefreshLocalMacAddressList()
{
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL)
		{
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

bool IsMacAddressLocalInner(LIST *o, void *addr)
{
	bool ret = false;
	UINT i;
	if (o == NULL || addr == NULL)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0)
		{
			ret = true;
			break;
		}
	}

	return ret;
}

LIST *GetNicList()
{
	LIST *o = NULL;

	o = Win32GetNicList();

	if (o != NULL)
	{
		return o;
	}


	return NewListFast(NULL);
}

LIST *Win32GetNicList()
{
	UINT i;
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL)
	{
		return NULL;
	}

	for (i = 0; i < al->Num; i++)
	{
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6)
		{
			// Skip interfaces whose state is unknown: the device is not plugged in.
			if (a->MediaConnectState == MediaConnectStateUnknown)
			{
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

void FreeNicList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

UINT GetNumIpClient(const IP *ip)
{
	IP_CLIENT *c;
	UINT ret = 0;
	if (ip == NULL)
	{
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Map a source address to its per-source rate-limit key: an IPv4 address keeps all 32 bits,
// an IPv6 address keeps only its /64 prefix, since one host can pick any address inside its /64
void GetRateLimitKey(IP *key, const IP *ip)
{
	if (key == NULL)
	{
		return;
	}

	Zero(key, sizeof(IP));

	if (ip == NULL)
	{
		return;
	}

	Copy(key->address, ip->address, sizeof(key->address));

	if (IsIP4(ip) == false)
	{
		Zero(&key->address[8], 8);
	}
}

// ip_clients is full: drop the key with the oldest last connection (ip_clients has no
// expired entries, a key leaves when its last connection closes), log the first time
static void EvictOldestIpClient()
{
	IP_CLIENT *oldest = NULL;
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		if (oldest == NULL || c->LastTick < oldest->LastTick)
		{
			oldest = c;
		}
	}

	if (oldest != NULL)
	{
		Delete(ip_clients, oldest);
		Free(oldest);
	}

	if (ip_clients_full_logged == false)
	{
		ip_clients_full_logged = true;
		Debug("ip_clients reached %u source keys, the least recently seen keys are dropped\n", RATE_LIMIT_TABLE_MAX);
	}
}

static void AddIpClient(IP *ip)
{
	IP_CLIENT *c;
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL)
		{
			if (LIST_NUM(ip_clients) >= RATE_LIMIT_TABLE_MAX)
			{
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

static void DelIpClient(IP *ip)
{
	IP_CLIENT *c;
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			c->NumConnections--;

			if (c->NumConnections == 0)
			{
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);

}

IP_CLIENT *SearchIpClient(const IP *ip)
{
	IP_CLIENT t;
	if (ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	GetRateLimitKey(&t.IpAddress, ip);

	return Search(ip_clients, &t);
}

static void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
	ip_clients_full_logged = false;
}

static void FreeIpClientList()
{
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

int CompareIpClientList(void *p1, void *p2)
{
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}


static void Win32InitSocketLibrary()
{
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);
}

static void Win32FreeAsyncSocket(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	if (sock->hEvent != NULL)
	{
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	if (sock->SockEvent != NULL)
	{
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}


bool IsIPv6Supported()
{
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	closesocket(s);

	return true;
}

bool HasIPv6Address()
{
	LIST *o;
	UINT i;
	bool ret = false;

	o = GetHostIPAddressList();

	ret = false;

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p))
		{
			UINT type = GetIPAddrType6(p);
			if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0))
			{
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
static LIST *chain_cert_list = NULL;				// X of the folder, each digest once
static HANDLE chain_cert_notify = INVALID_HANDLE_VALUE;	// Change notification of the folder
static bool chain_cert_valid = false;				// chain_cert_list is current
static UINT chain_cert_scans = 0;					// Scans of the folder so far

// Get the folder of the chain certificates
static void GetChainCertDirW(wchar_t *dirname, UINT size)
{
	wchar_t exedir[MAX_SIZE];

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, size, exedir, L"chain_certs");
}

// Create the folder of the chain certificates (once, at server start)
void PrepareChainCertDir()
{
	wchar_t dirname[MAX_SIZE];

	GetChainCertDirW(dirname, sizeof(dirname));

	MakeDirExW(dirname);
}

// Mark the cached chain certificates as out of date: the next connection scans the folder again
void InvalidateChainCertCache()
{
	if (chain_cert_lock == NULL)
	{
		return;
	}

	Lock(chain_cert_lock);
	{
		chain_cert_valid = false;
	}
	Unlock(chain_cert_lock);
}

// Number of scans of the chain_certs folder so far
UINT GetChainCertScanCount()
{
	UINT ret;

	if (chain_cert_lock == NULL)
	{
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
static void FreeChainCertCache()
{
	if (chain_cert_list != NULL)
	{
		FreeXList(chain_cert_list);
		chain_cert_list = NULL;
	}

	if (chain_cert_notify != INVALID_HANDLE_VALUE)
	{
		FindCloseChangeNotification(chain_cert_notify);
		chain_cert_notify = INVALID_HANDLE_VALUE;
	}

	chain_cert_valid = false;
}

// Read the folder into the cache. chain_cert_lock is held
static void ScanChainCertDir(wchar_t *dirname)
{
	DIRLIST *dir;
	LIST *o;
	LIST *hashes;
	UINT i;

	o = NewListFast(NULL);
	hashes = NewListFast(NULL);

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		for (i = 0; i < dir->NumFiles; i++)
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
					UINT j;
					bool exists = false;
					UCHAR hash[SHA1_SIZE];

					GetXDigest(x, hash, true);

					for (j = 0; j < LIST_NUM(hashes); j++)
					{
						UCHAR *hash2 = LIST_DATA(hashes, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						Add(hashes, Clone(hash, SHA1_SIZE));
						Add(o, x);
					}
					else
					{
						FreeX(x);
					}
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0; i < LIST_NUM(hashes); i++)
	{
		Free(LIST_DATA(hashes, i));
	}

	ReleaseList(hashes);

	chain_cert_list = o;
	chain_cert_scans++;
}

// Bring the cache up to date: read the folder again when it changed or was invalidated. chain_cert_lock is held
static void RefreshChainCertCache()
{
	if (chain_cert_valid && chain_cert_notify != INVALID_HANDLE_VALUE &&
		WaitForSingleObject(chain_cert_notify, 0) == WAIT_OBJECT_0)
	{
		// The folder changed: arm the notification again before the scan so that a change during it is seen
		if (FindNextChangeNotification(chain_cert_notify) == false)
		{
			FindCloseChangeNotification(chain_cert_notify);
			chain_cert_notify = INVALID_HANDLE_VALUE;
		}

		chain_cert_valid = false;
	}

	if (chain_cert_valid == false)
	{
		wchar_t dirname[MAX_SIZE];

		GetChainCertDirW(dirname, sizeof(dirname));

		if (chain_cert_list != NULL)
		{
			FreeXList(chain_cert_list);
			chain_cert_list = NULL;
		}

		// The notification is opened before the scan so that no change between them is lost
		if (chain_cert_notify == INVALID_HANDLE_VALUE)
		{
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
UINT GetChainCertGeneration()
{
	UINT ret;

	if (chain_cert_lock == NULL)
	{
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
UINT AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx)
{
	UINT i;
	UINT ret = 0;

	if (ctx == NULL || chain_cert_lock == NULL)
	{
		return 0;
	}

	Lock(chain_cert_lock);
	{
		RefreshChainCertCache();

		for (i = 0; i < LIST_NUM(chain_cert_list); i++)
		{
			if (AddChainSslCert(ctx, LIST_DATA(chain_cert_list, i)))
			{
				ret++;
			}
		}
	}
	Unlock(chain_cert_lock);

	return ret;
}

bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x)
{
	if (ctx == NULL || x == NULL || x->x509 == NULL)
	{
		return false;
	}

	// The context takes over the reference when it succeeds
	if (X509_up_ref(x->x509) != 1)
	{
		return false;
	}

	if (SSL_CTX_add_extra_chain_cert(ctx, x->x509) != 1)
	{
		X509_free(x->x509);
		return false;
	}

	return true;
}

// Drain the OpenSSL error queue of a failed SSL_accept or SSL_connect into the ssl_err code
static void SslHandshakeError(bool server_mode, UINT *ssl_err)
{
	unsigned long err;
	while ((err = ERR_get_error()) != 0)
	{
		Debug("%s error %X: %s\n", server_mode ? "SSL_accept" : "SSL_connect", (UINT)err, ERR_reason_error_string(err));
		if (ERR_GET_LIB(err) != ERR_LIB_SSL)
		{
			continue;
		}
		switch (ERR_GET_REASON(err))
		{
		case SSL_R_UNSUPPORTED_PROTOCOL:
		case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
		case SSL_R_VERSION_TOO_HIGH:
#endif
			*ssl_err = 150;
			break;
		// The two reasons the accept and connect mappings disagree on
		case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
			*ssl_err = (server_mode ? 152 : 150);
			break;
		case SSL_R_NO_SHARED_CIPHER:
			*ssl_err = (server_mode ? 151 : 152);
			break;
		default:
			*ssl_err = 152;
		}
	}
}

// Add the Windows ROOT store's certificates to a client's verification store
static void AddSslRootCerts(X509_STORE *store)
{
	UINT64 now = Tick64();
	int i;

	if (ssl_root_certs == NULL || now >= ssl_root_certs_tick + SSL_ROOT_CERTS_REFRESH_SPAN)
	{
		STACK_OF(X509) *certs = sk_X509_new_null();

		if (certs != NULL)
		{
			HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
			if (hStore != NULL)
			{
				PCCERT_CONTEXT pContext = NULL;
				while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL)
				{
					// d2i_X509 advances the pointer it is given: decode from a local copy, never the store's own context
					const unsigned char *der = pContext->pbCertEncoded;
					X509 *x509 = d2i_X509(NULL, &der, (long)pContext->cbCertEncoded);
					if (x509 != NULL && sk_X509_push(certs, x509) == 0)
					{
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

	if (ssl_root_certs != NULL)
	{
		for (i = 0; i < sk_X509_num(ssl_root_certs); i++)
		{
			X509_STORE_add_cert(store, sk_X509_value(ssl_root_certs, i));
		}
	}
}

static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err);

// A server context with every setting that does not depend on the connection applied: version flags, security
// level, certificate chain, certificate and key, cipher list and groups. x and priv may be NULL (no certificate),
// chain NULL takes the certificates of the chain_certs folder, cipher_list NULL keeps the OpenSSL default and
// settings NULL overrides nothing. Connections take the context by reference (ShareSSLCtx, FreeSSLCtx)
struct ssl_ctx_st *NewServerSSLCtx(X *x, K *priv, LIST *chain, char *cipher_list, SSL_ACCEPT_SETTINGS *settings)
{
	SSL_CTX *ctx;
	SSL_ACCEPT_SETTINGS none;
	bool use_cert = (x != NULL && priv != NULL && CheckXandK(x, priv));

	ctx = NewSSLCtx(true);
	if (ctx == NULL)
	{
		return NULL;
	}

	if (settings == NULL)
	{
		Zero(&none, sizeof(none));
		settings = &none;
	}

	if (settings->Tls_Disable1_0)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}

	if (settings->Tls_Disable1_1)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
	}

	if (settings->Tls_Disable1_2)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
	}

	if (settings->Tls_Disable1_3)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
	}

	if (chain == NULL)
	{
		AddChainSslCertOnDirectory(ctx);
	}
	else
	{
		UINT i;

		LockList(chain);
		{
			for (i = 0;i < LIST_NUM(chain);i++)
			{
				AddChainSslCert(ctx, LIST_DATA(chain, i));
			}
		}
		UnlockList(chain);
	}

	if (settings->Override_Security_Level)
	{
		SSL_CTX_set_security_level(ctx, settings->Override_Security_Level_Value);
	}

	if (use_cert)
	{
		SSL_CTX_use_certificate(ctx, x->x509);
		SSL_CTX_use_PrivateKey(ctx, priv->pkey);
	}

	if (cipher_list != NULL)
	{
		if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0)
		{
			SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
		}
	}

	SSL_CTX_set1_groups_list(ctx, PQ_GROUP_LIST);

	// A context that lives for many connections must not resume sessions: a fresh context per connection never did
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	return ctx;
}

bool StartSSL(SOCK *sock, X *x, K *priv)
{
	return StartSSLEx(sock, x, priv, NULL);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, char *sni_hostname)
{
	return StartSSLEx3(sock, x, priv, NULL, sni_hostname, NULL, NULL);
}
bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err)
{
	return StartSSLMain(sock, NULL, x, priv, chain, sni_hostname, ssl_option, ssl_err);
}
// Start TLS on an accepted connection with a server context that is shared by many connections (NewServerSSLCtx).
// The caller keeps its own reference of ctx
bool StartSSLServer(SOCK *sock, struct ssl_ctx_st *ctx, UINT *ssl_err)
{
	if (ctx == NULL)
	{
		return false;
	}

	return StartSSLMain(sock, ctx, NULL, NULL, NULL, NULL, NULL, ssl_err);
}
// server_ctx NULL: a context of this call (a client context, or a server one built from x, priv and chain)
static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err)
{
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout;
	SSL_CTX *ssl_ctx;
	UINT dummy_err = 0;
	long ssl_verify_err;
	int handshake_ret;

	if (sock == NULL)
	{
		return false;
	}
	if (ssl_err == NULL)
	{
		ssl_err = &dummy_err;
	}
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
	        sock->ListenMode != false)
	{
		return false;
	}
	if (x != NULL && priv == NULL)
	{
		return false;
	}
	if (server_ctx != NULL && sock->ServerMode == false)
	{
		return false;
	}

	if (sock->SecureMode)
	{
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode)
	{
		Unlock(sock->ssl_lock);
		return true;
	}

	if (server_ctx != NULL)
	{
		ShareSSLCtx(server_ctx);
		ssl_ctx = server_ctx;
	}
	else if (sock->ServerMode)
	{
		ssl_ctx = NewServerSSLCtx(x, priv, chain, NULL, NULL);
	}
	else
	{
		ssl_ctx = NewSSLCtx(false);
	}
	if (ssl_ctx == NULL)
	{
		goto FAIL;
	}

	if (sock->ServerMode == false)
	{
		if (ssl_option != NULL && ssl_option->VerifyPeer)
		{
			X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
			if (ssl_option->AddDefaultCA)
			{
				AddSslRootCerts(store);
			}

			UINT i;
			for (i = 0; i < LIST_NUM(ssl_option->CaList); ++i)
			{
				X *ca = LIST_DATA(ssl_option->CaList, i);
				X509_STORE_add_cert(store, ca->x509);
			}

			X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ssl_ctx);
			X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);

			// Enable hostname verification (by default CN is only checked if SAN is not available)
			if (ssl_option->VerifyHostname && IsEmptyStr(sni_hostname) == false)
			{
				X509_VERIFY_PARAM_set1_host(vpm, sni_hostname, StrLen(sni_hostname));
			}
		}
	}

	sock->ssl = SSL_new(ssl_ctx);

	if (sock->ssl == NULL)
	{
		goto FAIL;
	}

	SSL_set_fd(sock->ssl, (int)sock->socket);

	if (sock->ServerMode == false)
	{
		if (IsEmptyStr(sni_hostname) == false)
		{
			SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
		}
	}

	if (sock->ServerMode == false)
	{
		// A client: certificate and groups of this connection (a server has them in its context)
		if (x != NULL)
		{
			if (CheckXandK(x, priv))
			{
				x509 = x->x509;
				key = priv->pkey;

				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
		}

		SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);
	}

	if (sock->ServerMode)
	{
		handshake_ret = SSL_accept(sock->ssl);
	}
	else
	{
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, TIMEOUT_SSL_CONNECT);
		handshake_ret = SSL_connect(sock->ssl);
		SetTimeout(sock, prev_timeout);
	}

	if (handshake_ret <= 0)
	{
		SslHandshakeError(sock->ServerMode, ssl_err);
		goto FAIL;
	}

	x509 = SSL_get_peer_certificate(sock->ssl);
	ssl_verify_err = SSL_get_verify_result(sock->ssl);
	sock->SslVersion = SSL_get_version(sock->ssl);

	if (x509 == NULL)
	{
		sock->RemoteX = NULL;
	}
	else
	{
		sock->RemoteX = X509ToX(x509);
		if (sock->RemoteX == NULL)
		{
			// X509ToX leaves a certificate it refuses to the caller: our reference
			FreeX509(x509);
		}
	}

	if (ssl_option != NULL && ssl_option->VerifyPeer)
	{
		// OpenSSL checks no name when none is given: hostname verification without a hostname is a mismatch
		if (ssl_verify_err == X509_V_OK && sock->ServerMode == false && ssl_option->VerifyHostname && IsEmptyStr(sni_hostname))
		{
			ssl_verify_err = X509_V_ERR_HOSTNAME_MISMATCH;
		}

		if (ssl_verify_err != X509_V_OK)
		{
			// Clear any error if matching saved certificate and not expired
			if (ssl_option->SavedCert != NULL && sock->RemoteX != NULL && CheckXDateNow(sock->RemoteX) && CompareX(ssl_option->SavedCert, sock->RemoteX))
			{
				ssl_verify_err = X509_V_OK;
			}
			else
			{
				switch (ssl_verify_err)
				{
				case X509_V_ERR_CERT_HAS_EXPIRED:
					*ssl_err = 106;
					break;
				case X509_V_ERR_HOSTNAME_MISMATCH:
					*ssl_err = 149;
					break;
				default:
					*ssl_err = 85;
				}

				goto FAIL;
			}
		}
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
	if (sock->ssl != NULL)
	{
		SSL_free(sock->ssl);
		sock->ssl = NULL;
	}
	FreeSSLCtx(ssl_ctx);
	sock->SecureMode = false;

	Unlock(sock->ssl_lock);

	return false;
}

// A failed recv, send or SSL call: SOCK_LATER when an async socket only has to wait, else the socket is disconnected
static UINT SockFailResult(SOCK *sock, bool later)
{
	if (later)
	{
		return SOCK_LATER;
	}

	Disconnect(sock);
	return 0;
}

// The SSL_get_error code of a failed SSL_peek, SSL_read or SSL_write: an async socket waits on WANT_READ/WANT_WRITE
static UINT SslFailResult(SOCK *sock, int e)
{
	if (sock->AsyncMode && e == SSL_ERROR_SSL)
	{
		DrainCryptErrors("SSL_ERROR_SSL on ASYNC socket");
	}

	return SockFailResult(sock, sock->AsyncMode && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE));
}

static UINT SecureRecv(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;

	if (sock->AsyncMode)
	{
		// In async mode, check that at least 1 byte is readable: SSL_read would block otherwise.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false || sock->ssl == NULL)
			{
				Unlock(sock->ssl_lock);
				return 0;
			}
			ERR_clear_error();
			ret = SSL_peek(sock->ssl, &c, sizeof(c));
			if (ret <= 0)
			{
				e = SSL_get_error(sock->ssl, ret);
			}
		}
		Unlock(sock->ssl_lock);
		// Both 0 and negative values may be retryable: use SSL_get_error().
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		if (ret <= 0 && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL))
		{
			return SslFailResult(sock, e);
		}
	}

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_read(sock->ssl, data, size);

		if (ret <= 0)
		{
			e = SSL_get_error(sock->ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

static UINT SecureSend(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		if (sock->AsyncMode)
		{
			SSL_set_mode(sock->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
		}

		ERR_clear_error();
		ret = SSL_write(sock->ssl, data, size);
		if (ret <= 0)
		{
			e = SSL_get_error(sock->ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

UINT Recv(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;

	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	// recv and SSL_read take an int: the same cap as Send
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);

	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureRecv(sock, data, size);
	}

	s = sock->socket;

	ret = recv(s, data, size, 0);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

UINT Send(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureSend(sock, data, size);
	}

	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

void DisableGetHostNameWhenAcceptInit()
{
	disable_gethostname_by_accept = true;
}

void AcceptInitEx(SOCK *s, bool no_lookup_hostname)
{
	char tmp[MAX_SIZE];
	if (s == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false)
	{
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		        IsEmptyStr(tmp))
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	}
	else
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL)
	{
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

SOCK *Accept(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_storage addr;
	UINT true_flag = 1;
	bool is_ipv6;
	if (sock == NULL)
	{
		return NULL;
	}
	sock->AcceptError = 0;
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

	new_socket = accept(s, (struct sockaddr *)&addr, &size);
	if (new_socket == INVALID_SOCKET)
	{
		sock->AcceptError = WSAGetLastError();
		return NULL;
	}
	if (sock->CancelAccept)
	{
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
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
	is_ipv6 = IsIP6(&ret->RemoteIP);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	return ret;
}

void Disconnect(SOCK *sock)
{
	SOCKET s;
	if (sock == NULL)
	{
		return;
	}

	if (sock->Type == SOCK_TCP && sock->ListenMode)
	{
		sock->CancelAccept = true;
	}

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected)
			{
				shutdown(s, SD_BOTH);
			}

			closesocket(s);

			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode)
				{
					if (sock->ssl != NULL)
					{
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

			if (sock->IpClientAdded)
			{
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);
	}
	else if (sock->Type == SOCK_UDP)
	{
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
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


void CleanupSock(SOCK *s)
{
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);

	Win32FreeAsyncSocket(s);

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET)
	{
		closesocket(s->socket);
	}
	Free(s->RemoteHostname);

	if (s->RemoteX != NULL)
	{
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}

	if (s->CipherName != NULL)
	{
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

SOCK *NewSock()
{
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

void GetMachineName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	DWORD tmp_size = sizeof(tmp);
	if (name == NULL)
	{
		return;
	}

	if (GetComputerNameExA(ComputerNameDnsHostname, tmp, &tmp_size) == false)
	{
		StrCpy(name, size, "Unknown");
		return;
	}

	StrCpy(name, size, tmp);
}

bool GetHostName(char *hostname, UINT size, const IP *ip)
{
	if (hostname == NULL || size == 0 || ip == NULL)
	{
		return false;
	}

	if (DnsResolveReverse(hostname, size, ip, 0, NULL))
	{
		return true;
	}

	if (IsIP4(ip) && GetNetBiosName(hostname, size, ip))
	{
		DnsCacheReverseUpdate(ip, hostname);
		return true;
	}

	return false;
}

#define	NUM_NBT_QUERYS_SEND			3

bool GetNetBiosName(char *name, UINT size, const IP *ip)
{
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	if (name == NULL || ip == NULL)
	{
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
	{
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL)
	{
		return false;
	}

	for (j = 0; j < NUM_NBT_QUERYS_SEND; j++)
	{
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3; i <= 32; i++)
		{
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0)
		{
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick64() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1)
	{
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick64() >= timeout_tick)
		{
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false)
		{
			flag = true;
		}
		else
		{
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER)
		{
			continue;
		}
		else if (ret == 0)
		{
			break;
		}
		else
		{
			// Only a reply from the queried host's NetBIOS port counts; anything else may be spoofed
			if (ret >= sizeof(NBTRESPONSE) && src_port == 137 && CmpIpAddr(&src_ip, ip) == 0)
			{
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
				{
					if (id == tran_id[i])
					{
						b = true;
						break;
					}
				}
				if (b)
				{
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1)
					{
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
						        r->Response[2] == 0x4b)
						{
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
							        r->Response[36] == 0x00 && r->Response[37] == 0x01)
							{
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15))
								{
									if (IsEmptyStr(a) == false)
									{
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									}
									else
									{
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
}

static DH *TmpDhCallback(SSL *ssl, int is_export, int keylength)
{
	DH *ret = NULL;

	if (dh_param != NULL)
	{
		ret = dh_param->dh;
	}

	return ret;
}

struct ssl_ctx_st *NewSSLCtx(bool server_mode)
{
	struct ssl_ctx_st *ctx = SSL_CTX_new(server_mode ? TLS_server_method() : TLS_client_method());
	if(ctx == NULL)
	{
		return NULL;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

	if (server_mode)
	{
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

	return ctx;
}

// Take one more reference of ctx: each holder calls FreeSSLCtx once
void ShareSSLCtx(struct ssl_ctx_st *ctx)
{
	if (ctx == NULL)
	{
		return;
	}

	SSL_CTX_up_ref(ctx);
}

void FreeSSLCtx(struct ssl_ctx_st *ctx)
{
	if (ctx == NULL)
	{
		return;
	}

	SSL_CTX_free(ctx);
}

UINT GetOSSecurityLevel()
{
	UINT security_level_new = 0, security_level_set_ssl_version = 0;
	struct ssl_ctx_st *ctx = SSL_CTX_new(TLS_method());

	if (ctx == NULL)
	{
		return security_level_new;
	}


	security_level_new = SSL_CTX_get_security_level(ctx);

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, TLS_server_method());

	FreeSSLCtx(ctx);

	if(security_level_new >= security_level_set_ssl_version)
	{
		return security_level_new;
	}

	return security_level_set_ssl_version;
}

void InitNetwork()
{
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

TOKEN_LIST *GetCipherList()
{
	int i, num;
	SSL *ssl;
	SSL_CTX *ctx;
	const char *name;
	STACK_OF(SSL_CIPHER) *sk;

	TOKEN_LIST *ciphers = ZeroMalloc(sizeof(TOKEN_LIST));

	ctx = NewSSLCtx(true);
	if (ctx == NULL)
	{
		return ciphers;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
		FreeSSLCtx(ctx);
		return ciphers;
	}

	// A copy of the list (OpenSSL 1.1.1 or later is required): NULL when no cipher is enabled
	sk = SSL_get1_supported_ciphers(ssl);
	num = (sk != NULL ? sk_SSL_CIPHER_num(sk) : 0);

	if (num > 0)
	{
		ciphers->Token = ZeroMalloc(sizeof(char *) * (UINT)num);
	}

	for (i = 0; i < num; i++)
	{
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL)
		{
			continue;
		}

		name = SSL_CIPHER_get_name(c);
		if (IsEmptyStr((char *)name))
		{
			break;
		}

		ciphers->Token[ciphers->NumTokens++] = CopyStr((char *)name);
	}

	sk_SSL_CIPHER_free(sk);
	SSL_free(ssl);
	// SSL_free drops only the SSL's own reference: the context is ours
	FreeSSLCtx(ctx);

	return ciphers;
}

COUNTER *GetNumTcpConnectionsCounter()
{
	return num_tcp_connections;
}

bool IsIPMyHost(const IP *ip)
{
	LIST *o;
	UINT i;
	bool ret = false;
	if (ip == NULL)
	{
		return false;
	}

	if (IsZeroIP(ip))
	{
		return false;
	}

	o = GetHostIPAddressList();

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0)
		{
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false)
	{
		if (IsLocalHostIP(ip))
		{
			ret = true;
		}
	}

	return ret;
}

bool IsIPPrivate(const IP *ip)
{
	if (IsIP4(ip) == false)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	// RFC 1918 defines 10.0.0.0/8
	if (ipv4[0] == 10)
	{
		return true;
	}

	// RFC 1918 defines 172.16.0.0/12
	if (ipv4[0] == 172)
	{
		if (ipv4[1] >= 16 && ipv4[1] <= 31)
		{
			return true;
		}
	}

	// RFC 1918 defines 192.168.0.0/16
	if (ipv4[0] == 192 && ipv4[1] == 168)
	{
		return true;
	}

	// RFC 3927 defines 169.254.0.0/16
	if (ipv4[0] == 169 && ipv4[1] == 254)
	{
		return true;
	}

	// RFC 6598 defines 100.64.0.0/10
	if (ipv4[0] == 100)
	{
		if (ipv4[1] >= 64 && ipv4[1] <= 127)
		{
			return true;
		}
	}

	if (g_private_ip_list != NULL)
	{
		return IsOnPrivateIPFile(IPToUINT(ip));
	}

	return false;
}

void LoadPrivateIPFile()
{
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	LIST *o;
	if (b == NULL)
	{
		return;
	}

	o = NewList(NULL);

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask))
			{
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

bool IsOnPrivateIPFile(UINT ip)
{
	bool ret = false;

	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2)
			{
				ret = true;
			}
		}
	}

	return ret;
}

void FreePrivateIPFile()
{
	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		g_private_ip_list = NULL;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}
}

void FreeNetwork()
{

	if (dh_param != NULL)
	{
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

	if (local_mac_list != NULL)
	{
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



static int CmpIpAddressList(void *p1, void *p2)
{
	IP *ip1, *ip2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	ip1 = *(IP **)p1;
	ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL)
	{
		return 0;
	}

	// IPv4 < IPv6
	r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0)
	{
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false)
	{
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2))
	{
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false)
	{
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2))
	{
		return -1;
	}

	r = CmpIpAddr(ip1, ip2);
	if (r != 0)
	{
		return r;
	}

	if (IsIP6(ip1))
	{
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	}
	else
	{
		r = 0;
	}

	return r;
}

LIST *GetHostIPAddressList()
{
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL)
	{
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
		        ((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
		        host_ip_address_cache == NULL)
		{
			if (host_ip_address_cache != NULL)
			{
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL)
	{
		o = GetHostIPAddressListInternal();
	}

	return o;
}

LIST *GetHostIPAddressListInternal()
{
	char hostname[MAX_SIZE];
	LIST *o;
	IP any6, any4;
	IP local6, local4;
	struct addrinfo hint;
	struct addrinfo *info;
	bool is_v6_supported = IsIPv6Supported();

	GetLocalHostIP4(&local4);
	GetLocalHostIP6(&local6);

	ZeroIP4(&any4);
	Zero(&any6, sizeof(any6));

	Zero(hostname, sizeof(hostname));

	gethostname(hostname, sizeof(hostname));

	o = NewListFast(CmpIpAddressList);

	AddHostIPAddressToList(o, &any4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &any6);
	}

	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &local6);
	}

	Zero(&hint, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;
	info = NULL;

	if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
	{
		struct addrinfo *current;

		for (current = info; current != NULL; current = current->ai_next)
		{
			IP ip;

			if (current->ai_family == AF_INET)
			{
				struct sockaddr_in in;

				Copy(&in, current->ai_addr, sizeof(in));

				InAddrToIP(&ip, &in.sin_addr);
				AddHostIPAddressToList(o, &ip);
			}
			else if (current->ai_family == AF_INET6 && is_v6_supported)
			{
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

// Read cursor over a byte range: a read that does not fit fails and moves nothing
typedef struct PKT_CURSOR
{
	UCHAR *Pos;
	UINT Left;
} PKT_CURSOR;

static void PktCursorInit(PKT_CURSOR *c, UCHAR *buf, UINT size)
{
	c->Pos = buf;
	c->Left = size;
}

// Takes the next size bytes as a cursor of their own; sub NULL skips them
static bool PktCursorTake(PKT_CURSOR *c, UINT size, PKT_CURSOR *sub)
{
	if (size > c->Left)
	{
		return false;
	}

	if (sub != NULL)
	{
		PktCursorInit(sub, c->Pos, size);
	}

	c->Pos += size;
	c->Left -= size;

	return true;
}

static bool PktCursorU8(PKT_CURSOR *c, UCHAR *v)
{
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 1, NULL) == false)
	{
		return false;
	}

	*v = p[0];

	return true;
}

// Big-endian
static bool PktCursorU16(PKT_CURSOR *c, USHORT *v)
{
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 2, NULL) == false)
	{
		return false;
	}

	*v = (USHORT)((p[0] << 8) | p[1]);

	return true;
}

// Host name from the server_name extension of a TLS ClientHello at the start of a TCP payload, read in
// place. The handshake fields are bounded by the record length (not by the handshake length), each
// extension by the extensions length. The first host_name entry that is not empty up to its first NUL
// ends the search: it is cut to sni_size - 1 bytes, then spaces and tabs at both ends are dropped.
bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size)
{
	PKT_CURSOR rec, hello, exts, data, name;
	USHORT version, record_len, hello_type, hello_len, len16, type;
	UCHAR len8;

	if (packet_buf == NULL || packet_size <= 11 || sni == NULL || sni_size == 0)
	{
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	        packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	        packet_buf[9] >= 0x03))
	{
		return false;
	}

	// Record header: content type 0x16 (checked above), version, length
	PktCursorInit(&rec, packet_buf, packet_size);
	if (PktCursorTake(&rec, 1, NULL) == false || PktCursorU16(&rec, &version) == false ||
	        PktCursorU16(&rec, &record_len) == false || version < 0x0301 ||
	        PktCursorTake(&rec, record_len, &hello) == false)
	{
		return false;
	}

	// Handshake type 1 with the top length byte 0, then a 16-bit length that fits in the record
	if (PktCursorU16(&hello, &hello_type) == false || PktCursorU16(&hello, &hello_len) == false ||
	        hello_type != 0x0100 || hello_len > record_len - 4)
	{
		return false;
	}

	// client_version, random, session_id, cipher_suites, compression_methods, extensions
	if (PktCursorU16(&hello, &version) == false || version < 0x0301 ||
	        PktCursorTake(&hello, 32, NULL) == false ||
	        PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	        PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, NULL) == false ||
	        PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	        PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, &exts) == false)
	{
		return false;
	}

	while (PktCursorU16(&exts, &type) && PktCursorU16(&exts, &len16) && PktCursorTake(&exts, len16, &data))
	{
		UINT n, start, end;

		// server_name: list length (not checked), name type 0 (host_name), name length, name
		if (type != 0x0000 || PktCursorTake(&data, 2, NULL) == false ||
		        PktCursorU8(&data, &len8) == false || len8 != 0 ||
		        PktCursorU16(&data, &len16) == false || PktCursorTake(&data, len16, &name) == false)
		{
			continue;
		}

		n = 0;
		while (n < name.Left && name.Pos[n] != 0)
		{
			n++;
		}

		if (n == 0)
		{
			continue;
		}

		end = MIN(n, sni_size - 1);
		start = 0;
		while (start < end && (name.Pos[start] == ' ' || name.Pos[start] == '\t'))
		{
			start++;
		}
		while (end > start && (name.Pos[end - 1] == ' ' || name.Pos[end - 1] == '\t'))
		{
			end--;
		}

		Copy(sni, name.Pos + start, end - start);
		sni[end - start] = '\0';

		return end != start;
	}

	return false;
}

void SetDhParam(DH_CTX *dh)
{
	if (dh_param)
	{
		DhFree(dh_param);
	}

	dh_param = dh;
}
