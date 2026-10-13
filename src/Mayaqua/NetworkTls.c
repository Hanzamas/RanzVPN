// NetworkTls.c
// TLS: SSL context, cipher list, the TLS handshake (StartSSL) and secure send and receive

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "HTTP.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Pack.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

void SetWantToUseCipher(SOCK *sock, char *name)
{
	if (sock == NULL || name == NULL)
	{
		return;
	}

	if (sock->WaitToUseCipher)
	{
		Free(sock->WaitToUseCipher);
	}

	sock->WaitToUseCipher = CopyStr(name);
}

void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	wchar_t txtname[MAX_SIZE];
	DIRLIST *dir;
	LIST *o;
	UINT i;

	if (ctx == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	CombinePathW(txtname, sizeof(txtname), dirname, L"Readme_Chain_Certs.txt");

	if (IsFileExistsW(txtname) == false)
	{
		FileCopyW(L"|chain_certs.txt", txtname);
	}

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

					for (j = 0; j < LIST_NUM(o); j++)
					{
						UCHAR *hash2 = LIST_DATA(o, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0)
						{
							exists = true;
						}
					}

					if (exists == false)
					{
						AddChainSslCert(ctx, x);

						Add(o, Clone(hash, SHA1_SIZE));
					}

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		UCHAR *hash = LIST_DATA(o, i);

		Free(hash);
	}

	ReleaseList(o);
}

bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x)
{
	bool ret = false;
	X *x_copy;
	if (ctx == NULL || x == NULL)
	{
		return ret;
	}

	x_copy = CloneX(x);

	if (x_copy != NULL)
	{
		SSL_CTX_add_extra_chain_cert(ctx, x_copy->x509);
		x_copy->do_not_free = true;

		ret = true;

		FreeX(x_copy);
	}

	return ret;
}

bool StartSSL(SOCK *sock, X *x, K *priv)
{
	return StartSSLEx(sock, x, priv, 0, NULL);
}

bool StartSSLEx(SOCK *sock, X *x, K *priv, UINT ssl_timeout, char *sni_hostname)
{
	return StartSSLEx3(sock, x, priv, NULL, ssl_timeout, sni_hostname, NULL, NULL);
}

bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, UINT ssl_timeout, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err)
{
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout = 1024;
	SSL_CTX *ssl_ctx;
	UINT dummy_err = 0;
	long ssl_verify_err;

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
	if (ssl_timeout == 0)
	{
		ssl_timeout = TIMEOUT_SSL_CONNECT;
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

	ssl_ctx = NewSSLCtx(sock->ServerMode);
	if (ssl_ctx == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	{
		if (sock->ServerMode)
		{
#ifdef	SSL_OP_NO_TLSv1
			if (sock->SslAcceptSettings.Tls_Disable1_0)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_1
			if (sock->SslAcceptSettings.Tls_Disable1_1)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_2
			if (sock->SslAcceptSettings.Tls_Disable1_2)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_3
			if (sock->SslAcceptSettings.Tls_Disable1_3)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
			}
#endif

			Unlock(openssl_lock);
			if (chain == NULL)
			{
				AddChainSslCertOnDirectory(ssl_ctx);
			}
			else
			{
				UINT i;
				X *x;
				LockList(chain);
				{
					for (i = 0;i < LIST_NUM(chain);i++)
					{
						x = LIST_DATA(chain, i);
						AddChainSslCert(ssl_ctx, x);
					}
				}
				UnlockList(chain);
			}
			Lock(openssl_lock);
		}
		else
		{
			if (ssl_option != NULL && ssl_option->VerifyPeer)
			{
				X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
				if (ssl_option->AddDefaultCA)
				{
					HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
					if (hStore != NULL)
					{
						PCCERT_CONTEXT pContext = NULL;
						while ((pContext = CertEnumCertificatesInStore(hStore, pContext)))
						{
							X509 *x509 = d2i_X509(NULL, (const unsigned char**)&pContext->pbCertEncoded, pContext->cbCertEncoded);
							if (x509 != NULL)
							{
								X509_STORE_add_cert(store, x509);
								X509_free(x509);
							}
						}
						CertCloseStore(hStore, 0);
					}
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) ||  LIBRESSL_VERSION_NUMBER >= 0x3060000L
		if (sock->SslAcceptSettings.Override_Security_Level)
		{
			SSL_CTX_set_security_level(ssl_ctx, sock->SslAcceptSettings.Override_Security_Level_Value);
		}
#endif

		sock->ssl = SSL_new(ssl_ctx);

		if (sock->ssl == NULL)
		{
			return false;
		}

		SSL_set_fd(sock->ssl, (int)sock->socket);

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
		if (sock->ServerMode == false)
		{
			if (IsEmptyStr(sni_hostname) == false)
			{
				SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
			}
		}
#endif

	}
	Unlock(openssl_lock);

	if (x != NULL)
	{
		if (CheckXandK(x, priv))
		{
			x509 = x->x509;
			key = priv->pkey;

			Lock(openssl_lock);
			{
				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
			Unlock(openssl_lock);
		}
	}

	if (sock->WaitToUseCipher != NULL)
	{
		Lock(openssl_lock);
		{
			if (SSL_set_cipher_list(sock->ssl, sock->WaitToUseCipher) == 0)
				SSL_set_cipher_list(sock->ssl, DEFAULT_CIPHER_LIST);
		}
		Unlock(openssl_lock);
	}

	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);
	#endif
	
	if (sock->ServerMode)
	{

		if (SSL_accept(sock->ssl) <= 0)
		{

			Lock(openssl_lock);
			{
				unsigned long err;
				while (err = ERR_get_error())
				{
					Debug("SSL_accept error %X: %s\n", err, ERR_reason_error_string(err));
					if (ERR_GET_LIB(err) == ERR_LIB_SSL)
					{
						switch (ERR_GET_REASON(err))
						{
						case SSL_R_UNSUPPORTED_PROTOCOL:
						case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
						case SSL_R_VERSION_TOO_HIGH:
#endif
							*ssl_err = 150;
							break;
						case SSL_R_NO_SHARED_CIPHER:
							*ssl_err = 151;
							break;
						default:
							*ssl_err = 152;
						}
					}
				}
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			FreeSSLCtx(ssl_ctx);
			return false;
		}

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef	TLSEXT_NAMETYPE_host_name
		if (true)
		{
			const char *sni_recv_hostname = SSL_get_servername(sock->ssl, TLSEXT_NAMETYPE_host_name);

			if (IsEmptyStr((char *)sni_recv_hostname) == false)
			{
				StrCpy(sock->SniHostname, sizeof(sock->SniHostname), (char *)sni_recv_hostname);
			}
		}
#endif
#endif

	}
	else
	{	
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, ssl_timeout);
		if (SSL_connect(sock->ssl) <= 0)
		{
			Lock(openssl_lock);
			{
				unsigned long err;
				while (err = ERR_get_error())
				{
					Debug("SSL_connect error %X: %s\n", err, ERR_reason_error_string(err));
					if (ERR_GET_LIB(err) == ERR_LIB_SSL)
					{
						switch (ERR_GET_REASON(err))
						{
						case SSL_R_UNSUPPORTED_PROTOCOL:
						case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
						case SSL_R_VERSION_TOO_HIGH:
#endif
						case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
							*ssl_err = 150;
							break;
						default:
							*ssl_err = 152;
						}
					}
				}
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			SetTimeout(sock, prev_timeout);
			FreeSSLCtx(ssl_ctx);
			return false;
		}
		SetTimeout(sock, prev_timeout);
	}

	sock->SecureMode = true;

	Lock(openssl_lock);
	{
		x509 = SSL_get_peer_certificate(sock->ssl);
		ssl_verify_err = SSL_get_verify_result(sock->ssl);
		sock->SslVersion = SSL_get_version(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		sock->RemoteX = NULL;
	}
	else
	{
		sock->RemoteX = X509ToX(x509);
	}

	if (ssl_option != NULL && ssl_option->VerifyPeer)
	{
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

				if (ssl_option->PromptOnVerifyFail == false)
				{
					Lock(openssl_lock);
					{
						SSL_free(sock->ssl);
						sock->ssl = NULL;
					}
					Unlock(openssl_lock);

					Unlock(sock->ssl_lock);
					FreeSSLCtx(ssl_ctx);
					return false;
				}
			}
		}
	}

	Lock(openssl_lock);
	{
		x509 = SSL_get_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		sock->LocalX = NULL;
	}
	else
	{
		X *local_x;
		local_x = X509ToX(x509);
		local_x->do_not_free = true;
		sock->LocalX = CloneX(local_x);
		FreeX(local_x);
	}

	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	Lock(openssl_lock);
	{
		sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));
	}
	Unlock(openssl_lock);

	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (sock->ServerMode)
	{
		SockEnableSslLogging(sock);
	}
#endif

	return true;
}

#ifdef	ENABLE_SSL_LOGGING

void SockEnableSslLogging(SOCK *s)
{
	char dirname[MAX_PATH];
	char tmp[MAX_PATH];
	char dtstr[MAX_PATH];
	char fn1[MAX_PATH], fn2[MAX_PATH];
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled)
	{
		return;
	}

	s->IsSslLoggingEnabled = true;

	GetDateTimeStrMilli64ForFileName(dtstr, sizeof(dtstr), LocalTime64());
	Format(tmp, sizeof(tmp), "%s__%r_%u__%r_%u", dtstr,
	       &s->LocalIP, s->LocalPort, &s->RemoteIP, s->RemotePort);

	ConbinePath(dirname, sizeof(dirname), SSL_LOGGING_DIRNAME, tmp);

	MakeDirEx(dirname);

	ConbinePath(fn1, sizeof(fn1), dirname, "send.c");
	ConbinePath(fn2, sizeof(fn2), dirname, "recv.c");

	s->SslLogging_Send = FileCreate(fn1);
	s->SslLogging_Recv = FileCreate(fn2);

	s->SslLogging_Lock = NewLock();
}

void SockCloseSslLogging(SOCK *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled == false)
	{
		return;
	}

	s->IsSslLoggingEnabled = false;

	FileClose(s->SslLogging_Recv);
	s->SslLogging_Recv = NULL;

	FileClose(s->SslLogging_Send);
	s->SslLogging_Send = NULL;

	DeleteLock(s->SslLogging_Lock);
	s->SslLogging_Lock = NULL;
}

void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size)
{
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled == false)
	{
		return;
	}

	Lock(s->SslLogging_Lock);
	{
		if (s->SslLogging_Send != NULL)
		{
			if (send_size >= 1 && send_data != NULL)
			{
				FileWrite(s->SslLogging_Send, send_data, send_size);
			}
		}

		if (s->SslLogging_Recv != NULL)
		{
			if (recv_size >= 1 && recv_data != NULL)
			{
				FileWrite(s->SslLogging_Recv, recv_data, recv_size);
			}
		}
	}
	Unlock(s->SslLogging_Lock);
}

#endif

UINT SecureRecv(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;
	SSL *ssl;

	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		// In async mode, check that at least 1 byte is readable: SSL_read would block otherwise.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false)
			{
				Unlock(sock->ssl_lock);
				return 0;
			}
			ERR_clear_error();
			ret = SSL_peek(ssl, &c, sizeof(c));
		}
		Unlock(sock->ssl_lock);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		// OpenSSL 3: both 0 and negative values may be retryable; use SSL_get_error().
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		if (ret == 0)
		{
			Disconnect(sock);
			return 0;
		}
#endif
		if (ret <= 0)
		{
			e = SSL_get_error(ssl, ret);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
			{
				if (e == SSL_ERROR_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
					&&
					sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
					sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
					sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1]
#endif
					)
				{
					UINT ssl_err_no;
					while (ssl_err_no = ERR_get_error()){
						Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
					};

					Disconnect(sock);
					return 0;
				}
				return SOCK_LATER;
			}
		}
	}

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_read(ssl, data, size);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0)
#else
		if (ret <= 0)
#endif
		{
			e = SSL_get_error(ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (ret > 0)
	{
		SockWriteSslLog(sock, NULL, 0, data, ret);
	}
#endif

	if (ret > 0)
	{
		sock->RecvSize += (UINT64)ret;
		sock->RecvNum++;

		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// OpenSSL 3: both 0 and negative values may be retryable; use SSL_get_error().
	// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
	if (ret == 0)
	{
		Disconnect(sock);
		return 0;
	}
#endif

	if (sock->AsyncMode)
	{
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			if (e == SSL_ERROR_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				&&
				sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
				sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
				sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1]
#endif
				)
			{
				UINT ssl_err_no;
				while (ssl_err_no = ERR_get_error()) {
					Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
				};

				Disconnect(sock);
				return 0;
			}

			return SOCK_LATER;
		}
	}
	Disconnect(sock);
	return 0;
}

UINT SecureSend(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;
	SSL *ssl;
	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_write(ssl, data, size);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0)
#else
		if (ret <= 0)
#endif
		{
			e = SSL_get_error(ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (ret > 0)
	{
		SockWriteSslLog(sock, data, ret, NULL, 0);
	}
#endif

	if (ret > 0)
	{
		sock->SendSize += (UINT64)ret;
		sock->SendNum++;
		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (ret == 0)
	{
		Disconnect(sock);
		return 0;
	}
#endif

	if (sock->AsyncMode)
	{
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			if (e == SSL_ERROR_SSL)
			{
				UINT ssl_err_no;
				while (ssl_err_no = ERR_get_error()) {
					Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
				};

				Disconnect(sock);
				return 0;
			}

			return SOCK_LATER;
		}
	}
	Disconnect(sock);
	return 0;
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
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());

	if (ctx == NULL)
	{
		return security_level_new;
	}


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x3060000L
	security_level_new = SSL_CTX_get_security_level(ctx);
#endif

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());

	FreeSSLCtx(ctx);

	if(security_level_new >= security_level_set_ssl_version)
	{
		return security_level_new;
	}

	return security_level_set_ssl_version;
}

TOKEN_LIST *GetCipherList()
{
	UINT i;
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x2090100L
	sk = SSL_get1_supported_ciphers(ssl);
#else
	sk = SSL_get_ciphers(ssl);
#endif

	for (i = 0; i < (UINT)sk_SSL_CIPHER_num(sk); i++)
	{
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);

		name = SSL_CIPHER_get_name(c);
		if (IsEmptyStr((char *)name))
		{
			break;
		}

		ciphers->NumTokens++;

		if (ciphers->Token != NULL)
		{
			ciphers->Token = ReAlloc(ciphers->Token, sizeof(char *) * ciphers->NumTokens);
		}
		else
		{
			ciphers->Token = Malloc(sizeof(char *));
		}

		ciphers->Token[i] = CopyStr((char *)name);
	}

	sk_SSL_CIPHER_free(sk);
	SSL_free(ssl);

	return ciphers;
}

bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size)
{
	BUF *buf;
	bool ret = false;
	UCHAR content_type;
	USHORT version;
	USHORT handshake_length;

	if (packet_buf == NULL || packet_size <= 11)
	{
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	        packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	        packet_buf[9] >= 0x03))
	{
		return false;
	}

	buf = NewBufFromMemory(packet_buf, packet_size);

	if (ReadBuf(buf, &content_type, sizeof(UCHAR)) == sizeof(UCHAR) &&
	        ReadBuf(buf, &version, sizeof(USHORT)) == sizeof(USHORT) &&
	        ReadBuf(buf, &handshake_length, sizeof(USHORT)) == sizeof(USHORT))
	{
		version = Endian16(version);
		handshake_length = Endian16(handshake_length);

		if (content_type == 0x16 && version >= 0x0301)
		{
			UCHAR *handshake_data = Malloc(handshake_length);

			if (ReadBuf(buf, handshake_data, handshake_length) == handshake_length)
			{
				BUF *buf2 = NewBufFromMemory(handshake_data, handshake_length);
				USHORT handshake_type;
				USHORT handshake_length_2;

				if (ReadBuf(buf2, &handshake_type, sizeof(USHORT)) == sizeof(USHORT) &&
				        ReadBuf(buf2, &handshake_length_2, sizeof(USHORT)) == sizeof(USHORT))
				{
					handshake_type = Endian16(handshake_type);
					handshake_length_2 = Endian16(handshake_length_2);

					if (handshake_type == 0x0100 && handshake_length_2 <= (handshake_length - 4))
					{
						USHORT version2;

						if (ReadBuf(buf2, &version2, sizeof(USHORT)) == sizeof(USHORT))
						{
							version2 = Endian16(version2);

							if (version2 >= 0x0301)
							{
								UCHAR rand[32];

								if (ReadBuf(buf2, rand, sizeof(rand)) == sizeof(rand))
								{
									UCHAR session_id_len;

									if (ReadBuf(buf2, &session_id_len, sizeof(UCHAR)) == sizeof(UCHAR))
									{
										if (ReadBuf(buf2, NULL, session_id_len) == session_id_len)
										{
											USHORT cipher_len;

											if (ReadBuf(buf2, &cipher_len, sizeof(USHORT)) == sizeof(USHORT))
											{
												cipher_len = Endian16(cipher_len);

												if (ReadBuf(buf2, NULL, cipher_len) == cipher_len)
												{
													UCHAR comps_len;

													if (ReadBuf(buf2, &comps_len, sizeof(UCHAR)) == sizeof(UCHAR))
													{
														if (ReadBuf(buf2, NULL, comps_len) == comps_len)
														{
															USHORT ext_length;

															if (ReadBuf(buf2, &ext_length, sizeof(USHORT)) == sizeof(USHORT))
															{
																UCHAR *ext_buf;

																ext_length = Endian16(ext_length);

																ext_buf = Malloc(ext_length);

																if (ReadBuf(buf2, ext_buf, ext_length) == ext_length)
																{
																	BUF *ebuf = NewBufFromMemory(ext_buf, ext_length);

																	while (ret == false)
																	{
																		USHORT type;
																		USHORT data_len;
																		UCHAR *data;

																		if (ReadBuf(ebuf, &type, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		if (ReadBuf(ebuf, &data_len, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		type = Endian16(type);
																		data_len = Endian16(data_len);

																		data = Malloc(data_len);

																		if (ReadBuf(ebuf, data, data_len) != data_len)
																		{
																			Free(data);
																			break;
																		}

																		if (type == 0x0000)
																		{
																			BUF *dbuf = NewBufFromMemory(data, data_len);

																			USHORT total_len;

																			if (ReadBuf(dbuf, &total_len, sizeof(USHORT)) == sizeof(USHORT))
																			{
																				UCHAR c;
																				total_len = Endian16(total_len);

																				if (ReadBuf(dbuf, &c, sizeof(UCHAR)) == sizeof(UCHAR))
																				{
																					if (c == 0)
																					{
																						USHORT name_len;

																						if (ReadBuf(dbuf, &name_len, sizeof(USHORT)) == sizeof(USHORT))
																						{
																							char *name_buf;
																							name_len = Endian16(name_len);

																							name_buf = ZeroMalloc(name_len + 1);

																							if (ReadBuf(dbuf, name_buf, name_len) == name_len)
																							{
																								if (StrLen(name_buf) >= 1)
																								{
																									ret = true;

																									StrCpy(sni, sni_size, name_buf);
																								}
																							}

																							Free(name_buf);
																						}
																					}
																				}
																			}

																			FreeBuf(dbuf);
																		}

																		Free(data);
																	}

																	FreeBuf(ebuf);
																}

																Free(ext_buf);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				FreeBuf(buf2);
			}

			Free(handshake_data);
		}
	}

	FreeBuf(buf);

	if (ret)
	{
		Trim(sni);

		if (IsEmptyStr(sni))
		{
			ret = false;
		}
	}

	return ret;
}
