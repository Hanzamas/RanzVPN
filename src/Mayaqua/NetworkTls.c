// NetworkTls.c
// TLS: the server SSL context, SSL context sharing and the cipher list, Recv and Send with the TLS record send and receive behind them, and the SNI parser

#include "Network.h"

#include "Cfg.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"
#include "TcpIp.h"

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

bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x) {
	if (ctx == NULL || x == NULL || x->x509 == NULL) {
		return false;
	}

	// The context takes over the reference when it succeeds
	if (X509_up_ref(x->x509) != 1) {
		return false;
	}

	if (SSL_CTX_add_extra_chain_cert(ctx, x->x509) != 1) {
		X509_free(x->x509);
		return false;
	}

	return true;
}

// A server context with every setting that does not depend on the connection applied: version flags, security
// level, certificate chain, certificate and key, cipher list and groups. x and priv may be NULL (no certificate),
// chain NULL takes the certificates of the chain_certs folder, cipher_list NULL keeps the OpenSSL default and
// settings NULL overrides nothing. Connections take the context by reference (ShareSSLCtx, FreeSSLCtx)
struct ssl_ctx_st *NewServerSSLCtx(X *x, K *priv, LIST *chain, char *cipher_list, SSL_ACCEPT_SETTINGS *settings) {
	SSL_CTX *ctx;
	SSL_ACCEPT_SETTINGS none;
	bool use_cert = (x != NULL && priv != NULL && CheckXandK(x, priv));

	ctx = NewSSLCtx(true);
	if (ctx == NULL) {
		return NULL;
	}

	if (settings == NULL) {
		Zero(&none, sizeof(none));
		settings = &none;
	}

	if (settings->Tls_Disable1_0) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}

	if (settings->Tls_Disable1_1) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
	}

	if (settings->Tls_Disable1_2) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
	}

	if (settings->Tls_Disable1_3) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
	}

	if (chain == NULL) {
		AddChainSslCertOnDirectory(ctx);
	} else {
		LockList(chain);
		{
			for (UINT i = 0; i < LIST_NUM(chain); i++) {
				AddChainSslCert(ctx, LIST_DATA(chain, i));
			}
		}
		UnlockList(chain);
	}

	if (settings->Override_Security_Level) {
		SSL_CTX_set_security_level(ctx, settings->Override_Security_Level_Value);
	}

	if (use_cert) {
		SSL_CTX_use_certificate(ctx, x->x509);
		SSL_CTX_use_PrivateKey(ctx, priv->pkey);
	}

	if (cipher_list != NULL) {
		if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0) {
			SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
		}
	}

	SSL_CTX_set1_groups_list(ctx, PQ_GROUP_LIST);

	// A context that lives for many connections must not resume sessions: a fresh context per connection never did
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	return ctx;
}

bool StartSSL(SOCK *sock, X *x, K *priv) {
	return StartSSLEx(sock, x, priv, NULL);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, char *sni_hostname) {
	return StartSSLEx3(sock, x, priv, NULL, sni_hostname, NULL, NULL);
}

// A failed recv, send or SSL call: SOCK_LATER when an async socket only has to wait, else the socket is disconnected
static UINT SockFailResult(SOCK *sock, bool later) {
	if (later) {
		return SOCK_LATER;
	}

	Disconnect(sock);
	return 0;
}

// The SSL_get_error code of a failed SSL_peek, SSL_read or SSL_write: an async socket waits on WANT_READ/WANT_WRITE
static UINT SslFailResult(SOCK *sock, int e) {
	if (sock->AsyncMode && e == SSL_ERROR_SSL) {
		DrainCryptErrors("SSL_ERROR_SSL on ASYNC socket");
	}

	return SockFailResult(sock, sock->AsyncMode && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE));
}

static UINT SecureRecv(SOCK *sock, void *data, UINT size) {
	int ret, e = SSL_ERROR_NONE;

	if (sock->AsyncMode) {
		// In async mode, check that at least 1 byte is readable: SSL_read would block otherwise.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false || sock->ssl == NULL) {
				Unlock(sock->ssl_lock);
				return 0;
			}
			ERR_clear_error();
			ret = SSL_peek(sock->ssl, &c, sizeof(c));
			if (ret <= 0) {
				e = SSL_get_error(sock->ssl, ret);
			}
		}
		Unlock(sock->ssl_lock);
		// Both 0 and negative values may be retryable: use SSL_get_error().
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		if (ret <= 0 && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)) {
			return SslFailResult(sock, e);
		}
	}

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL) {
			Unlock(sock->ssl_lock);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_read(sock->ssl, data, size);

		if (ret <= 0) {
			e = SSL_get_error(sock->ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0) {
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

static UINT SecureSend(SOCK *sock, void *data, UINT size) {
	int ret, e = SSL_ERROR_NONE;

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL) {
			Unlock(sock->ssl_lock);
			return 0;
		}

		if (sock->AsyncMode) {
			SSL_set_mode(sock->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
		}

		ERR_clear_error();
		ret = SSL_write(sock->ssl, data, size);
		if (ret <= 0) {
			e = SSL_get_error(sock->ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0) {
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

UINT Recv(SOCK *sock, void *data, UINT size, bool secure) {
	if (sock == NULL || data == NULL || size == 0) {
		return 0;
	}
	// recv and SSL_read take an int: the same cap as Send
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);

	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	    sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (secure != false && sock->SecureMode == false) {
		return 0;
	}

	if (secure) {
		return SecureRecv(sock, data, size);
	}

	SOCKET s = sock->socket;

	int ret = recv(s, data, size, 0);

	if (ret > 0) {
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

UINT Send(SOCK *sock, void *data, UINT size, bool secure) {
	if (sock == NULL || data == NULL || size == 0) {
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	    sock->socket == INVALID_SOCKET) {
		return 0;
	}
	if (secure != false && sock->SecureMode == false) {
		return 0;
	}

	if (secure) {
		return SecureSend(sock, data, size);
	}

	SOCKET s = sock->socket;
	int ret = send(s, data, size, 0);
	if (ret > 0) {
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

// Take one more reference of ctx: each holder calls FreeSSLCtx once
void ShareSSLCtx(struct ssl_ctx_st *ctx) {
	if (ctx == NULL) {
		return;
	}

	SSL_CTX_up_ref(ctx);
}

void FreeSSLCtx(struct ssl_ctx_st *ctx) {
	if (ctx == NULL) {
		return;
	}

	SSL_CTX_free(ctx);
}

UINT GetOSSecurityLevel() {
	UINT security_level_new = 0, security_level_set_ssl_version = 0;
	struct ssl_ctx_st *ctx = SSL_CTX_new(TLS_method());

	if (ctx == NULL) {
		return security_level_new;
	}


	security_level_new = SSL_CTX_get_security_level(ctx);

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, TLS_server_method());

	FreeSSLCtx(ctx);

	if (security_level_new >= security_level_set_ssl_version) {
		return security_level_new;
	}

	return security_level_set_ssl_version;
}

TOKEN_LIST *GetCipherList() {
	SSL_CTX *ctx;
	const char *name;
	STACK_OF(SSL_CIPHER) * sk;

	TOKEN_LIST *ciphers = ZeroMalloc(sizeof(TOKEN_LIST));

	ctx = NewSSLCtx(true);
	if (ctx == NULL) {
		return ciphers;
	}

	SSL *ssl = SSL_new(ctx);
	if (ssl == NULL) {
		FreeSSLCtx(ctx);
		return ciphers;
	}

	// A copy of the list (OpenSSL 1.1.1 or later is required): NULL when no cipher is enabled
	sk = SSL_get1_supported_ciphers(ssl);
	int num = (sk != NULL ? sk_SSL_CIPHER_num(sk) : 0);

	if (num > 0) {
		ciphers->Token = ZeroMalloc(sizeof(char *) * (UINT)num);
	}

	for (int i = 0; i < num; i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) {
			continue;
		}

		name = SSL_CIPHER_get_name(c);
		if (IsEmptyStr((char *)name)) {
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

// Read cursor over a byte range: a read that does not fit fails and moves nothing
typedef struct PKT_CURSOR {
	UCHAR *Pos;
	UINT Left;
} PKT_CURSOR;

static void PktCursorInit(PKT_CURSOR *c, UCHAR *buf, UINT size) {
	c->Pos = buf;
	c->Left = size;
}

// Takes the next size bytes as a cursor of their own; sub NULL skips them
static bool PktCursorTake(PKT_CURSOR *c, UINT size, PKT_CURSOR *sub) {
	if (size > c->Left) {
		return false;
	}

	if (sub != NULL) {
		PktCursorInit(sub, c->Pos, size);
	}

	c->Pos += size;
	c->Left -= size;

	return true;
}

static bool PktCursorU8(PKT_CURSOR *c, UCHAR *v) {
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 1, NULL) == false) {
		return false;
	}

	*v = p[0];

	return true;
}

// Big-endian
static bool PktCursorU16(PKT_CURSOR *c, USHORT *v) {
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 2, NULL) == false) {
		return false;
	}

	*v = (USHORT)((p[0] << 8) | p[1]);

	return true;
}

// Host name from the server_name extension of a TLS ClientHello at the start of a TCP payload, read in
// place. The handshake fields are bounded by the record length (not by the handshake length), each
// extension by the extensions length. The first host_name entry that is not empty up to its first NUL
// ends the search: it is cut to sni_size - 1 bytes, then spaces and tabs at both ends are dropped.
bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size) {
	PKT_CURSOR rec, hello, exts, data, name;
	USHORT version, record_len, hello_type, hello_len, len16, type;
	UCHAR len8;

	if (packet_buf == NULL || packet_size <= 11 || sni == NULL || sni_size == 0) {
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	      packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	      packet_buf[9] >= 0x03)) {
		return false;
	}

	// Record header: content type 0x16 (checked above), version, length
	PktCursorInit(&rec, packet_buf, packet_size);
	if (PktCursorTake(&rec, 1, NULL) == false || PktCursorU16(&rec, &version) == false ||
	    PktCursorU16(&rec, &record_len) == false || version < 0x0301 ||
	    PktCursorTake(&rec, record_len, &hello) == false) {
		return false;
	}

	// Handshake type 1 with the top length byte 0, then a 16-bit length that fits in the record
	if (PktCursorU16(&hello, &hello_type) == false || PktCursorU16(&hello, &hello_len) == false ||
	    hello_type != 0x0100 || hello_len > record_len - 4) {
		return false;
	}

	// client_version, random, session_id, cipher_suites, compression_methods, extensions
	if (PktCursorU16(&hello, &version) == false || version < 0x0301 ||
	    PktCursorTake(&hello, 32, NULL) == false ||
	    PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	    PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, NULL) == false ||
	    PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	    PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, &exts) == false) {
		return false;
	}

	while (PktCursorU16(&exts, &type) && PktCursorU16(&exts, &len16) && PktCursorTake(&exts, len16, &data)) {
		// server_name: list length (not checked), name type 0 (host_name), name length, name
		if (type != 0x0000 || PktCursorTake(&data, 2, NULL) == false ||
		    PktCursorU8(&data, &len8) == false || len8 != 0 ||
		    PktCursorU16(&data, &len16) == false || PktCursorTake(&data, len16, &name) == false) {
			continue;
		}

		UINT n = 0;
		while (n < name.Left && name.Pos[n] != 0) {
			n++;
		}

		if (n == 0) {
			continue;
		}

		UINT end = MIN(n, sni_size - 1);
		UINT start = 0;
		while (start < end && (name.Pos[start] == ' ' || name.Pos[start] == '\t')) {
			start++;
		}
		while (end > start && (name.Pos[end - 1] == ' ' || name.Pos[end - 1] == '\t')) {
			end--;
		}

		Copy(sni, name.Pos + start, end - start);
		sni[end - start] = '\0';

		return end != start;
	}

	return false;
}
