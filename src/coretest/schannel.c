// schannel.c
// A Schannel TLS 1.3 handshake in memory, client and server in this process, with the server
// key held in the CNG key storage provider (CORE-F1 acceptance criterion 2): once with a
// self-signed certificate read back from the My store by its thumbprint, as the new core reads
// its server certificate from LocalMachine\My, and once with the certificate of the OpenSSL 3
// PFX. The records go through two byte buffers instead of a socket.

#include "coretest.h"

#include <string.h>

#include <winternl.h>

#define SECURITY_WIN32
#include <security.h>

#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>

// TLS 1.3 cipher suites of AES-GCM (RFC 8446 appendix B.4)
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302

#define TLS_PIPE_SIZE 65536
#define TLS_MAX_STEPS 16

// The records one side has received and not yet consumed
typedef struct TLS_PIPE {
	UCHAR Data[TLS_PIPE_SIZE];
	UINT Size;
} TLS_PIPE;

// One end of the connection
typedef struct TLS_SIDE {
	bool Server;
	CredHandle Cred;
	CtxtHandle Ctx;
	bool HaveCred;
	bool HaveCtx;
	bool Done;     // The handshake is complete on this side
	TLS_PIPE In;   // What the peer sent
} TLS_SIDE;

static bool tls_pipe_append(TLS_PIPE *p, const void *data, UINT size) {
	if (size > TLS_PIPE_SIZE - p->Size)
		return false;

	CopyMemory(p->Data + p->Size, data, size);
	p->Size += size;
	return true;
}

// Keep the last 'extra' bytes, the ones SSPI left unread (SECBUFFER_EXTRA)
static void tls_pipe_keep_tail(TLS_PIPE *p, UINT extra) {
	if (extra == 0 || extra > p->Size) {
		p->Size = 0;
		return;
	}

	MoveMemory(p->Data, p->Data + p->Size - extra, extra);
	p->Size = extra;
}

// Credentials of one side, TLS 1.3 only. The server presents cert; the client checks the
// server certificate itself (SCH_CRED_MANUAL_CRED_VALIDATION), as the new core pins it.
static bool tls_acquire(TLS_SIDE *s, PCCERT_CONTEXT cert) {
	SCH_CREDENTIALS cred;
	TLS_PARAMETERS params;
	TimeStamp expiry;

	ZeroMemory(&params, sizeof(params));
	params.grbitDisabledProtocols = (DWORD)~SP_PROT_TLS1_3;

	ZeroMemory(&cred, sizeof(cred));
	cred.dwVersion = SCH_CREDENTIALS_VERSION;
	cred.cTlsParameters = 1;
	cred.pTlsParameters = &params;
	cred.dwFlags = SCH_USE_STRONG_CRYPTO;
	if (s->Server) {
		cred.cCreds = 1;
		cred.paCred = &cert;
	} else {
		cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
	}

	SECURITY_STATUS r = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, s->Server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->Cred, &expiry);
	if (r != SEC_E_OK) {
		coretest_info("AcquireCredentialsHandle (%s): 0x%08lX", s->Server ? "server" : "client", (unsigned long)r);
		return false;
	}

	s->HaveCred = true;
	return true;
}

#define TLS_ISC_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION)
#define TLS_ASC_FLAGS (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)

// One InitializeSecurityContext or AcceptSecurityContext call on what the side has received; its
// output goes to the peer. The client's first call has no input.
static SECURITY_STATUS tls_step(TLS_SIDE *s, TLS_SIDE *peer) {
	SecBuffer in[2], out[1];
	SecBufferDesc in_desc, out_desc;
	ULONG attr = 0;
	TimeStamp expiry;
	SECURITY_STATUS r;

	in[0].BufferType = SECBUFFER_TOKEN;
	in[0].cbBuffer = s->In.Size;
	in[0].pvBuffer = s->In.Data;
	in[1].BufferType = SECBUFFER_EMPTY;
	in[1].cbBuffer = 0;
	in[1].pvBuffer = NULL;
	in_desc.ulVersion = SECBUFFER_VERSION;
	in_desc.cBuffers = 2;
	in_desc.pBuffers = in;

	out[0].BufferType = SECBUFFER_TOKEN;
	out[0].cbBuffer = 0;
	out[0].pvBuffer = NULL;
	out_desc.ulVersion = SECBUFFER_VERSION;
	out_desc.cBuffers = 1;
	out_desc.pBuffers = out;

	if (s->Server)
		r = AcceptSecurityContext(&s->Cred, s->HaveCtx ? &s->Ctx : NULL, &in_desc, TLS_ASC_FLAGS, 0, &s->Ctx, &out_desc, &attr, &expiry);
	else
		r = InitializeSecurityContextW(&s->Cred, s->HaveCtx ? &s->Ctx : NULL, L"localhost", TLS_ISC_FLAGS, 0, 0,
		                               s->HaveCtx ? &in_desc : NULL, 0, &s->Ctx, &out_desc, &attr, &expiry);

	if (r == SEC_E_OK || r == SEC_I_CONTINUE_NEEDED)
		s->HaveCtx = true;

	if (out[0].pvBuffer != NULL) {
		if (out[0].cbBuffer != 0 && tls_pipe_append(&peer->In, out[0].pvBuffer, out[0].cbBuffer) == false)
			r = SEC_E_BUFFER_TOO_SMALL;
		FreeContextBuffer(out[0].pvBuffer);
	}

	if (r == SEC_E_OK || r == SEC_I_CONTINUE_NEEDED)
		tls_pipe_keep_tail(&s->In, in[1].BufferType == SECBUFFER_EXTRA ? in[1].cbBuffer : 0);
	if (r == SEC_E_OK)
		s->Done = true;

	return r;
}

// The handshake: the client starts, then each side answers what it received until both are done
static bool tls_handshake(TLS_SIDE *client, TLS_SIDE *server) {
	SECURITY_STATUS r = tls_step(client, server);

	for (UINT i = 0; r == SEC_I_CONTINUE_NEEDED || r == SEC_E_OK; i++) {
		if (client->Done && server->Done)
			return true;
		if (i >= TLS_MAX_STEPS)
			break;

		if (server->Done == false && server->In.Size != 0)
			r = tls_step(server, client);
		else if (client->Done == false && client->In.Size != 0)
			r = tls_step(client, server);
		else
			break;
	}

	coretest_info("handshake stopped: 0x%08lX (client %s, server %s)", (unsigned long)r, client->Done ? "done" : "not done", server->Done ? "done" : "not done");
	return false;
}

// Send one application message from s to its peer
static bool tls_send(TLS_SIDE *s, TLS_SIDE *peer, const char *msg) {
	SecPkgContext_StreamSizes sizes;
	SecBuffer buf[4];
	SecBufferDesc desc;
	UCHAR record[2048];
	UINT size = (UINT)strlen(msg);

	if (QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_STREAM_SIZES, &sizes) != SEC_E_OK || sizes.cbHeader + size + sizes.cbTrailer > sizeof(record))
		return false;

	CopyMemory(record + sizes.cbHeader, msg, size);
	buf[0].BufferType = SECBUFFER_STREAM_HEADER;
	buf[0].cbBuffer = sizes.cbHeader;
	buf[0].pvBuffer = record;
	buf[1].BufferType = SECBUFFER_DATA;
	buf[1].cbBuffer = size;
	buf[1].pvBuffer = record + sizes.cbHeader;
	buf[2].BufferType = SECBUFFER_STREAM_TRAILER;
	buf[2].cbBuffer = sizes.cbTrailer;
	buf[2].pvBuffer = record + sizes.cbHeader + size;
	buf[3].BufferType = SECBUFFER_EMPTY;
	buf[3].cbBuffer = 0;
	buf[3].pvBuffer = NULL;
	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = buf;

	if (EncryptMessage(&s->Ctx, 0, &desc, 0) != SEC_E_OK)
		return false;

	// The trailer may come out shorter than the maximum: the record is the three buffers as written
	return tls_pipe_append(&peer->In, buf[0].pvBuffer, buf[0].cbBuffer) && tls_pipe_append(&peer->In, buf[1].pvBuffer, buf[1].cbBuffer) &&
	       tls_pipe_append(&peer->In, buf[2].pvBuffer, buf[2].cbBuffer);
}

// Receive one application message. TLS 1.3 post-handshake messages (the server's NewSessionTicket)
// come back from DecryptMessage as SEC_I_RENEGOTIATE with the record as extra data, which goes
// through InitializeSecurityContext or AcceptSecurityContext again.
static bool tls_recv(TLS_SIDE *s, TLS_SIDE *peer, char *msg, UINT size) {
	for (UINT i = 0; i < TLS_MAX_STEPS && s->In.Size != 0; i++) {
		SecBuffer buf[4];
		SecBufferDesc desc;

		buf[0].BufferType = SECBUFFER_DATA;
		buf[0].cbBuffer = s->In.Size;
		buf[0].pvBuffer = s->In.Data;
		for (UINT j = 1; j < 4; j++) {
			buf[j].BufferType = SECBUFFER_EMPTY;
			buf[j].cbBuffer = 0;
			buf[j].pvBuffer = NULL;
		}
		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = buf;

		SECURITY_STATUS r = DecryptMessage(&s->Ctx, &desc, 0, NULL);
		UINT extra = 0;
		SecBuffer *data = NULL;
		for (UINT j = 0; j < 4; j++) {
			if (buf[j].BufferType == SECBUFFER_EXTRA)
				extra = buf[j].cbBuffer;
			if (buf[j].BufferType == SECBUFFER_DATA)
				data = &buf[j];
		}

		if (r == SEC_E_OK) {
			bool ok = data != NULL && data->cbBuffer < size;
			if (ok) {
				CopyMemory(msg, data->pvBuffer, data->cbBuffer);
				msg[data->cbBuffer] = 0;
			}
			tls_pipe_keep_tail(&s->In, extra);
			return ok;
		}

		if (r != SEC_I_RENEGOTIATE) {
			coretest_info("DecryptMessage (%s): 0x%08lX", s->Server ? "server" : "client", (unsigned long)r);
			return false;
		}

		tls_pipe_keep_tail(&s->In, extra);
		r = tls_step(s, peer);
		if (r != SEC_E_OK) {
			coretest_info("post-handshake message (%s): 0x%08lX", s->Server ? "server" : "client", (unsigned long)r);
			return false;
		}
	}

	return false;
}

static void tls_free(TLS_SIDE *s) {
	if (s->HaveCtx)
		DeleteSecurityContext(&s->Ctx);
	if (s->HaveCred)
		FreeCredentialsHandle(&s->Cred);
	s->HaveCtx = false;
	s->HaveCred = false;
}

// The checks of one connection with cert as the server certificate: TLS 1.3, AES-GCM, the client
// sees the server's certificate, and one message each way
static void tls_connection_checks(TLS_SIDE *client, TLS_SIDE *server, PCCERT_CONTEXT cert) {
	SecPkgContext_ConnectionInfo conn;
	SecPkgContext_CipherInfo cipher;
	PCCERT_CONTEXT remote = NULL;
	char msg[256];

	server->Server = true;
	if (coretest_check(tls_acquire(server, cert) && tls_acquire(client, NULL), "credentials: server with the certificate, client; TLS 1.3 only") == false)
		return;
	if (coretest_check(tls_handshake(client, server), "handshake complete on both sides") == false)
		return;

	coretest_check(QueryContextAttributesW(&client->Ctx, SECPKG_ATTR_CONNECTION_INFO, &conn) == SEC_E_OK && (conn.dwProtocol & SP_PROT_TLS1_3_CLIENT) != 0,
	               "client: TLS 1.3");
	coretest_check(QueryContextAttributesW(&server->Ctx, SECPKG_ATTR_CONNECTION_INFO, &conn) == SEC_E_OK && (conn.dwProtocol & SP_PROT_TLS1_3_SERVER) != 0,
	               "server: TLS 1.3");

	ZeroMemory(&cipher, sizeof(cipher));
	if (coretest_check(QueryContextAttributesW(&client->Ctx, SECPKG_ATTR_CIPHER_INFO, &cipher) == SEC_E_OK, "cipher information")) {
		// dwKeyType is the TLS NamedGroup of the key exchange: 0x001D x25519, 0x11EC X25519MLKEM768
		coretest_info("cipher suite 0x%04lX %ls, key exchange group 0x%04lX%s", (unsigned long)cipher.dwCipherSuite, cipher.szCipherSuite,
		              (unsigned long)cipher.dwKeyType, cipher.dwKeyType == CRYPTO_GROUP_X25519MLKEM768 ? " (ML-KEM hybrid)" : "");
		coretest_check(cipher.dwCipherSuite == TLS_AES_128_GCM_SHA256 || cipher.dwCipherSuite == TLS_AES_256_GCM_SHA384,
		               "AES-GCM cipher suite (TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384)");
	}

	coretest_check(QueryContextAttributesW(&client->Ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote) == SEC_E_OK && remote != NULL &&
	                   remote->cbCertEncoded == cert->cbCertEncoded && memcmp(remote->pbCertEncoded, cert->pbCertEncoded, cert->cbCertEncoded) == 0,
	               "the client received the server certificate");
	CryptoCertFree(remote);

	coretest_check(tls_send(server, client, "server to client") && tls_recv(client, server, msg, sizeof(msg)) && strcmp(msg, "server to client") == 0,
	               "a message from the server reaches the client (after the session tickets)");
	coretest_check(tls_send(client, server, "client to server") && tls_recv(server, client, msg, sizeof(msg)) && strcmp(msg, "client to server") == 0,
	               "a message from the client reaches the server");
}

static void tls_connection(const char *label, PCCERT_CONTEXT cert) {
	TLS_SIDE *client = (TLS_SIDE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TLS_SIDE));
	TLS_SIDE *server = (TLS_SIDE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TLS_SIDE));

	printf("  %s\n", label);
	if (coretest_check(client != NULL && server != NULL, "two connection ends allocated"))
		tls_connection_checks(client, server, cert);

	if (client != NULL) {
		tls_free(client);
		HeapFree(GetProcessHeap(), 0, client);
	}
	if (server != NULL) {
		tls_free(server);
		HeapFree(GetProcessHeap(), 0, server);
	}
}

void schannel_test() {
	char thumbprint[2 * CRYPTO_THUMBPRINT_SIZE + 1];
	UINT scope = coretest_scope();

	coretest_info("scope: %s", coretest_scope_name());

	// The new core's path: a certificate in the My store, found by its thumbprint
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(L"CN=localhost", L"localhost", NULL, 30, scope);
	if (coretest_check(cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope),
	                   "self-signed ECDSA P-256 certificate created and added to the My store")) {
		PCCERT_CONTEXT found = CryptoCertFindByThumbprint(thumbprint, NULL, scope);
		if (coretest_check(found != NULL && CryptoCertHasKspKey(found), "read back from the store by its thumbprint, key in the KSP"))
			tls_connection("self-signed certificate from the store:", found);
		CryptoCertFree(found);
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
	}
	if (cert != NULL)
		CryptoCertDeleteKey(cert);
	CryptoCertFree(cert);

	// The certificate an operator brings: the OpenSSL 3 PFX
	cert = CryptoCertImportPfx(coretest_pfx, coretest_pfx_size, CORETEST_PFX_PASSWORD, scope);
	if (coretest_check(cert != NULL && CryptoCertHasKspKey(cert), "OpenSSL 3 PFX imported, key in the KSP")) {
		tls_connection("certificate of the OpenSSL 3 PFX:", cert);
		CryptoCertDeleteKey(cert);
	}
	CryptoCertFree(cert);
}
