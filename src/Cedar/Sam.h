// Sam.h
// Header of Sam.c

#ifndef SAM_H
#define SAM_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

// Receives a log line of a credential check, formatted as HLog formats it (param: AUTH_REQUEST LogParam)
typedef void(AUTH_LOG_PROC)(void *param, wchar_t *line);

// The credentials of a login as the client sent them, for SamAuthenticate
struct AUTH_REQUEST {
	char *Username;             // The user name of the login
	UINT AuthType;              // The authentication method of the client (CLIENT_AUTHTYPE_*)
	UCHAR *SecurePassword;      // CLIENT_AUTHTYPE_PASSWORD: SHA1_SIZE bytes, NULL when the client sent none of that size
	UCHAR *Random;              // The SHA1_SIZE random bytes of the server hello
	char *PlainPassword;        // CLIENT_AUTHTYPE_PLAIN_PASSWORD: the password
	X *Cert;                    // CLIENT_AUTHTYPE_CERT: the client certificate, NULL when it is missing or unreadable
	UCHAR *Sign;                // CLIENT_AUTHTYPE_CERT: the client's signature of Random by the key of Cert
	UINT SignSize;              // Size of Sign in bytes
	LOCK *YieldForBlockingCall; // A lock the caller holds, released around a blocking call (MsCheckLogon); NULL for none
	AUTH_LOG_PROC *Log;         // Receives the log lines of the certificate check; NULL for none
	void *LogParam;             // The first parameter of Log
};

// The outcome of SamAuthenticate
struct AUTH_RESULT {
	bool Ok;              // The credentials log the user in
	UINT Error;           // ERR_NO_ERROR, ERR_AUTH_FAILED, or ERR_AUTHTYPE_NOT_SUPPORTED for an unknown method
	POLICY *Policy;       // A clone of the user's policy, NULL when it was not read; the caller frees it (Free)
	bool IsEmptyPassword; // The login carries no password: an anonymous user or the empty password
	X *ClientX;           // A clone of the certificate that logged the user in, NULL otherwise; the caller takes it
};

void SamAuthenticate(HUB *hub, AUTH_REQUEST *req, AUTH_RESULT *ret);

void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark);

#endif // SAM_H

