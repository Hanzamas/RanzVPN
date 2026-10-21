// Sam.c
// Security Accounts Manager: the credential gate of a login (SamAuthenticate)

#include "Sam.h"

#include "Account.h"
#include "Cedar.h"
#include "Hub.h"
#include "LogWriter.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

// Formats a log line of a credential check as HLog does and hands it to the log callback of req
static void SamLog(AUTH_REQUEST *req, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (req->Log == NULL || name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	req->Log(req->LogParam, buf);
	va_end(args);
}

static bool SamAuthUserByAnonymous(HUB *h, char *username)
{
	bool b = false;
	if (h == NULL || username == NULL)
	{
		return false;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_ANONYMOUS)
				{
					b = true;
				}
			}
			Unlock(u->lock);
		}
		ReleaseUser(u);
	}
	AcUnlock(h);

	return b;
}

// The domain password of an NT domain user (AUTHTYPE_NT; the "*" user stands for an unknown name), checked by
// MsCheckLogon. That call blocks, so the lock yield, which the caller holds, is released around it.
static bool SamAuthUserByPlainPassword(HUB *hub, char *username, char *password, LOCK *yield)
{
	bool b = false;
	wchar_t *name = NULL;
	if (hub == NULL || username == NULL || password == NULL)
	{
		return false;
	}

	AcLock(hub);
	{
		USER *u = AcGetUser(hub, username);
		if (u == NULL)
		{
			u = AcGetUser(hub, "*");
		}

		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_NT)
				{
					AUTHNT *auth = (AUTHNT *)u->AuthData;
					if (auth->NtUsername == NULL || UniStrLen(auth->NtUsername) == 0)
					{
						name = CopyStrToUni(username);
					}
					else
					{
						name = CopyUniStr(auth->NtUsername);
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(hub);

	if (name != NULL)
	{
		if (yield != NULL)
		{
			Unlock(yield);
		}

		b = MsCheckLogon(name, password);

		if (yield != NULL)
		{
			Lock(yield);
		}

		Free(name);
	}

	return b;
}

// The certificate req->Cert against the user req->Username; the result is logged through req->Log
static bool SamAuthUserByCert(HUB *h, AUTH_REQUEST *req)
{
	bool b = false;
	char *username = req->Username;
	X *x = req->Cert;
	if (h == NULL || username == NULL || x == NULL)
	{
		return false;
	}

	if (CheckXDateNow(x) == false)
	{
		return false;
	}

	if (IsValidCertInHub(h, x) == false)
	{
		wchar_t tmp[MAX_SIZE * 2];

		GetAllNameFromX(tmp, sizeof(tmp), x);

		SamLog(req, "LH_AUTH_NG_CERT", username, tmp);
		return false;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_USERCERT)
				{
					AUTHUSERCERT *auth = (AUTHUSERCERT *)u->AuthData;
					if (CompareX(auth->UserX, x))
					{
						b = true;
					}
				}
				else if (u->AuthType == AUTHTYPE_ROOTCERT)
				{
					AUTHROOTCERT *auth = (AUTHROOTCERT *)u->AuthData;
					if (h->HubDb != NULL)
					{
						LockList(h->HubDb->RootCertList);
						{
							X *root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
							if (root_cert != NULL)
							{
								b = true;
								if (auth->CommonName != NULL && UniIsEmptyStr(auth->CommonName) == false)
								{
									if (UniStrCmpi(x->subject_name->CommonName, auth->CommonName) != 0)
									{
										b = false;
									}
								}
								if (auth->Serial != NULL && auth->Serial->size >= 1)
								{
									if (CompareXSerial(x->serial, auth->Serial) == false)
									{
										b = false;
									}
								}
							}
						}
						UnlockList(h->HubDb->RootCertList);
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (b)
	{
		wchar_t tmp[MAX_SIZE * 2];

		GetAllNameFromX(tmp, sizeof(tmp), x);

		SamLog(req, "LH_AUTH_OK_CERT", username, tmp);
	}

	return b;
}

static POLICY *SamGetUserPolicy(HUB *h, char *username)
{
	POLICY *ret = NULL;
	if (h == NULL || username == NULL)
	{
		return NULL;
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			USERGROUP *g = NULL;
			Lock(u->lock);
			{
				if (u->Policy != NULL)
				{
					ret = ClonePolicy(u->Policy);
				}

				g = u->Group;

				if (g != NULL)
				{
					AddRef(g->ref);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
			u = NULL;

			if (ret == NULL)
			{
				if (g != NULL)
				{
					Lock(g->lock);
					{
						ret = ClonePolicy(g->Policy);
					}
					Unlock(g->lock);
				}
			}

			if (g != NULL)
			{
				ReleaseGroup(g);
			}
		}
	}
	AcUnlock(h);

	return ret;
}

static bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password)
{
	bool b = false;
	UCHAR secure_password_check[SHA1_SIZE];
	if (h == NULL || username == NULL || secure_password == NULL)
	{
		return false;
	}

	if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0)
	{
		SecurePassword(secure_password_check, h->SecurePassword, random);
		return (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0);
	}

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u)
		{
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_PASSWORD)
				{
					AUTHPASSWORD *auth = (AUTHPASSWORD *)u->AuthData;

					SecurePassword(secure_password_check, auth->HashedKey, random);
					if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
					{
						b = true;
					}
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	return b;
}

// CLIENT_AUTHTYPE_PASSWORD: the secure password against a password user. The user's policy is read also when
// the password is wrong: the error PACK of a refused login carries its NoSavePassword.
static void SamAuthenticateSecurePassword(HUB *hub, AUTH_REQUEST *req, AUTH_RESULT *ret)
{
	if (req->SecurePassword == NULL)
	{
		return;
	}

	ret->Ok = SamAuthUserByPassword(hub, req->Username, req->Random, req->SecurePassword);

	ret->Policy = SamGetUserPolicy(hub, req->Username);

	if (ret->Ok)
	{
		UCHAR hashed_empty_password[SHA1_SIZE];
		UCHAR secure_empty_password[SHA1_SIZE];
		HashPassword(hashed_empty_password, req->Username, "");
		SecurePassword(secure_empty_password, hashed_empty_password, req->Random);
		if (Cmp(req->SecurePassword, secure_empty_password, SHA1_SIZE) == 0)
		{
			ret->IsEmptyPassword = true;
		}
	}
}

// CLIENT_AUTHTYPE_PLAIN_PASSWORD: the password of a password user, else the domain password of an NT domain user
static void SamAuthenticatePlainPassword(HUB *hub, AUTH_REQUEST *req, AUTH_RESULT *ret)
{
	UCHAR secure_password[SHA1_SIZE];
	UCHAR hash_password[SHA1_SIZE];

	if (req->PlainPassword == NULL)
	{
		return;
	}

	HashPassword(hash_password, req->Username, req->PlainPassword);
	SecurePassword(secure_password, hash_password, req->Random);
	ret->Ok = SamAuthUserByPassword(hub, req->Username, req->Random, secure_password);

	if (ret->Ok)
	{
		ret->Policy = SamGetUserPolicy(hub, req->Username);
	}

	if (ret->Ok == false)
	{
		ret->Ok = SamAuthUserByPlainPassword(hub, req->Username, req->PlainPassword, req->YieldForBlockingCall);

		if (ret->Ok)
		{
			ret->Policy = SamGetUserPolicy(hub, req->Username);
		}
	}

	if (ret->Ok)
	{
		if (IsEmptyStr(req->PlainPassword))
		{
			ret->IsEmptyPassword = true;
		}
	}
}

// CLIENT_AUTHTYPE_CERT: the signature of the server random by the key of the certificate, then the certificate
// against the user. The certificate that logs the user in is cloned into the result.
static void SamAuthenticateCert(HUB *hub, AUTH_REQUEST *req, AUTH_RESULT *ret)
{
	X *x = req->Cert;

	if (x != NULL && req->Sign != NULL && x->is_compatible_bit &&
		req->SignSize == (x->bits / 8))
	{
		K *k = GetKFromX(x);
		if (RsaVerifyEx(req->Random, SHA1_SIZE, req->Sign, req->SignSize, k))
		{
			// A matching signature proves the client holds this certificate.
			ret->Ok = SamAuthUserByCert(hub, req);
			if (ret->Ok)
			{
				ret->ClientX = CloneX(x);
			}
		}
		FreeK(k);
	}
}

// Checks the credentials of a login against the users of hub: first whether the user is an anonymous user,
// then the method of req->AuthType. The caller holds req->YieldForBlockingCall (if any), and holds it again
// when this returns. ret receives the outcome; the caller frees ret->Policy (Free) and takes ret->ClientX.
void SamAuthenticate(HUB *hub, AUTH_REQUEST *req, AUTH_RESULT *ret)
{
	if (ret == NULL)
	{
		return;
	}

	Zero(ret, sizeof(AUTH_RESULT));
	ret->Error = ERR_AUTH_FAILED;

	if (hub == NULL || req == NULL || req->Username == NULL)
	{
		return;
	}

	ret->Ok = SamAuthUserByAnonymous(hub, req->Username);
	if (ret->Ok)
	{
		ret->IsEmptyPassword = true;
	}

	if (ret->Ok == false)
	{
		switch (req->AuthType)
		{
		case CLIENT_AUTHTYPE_ANONYMOUS:
			break;

		case CLIENT_AUTHTYPE_PASSWORD:
			SamAuthenticateSecurePassword(hub, req, ret);
			break;

		case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
			SamAuthenticatePlainPassword(hub, req, ret);
			break;

		case CLIENT_AUTHTYPE_CERT:
			SamAuthenticateCert(hub, req, ret);
			break;

		default:
			ret->Error = ERR_AUTHTYPE_NOT_SUPPORTED;
			return;
		}
	}

	if (ret->Ok)
	{
		ret->Error = ERR_NO_ERROR;
	}
}

void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark)
{
	char tmp_username[MAX_SIZE];
	char tmp_domain[MAX_SIZE];
	TOKEN_LIST *t;

	if (src_username != dst_username)
	{
		ClearStr(dst_username, dst_username_size);
	}

	ClearStr(dst_domain, dst_domain_size);
	if (src_username == NULL || dst_username == NULL || dst_domain == NULL)
	{
		return;
	}

	StrCpy(tmp_username, sizeof(tmp_username), src_username);
	ClearStr(tmp_domain, sizeof(tmp_domain));

	if (do_not_parse_atmark == false)
	{
		t = ParseTokenWithNullStr(tmp_username, "@");
		if (t->NumTokens >= 1)
		{
			StrCpy(tmp_username, sizeof(tmp_username), t->Token[0]);
		}
		if (t->NumTokens >= 2)
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[1]);
		}
		FreeToken(t);
	}

	t = ParseTokenWithNullStr(tmp_username, "\\");
	if (t->NumTokens >= 2)
	{
		if (IsEmptyStr(tmp_domain))
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[0]);
		}

		StrCpy(tmp_username, sizeof(tmp_username), t->Token[1]);
	}
	FreeToken(t);

	StrCpy(dst_username, dst_username_size, tmp_username);
	StrCpy(dst_domain, dst_domain_size, tmp_domain);
}
