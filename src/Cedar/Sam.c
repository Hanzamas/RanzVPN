// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Sam.c
// Security Accounts Manager

#include "Sam.h"

#include "Account.h"
#include "Cedar.h"
#include "Connection.h"
#include "Hub.h"
#include "MsChapV2.h"
#include "Server.h"

#include "Mayaqua/Encoding.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include <string.h>

// Password encryption
void SecurePassword(void *secure_password, void *password, void *random) {
	BUF *b;
	// Validate arguments
	if (secure_password == NULL || password == NULL || random == NULL)
		return;

	b = NewBuf();
	WriteBuf(b, password, SHA1_SIZE);
	WriteBuf(b, random, SHA1_SIZE);
	Sha0(secure_password, b->Buf, b->Size);

	FreeBuf(b);
}

// Anonymous authentication of user
bool SamAuthUserByAnonymous(HUB *h, char *username) {
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL)
		return false;

	AcLock(h);
	{
		USER *u = AcGetUser(h, username);
		if (u) {
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_ANONYMOUS)
					b = true;
			}
			Unlock(u->lock);
		}
		ReleaseUser(u);
	}
	AcUnlock(h);

	return b;
}

// Plaintext password authentication of user
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast) {
	bool b = false;
	wchar_t *name = NULL;
	wchar_t *groupname = NULL;
	UINT timeout = 90;
	HUB *h;
	// Validate arguments
	if (hub == NULL || c == NULL || username == NULL || password == NULL)
		return false;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
		return false;

	h = hub;

	AddRef(h->ref);

	// Get the user name on authentication system
	AcLock(hub);
	{
		USER *u;

		// Find exact user first
		u = AcGetUser(hub, username);
		if (u == NULL && ast)
			u = AcGetUser(hub, "*");

		if (u) {
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_NT) {
					// NT authentication
					AUTHNT *auth = (AUTHNT *)u->AuthData;
					if (auth->NtUsername == NULL || UniStrLen(auth->NtUsername) == 0)
						name = CopyStrToUni(username);
					else
						name = CopyUniStr(auth->NtUsername);

					groupname = CopyStrToUni(u->GroupName);

					if (u->Policy)
						timeout = u->Policy->TimeOut;
				}
			}
			Unlock(u->lock);
			ReleaseUser(u);
		}
	}
	AcUnlock(hub);

	if (name != NULL) {
		// NT authentication
#ifdef OS_WIN32
		Unlock(hub->lock);

		// Plaintext password authentication
		b = MsCheckLogon(name, password);

		Lock(hub->lock);
#endif // OS_WIN32

		// Memory release
		if (groupname != NULL)
			Free(groupname);
		Free(name);
	}

	ReleaseHub(h);

	return b;
}

// Certificate authentication of user
bool SamAuthUserByCert(HUB *h, char *username, X *x) {
	bool b = false;
	// Validate arguments
	if (h == NULL || username == NULL || x == NULL)
		return false;

	if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) != 0)
		return false;

	// Check expiration date
	if (CheckXDateNow(x) == false)
		return false;

	// Check the Certification Revocation List
	if (IsValidCertInHub(h, x) == false) {
		// Bad
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_NG_CERT", username, tmp);
		return false;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u) {
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_USERCERT) {
					// Check whether to matche with the registered certificate
					AUTHUSERCERT *auth = (AUTHUSERCERT *)u->AuthData;
					if (CompareX(auth->UserX, x))
						b = true;
				} else if (u->AuthType == AUTHTYPE_ROOTCERT) {
					// Check whether the certificate has been signed by the root certificate
					AUTHROOTCERT *auth = (AUTHROOTCERT *)u->AuthData;
					if (h->HubDb != NULL) {
						LockList(h->HubDb->RootCertList);
						{
							X *root_cert;
							root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
							if (root_cert != NULL) {
								b = true;
								if (auth->CommonName != NULL && UniIsEmptyStr(auth->CommonName) == false) {
									// Compare the CN
									if (UniStrCmpi(x->subject_name->CommonName, auth->CommonName) != 0)
										b = false;
								}
								if (auth->Serial != NULL && auth->Serial->size >= 1) {
									// Compare the serial number
									if (CompareXSerial(x->serial, auth->Serial) == false)
										b = false;
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

	if (b) {
		wchar_t tmp[MAX_SIZE * 2];

		// Log the contents of the certificate
		GetAllNameFromX(tmp, sizeof(tmp), x);

		HLog(h, "LH_AUTH_OK_CERT", username, tmp);
	}

	return b;
}

// Get the root certificate that signed the specified certificate from the list
X *GetIssuerFromList(LIST *cert_list, X *cert) {
	UINT i;
	X *ret = NULL;
	// Validate arguments
	if (cert_list == NULL || cert == NULL)
		return NULL;

	for (i = 0; i < LIST_NUM(cert_list); i++) {
		X *x = LIST_DATA(cert_list, i);
		// Name comparison
		if (CheckXDateNow(x)) {
			if (CompareName(x->subject_name, cert->issuer_name)) {
				// Get the public key of the root certificate
				K *k = GetKFromX(x);

				if (k != NULL) {
					// Check the signature
					if (CheckSignature(cert, k))
						ret = x;
					FreeK(k);
				}
			}
		}
		if (CompareX(x, cert)) {
			// Complete identical
			ret = x;
		}
	}

	return ret;
}

// Get the policy to be applied for the user
POLICY *SamGetUserPolicy(HUB *h, char *username) {
	POLICY *ret = NULL;
	// Validate arguments
	if (h == NULL || username == NULL)
		return NULL;

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u) {
			USERGROUP *g = NULL;
			Lock(u->lock);
			{
				if (u->Policy != NULL)
					ret = ClonePolicy(u->Policy);

				g = u->Group;

				if (g != NULL)
					AddRef(g->ref);
			}
			Unlock(u->lock);

			ReleaseUser(u);
			u = NULL;

			if (ret == NULL) {
				if (g != NULL) {
					Lock(g->lock);
					{
						ret = ClonePolicy(g->Policy);
					}
					Unlock(g->lock);
				}
			}

			if (g != NULL)
				ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	return ret;
}

// Password authentication of user
bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password, char *mschap_v2_password, UCHAR *mschap_v2_server_response_20, UINT *err) {
	bool b = false;
	UCHAR secure_password_check[SHA1_SIZE];
	bool is_mschap = false;
	IPC_MSCHAP_V2_AUTHINFO mschap;
	UINT dummy = 0;
	// Validate arguments
	if (h == NULL || username == NULL || secure_password == NULL)
		return false;
	if (err == NULL)
		err = &dummy;

	*err = 0;

	Zero(&mschap, sizeof(mschap));

	is_mschap = ParseAndExtractMsChapV2InfoFromPassword(&mschap, mschap_v2_password);

	if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0) {
		// Administrator mode
		SecurePassword(secure_password_check, h->SecurePassword, random);
		if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
			return true;
		else
			return false;
	}

	AcLock(h);
	{
		USER *u;
		u = AcGetUser(h, username);
		if (u) {
			Lock(u->lock);
			{
				if (u->AuthType == AUTHTYPE_PASSWORD) {
					AUTHPASSWORD *auth = (AUTHPASSWORD *)u->AuthData;

					if (is_mschap == false) {
						// Normal password authentication
						SecurePassword(secure_password_check, auth->HashedKey, random);
						if (Cmp(secure_password_check, secure_password, SHA1_SIZE) == 0)
							b = true;
					} else {
						// MS-CHAP v2 authentication via PPP
						UCHAR challenge8[8];
						UCHAR client_response[24];

						if (IsZero(auth->NtLmSecureHash, MD5_SIZE)) {
							// NTLM hash is not registered in the user account
							*err = ERR_MSCHAP2_PASSWORD_NEED_RESET;
						} else {
							UCHAR nt_pw_hash_hash[16];
							Zero(challenge8, sizeof(challenge8));
							Zero(client_response, sizeof(client_response));

							MsChapV2_GenerateChallenge8(challenge8, mschap.MsChapV2_ClientChallenge, mschap.MsChapV2_ServerChallenge,
							                            mschap.MsChapV2_PPPUsername);

							MsChapV2Client_GenerateResponse(client_response, challenge8, auth->NtLmSecureHash);

							if (Cmp(client_response, mschap.MsChapV2_ClientResponse, 24) == 0) {
								// Hash matched
								b = true;

								// Calculate the response
								GenerateNtPasswordHashHash(nt_pw_hash_hash, auth->NtLmSecureHash);
								MsChapV2Server_GenerateResponse(mschap_v2_server_response_20, nt_pw_hash_hash,
								                                client_response, challenge8);
							}
						}
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

