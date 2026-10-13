// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// MsChapV2.c
// MS-CHAPv2 and NT-hash authentication helpers

#include "MsChapV2.h"

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"

// Generate the NT hash of the password
void GenerateNtPasswordHash(UCHAR *dst, char *password) {
	UCHAR *tmp;
	UINT tmp_size;
	UINT i, len;
	// Validate arguments
	if (dst == NULL || password == NULL) {
		return;
	}

	// Generate a Unicode password
	len = StrLen(password);
	tmp_size = len * 2;

	tmp = ZeroMalloc(tmp_size);

	for (i = 0; i < len; i++) {
		tmp[i * 2] = password[i];
	}

	// Hashing
	HashMd4(dst, tmp, tmp_size);

	Free(tmp);
}

// Generate a 8 bytes challenge
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username) {
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	char username2[MAX_SIZE];
	char domainname2[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || client_challenge == NULL || server_challenge == NULL) {
		return;
	}

	b = NewBuf();

	WriteBuf(b, client_challenge, 16);
	WriteBuf(b, server_challenge, 16);

	ParseNtUsername(username, username2, sizeof(username2), domainname2, sizeof(domainname2), true);

	if (IsEmptyStr(username2) == false) {
		WriteBuf(b, username2, StrLen(username2));
	}

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(dst, hash, 8);
}

// Generate the MS-CHAPv2 client response
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash) {
	UCHAR password_hash_2[21];
	UCHAR key1[8], key2[8], key3[8];
	// Validate arguments
	if (dst == NULL || challenge8 == NULL || nt_password_hash == NULL) {
		return;
	}

	Zero(password_hash_2, sizeof(password_hash_2));
	Copy(password_hash_2, nt_password_hash, 16);

	Zero(key1, sizeof(key1));
	Zero(key2, sizeof(key2));
	Zero(key3, sizeof(key3));

	Copy(key1, password_hash_2 + 0, 7);
	Copy(key2, password_hash_2 + 7, 7);
	Copy(key3, password_hash_2 + 14, 7);

	DesEcbEncrypt(dst + 0, challenge8, key1);
	DesEcbEncrypt(dst + 8, challenge8, key2);
	DesEcbEncrypt(dst + 16, challenge8, key3);
}

// Generate a hash of the hash of the NT password
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash) {
	// Validate arguments
	if (dst_hash == NULL || src_hash == NULL) {
		return;
	}

	HashMd4(dst_hash, src_hash, 16);
}

// Generate the MS-CHAPv2 server response
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8) {
	UCHAR digest[SHA1_SIZE];
	BUF *b;
	char *magic1 = "Magic server to client signing constant";
	char *magic2 = "Pad to make it do more than one iteration";
	// Validate arguments
	if (dst == NULL || nt_password_hash_hash == NULL || client_response == NULL || challenge8 == NULL) {
		return;
	}

	b = NewBuf();
	WriteBuf(b, nt_password_hash_hash, 16);
	WriteBuf(b, client_response, 24);
	WriteBuf(b, magic1, StrLen(magic1));
	Sha1(digest, b->Buf, b->Size);
	FreeBuf(b);

	b = NewBuf();
	WriteBuf(b, digest, sizeof(digest));
	WriteBuf(b, challenge8, 8);
	WriteBuf(b, magic2, StrLen(magic2));
	Sha1(dst, b->Buf, b->Size);
	FreeBuf(b);
}

// Extract the MS-CHAP v2 authentication information by parsing the password string
bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password) {
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (d == NULL || password == NULL) {
		return false;
	}

	Zero(d, sizeof(IPC_MSCHAP_V2_AUTHINFO));

	if (StartWith(password, IPC_PASSWORD_MSCHAPV2_TAG) == false) {
		return false;
	}

	t = ParseTokenWithNullStr(password, ":");

	if (t->NumTokens == 6) {
		BUF *b1, *b2, *b3, *b4;

		b1 = StrToBin(t->Token[2]);
		b2 = StrToBin(t->Token[3]);
		b3 = StrToBin(t->Token[4]);
		b4 = StrToBin(t->Token[5]);

		if (IsEmptyStr(t->Token[1]) == false && b1->Size == 16 && b2->Size == 16 && b3->Size == 24 && b4->Size == 8) {
			StrCpy(d->MsChapV2_PPPUsername, sizeof(d->MsChapV2_PPPUsername), t->Token[1]);
			Copy(d->MsChapV2_ServerChallenge, b1->Buf, 16);
			Copy(d->MsChapV2_ClientChallenge, b2->Buf, 16);
			Copy(d->MsChapV2_ClientResponse, b3->Buf, 24);

			ret = true;
		}

		FreeBuf(b1);
		FreeBuf(b2);
		FreeBuf(b3);
		FreeBuf(b4);
	}

	FreeToken(t);

	return ret;
}
