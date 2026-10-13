// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// MsChapV2.h
// Header of MsChapV2.c

#ifndef	MSCHAPV2_H
#define	MSCHAPV2_H

#include "Cedar.h"

// Constants
#define	IPC_PASSWORD_MSCHAPV2_TAG		"xH7DiNlurDhcYV4a:"

// MS-CHAPv2 authentication information
struct IPC_MSCHAP_V2_AUTHINFO
{
	char MsChapV2_PPPUsername[MAX_SIZE];	// MS-CHAPv2 Username
	UCHAR MsChapV2_ServerChallenge[16];	// MS-CHAPv2 Server Challenge
	UCHAR MsChapV2_ClientChallenge[16];	// MS-CHAPv2 Client Challenge
	UCHAR MsChapV2_ClientResponse[24];	// MS-CHAPv2 Client Response
};

void GenerateNtPasswordHash(UCHAR *dst, char *password);
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash);
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username);
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash);
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8);
bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);

#endif	// MSCHAPV2_H
