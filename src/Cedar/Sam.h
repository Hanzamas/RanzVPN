// Sam.h
// Header of Sam.c

#ifndef	SAM_H
#define	SAM_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password);
bool SamAuthUserByAnonymous(HUB *h, char *username);
bool SamAuthUserByCert(HUB *h, char *username, X *x);
bool SamAuthUserByPlainPassword(HUB *hub, char *username, char *password);
POLICY *SamGetUserPolicy(HUB *h, char *username);

void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark);

#endif	// SAM_H

