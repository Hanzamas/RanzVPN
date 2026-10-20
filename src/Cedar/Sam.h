// Sam.h
// Header of Sam.c

#ifndef	SAM_H
#define	SAM_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

bool SamAuthUserByPassword(HUB *h, char *username, void *random, void *secure_password);
bool SamAuthUserByAnonymous(HUB *h, char *username);
bool SamAuthUserByCert(HUB *h, char *username, X *x);
bool SamAuthUserByPlainPassword(CONNECTION *c, HUB *hub, char *username, char *password, bool ast);
POLICY *SamGetUserPolicy(HUB *h, char *username);

void SecurePassword(void *secure_password, void *password, void *random);
X *GetIssuerFromList(LIST *cert_list, X *cert);

#endif	// SAM_H

