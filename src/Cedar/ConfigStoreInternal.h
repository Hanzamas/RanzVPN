// ConfigStoreInternal.h
// Module-internal declarations of the ConfigStore module: only its own files include this header

#ifndef CONFIGSTORE_INTERNAL_H
#define CONFIGSTORE_INTERNAL_H

bool CsBegin(CONFIG_STORE *s);
bool CsCommit(CONFIG_STORE *s);
void CsRollback(CONFIG_STORE *s);

#endif // CONFIGSTORE_INTERNAL_H
