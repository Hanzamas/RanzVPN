// ServerInternal.h
// Module-internal declarations of the Server module: only its own files include this header

#ifndef	SERVER_INTERNAL_H
#define	SERVER_INTERNAL_H

bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g);
CAPS *NewCaps(char *name, UINT value);
void FreeCaps(CAPS *c);
CAPSLIST *NewCapsList();
int CompareCaps(void *p1, void *p2);
void AddCaps(CAPSLIST *caps, CAPS *c);
UINT GetCapsInt(CAPSLIST *caps, char *name);

#endif	// SERVER_INTERNAL_H
