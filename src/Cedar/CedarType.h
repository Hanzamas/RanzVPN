// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// CedarType.h
// List of types that Cedar using

#ifndef	CEDARTYPE_H
#define	CEDARTYPE_H

typedef struct CEDAR CEDAR;
typedef struct TRAFFIC TRAFFIC;


// ==============================================================
//   Remote Procedure Call
// ==============================================================

typedef struct RPC RPC;


// ==============================================================
//   Account
// ==============================================================

typedef struct POLICY_ITEM POLICY_ITEM;
typedef struct POLICY POLICY;
typedef struct USERGROUP USERGROUP;
typedef struct USER USER;
typedef struct AUTHPASSWORD AUTHPASSWORD;
typedef struct AUTHUSERCERT AUTHUSERCERT;
typedef struct AUTHROOTCERT AUTHROOTCERT;
typedef struct AUTHNT AUTHNT;


// ==============================================================
//   Listener
// ==============================================================

typedef struct DOS DOS;
typedef struct LISTENER LISTENER;
typedef struct TCP_ACCEPTED_PARAM TCP_ACCEPTED_PARAM;
typedef struct UDP_ENTRY UDP_ENTRY;


// ==============================================================
//   Logging
// ==============================================================

typedef struct PACKET_LOG PACKET_LOG;
typedef struct HUB_LOG HUB_LOG;
typedef struct RECORD RECORD;
typedef struct LOG LOG;
typedef struct ERASER ERASER;
typedef struct SLOG SLOG;


// ==============================================================
//   Connection
// ==============================================================

typedef struct RC4_KEY_PAIR RC4_KEY_PAIR;
typedef struct CLIENT_OPTION CLIENT_OPTION;
typedef struct CLIENT_AUTH CLIENT_AUTH;
typedef struct TCPSOCK TCPSOCK;
typedef struct TCP TCP;
typedef struct UDP UDP;
typedef struct BLOCK BLOCK;
typedef struct CONNECTION CONNECTION;


// ==============================================================
//   Session
// ==============================================================

typedef struct NODE_INFO NODE_INFO;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;
typedef struct SESSION SESSION;


// ==============================================================
//   Hub
// ==============================================================

typedef struct SE_LINK SE_LINK;
typedef struct TEST_HISTORY TEST_HISTORY;
typedef struct SE_TEST SE_TEST;
typedef struct HUBDB HUBDB;
typedef struct TRAFFIC_LIMITER TRAFFIC_LIMITER;
typedef struct STORM STORM;
typedef struct HUB_PA HUB_PA;
typedef struct HUB_OPTION HUB_OPTION;
typedef struct MAC_TABLE_ENTRY MAC_TABLE_ENTRY;
typedef struct IP_TABLE_ENTRY IP_TABLE_ENTRY;
typedef struct LOOP_LIST LOOP_LIST;
typedef struct ACCESS ACCESS;
typedef struct HUB HUB;
typedef struct ADMIN_OPTION ADMIN_OPTION;
typedef struct CRL CRL;
typedef struct AC AC;
typedef struct USERLIST USERLIST;


// ==============================================================
//   Protocol
// ==============================================================

typedef struct CHECK_CERT_THREAD_PROC CHECK_CERT_THREAD_PROC;
typedef struct RAND_CACHE RAND_CACHE;
typedef struct BLACK BLACK;
typedef struct SEND_SIGNATURE_PARAM SEND_SIGNATURE_PARAM;


// ==============================================================
//   Link
// ==============================================================

typedef struct LINK LINK;


// ==============================================================
//   WPC
// ==============================================================

typedef struct INTERNET_SETTING INTERNET_SETTING;
typedef struct URL_DATA URL_DATA;
typedef struct WPC_ENTRY WPC_ENTRY;
typedef struct WPC_PACKET WPC_PACKET;

// ==============================================================
//   VLAN
// ==============================================================

typedef struct VLAN VLAN;
typedef struct VLAN_PARAM VLAN_PARAM;

// ==============================================================
//   Bridge
// ==============================================================

typedef struct ETH ETH;
typedef struct BRIDGE BRIDGE;
typedef struct LOCALBRIDGE LOCALBRIDGE;


// ==============================================================
//   Client
// ==============================================================

typedef struct ACCOUNT ACCOUNT;
typedef struct RPC_CLIENT_GET_CONNECTION_STATUS RPC_CLIENT_GET_CONNECTION_STATUS;


// ==============================================================
//   Server
// ==============================================================

typedef struct SERVER_LISTENER SERVER_LISTENER;
typedef struct SERVER SERVER;
typedef struct RPC_ENUM_SESSION RPC_ENUM_SESSION;
typedef struct RPC_SESSION_STATUS RPC_SESSION_STATUS;
typedef struct CAPS CAPS;
typedef struct CAPSLIST CAPSLIST;
typedef struct LOG_FILE LOG_FILE;
typedef struct SYSLOG_SETTING SYSLOG_SETTING;
typedef struct HUB_SNAPSHOT HUB_SNAPSHOT;
typedef struct SERVER_SNAPSHOT SERVER_SNAPSHOT;
typedef struct SERVER_HUB_CREATE_HISTORY SERVER_HUB_CREATE_HISTORY;

// ==============================================================
//   Server Admin Tool
// ==============================================================

typedef struct ADMIN ADMIN;
typedef struct RPC_TEST RPC_TEST;
typedef struct RPC_SERVER_INFO RPC_SERVER_INFO;
typedef struct RPC_SERVER_STATUS RPC_SERVER_STATUS;
typedef struct RPC_LISTENER RPC_LISTENER;
typedef struct RPC_LISTENER_LIST RPC_LISTENER_LIST;
typedef struct RPC_STR RPC_STR;
typedef struct RPC_SET_PASSWORD RPC_SET_PASSWORD;
typedef struct RPC_KEY_PAIR RPC_KEY_PAIR;
typedef struct RPC_HUB_OPTION RPC_HUB_OPTION;
typedef struct RPC_HUB RPC_HUB;
typedef struct RPC_CREATE_HUB RPC_CREATE_HUB;
typedef struct RPC_ENUM_HUB_ITEM RPC_ENUM_HUB_ITEM;
typedef struct RPC_ENUM_HUB RPC_ENUM_HUB;
typedef struct RPC_DELETE_HUB RPC_DELETE_HUB;
typedef struct RPC_ENUM_CONNECTION_ITEM RPC_ENUM_CONNECTION_ITEM;
typedef struct RPC_ENUM_CONNECTION RPC_ENUM_CONNECTION;
typedef struct RPC_DISCONNECT_CONNECTION RPC_DISCONNECT_CONNECTION;
typedef struct RPC_CONNECTION_INFO RPC_CONNECTION_INFO;
typedef struct RPC_SET_HUB_ONLINE RPC_SET_HUB_ONLINE;
typedef struct RPC_HUB_STATUS RPC_HUB_STATUS;
typedef struct RPC_HUB_LOG RPC_HUB_LOG;
typedef struct RPC_HUB_ADD_CA RPC_HUB_ADD_CA;
typedef struct RPC_HUB_ENUM_CA_ITEM RPC_HUB_ENUM_CA_ITEM;
typedef struct RPC_HUB_ENUM_CA RPC_HUB_ENUM_CA;
typedef struct RPC_HUB_GET_CA RPC_HUB_GET_CA;
typedef struct RPC_HUB_DELETE_CA RPC_HUB_DELETE_CA;
typedef struct RPC_CREATE_LINK RPC_CREATE_LINK;
typedef struct RPC_ENUM_LINK_ITEM RPC_ENUM_LINK_ITEM;
typedef struct RPC_ENUM_LINK RPC_ENUM_LINK;
typedef struct RPC_LINK_STATUS RPC_LINK_STATUS;
typedef struct RPC_LINK RPC_LINK;
typedef struct RPC_ENUM_ACCESS_LIST RPC_ENUM_ACCESS_LIST;
typedef struct RPC_ADD_ACCESS RPC_ADD_ACCESS;
typedef struct RPC_DELETE_ACCESS RPC_DELETE_ACCESS;
typedef struct RPC_SET_USER RPC_SET_USER;
typedef struct RPC_ENUM_USER_ITEM RPC_ENUM_USER_ITEM;
typedef struct RPC_ENUM_USER RPC_ENUM_USER;
typedef struct RPC_SET_GROUP RPC_SET_GROUP;
typedef struct RPC_ENUM_GROUP_ITEM RPC_ENUM_GROUP_ITEM;
typedef struct RPC_ENUM_GROUP RPC_ENUM_GROUP;
typedef struct RPC_DELETE_USER RPC_DELETE_USER;
typedef struct RPC_ENUM_SESSION_ITEM RPC_ENUM_SESSION_ITEM;
typedef struct RPC_DELETE_SESSION RPC_DELETE_SESSION;
typedef struct RPC_ENUM_MAC_TABLE_ITEM RPC_ENUM_MAC_TABLE_ITEM;
typedef struct RPC_ENUM_MAC_TABLE RPC_ENUM_MAC_TABLE;
typedef struct RPC_ENUM_IP_TABLE_ITEM RPC_ENUM_IP_TABLE_ITEM;
typedef struct RPC_ENUM_IP_TABLE RPC_ENUM_IP_TABLE;
typedef struct RPC_DELETE_TABLE RPC_DELETE_TABLE;
typedef struct RPC_ENUM_ETH_ITEM RPC_ENUM_ETH_ITEM;
typedef struct RPC_ENUM_ETH RPC_ENUM_ETH;
typedef struct RPC_LOCALBRIDGE RPC_LOCALBRIDGE;
typedef struct RPC_ENUM_LOCALBRIDGE RPC_ENUM_LOCALBRIDGE;
typedef struct RPC_BRIDGE_SUPPORT RPC_BRIDGE_SUPPORT;
typedef struct RPC_CONFIG RPC_CONFIG;
typedef struct RPC_ADMIN_OPTION RPC_ADMIN_OPTION;
typedef struct RPC_CRL RPC_CRL;
typedef struct RPC_ENUM_CRL_ITEM RPC_ENUM_CRL_ITEM;
typedef struct RPC_ENUM_CRL RPC_ENUM_CRL;
typedef struct RPC_INT RPC_INT;
typedef struct RPC_AC_LIST RPC_AC_LIST;
typedef struct RPC_ENUM_LOG_FILE_ITEM RPC_ENUM_LOG_FILE_ITEM;
typedef struct RPC_ENUM_LOG_FILE RPC_ENUM_LOG_FILE;
typedef struct RPC_READ_LOG_FILE RPC_READ_LOG_FILE;
typedef struct DOWNLOAD_PROGRESS DOWNLOAD_PROGRESS;
typedef struct RPC_RENAME_LINK RPC_RENAME_LINK;
typedef struct RPC_ENUM_LICENSE_KEY RPC_ENUM_LICENSE_KEY;
typedef struct RPC_ENUM_LICENSE_KEY_ITEM RPC_ENUM_LICENSE_KEY_ITEM;
typedef struct RPC_LICENSE_STATUS RPC_LICENSE_STATUS;
typedef struct RPC_ENUM_ETH_VLAN_ITEM RPC_ENUM_ETH_VLAN_ITEM;
typedef struct RPC_ENUM_ETH_VLAN RPC_ENUM_ETH_VLAN;
typedef struct RPC_MSG RPC_MSG;
typedef struct RPC_WINVER RPC_WINVER;


// ==============================================================
//  WinUI
// ==============================================================




// ==============================================================
//  Console
// ==============================================================

typedef struct PARAM PARAM;
typedef struct PARAM_VALUE PARAM_VALUE;
typedef struct CONSOLE CONSOLE;
typedef struct LOCAL_CONSOLE_PARAM LOCAL_CONSOLE_PARAM;
typedef struct CMD CMD;
typedef struct CMD_EVAL_MIN_MAX CMD_EVAL_MIN_MAX;


// ==============================================================
//  Command
// ==============================================================

typedef struct PS PS;
typedef struct CT CT;
typedef struct CTC CTC;
typedef struct CTR CTR;
typedef struct TTC TTC;
typedef struct TTS TTS;
typedef struct TTS_WORKER TTS_WORKER;
typedef struct TTC_WORKER TTC_WORKER;
typedef struct TT_RESULT TT_RESULT;
typedef struct TTS_SOCK TTS_SOCK;
typedef struct TTC_SOCK TTC_SOCK;
typedef struct PT PT;


// ==============================================================
//  Database
// ==============================================================

typedef struct LICENSE_PRODUCT LICENSE_PRODUCT;
typedef struct LICENSE_SYSTEM LICENSE_SYSTEM;
typedef struct LICENSE_DATA LICENSE_DATA;
typedef struct LICENSE LICENSE;
typedef struct LICENSE_STATUS LICENSE_STATUS;
typedef struct SECURE_PACK_FOLDER SECURE_PACK_FOLDER;
typedef struct WIDE_MACHINE_ID WIDE_MACHINE_ID;
typedef struct TRIAL_INFO TRIAL_INFO;


// ==============================================================
//  In-Process VPN Client
// ==============================================================

typedef struct IPC_MSCHAP_V2_AUTHINFO IPC_MSCHAP_V2_AUTHINFO;


// ==============================================================
//   UDP Acceleration
// ==============================================================

typedef struct UDP_ACCEL UDP_ACCEL;


// ==============================================================
//  SeLow User-mode
// ==============================================================

typedef struct SU SU;
typedef struct SU_ADAPTER SU_ADAPTER;
typedef struct SU_ADAPTER_LIST SU_ADAPTER_LIST;



#endif	// CEDARTYPE_H
