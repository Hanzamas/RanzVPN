// CedarType.h
// List of types that Cedar using

#ifndef CEDARTYPE_H
#define CEDARTYPE_H

typedef struct CEDAR CEDAR;
typedef struct TRAFFIC TRAFFIC;


typedef struct POLICY_ITEM POLICY_ITEM;
typedef struct POLICY POLICY;
typedef struct USERGROUP USERGROUP;
typedef struct USER USER;
typedef struct AUTHPASSWORD AUTHPASSWORD;
typedef struct AUTHUSERCERT AUTHUSERCERT;
typedef struct AUTHROOTCERT AUTHROOTCERT;
typedef struct AUTHNT AUTHNT;


typedef struct PACKET_LOG PACKET_LOG;
typedef struct HUB_LOG HUB_LOG;


typedef struct CLIENT_OPTION CLIENT_OPTION;
typedef struct CLIENT_AUTH CLIENT_AUTH;
typedef struct BLOCK BLOCK;
typedef struct CONNECTION CONNECTION;
typedef struct TUNNEL TUNNEL;
typedef struct TUNNEL_STATUS TUNNEL_STATUS;


typedef struct NODE_INFO NODE_INFO;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;
typedef struct SESSION SESSION;


typedef struct HUBDB HUBDB;
typedef struct TRAFFIC_LIMITER TRAFFIC_LIMITER;
typedef struct STORM STORM;
typedef struct HUB_PA HUB_PA;
typedef struct HUB_OPTION HUB_OPTION;
typedef struct HUB_OPTION_FIELD HUB_OPTION_FIELD;
typedef struct MAC_TABLE_ENTRY MAC_TABLE_ENTRY;
typedef struct IP_TABLE_ENTRY IP_TABLE_ENTRY;
typedef struct IP_TABLE_EXPIRY IP_TABLE_EXPIRY;
typedef struct ACCESS ACCESS;
typedef struct HUB HUB;
typedef struct HUB_STATS HUB_STATS;
typedef struct ADMIN_OPTION ADMIN_OPTION;
typedef struct CRL CRL;
typedef struct AC AC;
typedef struct USERLIST USERLIST;


typedef struct AUTH_REQUEST AUTH_REQUEST;
typedef struct AUTH_RESULT AUTH_RESULT;


typedef struct LOG_FILE LOG_FILE;


typedef struct SU SU;
typedef struct SU_ADAPTER SU_ADAPTER;
typedef struct SU_ADAPTER_LIST SU_ADAPTER_LIST;


typedef struct NODE NODE;
typedef struct NODE_STATUS NODE_STATUS;
typedef struct NODE_CLIENT NODE_CLIENT;
typedef struct NODE_CLIENT_STATUS NODE_CLIENT_STATUS;
typedef struct NODE_CONTROLLER NODE_CONTROLLER;
typedef struct NODE_CONTROLLER_STATUS NODE_CONTROLLER_STATUS;
typedef struct NODE_WINTUN NODE_WINTUN;
typedef struct NODE_PREFIX NODE_PREFIX;
typedef struct NODE_VRF_ADAPTERS NODE_VRF_ADAPTERS;
typedef struct NODE_VRF_ADAPTER_STATUS NODE_VRF_ADAPTER_STATUS;
typedef struct NODE_WORKER NODE_WORKER;
typedef struct NODE_QUEUE NODE_QUEUE;
typedef struct NODE_READER NODE_READER;
typedef struct NODE_TABLE_ENTRY NODE_TABLE_ENTRY;
typedef struct NODE_TABLE NODE_TABLE;
typedef struct NODE_TABLES NODE_TABLES;
typedef struct NODE_VRF_ROUTE NODE_VRF_ROUTE;
typedef struct NODE_VRF_TABLE NODE_VRF_TABLE;
typedef struct NODE_VRF_TABLES NODE_VRF_TABLES;
typedef struct NODE_NAT NODE_NAT;
typedef struct NODE_POLICY NODE_POLICY;
typedef struct NODE_POLICY_TABLE NODE_POLICY_TABLE;
typedef struct NODE_POLICY_VRF_STATUS NODE_POLICY_VRF_STATUS;
typedef struct NODE_BGP NODE_BGP;
typedef struct NODE_BGP_STATUS NODE_BGP_STATUS;
typedef struct NODE_MIMIC NODE_MIMIC;
typedef struct NODE_MIMIC_TEST NODE_MIMIC_TEST;
typedef struct NODE_MIMIC_STATUS NODE_MIMIC_STATUS;
typedef struct NODE_MIMIC_MESSAGE NODE_MIMIC_MESSAGE;
typedef struct NODE_MITIGATION NODE_MITIGATION;
typedef struct NODE_MIRROR NODE_MIRROR;
typedef struct NODE_MIRROR_TABLE NODE_MIRROR_TABLE;
typedef struct NODE_MIRROR_STATUS NODE_MIRROR_STATUS;
typedef struct NODE_OVERLAY NODE_OVERLAY;
typedef struct NODE_OVERLAY_CONFIG NODE_OVERLAY_CONFIG;
typedef struct NODE_OVERLAY_STATUS NODE_OVERLAY_STATUS;
typedef struct NODE_OVERLAY_SESSION NODE_OVERLAY_SESSION;
typedef struct NODE_SHAPE NODE_SHAPE;
typedef struct NODE_SHAPE_TABLE NODE_SHAPE_TABLE;
typedef struct NODE_SHAPE_STATUS NODE_SHAPE_STATUS;
typedef struct NODE_DHCP NODE_DHCP;
typedef struct NODE_DHCPS NODE_DHCPS;
typedef struct NODE_DHCP_CONFIG NODE_DHCP_CONFIG;
typedef struct NODE_DHCP_LEASE NODE_DHCP_LEASE;
typedef struct NODE_DHCP_STATUS NODE_DHCP_STATUS;
typedef struct NODE_DNS NODE_DNS;
typedef struct NODE_DNS_NAME NODE_DNS_NAME;
typedef struct NODE_DNS_ZONE NODE_DNS_ZONE;
typedef struct NODE_DNS_STATUS NODE_DNS_STATUS;
typedef struct NODE_LISTENER NODE_LISTENER;
typedef struct NODE_LISTENER_STATUS NODE_LISTENER_STATUS;
typedef struct NODE_WIREGUARD NODE_WIREGUARD;
typedef struct NODE_WIREGUARD_STATUS NODE_WIREGUARD_STATUS;


typedef struct CONFIG_STORE CONFIG_STORE;
typedef struct CS_NETWORK CS_NETWORK;
typedef struct CS_USER CS_USER;
typedef struct CS_ADMIN CS_ADMIN;
typedef struct CS_IMPORT CS_IMPORT;
typedef struct CS_GROUP CS_GROUP;
typedef struct CS_RULE_VALUE CS_RULE_VALUE;
typedef struct CS_RULE CS_RULE;
typedef struct CS_PORT CS_PORT;



#endif
