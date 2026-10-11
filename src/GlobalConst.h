// SoftEther VPN Source Code - Developer Edition Master Branch
// Global Constants Header

#pragma warning(disable : 4819)

#ifndef	GLOBAL_CONST_H
#define	GLOBAL_CONST_H

//// Brand
// (Define it if building SoftEther VPN Project.)
#define	GC_SOFTETHER_VPN
#define	GC_SOFTETHER_OSS

//// Basic Variables

#define	CEDAR_PRODUCT_STR			"Burrow"
#define	CEDAR_PRODUCT_STR_W			L"Burrow"
#define	CEDAR_SERVER_STR			"Burrow VPN Server"
#define	CEDAR_BRIDGE_STR			"Burrow VPN Bridge"
#define	CEDAR_BETA_SERVER			"Burrow VPN Server Pre Release"
#define	CEDAR_MANAGER_STR			"Burrow VPN Server Manager"
#define	CEDAR_CUI_STR				"Burrow VPN Command-Line Admin Tool"
#define CEDAR_ELOG					"Burrow EtherLogger"
#define	CEDAR_CLIENT_STR			"Burrow VPN Client"
#define CEDAR_CLIENT_MANAGER_STR	"Burrow VPN Client Connection Manager"
#define	CEDAR_SERVER_LINK_STR		"Burrow VPN Server (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"Burrow VPN Bridge (Cascade Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVERDEV"



//// Registry

// Product key under Software\ (organisation\product): Software\Hanzcodes\Burrow VPN
#define	GC_REG_COMPANY_NAME			"Hanzcodes\\Burrow VPN"




//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"Burrow VPN Client UI Helper"
#define	GC_SW_SOFTETHER_PREFIX		"sedev"
#define	GC_SW_SOFTETHER_PREFIX_W	L"sedev"



//// VPN UI Components

#define	GC_UI_APPID_CM				L"Hanzcodes.Burrow VPN Client"

#endif	// GLOBAL_CONST_H
