// SwitchSecurity.c
// The security of an L2 Network (SwitchSecurity.h): the guard of each role of a port, its member in the policy engine,
// and the policy engine as the filter of the switch.

#include "Core/SwitchSecurity.h"

// The guard of a port of the role role in a Network of the security sec, NULL for none: POLICY_GUARD_* flags. A client
// has the flags of the protections that sec turns on. The gateway has POLICY_GUARD_GATEWAY while a MAC or IP check is on,
// so that it owns the addresses it sends from, and no other flag. A role that is no gateway's is a client's.
UINT SwitchSecurityGuard(const SWITCH_SECURITY *sec, UINT role) {
	UINT guard = 0;

	if (sec == NULL)
		return 0;
	if (role == SWITCH_GATEWAY)
		return ((sec->CheckMac || sec->CheckIp) ? POLICY_GUARD_GATEWAY : 0);

	if (sec->CheckMac)
		guard |= POLICY_GUARD_CHECK_MAC;
	if (sec->CheckIp)
		guard |= POLICY_GUARD_CHECK_IP;
	if (sec->ArpDhcpOnly)
		guard |= POLICY_GUARD_ARP_DHCP_ONLY;
	if (sec->DhcpGuard)
		guard |= POLICY_GUARD_NO_DHCP_SERVER;
	if (sec->RaGuard)
		guard |= POLICY_GUARD_NO_ROUTER;

	return guard;
}

// Add the member of a port of the role role to the policy engine p, in a Network of the security sec (NULL for none): the
// member that cfg configures, with the guard of its role besides its own, and the limits of sec where cfg sets none. Its
// number, or POLICY_NO_MEMBER as PolicyAddMember gives it, as for a limit above POLICY_MAX_BOUND.
UINT SwitchSecurityMember(POLICY_ENGINE *p, const POLICY_MEMBER_CONFIG *cfg, const SWITCH_SECURITY *sec, UINT role) {
	POLICY_MEMBER_CONFIG c;

	if (cfg == NULL)
		return POLICY_NO_MEMBER;

	c = *cfg;
	c.Guard |= SwitchSecurityGuard(sec, role);
	if (sec != NULL && role != SWITCH_GATEWAY) {
		if (c.MaxMacs == 0)
			c.MaxMacs = sec->MaxMacs;
		if (c.MaxIps == 0)
			c.MaxIps = sec->MaxIps;
	}

	return PolicyAddMember(p, &c);
}

// The policy engine as the filter of a switch (SWITCH_ADMIT_PROC): the verdict of PolicyInput on a frame of the member
// from to the member to, or to a group
static bool SwitchSecurityAdmit(void *param, UINT64 now, UINT from, UINT to, UINT vlan, const UCHAR *frame, UINT size) {
	return PolicyInput((POLICY_ENGINE *)param, now, from, (to == SWITCH_NO_MEMBER ? POLICY_NO_MEMBER : to), vlan, frame, size, NULL);
}

// ... (SWITCH_DELIVER_PROC): whether PolicyDeliver lets a frame of the member from, which PolicyInput let through, reach
// the member to
static bool SwitchSecurityDeliver(void *param, UINT from, UINT to, const UCHAR *frame, UINT size) {
	return PolicyDeliver((POLICY_ENGINE *)param, from, to, frame, size);
}

// Make the policy engine p the filter of the switch that cfg configures (SWITCH_CONFIG.Admit and Deliver). The engine
// must outlive the switch.
void SwitchSecurityFilter(SWITCH_CONFIG *cfg, POLICY_ENGINE *p) {
	if (cfg == NULL)
		return;

	cfg->Admit = SwitchSecurityAdmit;
	cfg->Deliver = SwitchSecurityDeliver;
	cfg->FilterParam = p;
}
