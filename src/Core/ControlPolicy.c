// ControlPolicy.c
// The policy of the VRFs in a desired state (Core/ControlPolicy.h; SDN-8, #184): the client copies the policy of each
// VRF (Vrf.policy), the tags of the node and of each peer, and the Rule objects into the state that it hands to its
// owner, the rules in name order. The node enforces a rule only as it was sent: an allow rule that cannot be read whole
// (a prefix that is neither IPv4 nor IPv6, a range of ports that is none, ports of a protocol that has none) is left
// out, and a deny rule that cannot be read whole denies every flow of its VRF, so the policy fails closed.

#include "Core/ControlPolicy.h"

#include <stdlib.h>
#include <string.h>

// Copy count tags of a message, max at most, into dst: their number
static UINT ControlCopyTags(char (*dst)[CONTROL_NAME_SIZE], const char (*src)[CONTROL_NAME_SIZE], pb_size_t count, UINT max) {
	UINT num = 0;

	for (pb_size_t i = 0; i < count && num < max; i++)
		strncpy_s(dst[num++], CONTROL_NAME_SIZE, src[i], _TRUNCATE);

	return num;
}

// The policy of a Vrf object into the VRF of the state that it made
static void ControlCopyVrfPolicy(CONTROL_STATE *st, const ranz_control_v1_Vrf *vrf) {
	for (UINT i = 0; i < st->NumVrfs; i++) {
		CONTROL_VRF *v = &st->Vrfs[i];

		if (v->Id != vrf->id || strcmp(v->Name, vrf->name) != 0)
			continue;

		v->Policy = vrf->has_policy;
		v->MaxFlows = vrf->policy.max_flows;
		v->TcpEstablished = vrf->policy.tcp_established;
		v->TcpTransitory = vrf->policy.tcp_transitory;
		v->Udp = vrf->policy.udp;
		v->Icmp = vrf->policy.icmp;
		v->Other = vrf->policy.other;
		return;
	}
}

// The tags of a Peer object into the peer of the state that it made
static void ControlCopyPeerTags(CONTROL_STATE *st, const ranz_control_v1_Peer *peer) {
	for (UINT i = 0; i < st->NumPeers; i++) {
		CONTROL_PEER *p = &st->Peers[i];

		if (strcmp(p->Name, peer->name) == 0) {
			p->NumTags = ControlCopyTags(p->Tags, peer->tags, peer->tags_count, CONTROL_MAX_TAGS);
			return;
		}
	}
}

// Copy an end of a rule: false for a prefix that is neither IPv4 nor IPv6 or longer than its address
static bool ControlCopyRuleEnd(CONTROL_RULE_END *dst, const ranz_control_v1_RuleEnd *src) {
	dst->NumTags = ControlCopyTags(dst->Tags, src->tags, src->tags_count, CONTROL_RULE_VALUES);

	for (pb_size_t i = 0; i < src->prefixes_count && dst->NumPrefixes < CONTROL_RULE_VALUES; i++) {
		const ranz_control_v1_Prefix *p = &src->prefixes[i];
		CONTROL_PREFIX *c = &dst->Prefixes[dst->NumPrefixes];

		if ((p->address.size != 4 && p->address.size != 16) || p->length > (uint32_t)p->address.size * 8)
			return false;

		CopyMemory(c->Address, p->address.bytes, p->address.size);
		c->AddressSize = p->address.size;
		c->Length = p->length;
		dst->NumPrefixes++;
	}

	return true;
}

// Copy a Rule object into r: false when it cannot be read whole
static bool ControlCopyRule(CONTROL_RULE *r, const ranz_control_v1_Rule *src) {
	bool ok = (src->protocol <= 255 && (src->ports_count == 0 || src->protocol == 6 || src->protocol == 17));

	ZeroMemory(r, sizeof(CONTROL_RULE));
	strncpy_s(r->Name, sizeof(r->Name), src->name, _TRUNCATE);
	r->VrfId = src->vrf_id;
	r->Priority = src->priority;
	r->Deny = (src->action != ranz_control_v1_RuleAction_RULE_ACTION_ALLOW);
	r->Protocol = src->protocol;

	if (ok && src->has_from)
		ok = ControlCopyRuleEnd(&r->From, &src->from);
	if (ok && src->has_to)
		ok = ControlCopyRuleEnd(&r->To, &src->to);

	for (pb_size_t i = 0; i < src->ports_count && ok && r->NumPorts < CONTROL_RULE_VALUES; i++) {
		ok = (src->ports[i].first <= src->ports[i].last && src->ports[i].last <= 65535);
		r->FirstPort[r->NumPorts] = src->ports[i].first;
		r->LastPort[r->NumPorts] = src->ports[i].last;
		r->NumPorts++;
	}

	return ok;
}

static int ControlCompareRules(const void *a, const void *b) {
	return strcmp(((const CONTROL_RULE *)a)->Name, ((const CONTROL_RULE *)b)->Name);
}

// Put into st, whose VRFs and peers the client took from the num objects already, the policy of each of its VRFs, the
// tags of the node and of its peers, and its rules (see above). With no memory for the rules, the state has none: the
// VRFs with a policy deny every flow then.
void ControlCopyPolicy(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	UINT max = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_node_tag)
			st->NumTags = ControlCopyTags(st->Tags, o->kind.node.tags, o->kind.node.tags_count, CONTROL_MAX_TAGS);
		else if (o->which_kind == ranz_control_v1_Object_vrf_tag)
			ControlCopyVrfPolicy(st, &o->kind.vrf);
		else if (o->which_kind == ranz_control_v1_Object_peer_tag)
			ControlCopyPeerTags(st, &o->kind.peer);
		else if (o->which_kind == ranz_control_v1_Object_rule_tag)
			max++;
	}

	st->NumRules = 0;
	st->Rules = (CONTROL_RULE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTROL_RULE) * (max != 0 ? max : 1));
	if (st->Rules == NULL)
		return;

	for (UINT i = 0; i < num && st->NumRules < max; i++) {
		if (objects[i].which_kind != ranz_control_v1_Object_rule_tag)
			continue;

		CONTROL_RULE *r = &st->Rules[st->NumRules];
		if (ControlCopyRule(r, &objects[i].kind.rule) == false) {
			if (r->Deny == false)
				continue;

			// A deny rule that cannot be read whole matches every flow of its VRF
			ZeroMemory(&r->From, sizeof(r->From));
			ZeroMemory(&r->To, sizeof(r->To));
			r->Protocol = 0;
			r->NumPorts = 0;
		}
		st->NumRules++;
	}

	qsort(st->Rules, st->NumRules, sizeof(CONTROL_RULE), ControlCompareRules);
}

// Free the rules that ControlCopyPolicy put into st
void ControlFreePolicy(CONTROL_STATE *st) {
	if (st->Rules == NULL)
		return;

	SecureZeroMemory(st->Rules, sizeof(CONTROL_RULE) * st->NumRules);
	HeapFree(GetProcessHeap(), 0, st->Rules);
	st->Rules = NULL;
	st->NumRules = 0;
}
