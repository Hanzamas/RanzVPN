package controller

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// The licence of the BGP peering of the standard mode (SDN-77 #357, intent/peering.go): BGP between
// the Nodes of a VRF is part of the Enterprise feature EVPN and BGP (ADR-0032 decision 7, ADR-0036),
// so a VRF whose Nodes peer by BGP needs a licence that has it, as the BGP and EVPN peers of a gateway
// do (enterpriseKinds).

// peeringFeatures returns a problem for each VRF of doc whose Nodes peer by BGP while the licence in
// force st lacks the feature.
func peeringFeatures(doc intent.Document, st licence.Status) []error {
	if st.Allows(licence.FeatureEVPN) {
		return nil
	}
	var problems []error
	for _, r := range doc.Resources {
		var v intent.VRF
		if r.Kind != intent.KindVRF || json.Unmarshal(r.Spec, &v) != nil || !strings.EqualFold(v.Peering.Protocol, intent.PeeringBGP) {
			continue
		}
		problems = append(problems, fmt.Errorf("VRF %q: the BGP peering of its Nodes is part of %s, an Enterprise feature, and the licence in force is %s", r.Name, licence.FeatureEVPN.Name(), st.Tier))
	}
	return problems
}
