package desired

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The session profiles of the devices (SDN-40 #233): a Node that a User owns runs under the effective
// session profile of that User, its own or the one of its first Group that names one
// (intent.EffectiveProfile). The profile goes in the NodeConfig of the Node, whose flags the Node
// enforces on itself, and in the Peer object of the Node that each other Node holds, which enforces it
// on its session with that Node (src/Cedar/NodeProfile.c). A Node without an owner, or whose owner runs
// under none, has none.

// nodeProfiles returns the session profile of each Node of in that runs under one, by Node name.
func nodeProfiles(in intent.Intent) map[string]*controlpb.SessionProfile {
	out := map[string]*controlpb.SessionProfile{}
	for name, n := range in.Nodes {
		if p := userProfile(in, n.Owner); p != nil {
			out[name] = p
		}
	}
	return out
}

// userProfile returns the session profile of the devices of the User user as the control protocol
// carries it, nil when the user runs under none.
func userProfile(in intent.Intent, user string) *controlpb.SessionProfile {
	of := in.EffectiveProfile(user)
	p, ok := in.SessionProfiles[of.Profile]
	if of.Profile == "" || !ok {
		return nil
	}
	return &controlpb.SessionProfile{
		Name:           of.Profile,
		User:           user,
		UploadLimit:    p.UploadLimit,
		DownloadLimit:  p.DownloadLimit,
		MaxSessions:    p.MaxSessions,
		MaxMacs:        p.MaxMACs,
		MaxIpv4:        p.MaxIPv4,
		MaxIpv6:        p.MaxIPv6,
		IdleTimeout:    p.IdleTimeout,
		AutoDisconnect: p.AutoDisconnect,
		NoBridge:       p.NoBridge,
		NoRouting:      p.NoRouting,
		NoServer:       p.NoServer,
		PrivacyFilter:  p.PrivacyFilter,
	}
}
