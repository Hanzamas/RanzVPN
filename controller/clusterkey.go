package controllercmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/clusterkey"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// sealClusterTargets is sealTargets for a member of a cluster, a Controller with -rqlite-join (AUD1-DT-16,
// #501): the store seals the secrets of the targets with the Cluster key of the cluster, which the first
// member of the cluster makes and each member holds once its copy opens with the sealing key of its own
// host (internal/clusterkey). The member waits a moment at its start for its copy, so that it holds the
// key before it can lead, and then seals the secrets that an earlier release kept in clear and logs how
// many. A member that holds no key yet keeps no secret in clear, and says so in the log.
func sealClusterTargets(ctx context.Context, cfg config, st *store.Store, log *slog.Logger) error {
	own, err := keys.LoadSealer(cfg.dataDir)
	if err != nil {
		return fmt.Errorf("the sealing key of this member: %w", err)
	}
	k := clusterkey.New(clusterkey.Config{Store: st, Member: cfg.name, Sealing: own, Log: log})
	st.SetSealer(k, func(table, name string) {
		kind := strings.TrimSuffix(table, "_targets")
		if !k.Holds() {
			log.Warn("the secret of a target cannot be opened: this member does not hold the Cluster key yet, so the target is sent without it until a member that holds the key gives it a copy",
				"kind", kind, "target", name)
			return
		}
		log.Warn("the secret of a target cannot be opened with the Cluster key, which did not seal it, so the target is sent without it until it is put again",
			"kind", kind, "target", name)
	})
	return k.Start(ctx)
}
