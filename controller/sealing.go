package controllercmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// resealEvery is how often a Controller that seals with the key of its host looks again for secrets of its
// targets that are in clear: a backup that an earlier release made brings them back when it is restored
// under the running service, and the service seals them within this time, without a restart (AUD1-DT-17,
// #502). A member of a cluster does the same every minute (internal/clusterkey).
const resealEvery = time.Minute

// sealTargets has the store keep the secrets of the export and audit targets sealed to the sealing key
// of this host's data directory (AUD1-DT-10, #458), and seals the ones that an earlier release left in
// clear. The key is a key of the key storage provider on Windows, so a backup of the store holds no
// secret in clear, and a restore of it on the same host keeps the secrets working. On another host the
// restored targets have no secret, and the log names them at the start: the operator puts each one
// again with its secret (ADR-0026, the amendment of 2026-10-27). A secret opens for the URL it was
// sealed with only, so a target whose URL was changed in the store has none either, and the log names it
// the same way (AUD1-DT-17, #502).
//
// The members of a cluster have no sealing key in common: each member has its own key in its own
// provider, and the member that leads next could not open what the member before it sealed. A member
// of a cluster, which is a Controller with -rqlite-join, seals them with the Cluster key of the cluster
// instead (sealClusterTargets, AUD1-DT-16). The cluster is told by that flag alone: two Controllers that
// use one store through -rqlite-external, or through an rqlite that another process runs, are two single
// Controllers as far as the sealing goes, each with the key of its own host, and neither opens what the
// other sealed. The log of each names the secrets that it cannot open, and the text of ADR-0026 says to
// use -rqlite-join for two Controllers on one store.
//
// The store's Sealer also seals the PresharedKeys of the WireGuard Devices (SDN-82, #377), which the
// controller reads from it (store.Sealer): the sealing key of this host, or the Cluster key for a member
// of a cluster. A PresharedKey is never kept in clear.
func sealTargets(ctx context.Context, cfg config, st *store.Store, log *slog.Logger) error {
	return sealTargetsEvery(ctx, cfg, st, log, resealEvery)
}

// sealTargetsEvery is sealTargets with the time between two looks for secrets in clear, which the test of
// the restore shortens.
func sealTargetsEvery(ctx context.Context, cfg config, st *store.Store, log *slog.Logger, every time.Duration) error {
	lost := func(table, name string) {
		log.Warn("the secret of a target cannot be opened with the sealing key of this host, so the target is sent without it until it is put again: another key sealed it (a backup of another host, or another Controller that uses this store), or the URL of the target was changed after the secret was sealed",
			"kind", strings.TrimSuffix(table, "_targets"), "target", name)
	}
	if len(cfg.join) > 0 {
		return sealClusterTargets(ctx, cfg, st, log)
	}
	sealer, err := keys.LoadSealer(cfg.dataDir)
	if err != nil {
		return fmt.Errorf("the sealing key of the targets: %w", err)
	}
	st.SetSealer(sealer, lost)
	n, err := st.SealTargetSecrets(ctx)
	if err != nil {
		return fmt.Errorf("sealing the secrets of the targets: %w", err)
	}
	if n > 0 {
		log.Info("sealed the secrets of the targets that an earlier release kept in clear", "targets", n)
	}
	go sealAgain(ctx, st, log, every)
	return nil
}

// sealAgain seals the secrets of the targets that are in clear each time that every has passed, until ctx
// ends. The restore of a backup that an earlier release made brings them back under the running service
// (ranz controller restore), and the command that restores runs in a process of its own, with a key that
// may not be the key of the service, so the service seals them itself.
func sealAgain(ctx context.Context, st *store.Store, log *slog.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n, err := st.SealTargetSecrets(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				log.Warn("sealing the secrets of the targets that are in clear", "err", err)
			}
		case n > 0:
			log.Info("sealed the secrets of the targets that were in clear again, which the restore of a backup of an earlier release brings back", "targets", n)
		}
	}
}
