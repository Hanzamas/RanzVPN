package controllercmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// sealTargets has the store keep the secrets of the export and audit targets sealed to the sealing key
// of this host's data directory (AUD1-DT-10, #458), and seals the ones that an earlier release left in
// clear. The key is a key of the key storage provider on Windows, so a backup of the store holds no
// secret in clear, and a restore of it on the same host keeps the secrets working. On another host the
// restored targets have no secret, and the log names them at the start: the operator puts each one
// again with its secret (ADR-0026, the amendment of 2026-10-27).
//
// The members of a cluster have no sealing key in common: each member has its own key in its own
// provider, and the member that leads next could not open what the member before it sealed. A member
// of a cluster, which is a Controller with -rqlite-join, keeps the secrets as they are put, in clear,
// and says so in the log at each start.
//
// The store's Sealer also seals the PresharedKeys of the WireGuard Devices (SDN-82, #377), which the
// controller reads from it (store.Sealer). A PresharedKey is never kept in clear, so a member of a
// cluster, which has no Sealer, makes no Device with one: the administrator makes the Device without.
func sealTargets(ctx context.Context, cfg config, st *store.Store, log *slog.Logger) error {
	lost := func(table, name string) {
		log.Warn("the secret of a target cannot be opened with the sealing key of this host, so the target is sent without it until it is put again",
			"kind", strings.TrimSuffix(table, "_targets"), "target", name)
	}
	if len(cfg.join) > 0 {
		st.SetSealer(nil, lost)
		log.Warn("the secrets of the export and audit targets are kept in clear, and no Device is made with a PresharedKey: the members of a cluster have no sealing key in common (ADR-0026)")
		return nil
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
	return nil
}
