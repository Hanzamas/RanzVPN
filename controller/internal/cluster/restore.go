package cluster

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// RestoreHolder holds the lease of the leader while Restore runs: the status names it as the
// leader, and the standbys refuse nodes and API calls meanwhile.
const RestoreHolder = "(restore)"

// errRestoreLost ends a restore whose lease a member took before the backup was loaded.
var errRestoreLost = errors.New("cluster: a member took the lease during the restore, which loaded nothing: try again")

// Restore replaces the store of a controller cluster with backup (store.Backup), while its
// members run or while they are stopped (`ranz-controller restore`, SDN-52 #245). A leader keeps
// the intent in memory and writes its changes, so Restore first takes the lease as a member
// would, and holds it, renewing it as a leader does, for a whole lease duration: by then the
// leader has stepped down, since it could not renew (Member.renew), and no controller is left to
// write what it remembers of the old store over the restored one. When nobody held the lease, no
// member leads and Restore loads at once. It then loads backup and frees the lease with an epoch
// above every epoch before, of the cluster and of the backup (store.Restore): a member takes it at
// once and loads the restored intent, revisions and node states, as a new leader does. Data that
// is not a backup is refused before Restore takes the lease. lease is the lease duration of the
// members, DefaultLease when it is 0.
func Restore(ctx context.Context, st *store.Store, backup []byte, lease time.Duration) error {
	if err := store.CheckBackup(backup); err != nil {
		return err
	}
	if lease == 0 {
		lease = DefaultLease
	}
	retry := lease / 5
	epoch, held, err := takeLease(ctx, st, retry)
	if err != nil {
		return err
	}
	loaded := false
	defer func() {
		if !loaded {
			// Give the lease back, so a member takes it at once and leads on the store as it was.
			rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
			defer cancel()
			_ = st.Release(rctx, epoch)
		}
	}()
	if held {
		if err := holdLease(ctx, st, epoch, lease, retry); err != nil {
			return err
		}
	}
	// A standby takes the lease only once it has seen it unchanged for a whole lease duration, so
	// after this renewal the load has that long.
	if ok, err := st.Renew(ctx, epoch); err != nil {
		return fmt.Errorf("cluster: restore: %w", err)
	} else if !ok {
		return errRestoreLost
	}
	if err := st.Restore(ctx, backup, epoch); err != nil {
		return err
	}
	loaded = true
	return nil
}

// takeLease takes the lease of the leader for RestoreHolder and returns its epoch; held reports
// that a member held the lease, which must step down before the load.
func takeLease(ctx context.Context, st *store.Store, retry time.Duration) (epoch int64, held bool, err error) {
	for {
		l, err := st.Lease(ctx)
		if err != nil {
			return 0, false, fmt.Errorf("cluster: restore: %w", err)
		}
		won, err := st.Acquire(ctx, l, store.Lease{Holder: RestoreHolder})
		if err != nil {
			return 0, false, fmt.Errorf("cluster: restore: %w", err)
		}
		if won {
			return l.Epoch + 1, l.Holder != "", nil
		}
		// The holder renewed the lease between the read and the take-over: read it again.
		select {
		case <-ctx.Done():
			return 0, false, ctx.Err()
		case <-time.After(retry / 10):
		}
	}
}

// holdLease renews the lease of epoch every retry, as a leader does, for the lease duration
// lease: long enough for the member that held it before to step down, and no standby takes it
// over meanwhile. Like a leader, it gives up when it could not renew for two thirds of lease,
// before a standby may take the lease over.
func holdLease(ctx context.Context, st *store.Store, epoch int64, lease, retry time.Duration) error {
	t := time.NewTicker(retry)
	defer t.Stop()
	start := time.Now()
	renewed := start
	for time.Since(start) < lease {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		ok, err := st.Renew(ctx, epoch)
		switch {
		case err == nil && ok:
			renewed = time.Now()
		case err == nil:
			return errRestoreLost
		case time.Since(renewed) >= lease*2/3:
			return fmt.Errorf("cluster: restore: the lease could not be renewed, so nothing was loaded: %w", err)
		}
	}
	return nil
}
