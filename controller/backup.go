package controllercmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The backup and the restore of the controller's store (SDN-52, #245): a local administrator of
// the controller's host writes a backup of the whole store with `ranz controller backup -o FILE`
// and puts it back with `ranz controller restore -f FILE`, with the flags of the service, while
// it runs or while it is stopped, as reset-admin does. A backup holds the hashes of the API tokens
// and the licence key, so like reset-admin both need the rights of a local administrator and work
// on the store directly, not through the API. The intent alone moves through the API instead
// (`ranz export` and `ranz import`).

// backupTimeout bounds a backup or a restore: the start of rqlited while the service is stopped,
// the wait for the leader to step down, and the transfer of the store.
const backupTimeout = 10 * time.Minute

// runBackup runs `ranz controller backup -o FILE [flags]`, with the flags of the service.
func runBackup(args []string) error {
	file, rest := fileFlag(args, "o")
	cfg, err := parseFlags(rest)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if file == "" {
		return errors.New("-o FILE names no file: ranz controller backup -o FILE [flags of the service]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
	defer cancel()
	size, err := backup(ctx, cfg, file, adminRights, os.Stderr)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, backupMessage(file, size, len(cfg.join) > 0))
	return nil
}

// backupMessage is what `ranz controller backup` says once it wrote the backup file of size bytes: who
// may read it, and everything that it holds, which is all that the controller keeps, so the operator
// knows how safe to keep it (AUD1-DT-10, #458). A member of a cluster seals the secrets of the targets
// and the PresharedKeys of the Devices with the Cluster key of the cluster, as sealClusterTargets says
// (AUD1-DT-16, #501). It also says what is not sealed, the URL of a target, and what holds for a secret
// that the upgrade sealed, which the data of rqlite beside the store may still hold as it was
// (AUD1-DT-17, #502).
func backupMessage(file string, size int64, clusterMember bool) string {
	secrets := "the secrets of the targets (the export and audit targets) and the PresharedKeys of the WireGuard Devices, which the key of this host seals: " +
		"a restore on another host brings the targets back with no secret, and the log of the controller there names them, so that you put each one again with its secret; " +
		"it brings the Devices back with a PresharedKey that does not open, so that you make each one again"
	if clusterMember {
		secrets = "the secrets of the targets (the export and audit targets) and the PresharedKeys of the WireGuard Devices, which the Cluster key of the cluster seals, a key that the backup holds only as copies that the key of each member opens: " +
			"a restore into another cluster brings the targets back with no secret, and the log of the controller there names them, so that you put each one again with its secret; " +
			"it brings the Devices back with a PresharedKey that does not open, so that you make each one again"
	}
	return fmt.Sprintf("ranz controller backup: the store is in %s (%d bytes), %s.\n"+
		"  It holds everything that the controller keeps in its store: the Intent with every revision, the states and the Capabilities of the Nodes, the events and the audit log, the settings (the lists of admin sources and destinations, the certificate of the controller), the leases of DHCP, the hashes of the API tokens and of the passwords of the users, the licence key, and %s.\n"+
		"  The secrets are sealed, and the URL of a target is not: a token in the path or the query of a webhook URL is in this file as it was put, so keep the file as safe as that token. "+
		"A secret that an earlier release stored unsealed and that this release sealed is sealed in this file too, since the backup is vacuumed and holds none of the row that the sealing replaced; "+
		"the data of rqlite beside the store, which is no part of this file, may still hold the old text until it truncates its log, so put each such target again with a new secret, and change it at the receiver. "+
		"A backup that an earlier release made holds its secrets unsealed.\n"+
		"  Keep every copy of it as safe as the data directory.\n", file, size, backupAccess, secrets)
}

// runRestore runs `ranz controller restore -f FILE [flags]`, with the flags of the service.
func runRestore(args []string) error {
	file, rest := fileFlag(args, "f")
	cfg, err := parseFlags(rest)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if file == "" {
		return errors.New("-f FILE names no file: ranz controller restore -f FILE [flags of the service]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
	defer cancel()
	if err := restore(ctx, cfg, file, adminRights, os.Stderr); err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, restoreMessage(file))
	return nil
}

// restoreMessage is what `ranz controller restore` says once the store is the backup in file: the secrets
// of the targets and the PresharedKeys of the Devices in it open only with the key that sealed them, which
// a backup does not hold (AUD1-DT-10 #458, SDN-82 #377), and a restore keeps the Cluster key of the store
// that it replaces (AUD1-DT-16 #501). The secret of a target opens for its URL only, and a backup that an
// earlier release made holds the secrets unsealed, which the running controller seals without a restart
// (AUD1-DT-17 #502).
func restoreMessage(file string) string {
	return fmt.Sprintf("ranz controller restore: the store is the backup in %s; the leader loads it.\n"+
		"  The secrets of the targets in it open only with the key that sealed them, and for the URL that they were sealed with: the key of the host that made the backup, or the Cluster key of the cluster that made it, since a restore keeps the Cluster key that this store has. "+
		"On another host, or in another cluster, the targets come back with no secret, and the log of the controller names them, so that you put each one again with its secret. "+
		"A target whose URL was changed in the backup after its secret was sealed comes back with no secret too.\n"+
		"  So do the PresharedKeys of the WireGuard Devices: on another host, or in another cluster, the log of the controller says that they do not open, and the gateway terminates those Devices without a PresharedKey until you make each one again.\n"+
		"  A backup that an earlier release made holds the secrets of the targets unsealed. The controller seals them within a minute, without a restart, while it runs, and at its next start when it is stopped; the file of that backup keeps them unsealed, so delete it, or keep it as safe as the data directory.\n", file)
}

// backup writes a backup of the controller's store to file, for its owner only (on Windows for SYSTEM
// and the Administrators, whatever the access list of the folder of file says), and returns its size.
// rights must allow it (adminRights), and the data directory of cfg must exist. The backup goes to a
// temporary file first, so a failed one leaves an earlier backup in file as it was. The temporary file
// has its access list from the moment it exists, and no other handle of it is open while the store is
// written to it (createBackupFile). out receives the output of an rqlited that backup starts
// (openStore), and the warning for a volume that has no access lists.
func backup(ctx context.Context, cfg config, file string, rights func() error, out io.Writer) (int64, error) {
	if err := onHost(cfg, rights, "backup"); err != nil {
		return 0, err
	}
	st, stop, err := openStore(ctx, cfg, out)
	if err != nil {
		return 0, err
	}
	defer stop()
	tmp := file + ".tmp"
	f, protected, err := createBackupFile(tmp)
	if err != nil {
		return 0, err
	}
	if !protected {
		fmt.Fprintf(out, "ranz controller backup: warning: the volume of %s has no access lists, so whoever can read the volume can read the backup\n", file)
	}
	err = st.Backup(ctx, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, file)
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	fi, err := os.Stat(file)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// restore replaces the controller's store with the backup in file (cluster.Restore): while the
// service runs, its leader steps down first and then loads the restored store; while it is
// stopped, its next start loads it. rights must allow it (adminRights), and the data directory of
// cfg must exist. A file that is not a backup is refused before restore reaches the store. out
// receives the output of an rqlited that restore starts (openStore).
func restore(ctx context.Context, cfg config, file string, rights func() error, out io.Writer) error {
	if err := onHost(cfg, rights, "restore"); err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := store.CheckBackup(b); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	st, stop, err := openStore(ctx, cfg, out)
	if err != nil {
		return err
	}
	defer stop()
	return cluster.Restore(ctx, st, b, cfg.lease)
}

// onHost refuses a caller that rights do not allow, and a host without the data directory of
// cfg, as reset-admin does: the command cmd runs on the controller's host only. It refuses a data
// directory that another account than SYSTEM, the Administrators and the service's owns, since the
// command runs the rqlited of that directory as the administrator (checkDataDirOwner).
func onHost(cfg config, rights func() error, cmd string) error {
	if err := rights(); err != nil {
		return err
	}
	if fi, err := os.Stat(cfg.dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("the data directory %s (-data) does not exist: %s runs on the controller's host, with the flags of the service", cfg.dataDir, cmd)
	}
	return checkDataDirOwner(cfg.dataDir)
}

// fileFlag takes the flag -name FILE (or -name=FILE, with one or two dashes) out of args, and
// returns FILE and the other arguments, the flags of the service.
func fileFlag(args []string, name string) (file string, rest []string) {
	for i := 0; i < len(args); i++ {
		a := strings.TrimPrefix(args[i], "-")
		if a == args[i] {
			rest = append(rest, args[i])
			continue
		}
		a = strings.TrimPrefix(a, "-")
		switch {
		case a == name && i+1 < len(args):
			file = args[i+1]
			i++
		case strings.HasPrefix(a, name+"="):
			file = strings.TrimPrefix(a, name+"=")
		default:
			rest = append(rest, args[i])
		}
	}
	return file, rest
}
