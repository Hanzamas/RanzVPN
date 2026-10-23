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
	fmt.Fprintf(os.Stderr, "ranz controller backup: the store is in %s (%d bytes); it holds the hashes of the API tokens and the licence key, so keep it as safe as the data directory\n", file, size)
	return nil
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
	fmt.Fprintf(os.Stderr, "ranz controller restore: the store is the backup in %s; the leader loads it\n", file)
	return nil
}

// backup writes a backup of the controller's store to file, readable by its owner only, and
// returns its size. rights must allow it (adminRights), and the data directory of cfg must exist.
// The backup goes to a temporary file first, so a failed one leaves an earlier backup in file as
// it was. out receives the output of an rqlited that backup starts (openStore).
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
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
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
// cfg, as reset-admin does: the command cmd runs on the controller's host only.
func onHost(cfg config, rights func() error, cmd string) error {
	if err := rights(); err != nil {
		return err
	}
	if fi, err := os.Stat(cfg.dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("the data directory %s (-data) does not exist: %s runs on the controller's host, with the flags of the service", cfg.dataDir, cmd)
	}
	return nil
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
