package store

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rqlite/gorqlite"
)

// The backup of the store (SDN-52, #245) is rqlite's backup of its SQLite database: the whole
// store, which is the intent with every revision, the node states, the Capabilities, the events,
// the API tokens, the licence key and the lease. rqlite takes it on its Raft leader (GET
// /db/backup), and a restore loads it through Raft into every member (POST /db/load), so the same
// two calls serve a single controller and a cluster. A restore under a running controller is
// internal/cluster's Restore, which first makes the leader step down.

// sqliteHeader starts every SQLite database file (https://www.sqlite.org/fileformat.html).
const sqliteHeader = "SQLite format 3\x00"

// ErrNotBackup marks data that is not a backup of the store.
var ErrNotBackup = errors.New("not a backup of the store: a backup is an SQLite database file, as ranz-controller backup writes it")

// CheckBackup returns an error that wraps ErrNotBackup unless backup is an SQLite database file.
// rqlite runs any other data that it is asked to load as SQL, so Restore checks it first.
func CheckBackup(backup []byte) error {
	if !bytes.HasPrefix(backup, []byte(sqliteHeader)) {
		return fmt.Errorf("store: %w", ErrNotBackup)
	}
	return nil
}

// Backup writes a backup of the whole store to w.
func (s *Store) Backup(ctx context.Context, w io.Writer) error {
	resp, err := s.rqlite(ctx, http.MethodGet, "/db/backup", "", nil)
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if head, err := br.Peek(len(sqliteHeader)); err != nil || string(head) != sqliteHeader {
		return errors.New("store: backup: rqlite answered with something other than an SQLite database file")
	}
	if _, err := io.Copy(w, br); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return nil
}

// Restore replaces the whole store with backup, which Backup wrote, and frees the lease of the
// leader with an epoch above epoch and above the epoch that backup holds: every lease of before
// the restore has ended, and the member that takes the lease next loads the restored store. The
// tables that this release has and backup lacks are created, as Open creates them. Data that is
// not a backup is refused (CheckBackup) and changes nothing.
func (s *Store) Restore(ctx context.Context, backup []byte, epoch int64) error {
	if err := CheckBackup(backup); err != nil {
		return err
	}
	resp, err := s.rqlite(ctx, http.MethodPost, "/db/load", "application/octet-stream", backup)
	if err != nil {
		return fmt.Errorf("store: restore: %w", err)
	}
	resp.Body.Close()
	var stmts []gorqlite.ParameterizedStatement
	for _, q := range schemaStatements() {
		stmts = append(stmts, statement(q))
	}
	stmts = append(stmts, statement(`UPDATE lease SET epoch = MAX(epoch, ?) + 1, renewal = renewal + 1, holder = '', address = '', fingerprint = '' WHERE id = 1`, epoch))
	if _, err := s.conn.WriteParameterizedContext(ctx, stmts); err != nil {
		return fmt.Errorf("store: restore: %w", err)
	}
	return nil
}

// rqlite makes a request of rqlite's HTTP API, beside the calls that gorqlite makes, and returns
// the answer when it is 200 OK.
func (s *Store) rqlite(ctx context.Context, method, path, contentType string, body []byte) (*http.Response, error) {
	u, err := url.Parse(s.url)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawQuery = path, ""
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("rqlite answered %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return resp, nil
}
