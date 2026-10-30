package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// The secrets of the export and audit targets are kept sealed (AUD1-DT-10 #458, AUD1-DT-17 #502, ST-4 of
// docs/threat-model.md). The HMAC key of a webhook and the bearer token of an OTLP endpoint are in the
// JSON of a row of export_targets or audit_targets, and the store and every backup of it are read by
// more than the controller: a thief of the disk, of a snapshot or of a backup, and a user who can read a
// file. With a Sealer, PutTarget and PutAuditTarget write the secret as ranz-sealed:1: and the base64 of
// the sealed bytes, and Targets and AuditTargets open it again, so the exporters and the API see the
// secret as they always did and the table never holds it.
//
// A sealed secret opens only in the row it was sealed for. Its label names the table, the name of the
// target and its URL, so a secret that is copied to another row, or that stays in a row whose URL was
// changed, does not open: whoever can write a row, or change a backup, can point a target at a URL of its
// own, and the controller would send the secret there. The rest of the row is not sealed. The URL is in
// clear in the table, in the data of rqlite and in every backup, with the token that its path or its query
// may hold, since the controller must know where a target goes without the key; the name, the kind and
// the types are no secret.
//
// What a Sealer cannot open is a secret that another key sealed, the backup of another host or a store
// whose key is gone, and one whose URL was changed after it was sealed. The target keeps its name, its URL
// and its types and comes back with no secret, so the controller sends to it unsigned until an operator
// puts the target again, and the first read of such a secret calls the function that SetSealer was given,
// so the operator is told which targets they are.
//
// The secrets of a store that has no Sealer stay as they were put, in clear, and so do those of a store
// that a Sealer was set on after they were: SealTargetSecrets seals them. It does so by changing the row,
// which seals the secret in the table and in every backup (Backup vacuums, so a backup holds none of the
// row that was changed), and leaves its old text where rqlite keeps what it was told: in its Raft log until
// a snapshot truncates it, in its older snapshots until newer ones replace them, and in the free space of
// its SQLite file until the file is vacuumed. So a secret that an earlier release kept in clear is put
// again with a new secret after the upgrade, and a secret that is put after it has no clear text anywhere.

// Sealer seals secrets to a key of the controller and opens them with it. A label names where the
// secret is kept, and a secret opens only under the label it was sealed with (keys.Sealer is one).
type Sealer interface {
	Seal(label string, plain []byte) ([]byte, error)
	Open(label string, sealed []byte) ([]byte, error)
}

// sealedPrefix starts the secret of a target as a table holds it once it is sealed: the version of this
// form, then the base64 of the bytes that the Sealer made.
const sealedPrefix = "ranz-sealed:1:"

// The tables of the targets, which are also the first part of the label of a sealed secret, so that a
// secret of an export target does not open as the secret of an audit target of the same name.
const (
	exportTargetsTable = "export_targets"
	auditTargetsTable  = "audit_targets"
)

// sealing is what a Store keeps for its Sealer. It is shared by the stores that Fenced makes.
type sealing struct {
	sealer Sealer
	lost   func(table, name string)

	mu     sync.Mutex
	warned map[string]bool // the targets whose lost secret was reported already
}

// SetSealer makes the store seal the secrets of the targets that it writes with sealer, and open the
// ones that it reads, and have SealTargetSecrets seal those that are in clear. lost is called, once for
// each target until it is put again, with the table and the name of a target whose sealed secret
// cannot be opened: no Sealer set (sealer is nil), a secret that another key sealed, or a secret of a
// target whose URL was changed after the secret was sealed. Both may be nil. Call it right after Open,
// before the store is used: the stores that Fenced returns after it share it.
func (s *Store) SetSealer(sealer Sealer, lost func(table, name string)) {
	s.seal = &sealing{sealer: sealer, lost: lost, warned: map[string]bool{}}
}

// targetKey names the target name of table in what the store remembers of it: that the loss of its
// secret was told to the function of SetSealer.
func targetKey(table, name string) string {
	return table + ":" + name
}

// targetLabel is the label of the secret of the target name of table, which sends to url: the text that
// the sealed box authenticates, so that the secret opens in that row for that URL only. The URL is in it
// as its SHA-256, which has one length whatever a row holds, so that no two targets that differ in their
// table, their name or their URL have the same label.
func targetLabel(table, name, url string) string {
	sum := sha256.Sum256([]byte(url))
	return targetKey(table, name) + ":" + hex.EncodeToString(sum[:])
}

// encodeTarget returns the JSON of t as table keeps it: with its secret sealed when the store has a
// Sealer.
func (s *Store) encodeTarget(table string, t export.Target) (string, error) {
	if sl := s.seal; sl != nil && sl.sealer != nil && t.Secret != "" {
		sealed, err := sl.sealer.Seal(targetLabel(table, t.Name, t.URL), []byte(t.Secret))
		if err != nil {
			return "", fmt.Errorf("sealing the secret: %w", err)
		}
		t.Secret = sealedPrefix + base64.RawStdEncoding.EncodeToString(sealed)
		sl.mu.Lock()
		delete(sl.warned, targetKey(table, t.Name))
		sl.mu.Unlock()
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeTarget returns the target name of table that doc holds, with its secret opened.
func (s *Store) decodeTarget(table, name, doc string) (export.Target, error) {
	var t export.Target
	if err := json.Unmarshal([]byte(doc), &t); err != nil {
		return export.Target{}, err
	}
	t.Name = name
	if strings.HasPrefix(t.Secret, sealedPrefix) {
		t.Secret = s.openSecret(table, name, t.URL, t.Secret)
	}
	return t, nil
}

// openSecret returns the secret that the sealed form text holds, which the target name of table sends to
// url with, or none when it cannot be opened, and then tells the function of SetSealer, the first time
// for the target.
func (s *Store) openSecret(table, name, url, text string) string {
	sl := s.seal
	if sl != nil && sl.sealer != nil {
		sealed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(text, sealedPrefix))
		if err == nil {
			if plain, err := sl.sealer.Open(targetLabel(table, name, url), sealed); err == nil {
				return string(plain)
			}
		}
	}
	if sl == nil {
		return ""
	}
	key := targetKey(table, name)
	sl.mu.Lock()
	first := !sl.warned[key]
	sl.warned[key] = true
	sl.mu.Unlock()
	if first && sl.lost != nil {
		sl.lost(table, name)
	}
	return ""
}

// SealTargetSecrets seals the secrets of the export and audit targets that are in clear, which a store
// of an earlier release holds, and returns how many it sealed. It reads every target, so that a secret
// that cannot be opened is told to the function of SetSealer now and not at the first send. It does
// nothing without a Sealer. A target that is put while it runs keeps what was put: a row is sealed only
// when it is still as it was read. It seals by changing the row, so the old text of a secret that it
// seals stays in the data that rqlite keeps beside the table (see the top of this file): the caller
// tells the operator to put such a target again with a new secret.
func (s *Store) SealTargetSecrets(ctx context.Context) (int, error) {
	if s.seal == nil || s.seal.sealer == nil {
		return 0, nil
	}
	total := 0
	for _, table := range []string{exportTargetsTable, auditTargetsTable} {
		n, err := s.sealTable(ctx, table)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sealTable seals the secrets that are in clear in the targets of table, one of the two constants.
func (s *Store) sealTable(ctx context.Context, table string) (int, error) {
	qr, err := s.conn.QueryOneContext(ctx, `SELECT name, target FROM `+table+` ORDER BY name`)
	if err != nil {
		return 0, fmt.Errorf("store: reading the targets of %s: %w", table, err)
	}
	var stmts []gorqlite.ParameterizedStatement
	for qr.Next() {
		var name, doc string
		if err := qr.Scan(&name, &doc); err != nil {
			return 0, fmt.Errorf("store: reading the targets of %s: %w", table, err)
		}
		var t export.Target
		if err := json.Unmarshal([]byte(doc), &t); err != nil {
			return 0, fmt.Errorf("store: target %q of %s: %w", name, table, err)
		}
		t.Name = name
		switch {
		case t.Secret == "":
		case strings.HasPrefix(t.Secret, sealedPrefix):
			s.openSecret(table, name, t.URL, t.Secret)
		default:
			sealed, err := s.encodeTarget(table, t)
			if err != nil {
				return 0, fmt.Errorf("store: target %q of %s: %w", name, table, err)
			}
			stmts = append(stmts, statement(`UPDATE `+table+` SET target = ? WHERE name = ? AND target = ?`, sealed, name, doc))
		}
	}
	if len(stmts) == 0 {
		return 0, nil
	}
	if err := s.write(ctx, stmts); err != nil {
		return 0, fmt.Errorf("store: sealing the secrets of the targets of %s: %w", table, err)
	}
	return len(stmts), nil
}
