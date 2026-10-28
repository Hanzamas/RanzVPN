package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// The secrets of the export and audit targets are kept sealed (AUD1-DT-10 #458, ST-4 of
// docs/threat-model.md). The HMAC key of a webhook and the bearer token of an OTLP endpoint are in the
// JSON of a row of export_targets or audit_targets, and the store and every backup of it are read by
// more than the controller: a thief of the disk, of a snapshot or of a backup, and a user who can read a
// file. With a Sealer, PutTarget and PutAuditTarget write the secret as ranz-sealed:1: and the base64 of
// the sealed bytes, and Targets and AuditTargets open it again, so the exporters and the API see the
// secret as they always did and the table never holds it.
//
// What a Sealer cannot open is a secret that another key sealed: the backup of another host, or a store
// whose key is gone. The target keeps its name, its URL and its types and comes back with no secret, so
// the controller sends to it unsigned until an operator puts the target again, and the first read of such
// a secret calls the function that SetSealer was given, so the operator is told which targets they are.
// The secrets of a store that has no Sealer stay as they were put, in clear, and so do those of a store
// that a Sealer was set on after they were: SealTargetSecrets seals them.

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
// cannot be opened: no Sealer set (sealer is nil), or a secret that another key sealed. Both may be
// nil. Call it right after Open, before the store is used: the stores that Fenced returns after it
// share it.
func (s *Store) SetSealer(sealer Sealer, lost func(table, name string)) {
	s.seal = &sealing{sealer: sealer, lost: lost, warned: map[string]bool{}}
}

// targetLabel is the label of the secret of the target name of table.
func targetLabel(table, name string) string {
	return table + ":" + name
}

// encodeTarget returns the JSON of t as table keeps it: with its secret sealed when the store has a
// Sealer.
func (s *Store) encodeTarget(table string, t export.Target) (string, error) {
	if sl := s.seal; sl != nil && sl.sealer != nil && t.Secret != "" {
		sealed, err := sl.sealer.Seal(targetLabel(table, t.Name), []byte(t.Secret))
		if err != nil {
			return "", fmt.Errorf("sealing the secret: %w", err)
		}
		t.Secret = sealedPrefix + base64.RawStdEncoding.EncodeToString(sealed)
		sl.mu.Lock()
		delete(sl.warned, targetLabel(table, t.Name))
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
		t.Secret = s.openSecret(table, name, t.Secret)
	}
	return t, nil
}

// openSecret returns the secret that the sealed form text holds, or none when it cannot be opened, and
// then tells the function of SetSealer, the first time for the target.
func (s *Store) openSecret(table, name, text string) string {
	sl := s.seal
	if sl != nil && sl.sealer != nil {
		sealed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(text, sealedPrefix))
		if err == nil {
			if plain, err := sl.sealer.Open(targetLabel(table, name), sealed); err == nil {
				return string(plain)
			}
		}
	}
	if sl == nil {
		return ""
	}
	key := targetLabel(table, name)
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
// when it is still as it was read.
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
			s.openSecret(table, name, t.Secret)
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
