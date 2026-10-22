package store

import "sort"

// schemaEntry is one feature's DDL: the statements that create its tables and seed their fixed
// rows. The statements of one entry run in the order given, so a seed INSERT can follow the
// CREATE TABLE it needs.
type schemaEntry struct {
	name  string
	stmts []string
}

// schemaRegistry holds the DDL of every feature. Each feature file appends to it from its own
// init() through RegisterSchema, so a new table is a new file, not an edit of a shared slice.
var schemaRegistry []schemaEntry

// RegisterSchema adds a feature's tables to the store's migration under name. A feature file
// calls it once from its init(). The statements run in the order given within the feature; the
// features run sorted by name, so the migration Open runs is the same whatever order the init()
// functions happen to run in. The tables carry no foreign keys between features, so this order
// is only about being deterministic, not about one table needing another.
func RegisterSchema(name string, stmts ...string) {
	schemaRegistry = append(schemaRegistry, schemaEntry{name: name, stmts: stmts})
}

// schemaStatements returns every registered statement, the features sorted by name and each
// feature's statements in the order it registered them. Open runs these once, in one rqlite
// transaction, to create the tables the first time.
func schemaStatements() []string {
	entries := make([]schemaEntry, len(schemaRegistry))
	copy(entries, schemaRegistry)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var out []string
	for _, e := range entries {
		out = append(out, e.stmts...)
	}
	return out
}
