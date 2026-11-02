// Package forkimport reads the Config file of the fork (ranz_server.config, the text tree of the Cfg module of
// Mayaqua) and turns its Virtual Hubs into an intent document: each Virtual Hub becomes a VRF with one Network, its
// groups and users become Groups and Users, whose names are the tags of policy (ADR-0031 amendment of 2026-10-25),
// and its access list becomes the Policies of its VRF (SDN-27, #203; ADR-0031 decision 11). It builds on the import of
// the configuration store of a Node (src/Cedar/ConfigStoreImport.c; CORE-F5 #65, CORE-S4-3 #76) and keeps its reading
// of the access list: the order of the entries, what a Policy has no match for, and the rule that lets through what no
// entry matches, as the fork does. The old server runs on until every Virtual Hub has moved, so the import takes the
// hubs that its caller names and leaves the Config file as it is.
package forkimport

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
)

// MaxDepth is how deep the folders of a Config file nest. The fork refuses a file whose folders nest deeper
// (CFG_MAX_DEPTH of Cfg.c), and so does Parse.
const MaxDepth = 64

// binaryTag starts a Config file of the binary format, which the first versions of SoftEther wrote.
const binaryTag = "SEVPN_DB"

// ErrBinary marks a Config file of the binary format.
var ErrBinary = errors.New("the Config file is in the binary format of the first versions of SoftEther, which the import does not read")

// ErrNoRoot marks a file that has no folder root, which every Config file has.
var ErrNoRoot = errors.New("the file is no Config file: it has no folder root")

// ItemType is the type of an item of a Config file, the first word of its line.
type ItemType uint8

// The types of an item.
const (
	// TypeInt is a number of 32 bits, `uint`.
	TypeInt ItemType = iota + 1
	// TypeInt64 is a number of 64 bits, `uint64`.
	TypeInt64
	// TypeBool is `bool`.
	TypeBool
	// TypeByte is `byte`, the base64 of bytes.
	TypeByte
	// TypeString is `string`.
	TypeString
)

// Item is one line `<type> <name> <value>` of a folder.
type Item struct {
	Name string
	Type ItemType
	// Num is the value of an item of the type TypeInt, TypeInt64 or TypeBool, which is 0 or 1.
	Num uint64
	// Text is the value of an item of the type TypeString, Bytes the value of one of the type TypeByte.
	Text  string
	Bytes []byte
}

// Folder is a folder of a Config file: the items that it holds and the folders inside it, in the order of the file.
// The names of folders and items are matched without regard to case, as Cfg matches them.
type Folder struct {
	Name    string
	Items   []Item
	Folders []*Folder
}

// Parse reads the text of a Config file as Cfg does (CfgBufTextToFolder): a line is words that are separated by spaces
// and tabs; `declare NAME` opens a folder and `}` closes it; a line of three words or more whose first word is a type
// (string, uint, uint64, bool or byte) is an item, whose name and value are the second and third word, with each
// character that is no part of a name written as $ and its two hex digits; every other line is a comment, as the
// lines of the banner are. A file that ends before its folders are closed is read as far as it goes, as the fork
// reads it, and a closing brace outside every folder ends the reading. It returns the folder root.
func Parse(b []byte) (*Folder, error) {
	if bytes.HasPrefix(b, []byte(binaryTag)) {
		return nil, ErrBinary
	}
	top := &Folder{Name: "tmp"}
	stack := []*Folder{top}
parsing:
	for len(b) > 0 {
		var line []byte
		line, b = nextLine(b)
		words := strings.FieldsFunc(string(line), func(r rune) bool { return r == ' ' || r == '\t' })
		if len(words) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		switch {
		case strings.EqualFold(words[0], "declare"):
			if len(words) < 2 {
				continue
			}
			if len(stack) > MaxDepth {
				return nil, fmt.Errorf("a folder nests deeper than %d folders", MaxDepth)
			}
			folder := &Folder{Name: unescape(words[1])}
			current.Folders = append(current.Folders, folder)
			stack = append(stack, folder)
		case words[0] == "}":
			if len(stack) == 1 {
				break parsing
			}
			stack = stack[:len(stack)-1]
		case len(words) >= 3:
			current.add(words[0], unescape(words[1]), words[2])
		}
	}
	for _, f := range top.Folders {
		if strings.EqualFold(f.Name, "root") {
			return f, nil
		}
	}
	return nil, ErrNoRoot
}

// nextLine returns the first line of b without its end, and what follows it. A line ends at a CR, a LF or a CRLF, and
// at a NUL byte, where the C strings of the fork end.
func nextLine(b []byte) (line, rest []byte) {
	i := bytes.IndexAny(b, "\r\n")
	if i < 0 {
		line = b
	} else {
		line, rest = b[:i], b[i+1:]
		if b[i] == '\r' && len(rest) > 0 && rest[0] == '\n' {
			rest = rest[1:]
		}
	}
	if j := bytes.IndexByte(line, 0); j >= 0 {
		line = line[:j]
	}
	return line, rest
}

// add adds the item of the type word kind to f, as Cfg reads it: an item of an unknown type, and a byte item whose
// value is no base64, are left out.
func (f *Folder) add(kind, name, data string) {
	it := Item{Name: name}
	switch {
	case strings.EqualFold(kind, "string"):
		it.Type, it.Text = TypeString, unescape(data)
	case strings.EqualFold(kind, "uint"):
		it.Type, it.Num = TypeInt, uint64(toUint32(data))
	case strings.EqualFold(kind, "uint64"):
		it.Type, it.Num = TypeInt64, toUint64(data)
	case strings.EqualFold(kind, "bool"):
		it.Type = TypeBool
		if strings.EqualFold(data, "true") || toUint32(data) != 0 {
			it.Num = 1
		}
	case strings.EqualFold(kind, "byte"):
		b, ok := decodeBase64(unescape(data))
		if !ok {
			return
		}
		it.Type, it.Bytes = TypeByte, b
	default:
		return
	}
	f.Items = append(f.Items, it)
}

// unescape reads a name or a value as CfgUnescape does: $ and two hex digits are the character, a lone $ is the empty
// string, and the string ends at the first escape that is no character or is the character 0.
func unescape(s string) string {
	if s == "$" {
		return ""
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '$' {
			c = escaped(s, i+1)
			if c == 0 {
				break
			}
			i += 2
		}
		out = append(out, c)
	}
	return string(out)
}

// escaped reads the hex digits that start at s[i] as the character of an escape: two of them, one when the second is
// none, and 0 when the first is none or s ends.
func escaped(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	high, ok := hexDigit(s[i])
	if !ok {
		return 0
	}
	if i+1 >= len(s) {
		return high
	}
	low, ok := hexDigit(s[i+1])
	if !ok {
		return high
	}
	return high<<4 | low
}

// hexDigit returns the value of the hex digit c.
func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// toUint32 reads a number as ToInt of Mayaqua does: decimal, or hex after 0x, the zeros at its start left out, ending
// at the first character that is no digit, and the largest number when it does not fit.
func toUint32(s string) uint32 {
	for len(s) > 0 && s[0] == '0' && (len(s) < 2 || (s[1] != 'x' && s[1] != 'X')) {
		s = s[1:]
	}
	base := uint64(10)
	if len(s) >= 2 && s[0] == '0' {
		base, s = 16, s[2:]
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		d, ok := hexDigit(s[i])
		if !ok || uint64(d) >= base {
			break
		}
		n = n*base + uint64(d)
		if n > math.MaxUint32 {
			return math.MaxUint32
		}
	}
	return uint32(n)
}

// toUint64 reads a number as ToInt64 of Mayaqua does: decimal digits, commas left out, ending at the first other
// character.
func toUint64(s string) uint64 {
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' {
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// decodeBase64 reads the value of a byte item, with the padding or without it.
func decodeBase64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err == nil
}

// Child returns the first folder of f called name, or nil. It is no error to ask a nil folder.
func (f *Folder) Child(name string) *Folder {
	if f == nil {
		return nil
	}
	for _, c := range f.Folders {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

// Sorted returns the folders of f in the order that the fork enumerates them (CfgEnumFolderToTokenList): by name,
// without regard to case, a name once. The first folder of a name in the file is the one that stays.
func (f *Folder) Sorted() []*Folder {
	if f == nil {
		return nil
	}
	out := slices.Clone(f.Folders)
	slices.SortStableFunc(out, func(a, b *Folder) int {
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return slices.CompactFunc(out, func(a, b *Folder) bool { return strings.EqualFold(a.Name, b.Name) })
}

// item returns the first item of f called name.
func (f *Folder) item(name string) (Item, bool) {
	if f != nil {
		for _, it := range f.Items {
			if strings.EqualFold(it.Name, name) {
				return it, true
			}
		}
	}
	return Item{}, false
}

// Has reports whether f has an item called name, of any type.
func (f *Folder) Has(name string) bool {
	_, ok := f.item(name)
	return ok
}

// Str returns the string item called name, empty for none or for an item of another type, as CfgGetStr does.
func (f *Folder) Str(name string) string {
	if it, ok := f.item(name); ok && it.Type == TypeString {
		return it.Text
	}
	return ""
}

// Uint returns the number item `uint` called name, 0 for none.
func (f *Folder) Uint(name string) uint32 {
	if it, ok := f.item(name); ok && it.Type == TypeInt {
		return uint32(it.Num)
	}
	return 0
}

// Uint64 returns the number item `uint64` called name, 0 for none.
func (f *Folder) Uint64(name string) uint64 {
	if it, ok := f.item(name); ok && it.Type == TypeInt64 {
		return it.Num
	}
	return 0
}

// Bool returns the item `bool` called name, false for none.
func (f *Folder) Bool(name string) bool {
	it, ok := f.item(name)
	return ok && it.Type == TypeBool && it.Num != 0
}

// Bytes returns the byte item called name, nil for none.
func (f *Folder) Bytes(name string) []byte {
	if it, ok := f.item(name); ok && it.Type == TypeByte {
		return it.Bytes
	}
	return nil
}
