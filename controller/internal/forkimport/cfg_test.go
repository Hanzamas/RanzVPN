package forkimport

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
)

// Parse reads the lines of a Config file as Cfg does: folders, and items of each type, their names and values
// unescaped, a lone $ for the empty string.
func TestParseReadsTheTreeOfAConfigFile(t *testing.T) {
	text := "\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n#\r\n" +
		"declare root\r\n{\r\n" +
		"\tuint Number 42\r\n\tbool Flag true\r\n\tbool Off false\r\n\tbool Numeric 2\r\n" +
		"\tstring Text hello$20world\r\n\tstring Empty $\r\n\tuint64 Big 123,456\r\n\tbyte Data aGVsbG8=\r\n" +
		"\n\tdeclare Child\r\n\t{\r\n\t\tstring Name x\r\n\t}\r\n}\r\n"
	root, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "root" {
		t.Errorf("the folder is called %q, want root", root.Name)
	}
	if got := root.Uint("Number"); got != 42 {
		t.Errorf("Number is %d, want 42", got)
	}
	if !root.Bool("Flag") || root.Bool("Off") || !root.Bool("Numeric") {
		t.Errorf("the bools are %v %v %v, want true false true", root.Bool("Flag"), root.Bool("Off"), root.Bool("Numeric"))
	}
	if got := root.Str("Text"); got != "hello world" {
		t.Errorf("Text is %q, want \"hello world\"", got)
	}
	if !root.Has("Empty") || root.Str("Empty") != "" {
		t.Errorf("Empty is %q, it has the item: %v", root.Str("Empty"), root.Has("Empty"))
	}
	if got := root.Uint64("Big"); got != 123456 {
		t.Errorf("Big is %d, want 123456", got)
	}
	if got := string(root.Bytes("Data")); got != "hello" {
		t.Errorf("Data is %q, want hello", got)
	}
	child := root.Child("CHILD")
	if child == nil || child.Str("name") != "x" {
		t.Errorf("the folder Child is %+v, want one with Name x: names are matched without regard to case", child)
	}
	// An item of another type is no item of the one that is asked for, as CfgGetStr and CfgGetInt see it
	if root.Str("Number") != "" || root.Uint("Text") != 0 || root.Bool("Number") || root.Uint64("Number") != 0 || root.Bytes("Text") != nil {
		t.Error("an item answered for a type that it is not")
	}
	if root.Has("Missing") || root.Child("Missing") != nil {
		t.Error("the file has an item or a folder that it does not")
	}
}

// The names of the types and of the keyword are matched without regard to case, and a line that is no item or folder is a
// comment, as it is in the file that the fork reads. A file that ends inside a folder is read as far as it goes, and a
// closing brace outside every folder ends the reading.
func TestParseReadsAsCfgDoes(t *testing.T) {
	root, err := Parse([]byte("DECLARE root\n{\nUINT A 1\nBool B TRUE\nstring\nsomething else entirely here\nuint C\nunknown D 4\nuint E 5 six seven\n"))
	if err != nil {
		t.Fatal(err)
	}
	if root.Uint("a") != 1 || !root.Bool("b") || root.Uint("E") != 5 {
		t.Errorf("the items are A %d, B %v, E %d, want 1, true and 5", root.Uint("a"), root.Bool("b"), root.Uint("E"))
	}
	if root.Has("C") || root.Has("D") || len(root.Items) != 3 {
		t.Errorf("the items are %+v: a line of two words and a type that is none are no items", root.Items)
	}

	root, err = Parse([]byte("declare root\n{\nuint A 1\n}\n}\nuint B 2\ndeclare other\n{\n}\n"))
	if err != nil || root.Uint("A") != 1 {
		t.Errorf("a closing brace outside every folder: %v, A is %d", err, root.Uint("A"))
	}

	root, err = Parse([]byte("declare root\n{\ndeclare a\n{\ndeclare b\n{\nuint N 7\n"))
	if err != nil || root.Child("a").Child("b").Uint("N") != 7 {
		t.Errorf("a file that ends inside its folders: %v", err)
	}

	// A line ends at a NUL byte, where the C strings of the fork end
	root, err = Parse([]byte("declare root\n{\nuint A 1\x00 uint B 2\nuint C 3\n}\n"))
	if err != nil || root.Uint("A") != 1 || root.Uint("C") != 3 {
		t.Errorf("a line with a NUL byte: %v, A is %d, C is %d", err, root.Uint("A"), root.Uint("C"))
	}
}

// What Cfg refuses: the binary format, a file without the folder root, folders that nest too deep.
func TestParseRefusesWhatCfgRefuses(t *testing.T) {
	if _, err := Parse([]byte("SEVPN_DB\x00\x00")); !errors.Is(err, ErrBinary) {
		t.Errorf("a file of the binary format: %v, want ErrBinary", err)
	}
	for _, text := range []string{"", "# only a comment\n", "declare other\n{\n}\n"} {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrNoRoot) {
			t.Errorf("Parse(%q) = %v, want ErrNoRoot", text, err)
		}
	}
	nest := func(n int) []byte {
		lines := []string{"declare root"}
		for len(lines) < n {
			lines = append(lines, "declare a")
		}
		return []byte(strings.Join(lines, "\n") + "\n")
	}
	if _, err := Parse(nest(MaxDepth)); err != nil {
		t.Errorf("%d folders, the deepest the fork reads: %v", MaxDepth, err)
	}
	if _, err := Parse(nest(MaxDepth + 1)); err == nil || !strings.Contains(err.Error(), "deeper than 64") {
		t.Errorf("%d folders: %v, want a refusal", MaxDepth+1, err)
	}
}

// An escape is a $ and two hex digits, one digit where the second is none, and a string ends at an escape that is no
// character or is the character 0.
func TestUnescape(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "plain"},
		{"$", ""},
		{"no$20ssh", "no ssh"},
		{"a$41b", "aAb"},
		{"a$7eb", "a~b"},
		{"a$zzb", "a"},
		{"a$00b", "a"},
		{"ab$", "ab"},
		{"a$4", "a\x04"},
		{"a$4gb", "a\x04b"},
	} {
		if got := unescape(c.in); got != c.want {
			t.Errorf("unescape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The numbers: decimal or hex, the zeros at the start left out, the largest number when it does not fit, ending at the
// first other character; a number of 64 bits without hex and with commas left out.
func TestNumbers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"0", 0},
		{"7", 7},
		{"007", 7},
		{"0x10", 16},
		{"0XfF", 255},
		{"12abc", 12},
		{"abc", 0},
		{"4294967295", math.MaxUint32},
		{"4294967296", math.MaxUint32},
		{"99999999999999999999", math.MaxUint32},
	} {
		if got := toUint32(c.in); got != c.want {
			t.Errorf("toUint32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want uint64
	}{
		{"", 0},
		{"1,000", 1000},
		{"123x456", 123},
		{"18446744073709551615", math.MaxUint64},
	} {
		if got := toUint64(c.in); got != c.want {
			t.Errorf("toUint64(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// A byte item takes the base64 with or without its padding, and is no item when its value is no base64.
func TestByteItems(t *testing.T) {
	root, err := Parse([]byte("declare root\nbyte A aGk=\nbyte B aGk\nbyte C ***\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(root.Bytes("A")) != "hi" || string(root.Bytes("B")) != "hi" || root.Has("C") {
		t.Errorf("the byte items are %q, %q, and C is an item: %v", root.Bytes("A"), root.Bytes("B"), root.Has("C"))
	}
}

// The folders are listed in the order that the fork enumerates them: by name without regard to case, a name once, the
// first of a name in the file the one that stays. A nil folder has none.
func TestSorted(t *testing.T) {
	root, err := Parse([]byte("declare root\n{\ndeclare b\n{\n}\ndeclare A\n{\n}\ndeclare a\n{\n}\ndeclare 9\n{\n}\ndeclare 10\n{\n}\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range root.Sorted() {
		names = append(names, f.Name)
	}
	if want := []string{"10", "9", "A", "b"}; !slices.Equal(names, want) {
		t.Errorf("the folders are %v, want %v", names, want)
	}
	var none *Folder
	if none.Sorted() != nil || none.Child("x") != nil || none.Str("x") != "" || none.Uint("x") != 0 || none.Has("x") || none.Bytes("x") != nil {
		t.Error("a nil folder answered")
	}
}
