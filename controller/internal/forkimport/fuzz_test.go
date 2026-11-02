package forkimport

import (
	"os"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// fuzzSeeds returns the Config files that the fuzz targets start from: the sample Config file, one Virtual Hub with the
// entries of every kind, and the beginnings of files that Cfg reads.
func fuzzSeeds(t testing.TB) [][]byte {
	t.Helper()
	sample, err := os.ReadFile("../../../tests/golden/configimport/sample.config")
	if err != nil {
		t.Fatal(err)
	}
	acl := folder("AccessList",
		folder("1", "bool Active true", "bool Discard true", "uint Priority 100", "uint Protocol 6", "uint DestPortStart 22", "uint DestPortEnd 22",
			"string DestIpAddress 10.0.0.10", "string DestSubnetMask 255.255.255.255"),
		folder("2", "bool Active true", "uint Priority 100", "string SrcUsername CORP\\Alice@example.com", "uint SrcPortStart 1", "uint SrcPortEnd 9"),
		folder("3", "bool Active true", "bool IsIPv6 true", "bool Discard true", "uint Priority 7", "string DestIpAddress6 ::ffff:0:0", "string DestSubnetMask6 ffff::"))
	accounts := folder("SecurityAccountDatabase",
		folder("GroupList", folder("staff", "string RealName Staff$20Team")),
		folder("UserList", folder("alice", "string GroupName staff", "uint64 ExpireTime 1893423600000"), folder("*")))
	return [][]byte{
		sample,
		configText(folder("lab", acl, accounts)),
		[]byte("declare root\n{\ndeclare ServerConfiguration\n{\n}\ndeclare VirtualHUB\n{\n"),
		[]byte("\xef\xbb\xbfdeclare root\r\n{\r\n}\r\n"),
		[]byte("SEVPN_DB"),
		nil,
	}
}

// FuzzParse feeds Parse the bytes of a Config file, which the fork reads from a disk that an operator edits: it never
// panics, the folders that it returns nest at most MaxDepth deep, and every question that the import asks of them has
// an answer.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := Parse(b)
		if err != nil {
			return
		}
		var walk func(fd *Folder, depth int)
		walk = func(fd *Folder, depth int) {
			if depth > MaxDepth {
				t.Fatalf("a folder nests %d folders deep, more than %d", depth, MaxDepth)
			}
			for _, it := range fd.Items {
				_, _, _, _, _ = fd.Str(it.Name), fd.Uint(it.Name), fd.Uint64(it.Name), fd.Bool(it.Name), fd.Bytes(it.Name)
				if !fd.Has(it.Name) {
					t.Fatalf("the folder %q has the item %q and says that it has not", fd.Name, it.Name)
				}
			}
			for _, c := range fd.Sorted() {
				if fd.Child(c.Name) == nil {
					t.Fatalf("the folder %q has the folder %q and says that it has not", fd.Name, c.Name)
				}
				walk(c, depth+1)
			}
		}
		walk(root, 1)
	})
}

// FuzzImport reads the bytes as a Config file and imports it (Import): it never panics, and the intent document that it
// makes applies to an empty intent whatever the file holds, which is the one criterion of #203 that a fuzzer can hold it
// to: the names of the resources are DNS labels that no other has, the users and their Groups exist, and every Policy
// is one that the controller takes.
func FuzzImport(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := Parse(b)
		if err != nil {
			return
		}
		res, err := Import(root, Options{})
		if err != nil {
			return
		}
		if _, err := intent.Apply(intent.New(), res.Document, nil); err != nil {
			t.Fatalf("the import of %q does not apply: %v", b, err)
		}
		if res.Report() == "" {
			t.Fatal("the report is empty")
		}
	})
}
