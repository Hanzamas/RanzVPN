package control

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// No message of the control protocol has a field for the private key of a mimic server (SDN-94 #423, ADR-0023): the
// node makes the key pair of its mimic server itself, keeps the private key in its own Configuration store and reports
// the public key alone, in a Pins message, so the controller never holds the private key. The tests read the schema, the
// one file that both ends generate their code from, so a message that gains such a field fails here, and so does one of
// the messages of the mimic part that gains any field at all, until a person has looked at it.

// The messages of the mimic part of a state and of the report of the node, with all of their fields: a field that is
// added to one of them is a change of what the controller and the node exchange about a mimic server.
var mimicFields = map[protoreflect.Name][]protoreflect.Name{
	"Mimic":       {"server", "links"},
	"MimicServer": {"listen", "server_names", "max_time_diff_ms", "decoy", "short_id"},
	"MimicDecoy":  {"mode", "dest", "acme", "cert_file", "key_file", "self_signed"},
	"MimicAcme":   {"directory", "email", "cache_dir", "ca_file"},
	"MimicLink":   {"peer", "address", "server_name", "public_key", "short_id"},
	"Pins":        {"mimic_key"},
}

func messages() []protoreflect.MessageDescriptor {
	list := controlpb.File_ranz_control_v1_control_proto.Messages()
	out := make([]protoreflect.MessageDescriptor, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		out = append(out, list.Get(i))
	}
	return out
}

// No field of any message is named for a private key or another secret of a key pair, and none of the messages of the
// mimic part has a field that the list above does not name.
func TestNoMessageHasAFieldForAPrivateKey(t *testing.T) {
	seen := map[protoreflect.Name]bool{}
	for _, md := range messages() {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			for _, word := range []string{"private", "secret", "seed"} {
				if strings.Contains(strings.ToLower(string(fd.Name())), word) {
					t.Errorf("%s has the field %s, which is named for a secret: no message of the control protocol holds the private key of a mimic server", md.Name(), fd.Name())
				}
			}
		}
		want, ok := mimicFields[md.Name()]
		if !ok {
			continue
		}
		seen[md.Name()] = true
		var got []protoreflect.Name
		for i := 0; i < fields.Len(); i++ {
			got = append(got, fields.Get(i).Name())
		}
		slices.Sort(got)
		sorted := slices.Sorted(slices.Values(want))
		if !slices.Equal(got, sorted) {
			t.Errorf("%s has the fields %v, want %v: look at the new field, which must hold no private key, before this list takes it", md.Name(), got, sorted)
		}
	}
	for name := range mimicFields {
		if !seen[name] {
			t.Errorf("the schema has no message %s", name)
		}
	}
}

// The bytes that the mimic messages can hold are those of a public key, 32 bytes, and of a short id, 8 bytes, and
// the report of the node holds the public key alone: the only field of Pins is mimic_key, of 32 bytes, which is the size
// of an X25519 key and nothing longer.
func TestMimicBytesAreAPublicKeyAndAShortID(t *testing.T) {
	opts := readOptions(t, filepath.Join("..", "..", "..", "proto", "ranz", "control", "v1", "control.options"))
	sizes := map[protoreflect.FullName]int{
		"ranz.control.v1.Pins.mimic_key":       32,
		"ranz.control.v1.MimicLink.public_key": 32,
		"ranz.control.v1.MimicLink.short_id":   8,
		"ranz.control.v1.MimicServer.short_id": 8,
	}
	for _, md := range messages() {
		if _, ok := mimicFields[md.Name()]; !ok {
			continue
		}
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			if fd.Kind() != protoreflect.BytesKind {
				continue
			}
			want, ok := sizes[fd.FullName()]
			if !ok {
				t.Errorf("%s is a field of bytes that holds neither a public key nor a short id", fd.FullName())
				continue
			}
			if got := opts.of(t, fd.FullName(), "max_size"); got != want {
				t.Errorf("%s holds at most %d bytes in control.options, want %d", fd.FullName(), got, want)
			}
		}
	}
	for name := range sizes {
		if controlpb.File_ranz_control_v1_control_proto.Messages().ByName(name.Parent().Name()) == nil {
			t.Errorf("the schema has no message of the field %s", name)
		}
	}
}
