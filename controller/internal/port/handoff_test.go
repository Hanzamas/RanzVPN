package port

import (
	"encoding/binary"
	"errors"
	"testing"
)

// handoffMessage makes a handoff message as the front door writes it, for a socket of family,
// type and protocol.
func handoffMessage(family, typ, protocol int32) []byte {
	b := make([]byte, HandoffSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], handoffMagic)
	le.PutUint32(b[4:], HandoffSize)
	le.PutUint32(b[8+infoAddressFamily:], uint32(family))
	le.PutUint32(b[8+infoSocketType:], uint32(typ))
	le.PutUint32(b[8+infoProtocol:], uint32(protocol))
	// szProtocol without its terminator
	for i := 8 + 116; i < HandoffSize; i++ {
		b[i] = 'x'
	}
	return b
}

// A message of this version gives the WSAPROTOCOL_INFOW, with the name of its protocol terminated;
// any other size, magic, version or socket is no handoff.
func TestDecodeHandoff(t *testing.T) {
	for _, family := range []int32{afInet, afInet6} {
		m := handoffMessage(family, sockStream, ipprotoTCP)
		info, err := DecodeHandoff(m)
		if err != nil {
			t.Fatalf("family %d: %v", family, err)
		}
		if got := int32(binary.LittleEndian.Uint32(info[infoAddressFamily:])); got != family {
			t.Errorf("the decoded family is %d, not %d", got, family)
		}
		if info[protocolInfoSize-2] != 0 || info[protocolInfoSize-1] != 0 || info[protocolInfoSize-3] != 'x' {
			t.Error("the name of the protocol is not terminated by its last character alone")
		}
	}

	good := handoffMessage(afInet, sockStream, ipprotoTCP)
	wrongMagic := append([]byte(nil), good...)
	wrongMagic[0] ^= 1
	wrongVersion := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(wrongVersion[4:], HandoffSize-4)
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"one byte short", good[:HandoffSize-1]},
		{"one byte long", append(append([]byte(nil), good...), 0)},
		{"another magic", wrongMagic},
		{"another version", wrongVersion},
		{"UDP", handoffMessage(afInet, 2, 17)},
		{"a Unix socket", handoffMessage(1, sockStream, 0)},
		{"a raw socket", handoffMessage(afInet6, 3, ipprotoTCP)},
	} {
		if _, err := DecodeHandoff(c.b); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: %v, not ErrHandoff", c.name, err)
		}
	}
}

// FuzzDecodeHandoff drives DecodeHandoff with any bytes, as a process that writes the handoff pipe
// may send them: it never panics, and a message that it takes keeps its header and a socket of TCP.
func FuzzDecodeHandoff(f *testing.F) {
	f.Add(handoffMessage(afInet, sockStream, ipprotoTCP))
	f.Add(handoffMessage(afInet6, sockStream, ipprotoTCP))
	f.Add(handoffMessage(afInet, 2, 17))
	f.Add([]byte("RFD1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := DecodeHandoff(b)
		if err != nil {
			return
		}
		if len(b) != HandoffSize || binary.LittleEndian.Uint32(b) != handoffMagic {
			t.Fatalf("a message of %d bytes is taken", len(b))
		}
		if typ := binary.LittleEndian.Uint32(info[infoSocketType:]); typ != sockStream {
			t.Fatalf("a socket of type %d is taken", typ)
		}
		if info[protocolInfoSize-2] != 0 || info[protocolInfoSize-1] != 0 {
			t.Fatal("the name of the protocol is not terminated")
		}
	})
}
