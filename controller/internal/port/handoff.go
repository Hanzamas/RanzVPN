package port

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The handoff message of the front door (SDN-29, #205; ADR-0035), the contract of FRONT_DOOR_HANDOFF
// in src/Core/FrontDoor.h: the front door of the node on the same host duplicates the socket of a
// connection that belongs to the controller into the controller's process with WSADuplicateSocketW
// and writes the WSAPROTOCOL_INFOW that it got to the controller's handoff pipe, after a magic and
// the size of the message, little-endian. The controller makes its own socket of it (WSASocketW with
// FROM_PROTOCOL_INFO) and answers with one byte: handoffTaken, or handoffNotTaken, which makes the
// front door close the connection. SDN-73 (#352) is the controller's end (frontdoor_windows.go).
const (
	// handoffMagic is FRONT_DOOR_HANDOFF_MAGIC: "RFD1", the first four bytes of a message.
	handoffMagic = 0x31444652
	// protocolInfoSize is sizeof(WSAPROTOCOL_INFOW), the same on x64 and arm64: it holds no pointer.
	protocolInfoSize = 628
	// HandoffSize is sizeof(FRONT_DOOR_HANDOFF): the magic, the size and the WSAPROTOCOL_INFOW.
	HandoffSize = 8 + protocolInfoSize

	// The answer of the controller, FRONT_DOOR_TAKEN and FRONT_DOOR_NOT_TAKEN
	handoffTaken    = 1
	handoffNotTaken = 0
)

// The offsets of the fields of WSAPROTOCOL_INFOW that the decoder checks, and the values that a TCP
// socket of IPv4 or IPv6 has on Windows: the front door hands over nothing else.
const (
	infoAddressFamily = 76
	infoSocketType    = 88
	infoProtocol      = 92

	afInet     = 2  // AF_INET
	afInet6    = 23 // AF_INET6 of Windows
	sockStream = 1  // SOCK_STREAM
	ipprotoTCP = 6  // IPPROTO_TCP
)

// ErrHandoff is the error of a handoff message that is not one of this version.
var ErrHandoff = errors.New("port: not a handoff message of the front door")

// DecodeHandoff reads a handoff message as the controller received it from its pipe, the bytes of
// one message: the WSAPROTOCOL_INFOW of the socket that the front door duplicated, with the name of
// its protocol terminated. It returns ErrHandoff when the message is not one of this version: another
// size or magic, or a socket that is not TCP over IPv4 or IPv6. This is FrontDoorHandoffDecode of
// src/Core/FrontDoorHello.c in Go.
func DecodeHandoff(b []byte) ([protocolInfoSize]byte, error) {
	var info [protocolInfoSize]byte
	if len(b) != HandoffSize {
		return info, fmt.Errorf("%w: %d bytes, not %d", ErrHandoff, len(b), HandoffSize)
	}
	le := binary.LittleEndian
	if le.Uint32(b[0:]) != handoffMagic || le.Uint32(b[4:]) != HandoffSize {
		return info, fmt.Errorf("%w: another magic or version", ErrHandoff)
	}
	copy(info[:], b[8:])
	family, typ, protocol := int32(le.Uint32(info[infoAddressFamily:])), int32(le.Uint32(info[infoSocketType:])), int32(le.Uint32(info[infoProtocol:]))
	if (family != afInet && family != afInet6) || typ != sockStream || protocol != ipprotoTCP {
		return [protocolInfoSize]byte{}, fmt.Errorf("%w: a socket of family %d, type %d and protocol %d, not TCP", ErrHandoff, family, typ, protocol)
	}
	// The last character of szProtocol terminates it, as the C decoder makes it
	info[protocolInfoSize-2], info[protocolInfoSize-1] = 0, 0
	return info, nil
}
