// Command ranz-noisepeer is one end of a Noise_IK_25519_AESGCM_SHA256 session on flynn/noise,
// the Noise implementation of the control stream (internal/control). It is the established
// implementation that the C session module of the node (src/Core/Noise.h, CORE-F2 #62) is checked
// against: coretest noiseinterop starts it and talks to it over its standard input and output.
//
// Every message is a 4-byte big-endian length and the message, as on the control stream. The
// script: the two handshake messages with the payloads "ranz interop 1" and "ranz interop 2";
// then -messages rounds of "ping <i>" from the initiator and "pong <i>" from the responder, both
// ends rekeying both cipher states (Noise section 11.3) before round -rekey; last, the initiator
// and then the responder send their handshake hash. The peer checks every message it reads and
// exits with 0 only when the whole script passed.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/flynn/noise"
)

func main() {
	initiator := flag.Bool("initiator", false, "run the initiator (the responder otherwise)")
	static := flag.String("static", "", "the local static private key, 64 hex digits")
	remote := flag.String("remote", "", "the responder's static public key, 64 hex digits (initiator only)")
	prologue := flag.String("prologue", "", "the prologue, in hex")
	messages := flag.Int("messages", 4, "rounds of transport messages after the handshake")
	rekey := flag.Int("rekey", 2, "the round before which both ends rekey, -1 for none")
	flag.Parse()

	if err := run(*initiator, *static, *remote, *prologue, *messages, *rekey, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ranz-noisepeer:", err)
		os.Exit(1)
	}
}

func run(initiator bool, staticHex, remoteHex, prologueHex string, messages, rekey int, in io.Reader, out io.Writer) error {
	priv, err := hex.DecodeString(staticHex)
	if err != nil || len(priv) != 32 {
		return errors.New("-static: not 32 bytes in hex")
	}
	// DH25519 reads its private key from the random source: given the scalar, it computes the
	// public key
	key, err := noise.DH25519.GenerateKeypair(bytes.NewReader(priv))
	if err != nil {
		return err
	}
	var peer []byte
	if initiator {
		peer, err = hex.DecodeString(remoteHex)
		if err != nil || len(peer) != 32 {
			return errors.New("-remote: not 32 bytes in hex")
		}
	}
	pro, err := hex.DecodeString(prologueHex)
	if err != nil {
		return errors.New("-prologue: not hex")
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		Prologue:      pro,
		StaticKeypair: key,
		PeerStatic:    peer,
	})
	if err != nil {
		return err
	}

	var send, recv *noise.CipherState
	if initiator {
		msg, _, _, err := hs.WriteMessage(nil, []byte("ranz interop 1"))
		if err != nil {
			return err
		}
		if err := writeFrame(out, msg); err != nil {
			return err
		}
		msg, err = readFrame(in)
		if err != nil {
			return fmt.Errorf("message 2: %w", err)
		}
		payload, cs1, cs2, err := hs.ReadMessage(nil, msg)
		if err != nil {
			return fmt.Errorf("message 2: %w", err)
		}
		if string(payload) != "ranz interop 2" {
			return fmt.Errorf("message 2: payload %q", payload)
		}
		send, recv = cs1, cs2
	} else {
		msg, err := readFrame(in)
		if err != nil {
			return fmt.Errorf("message 1: %w", err)
		}
		payload, _, _, err := hs.ReadMessage(nil, msg)
		if err != nil {
			return fmt.Errorf("message 1: %w", err)
		}
		if string(payload) != "ranz interop 1" {
			return fmt.Errorf("message 1: payload %q", payload)
		}
		msg, cs1, cs2, err := hs.WriteMessage(nil, []byte("ranz interop 2"))
		if err != nil {
			return err
		}
		if err := writeFrame(out, msg); err != nil {
			return err
		}
		send, recv = cs2, cs1
	}

	for i := 0; i < messages; i++ {
		if i == rekey {
			send.Rekey()
			recv.Rekey()
		}
		ping := []byte(fmt.Sprintf("ping %d", i))
		pong := []byte(fmt.Sprintf("pong %d", i))
		if initiator {
			if err := sendMessage(out, send, ping); err != nil {
				return err
			}
			if err := expectMessage(in, recv, pong); err != nil {
				return err
			}
		} else {
			if err := expectMessage(in, recv, ping); err != nil {
				return err
			}
			if err := sendMessage(out, send, pong); err != nil {
				return err
			}
		}
	}

	h := hs.ChannelBinding()
	if initiator {
		if err := sendMessage(out, send, h); err != nil {
			return err
		}
		return expectMessage(in, recv, h)
	}
	if err := expectMessage(in, recv, h); err != nil {
		return err
	}
	return sendMessage(out, send, h)
}

func sendMessage(w io.Writer, cs *noise.CipherState, plaintext []byte) error {
	msg, err := cs.Encrypt(nil, nil, plaintext)
	if err != nil {
		return err
	}
	return writeFrame(w, msg)
}

func expectMessage(r io.Reader, cs *noise.CipherState, want []byte) error {
	msg, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("waiting for %q: %w", want, err)
	}
	got, err := cs.Decrypt(nil, nil, msg)
	if err != nil {
		return fmt.Errorf("waiting for %q: %w", want, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("got %q, want %q", got, want)
	}
	return nil
}

func writeFrame(w io.Writer, b []byte) error {
	frame := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	_, err := w.Write(append(frame, b...))
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 65535 {
		return nil, fmt.Errorf("a message of %d bytes is larger than a Noise message", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
