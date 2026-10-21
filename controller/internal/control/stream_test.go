package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

func newKey(t *testing.T) *keys.Soft {
	t.Helper()
	k, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// listen returns a TLS listener that offers ALPN, as the controller's port does.
func listen(t *testing.T) net.Listener {
	t.Helper()
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// accept runs the controller side of one handshake on ln and sends its result to the returned
// channels.
func accept(ln net.Listener, key keys.Static) (<-chan *Conn, <-chan error) {
	conns, errs := make(chan *Conn, 1), make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		c, err := Accept(context.Background(), raw.(*tls.Conn), key)
		if err != nil {
			errs <- err
			return
		}
		conns <- c
	}()
	return conns, errs
}

// Both ends learn each other's static key, and frames go through unchanged.
func TestHandshakeAndFrames(t *testing.T) {
	ctrl, node := newKey(t), newKey(t)
	ln := listen(t)
	conns, errs := accept(ln, ctrl)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, err := Dial(ctx, ln.Addr().String(), node, ctrl.Public())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	var cc *Conn
	select {
	case cc = <-conns:
	case err := <-errs:
		t.Fatal(err)
	}
	defer cc.Close()
	if !bytes.Equal(cc.PeerKey(), node.Public()) {
		t.Error("the controller end does not see the node's static key")
	}
	if !bytes.Equal(nc.PeerKey(), ctrl.Public()) {
		t.Error("the node end does not see the controller's static key")
	}

	hello := &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: &controlpb.Hello{
		SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, AppliedGeneration: 7,
	}}}
	sent, err := nc.Write(hello)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := cc.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, hello) || !bytes.Equal(raw, sent) {
		t.Errorf("the controller read %v (%x), the node sent %v (%x)", got, raw, hello, sent)
	}
}

// A node that expects another controller key fails the handshake, and so does the controller end.
func TestHandshakeWrongControllerKey(t *testing.T) {
	ctrl, other, node := newKey(t), newKey(t), newKey(t)
	ln := listen(t)
	conns, errs := accept(ln, ctrl)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := Dial(ctx, ln.Addr().String(), node, other.Public()); err == nil {
		c.Close()
		t.Fatal("the node opened a stream to a controller that does not hold the key it expects")
	}
	select {
	case c := <-conns:
		c.Close()
		t.Error("the controller completed a handshake that the node encrypted for another key")
	case <-errs:
	case <-time.After(15 * time.Second):
		t.Error("the controller end of the failed handshake did not end")
	}
}
