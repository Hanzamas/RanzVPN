package control

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.Private
}

// accept runs one server handshake on l and sends its result to the returned channels.
func accept(l *Listener) (<-chan *Conn, <-chan error) {
	conns, errs := make(chan *Conn, 1), make(chan error, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		c, err := l.Handshake(context.Background(), raw)
		if err != nil {
			raw.Close()
			errs <- err
			return
		}
		conns <- c
	}()
	return conns, errs
}

// Both ends learn each other's static key, and frames go through unchanged.
func TestHandshakeAndFrames(t *testing.T) {
	ctrl, err := PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	node, err := PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("127.0.0.1:0", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	conns, errs := accept(l)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, err := Dial(ctx, l.Addr().String(), node, ctrl.Public)
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
	if !bytes.Equal(cc.PeerKey(), node.Public) {
		t.Error("the controller end does not see the node's static key")
	}
	if !bytes.Equal(nc.PeerKey(), ctrl.Public) {
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
	ctrl, err := PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	other, err := PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	node, err := PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen("127.0.0.1:0", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	conns, errs := accept(l)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := Dial(ctx, l.Addr().String(), node, other.Public); err == nil {
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
