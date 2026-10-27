package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"log/slog"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// A standby member caps the control streams that wait for a Hello as its controller does (CS-4,
// AUD1-DT-2 #450): of two streams of one source the first waits and the second is closed, and the
// first is refused as a standby once it says Hello, which gives its place back.
func TestStandbyCapsTheStreamsThatWaitForAHello(t *testing.T) {
	memberKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{control.ALPN}, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	m := &Member{cfg: Config{Name: "b", Key: memberKey}, log: slog.New(slog.DiscardHandler), waiting: control.NewWaiting(5, 1)}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go m.ServeStream(raw.(*tls.Conn))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	first, err := control.Dial(ctx, ln.Addr().String(), nodeKey, memberKey.Public())
	if err != nil {
		t.Fatalf("the first stream: %v", err)
	}
	defer first.Close()
	if second, err := control.Dial(ctx, ln.Addr().String(), nodeKey, memberKey.Public()); err == nil {
		second.Close()
		t.Fatal("a second stream of one source was served while the first waits for its Hello")
	}

	hello := &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_2}}}
	if _, err := first.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := first.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _, err := first.Read()
	if err != nil || got.GetRefuse().GetReason() != controlpb.RefuseReason_REFUSE_REASON_NOT_LEADER {
		t.Fatalf("a standby answered the Hello with %v, %v, want the refusal that says it is a standby", got, err)
	}

	// The first stream gave its place back: a stream of the same source waits again
	third, err := control.Dial(ctx, ln.Addr().String(), nodeKey, memberKey.Public())
	if err != nil {
		t.Fatalf("a stream after the first one said Hello: %v", err)
	}
	third.Close()
}
