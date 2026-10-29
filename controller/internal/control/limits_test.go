package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The tests of the limits of the frames (limits.go, CS-4, AUD1-DT-2 #450). The frames that they build are
// padded with a field that no message has, which every reader of a protocol buffer takes in and
// ignores, so that a frame has exactly the size that a test asks for.

func helloMessage() *controlpb.ControlMessage {
	return &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_2, AppliedGeneration: 7}}}
}

// marshal returns the bytes of m.
func marshal(t *testing.T, m *controlpb.ControlMessage) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// frameOf returns the frame that carries body: its length, then its bytes.
func frameOf(body []byte) []byte {
	var b bytes.Buffer
	if err := writeFrame(&b, body); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// header returns the 4 bytes of the length of a frame of n bytes.
func header(n uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, n)
}

// padTo returns msg, the bytes of a message, with a field of the number 15 that no message has added
// at its end, so that it is size bytes long.
func padTo(t *testing.T, msg []byte, size int) []byte {
	t.Helper()
	room := size - len(msg)
	if room == 0 {
		return msg
	}
	for payload := room; payload >= 0; payload-- {
		if 1+protowire.SizeBytes(payload) == room {
			out := protowire.AppendTag(slices.Clone(msg), 15, protowire.BytesType)
			out = protowire.AppendVarint(out, uint64(payload))
			return append(out, make([]byte, payload)...)
		}
	}
	t.Fatalf("no field makes a message of %d bytes %d bytes long", len(msg), size)
	return nil
}

// stalled is the reader of a peer that sends its data and then nothing: its Read blocks, once it has
// said so on reached, until release is closed, as the Read of a connection whose peer went quiet does.
type stalled struct {
	data    []byte
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newStalled(data []byte) *stalled {
	return &stalled{data: data, reached: make(chan struct{}), release: make(chan struct{})}
}

func (s *stalled) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		s.once.Do(func() { close(s.reached) })
		<-s.release
		return 0, io.ErrClosedPipe
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

// A peer that sends the length of a frame and then stops holds no more than the bytes that it sent
// and a small buffer: the first criterion of #450. The frame is read as its bytes arrive, and not
// allocated for its whole length as soon as the length is read. The test counts the bytes that Read
// allocates until it blocks for the peer, on the end of a node, which takes frames of 16 MiB, and on
// the end of the controller, after the Hello.
func TestStalledFrameHoldsOnlyWhatArrived(t *testing.T) {
	const smallBuffer = 64 << 10
	hello := frameOf(marshal(t, helloMessage()))
	leases := protowire.AppendTag(nil, fieldLeases, protowire.BytesType)
	for _, c := range []struct {
		name     string
		fromNode bool
		data     []byte
		sent     int
	}{
		{"the length of 16 MiB, to a node", false, header(MaxFrame), 0},
		{"1 MiB of 16 MiB, to a node", false, slices.Concat(header(MaxFrame), make([]byte, 1<<20)), 1 << 20},
		{"the length of a Leases message and its first byte, to the controller", true, slices.Concat(hello, header(MaxLeases), leases), 1},
		{"40 KiB of a Leases message, to the controller", true, slices.Concat(hello, header(MaxLeases), leases, make([]byte, 40<<10-1)), 40 << 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStalled(c.data)
			conn := &Conn{r: s, fromNode: c.fromNode}
			if c.fromNode {
				if _, _, err := conn.Read(); err != nil {
					t.Fatalf("the Hello: %v", err)
				}
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			done := make(chan error, 1)
			go func() {
				_, _, err := conn.Read()
				done <- err
			}()
			<-s.reached
			runtime.ReadMemStats(&after)
			close(s.release)
			if err := <-done; err == nil {
				t.Error("the frame of a peer that stopped was read to its end")
			}
			held := after.TotalAlloc - before.TotalAlloc
			limit := uint64(4 + c.sent + smallBuffer)
			if held > limit {
				t.Errorf("a peer that sent %d bytes of its frame made Read allocate %d bytes, want at most %d: the length, the bytes sent and a small buffer", c.sent, held, limit)
			}
		})
	}
}

// A frame over its limit costs no memory: its length is refused before any of its bytes are read.
func TestFrameOverItsLimitAllocatesNothing(t *testing.T) {
	const smallBuffer = 64 << 10
	conn := &Conn{r: bytes.NewReader(header(MaxFrame)), fromNode: true}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := conn.Read()
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a Hello of 16 MiB: %v, want ErrFrameTooLarge", err)
	}
	if held := after.TotalAlloc - before.TotalAlloc; held > smallBuffer {
		t.Errorf("a Hello of 16 MiB made Read allocate %d bytes, want at most %d", held, smallBuffer)
	}
}

// The Hello is taken at MaxHello bytes and refused above it, at its length; after it each kind of
// frame has its limit, taken at the limit and refused above it at its first byte, which tells the
// kind; and a frame of a kind that a node does not send after its Hello has the limit of a Hello.
func TestFrameLimits(t *testing.T) {
	hello := marshal(t, helloMessage())

	t.Run("the Hello", func(t *testing.T) {
		at := bytes.NewReader(frameOf(padTo(t, hello, MaxHello)))
		if _, b, err := (&Conn{r: at, fromNode: true}).Read(); err != nil || len(b) != MaxHello {
			t.Fatalf("a Hello of %d bytes: %d bytes taken, %v", MaxHello, len(b), err)
		}
		over := bytes.NewReader(frameOf(padTo(t, hello, MaxHello+1)))
		_, b, err := (&Conn{r: over, fromNode: true}).Read()
		if !errors.Is(err, ErrFrameTooLarge) || b != nil {
			t.Fatalf("a Hello of %d bytes: %d bytes taken, %v, want ErrFrameTooLarge", MaxHello+1, len(b), err)
		}
		if over.Len() != MaxHello+1 {
			t.Errorf("a Hello over its limit was read for %d bytes, want its length alone", 4+MaxHello+1-over.Len())
		}
	})

	for _, k := range []struct {
		name  string
		msg   *controlpb.ControlMessage
		limit int
	}{
		{"an Ack", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Ack{Ack: &controlpb.Ack{Generation: 7}}}, MaxAck},
		{"a Signal", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Signal{Signal: &controlpb.Signal{Peer: "branch-2", Envelope: []byte{4, 1, 2, 3}}}}, MaxSignal},
		{"a Telemetry message", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Telemetry{Telemetry: &controlpb.Telemetry{Vrfs: []*controlpb.VrfCounters{{VrfId: 10, TxPackets: 3}}}}}, MaxTelemetry},
		{"a Leases message", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Leases{Leases: &controlpb.Leases{Network: "corp-lan"}}}, MaxLeases},
		{"an OperationResult", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_OperationResult{OperationResult: &controlpb.OperationResult{Id: 7, Total: 3}}}, MaxOperationResult},
		{"a Pins message", &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Pins{Pins: &controlpb.Pins{MimicKey: make([]byte, 32)}}}, MaxPins},
		{"a second Hello", helloMessage(), MaxHello},
	} {
		t.Run(k.name, func(t *testing.T) {
			body := marshal(t, k.msg)
			r := bytes.NewReader(slices.Concat(frameOf(hello), frameOf(padTo(t, body, k.limit)), frameOf(padTo(t, body, k.limit+1))))
			c := &Conn{r: r, fromNode: true}
			if _, _, err := c.Read(); err != nil {
				t.Fatalf("the Hello: %v", err)
			}
			if _, b, err := c.Read(); err != nil || len(b) != k.limit {
				t.Fatalf("%s of %d bytes: %d bytes taken, %v", k.name, k.limit, len(b), err)
			}
			before := r.Len()
			_, b, err := c.Read()
			if !errors.Is(err, ErrFrameTooLarge) || b != nil {
				t.Fatalf("%s of %d bytes: %d bytes taken, %v, want ErrFrameTooLarge", k.name, k.limit+1, len(b), err)
			}
			// The length, and the first byte that tells the kind, unless the length is over the largest
			// limit of any kind, which fails at the length
			want := 5
			if k.limit == MaxLeases {
				want = 4
			}
			if read := before - r.Len(); read != want {
				t.Errorf("%s over its limit was read for %d bytes, want %d", k.name, read, want)
			}
		})
	}
}

// The frames of the controller keep their limit, MaxFrame: a node takes an Update that is larger than
// any frame that a node sends, and refuses a length over MaxFrame at once.
func TestControllerFramesKeepTheirLimit(t *testing.T) {
	update := marshal(t, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Update{Update: &controlpb.Update{Generation: 1}}})
	big := padTo(t, update, 3*MaxLeases)
	if _, b, err := (&Conn{r: bytes.NewReader(frameOf(big))}).Read(); err != nil || !bytes.Equal(b, big) {
		t.Fatalf("an Update of %d bytes: %d bytes taken, %v", len(big), len(b), err)
	}
	over := bytes.NewReader(header(MaxFrame + 1))
	if _, _, err := (&Conn{r: over}).Read(); !errors.Is(err, ErrFrameTooLarge) || over.Len() != 0 {
		t.Errorf("a frame of %d bytes: %v, want ErrFrameTooLarge", MaxFrame+1, err)
	}
}

// A frame comes out as it went in, whatever the number of chunks that it takes and the pieces that
// its bytes arrive in.
func TestReadFrameSizes(t *testing.T) {
	for _, n := range []int{0, 1, 2, frameChunk - 1, frameChunk, frameChunk + 1, 2 * frameChunk, 2*frameChunk + 1, 10 * frameChunk, 123457} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i * 7)
		}
		for name, wrap := range map[string]func(io.Reader) io.Reader{
			"whole":     func(r io.Reader) io.Reader { return r },
			"one byte":  iotest.OneByteReader,
			"half read": iotest.HalfReader,
		} {
			got, err := readFrame(wrap(bytes.NewReader(frameOf(body))), controllerFrame)
			if err != nil || !bytes.Equal(got, body) {
				t.Errorf("a frame of %d bytes that arrives %s: %d bytes taken, %v", n, name, len(got), err)
			}
		}
		// A frame cut short is an error
		if n > 0 {
			cut := bytes.NewReader(frameOf(body)[:4+n/2])
			if _, err := readFrame(cut, controllerFrame); err == nil {
				t.Errorf("a frame of %d bytes cut after %d bytes was read to its end", n, n/2)
			}
		}
	}
}

// On a stream of TLS the controller refuses the length of a frame of 16 MiB in place of the Hello at
// once, where it would wait for the 16 MiB, or for its Hello timeout, if it read the length and then
// the frame.
func TestHelloLengthOverItsLimitIsRefusedAtOnce(t *testing.T) {
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

	if _, err := nc.tc.Write(header(MaxFrame)); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cc.Read(); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("the length of a Hello of 16 MiB: %v, want ErrFrameTooLarge before any of its bytes", err)
	}
}

// options holds what control.options sets for the fields that it sizes: max_size and max_count, by
// the full name of the field.
type options map[string]map[string]int

// readOptions reads the nanopb options file at path.
func readOptions(t *testing.T, path string) options {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := options{}
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		set := map[string]int{}
		for _, f := range fields[1:] {
			name, value, ok := strings.Cut(f, ":")
			n, err := strconv.Atoi(value)
			if !ok || err != nil {
				t.Fatalf("%s: %q is no option of the form name:number", path, f)
			}
			set[name] = n
		}
		out[fields[0]] = set
	}
	return out
}

// of returns the option of the field, and fails the test when control.options sets none.
func (o options) of(t *testing.T, field protoreflect.FullName, option string) int {
	t.Helper()
	n, ok := o[string(field)][option]
	if !ok {
		t.Fatalf("control.options sets no %s for %s, which a node sends", option, field)
	}
	return n
}

// messageSize returns the largest size, in the wire format, of a message of the type md that the
// options allow: every field present at its largest, and the largest member of a oneof.
func (o options) messageSize(t *testing.T, md protoreflect.MessageDescriptor) int {
	t.Helper()
	size := 0
	oneofs := map[protoreflect.FullName]int{}
	for i := 0; i < md.Fields().Len(); i++ {
		fd := md.Fields().Get(i)
		n := o.fieldSize(t, fd)
		if oo := fd.ContainingOneof(); oo != nil && !oo.IsSynthetic() {
			oneofs[oo.FullName()] = max(oneofs[oo.FullName()], n)
			continue
		}
		size += n
	}
	for _, n := range oneofs {
		size += n
	}
	return size
}

// fieldSize returns the largest size of the field fd, with its tag. A number is taken at the longest
// varint that its type has, and a repeated field at its max_count.
func (o options) fieldSize(t *testing.T, fd protoreflect.FieldDescriptor) int {
	t.Helper()
	count := 1
	if fd.IsList() {
		count = o.of(t, fd.FullName(), "max_count")
	}
	elem := 0
	switch fd.Kind() {
	case protoreflect.BoolKind:
		elem = 1
	case protoreflect.EnumKind, protoreflect.Uint32Kind:
		elem = protowire.SizeVarint(math.MaxUint32)
	case protoreflect.Uint64Kind:
		elem = protowire.SizeVarint(math.MaxUint64)
	case protoreflect.StringKind, protoreflect.BytesKind:
		elem = protowire.SizeBytes(o.of(t, fd.FullName(), "max_size"))
	case protoreflect.MessageKind:
		elem = protowire.SizeBytes(o.messageSize(t, fd.Message()))
	default:
		t.Fatalf("%s is a field of the kind %v, which this test does not size", fd.FullName(), fd.Kind())
	}
	return count * (protowire.SizeTag(fd.Number()) + elem)
}

// The limits sit beside control.options (#450): for each kind of frame that a node sends, the largest
// frame that the sizes of the file allow is no larger than the limit of the kind. A size that grows
// past its limit fails here, so that the limit is raised with it, and the controller never closes the
// stream of a node that keeps to the options. The numbers that tell the kind of a frame are the ones
// of the schema.
func TestLimitsHoldTheOptions(t *testing.T) {
	opts := readOptions(t, filepath.Join("..", "..", "..", "proto", "ranz", "control", "v1", "control.options"))
	md := (&controlpb.ControlMessage{}).ProtoReflect().Descriptor()
	for _, k := range []struct {
		field  protoreflect.Name
		number protoreflect.FieldNumber
		limit  int
	}{
		{"hello", 0, MaxHello},
		{"ack", fieldAck, MaxAck},
		{"signal", fieldSignal, MaxSignal},
		{"telemetry", fieldTelemetry, MaxTelemetry},
		{"leases", fieldLeases, MaxLeases},
		{"operation_result", fieldOperationResult, MaxOperationResult},
		{"pins", fieldPins, MaxPins},
	} {
		fd := md.Fields().ByName(k.field)
		if fd == nil {
			t.Fatalf("ControlMessage has no field %s", k.field)
		}
		if k.number != 0 && fd.Number() != k.number {
			t.Errorf("the field %s of ControlMessage is number %d, and limits.go tells its frames by %d", k.field, fd.Number(), k.number)
		}
		// The frame of the largest message of the kind: the tag of its field, its length and the message
		largest := protowire.SizeTag(fd.Number()) + protowire.SizeBytes(opts.messageSize(t, fd.Message()))
		t.Logf("the largest %s frame that control.options allows is %d bytes; the limit is %d", k.field, largest, k.limit)
		if largest > k.limit {
			t.Errorf("control.options allows a %s frame of %d bytes, over its limit of %d: raise the limit in limits.go", k.field, largest, k.limit)
		}
	}
}
