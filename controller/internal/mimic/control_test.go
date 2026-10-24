package mimic

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// The messages of the control pipe: one JSON object a line, in both directions.

func TestReaderReadsMessages(t *testing.T) {
	in := `{"type":"stats"}` + "\n\n  \r\n" + `{"type":"start","role":"server","pipe":"p"}` + "\r\n"
	r := NewReader(strings.NewReader(in))
	m, err := r.Read()
	if err != nil || m.Type != TypeStats {
		t.Fatalf("the first message is %+v, %v", m, err)
	}
	m, err = r.Read()
	if err != nil || m.Type != TypeStart || m.Role != RoleServer || m.Pipe != "p" {
		t.Fatalf("the second message is %+v, %v", m, err)
	}
	if m, err = r.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last message Read returned %+v, %v, want io.EOF", m, err)
	}
}

func TestReaderRefusesWhatIsNoMessage(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"text", "stats\n", "not a message"},
		{"an array", "[1]\n", "not a message"},
		{"a field that is not known", `{"type":"stats","bogus":1}` + "\n", "not a message"},
		{"a field of a setting that is not known", `{"type":"start","server":{"private_key":"00","extra":true}}` + "\n", "not a message"},
		{"a second object on the line", `{"type":"stats"} {"type":"stats"}` + "\n", "data after the object"},
		{"no type", "{}\n", "without a type"},
		{"an empty type", `{"type":""}` + "\n", "without a type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewReader(strings.NewReader(c.in)).Read()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Read = %v, want an error with %q", err, c.want)
			}
		})
	}
}

func TestReaderRefusesALineThatIsTooLong(t *testing.T) {
	in := `{"type":"error","error":"` + strings.Repeat("x", MaxLine) + `"}` + "\n" + `{"type":"stats"}` + "\n"
	if _, err := NewReader(strings.NewReader(in)).Read(); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("Read = %v, want ErrLineTooLong", err)
	}
	// A message that fits is read, whatever its size
	small := `{"type":"error","error":"` + strings.Repeat("x", MaxLine-100) + `"}` + "\n"
	if m, err := NewReader(strings.NewReader(small)).Read(); err != nil || len(m.Error) != MaxLine-100 {
		t.Errorf("a message of %d bytes: %d bytes of error, %v", len(small), len(m.Error), err)
	}
}

func TestWriterWritesOneLineForEachMessage(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	if err := w.Write(Message{Type: TypeReady, Version: "v", Protocol: ProtocolVersion, Listen: "127.0.0.1:443"}); err != nil {
		t.Fatal(err)
	}
	want := `{"type":"ready","version":"v","protocol":1,"listen":"127.0.0.1:443"}` + "\n"
	if b.String() != want {
		t.Errorf("Write wrote %q, want %q", b.String(), want)
	}

	b.Reset()
	if err := w.Write(Message{Type: TypeError, Error: strings.Repeat("x", MaxLine)}); !errors.Is(err, ErrLineTooLong) || b.Len() != 0 {
		t.Errorf("Write of a message that is too long: %v, %d bytes written", err, b.Len())
	}
}

func TestWriterIsSafeForConcurrentUse(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := w.Write(Message{Type: TypeProbe, Peer: "192.0.2.1:1234", Reason: "a reason that is long enough to be split by a writer that does not lock"}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	r := NewReader(&b)
	n := 0
	for {
		m, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || m.Type != TypeProbe {
			t.Fatalf("message %d is %+v, %v", n, m, err)
		}
		n++
	}
	if n != 1000 {
		t.Errorf("%d messages came back, want 1000", n)
	}
}

// A start message goes through the writer and the reader unchanged, settings and all.
func TestStartMessageRoundTrip(t *testing.T) {
	start := Message{
		Type: TypeStart,
		Role: RoleServer,
		Pipe: `\\.\pipe\ranz-mimic-data-1`,
		Server: &ServerSettings{
			Listen:        ":443",
			PrivateKey:    testPrivate,
			ShortIDs:      []string{"", testShortID},
			ServerNames:   []string{testName},
			MaxTimeDiffMs: 90000,
			Decoy:         Decoy{Mode: DecoyOwn, Name: testName, Page: "<p>x</p>", ACME: &ACME{Directory: "https://ca.example/dir", Email: "a@example.com", CacheDir: "cache", CAFile: "ca.pem"}},
			Padding:       Padding{Profile: ProfileShape, Sizes: []int{512, 1500}, MinGapMs: 2, JitterMs: 5},
		},
	}
	client := Message{
		Type: TypeStart,
		Role: RoleClient,
		Pipe: `\\.\pipe\ranz-mimic-data-2`,
		Client: &ClientSettings{
			Links:         []Link{{Address: "192.0.2.1:443", ServerName: testName, PublicKey: testPrivate, ShortID: "ab", Fingerprint: FingerprintChrome, Padding: Padding{Profile: ProfileSize}}},
			DialTimeoutMs: 5000,
		},
	}

	var b bytes.Buffer
	w := NewWriter(&b)
	for _, m := range []Message{start, client} {
		if err := w.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReader(&b)
	for _, want := range []Message{start, client} {
		got, err := r.Read()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("a message came back as %+v, %v, want %+v", got, err, want)
		}
	}
}
