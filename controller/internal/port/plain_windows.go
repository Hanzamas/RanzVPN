//go:build windows

package port

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the plain-HTTP port runs on HTTP.sys, the kernel HTTP listener, through the HTTP
// Server API (httpapi.dll), so the controller shares port 80 with IIS and everything else that
// uses HTTP.sys instead of holding the socket itself. It registers two URL prefixes in a request
// queue of its own:
//
//   - http://+:<port>/.well-known/acme-challenge/, a strong wildcard: HTTP.sys gives the
//     controller every ACME HTTP-01 challenge on the port, whatever the host;
//   - http://*:<port>/, a weak wildcard: the controller redirects only the requests that no other
//     HTTP.sys user (an IIS site, for example) takes.
//
// A prefix that another HTTP.sys user registered already is left to it, with a warning; when
// neither registers, the port does not open. install reserves both prefixes for the account of
// the service (Reserve), and uninstall removes the reservations it made.

// The HTTP Server API names and values (http.h) this file uses.
const (
	httpAPIVersion2 = 2 // HTTPAPI_VERSION_2, {2, 0}, passed by value: the major version is the low 16 bits

	initializeServer = 1 // HTTP_INITIALIZE_SERVER
	initializeConfig = 2 // HTTP_INITIALIZE_CONFIG

	serverBindingProperty = 7 // HttpServerBindingProperty
	serviceConfigURLACL   = 2 // HttpServiceConfigUrlAclInfo

	responseHeaderMax = 30 // HttpHeaderResponseMaximum

	errMoreData         = 234 // ERROR_MORE_DATA
	errAlreadyExists    = 183 // ERROR_ALREADY_EXISTS
	errOperationAborted = 995 // ERROR_OPERATION_ABORTED
	errFileNotFound     = 2   // ERROR_FILE_NOT_FOUND

	// maxRequest bounds the buffer of one request: the plain-HTTP port takes no bodies.
	maxRequest = 1 << 20
)

// The HTTP_VERB values of http.h, as method names.
var verbs = map[int32]string{3: "OPTIONS", 4: "GET", 5: "HEAD", 6: "POST", 7: "PUT", 8: "DELETE", 9: "TRACE", 10: "CONNECT"}

// The HTTP_HEADER_ID values of the response headers that HTTP.sys knows by number.
var knownResponseHeaders = map[string]int{
	"Cache-Control":  0,
	"Connection":     1,
	"Allow":          10,
	"Content-Length": 11,
	"Content-Type":   12,
	"Location":       23,
	"Retry-After":    25,
}

var (
	httpapi                        = windows.NewLazySystemDLL("httpapi.dll")
	procInitialize                 = httpapi.NewProc("HttpInitialize")
	procTerminate                  = httpapi.NewProc("HttpTerminate")
	procCreateServerSession        = httpapi.NewProc("HttpCreateServerSession")
	procCloseServerSession         = httpapi.NewProc("HttpCloseServerSession")
	procCreateURLGroup             = httpapi.NewProc("HttpCreateUrlGroup")
	procCloseURLGroup              = httpapi.NewProc("HttpCloseUrlGroup")
	procAddURLToURLGroup           = httpapi.NewProc("HttpAddUrlToUrlGroup")
	procSetURLGroupProperty        = httpapi.NewProc("HttpSetUrlGroupProperty")
	procCreateRequestQueue         = httpapi.NewProc("HttpCreateRequestQueue")
	procShutdownRequestQueue       = httpapi.NewProc("HttpShutdownRequestQueue")
	procCloseRequestQueue          = httpapi.NewProc("HttpCloseRequestQueue")
	procReceiveHTTPRequest         = httpapi.NewProc("HttpReceiveHttpRequest")
	procSendHTTPResponse           = httpapi.NewProc("HttpSendHttpResponse")
	procSetServiceConfiguration    = httpapi.NewProc("HttpSetServiceConfiguration")
	procDeleteServiceConfiguration = httpapi.NewProc("HttpDeleteServiceConfiguration")
)

// httpRequestHead is the start of HTTP_REQUEST_V1, up to the cooked URL, which is all the
// plain-HTTP port reads. The pointers point into the same receive buffer.
type httpRequestHead struct {
	Flags             uint32
	_                 uint32
	ConnectionID      uint64
	RequestID         uint64
	URLContext        uint64
	VersionMajor      uint16
	VersionMinor      uint16
	Verb              int32
	UnknownVerbLength uint16
	RawURLLength      uint16
	_                 uint32
	UnknownVerb       *byte
	RawURL            *byte
	FullURLLength     uint16 // the lengths of the cooked URL are in bytes
	HostLength        uint16
	AbsPathLength     uint16
	QueryStringLength uint16
	FullURL           *uint16
	Host              *uint16
	AbsPath           *uint16
	QueryString       *uint16
}

// httpKnownHeader, httpUnknownHeader, httpDataChunk (its FromMemory form) and httpResponse are
// HTTP_KNOWN_HEADER, HTTP_UNKNOWN_HEADER, HTTP_DATA_CHUNK and HTTP_RESPONSE_V1.
type httpKnownHeader struct {
	RawValueLength uint16
	RawValue       *byte
}

type httpUnknownHeader struct {
	NameLength     uint16
	RawValueLength uint16
	Name           *byte
	RawValue       *byte
}

type httpDataChunk struct {
	Type   int32 // HttpDataChunkFromMemory, 0
	Buffer *byte
	Length uint32
	_      [12]byte // the rest of the union of HTTP_DATA_CHUNK
}

type httpResponse struct {
	Flags              uint32
	VersionMajor       uint16
	VersionMinor       uint16
	StatusCode         uint16
	ReasonLength       uint16
	Reason             *byte
	UnknownHeaderCount uint16
	UnknownHeaders     *httpUnknownHeader
	TrailerCount       uint16
	Trailers           *httpUnknownHeader
	KnownHeaders       [responseHeaderMax]httpKnownHeader
	EntityChunkCount   uint16
	EntityChunks       *httpDataChunk
}

// httpBindingInfo is HTTP_BINDING_INFO; urlACLSet is HTTP_SERVICE_CONFIG_URLACL_SET.
type httpBindingInfo struct {
	Present uint32
	Queue   windows.Handle
}

type urlACLSet struct {
	URLPrefix *uint16
	SDDL      *uint16
}

func apiError(fn string, r uintptr) error {
	if e := uint32(r); e != 0 {
		return fmt.Errorf("port: %s: %w", fn, windows.Errno(e))
	}
	return nil
}

func utf16z(s string) *uint16 {
	// The prefixes and descriptors of this package hold no NUL, so the conversion cannot fail.
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// PlainPrefixes returns the HTTP.sys URL prefixes of the plain-HTTP port for the -http-listen
// address addr: the ACME challenge path, then the redirect. An empty or wildcard host gives the
// strong wildcard for the ACME path and the weak one for the redirect; any other host is used as
// it is for both.
func PlainPrefixes(addr string) ([]string, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("port: %q: %w", addr, err)
	}
	if _, err := strconv.ParseUint(p, 10, 16); err != nil {
		return nil, fmt.Errorf("port: %q has no port number", addr)
	}
	acme, rest := "+", "*"
	if host != "" && host != "0.0.0.0" && host != "::" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		acme, rest = host, host
	}
	return []string{"http://" + acme + ":" + p + acmePrefix, "http://" + rest + ":" + p + "/"}, nil
}

// ListenPlain opens the plain-HTTP port of the -http-listen address addr on HTTP.sys and serves
// h on it.
func ListenPlain(addr string, h http.Handler, log *slog.Logger) (Plain, error) {
	prefixes, err := PlainPrefixes(addr)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &httpSys{handler: h, log: log}
	if err := s.open(prefixes); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// httpSys is the plain-HTTP port on HTTP.sys.
type httpSys struct {
	handler http.Handler
	log     *slog.Logger

	initialized bool
	session     uint64
	group       uint64
	queue       windows.Handle
	prefixes    []string // the prefixes that registered
	closed      atomic.Bool
	once        sync.Once
}

func (s *httpSys) open(prefixes []string) error {
	r, _, _ := procInitialize.Call(httpAPIVersion2, initializeServer, 0)
	if err := apiError("HttpInitialize", r); err != nil {
		return err
	}
	s.initialized = true
	r, _, _ = procCreateServerSession.Call(httpAPIVersion2, uintptr(unsafe.Pointer(&s.session)), 0)
	if err := apiError("HttpCreateServerSession", r); err != nil {
		return err
	}
	r, _, _ = procCreateURLGroup.Call(uintptr(s.session), uintptr(unsafe.Pointer(&s.group)), 0)
	if err := apiError("HttpCreateUrlGroup", r); err != nil {
		return err
	}
	r, _, _ = procCreateRequestQueue.Call(httpAPIVersion2, 0, 0, 0, uintptr(unsafe.Pointer(&s.queue)))
	if err := apiError("HttpCreateRequestQueue", r); err != nil {
		return err
	}
	binding := httpBindingInfo{Present: 1, Queue: s.queue}
	r, _, _ = procSetURLGroupProperty.Call(uintptr(s.group), serverBindingProperty, uintptr(unsafe.Pointer(&binding)), unsafe.Sizeof(binding))
	if err := apiError("HttpSetUrlGroupProperty", r); err != nil {
		return err
	}
	var errs []error
	for _, p := range prefixes {
		r, _, _ = procAddURLToURLGroup.Call(uintptr(s.group), uintptr(unsafe.Pointer(utf16z(p))), 0, 0)
		if uint32(r) == errAlreadyExists {
			s.log.Warn("another HTTP.sys user holds this URL prefix: the controller leaves it to that user", "prefix", p)
			continue
		}
		if err := apiError("HttpAddUrlToUrlGroup "+p, r); err != nil {
			errs = append(errs, err)
			continue
		}
		s.prefixes = append(s.prefixes, p)
	}
	if len(s.prefixes) == 0 {
		return fmt.Errorf("port: no URL prefix of the plain-HTTP port registers with HTTP.sys: %w", errors.Join(errs...))
	}
	return errors.Join(errs...)
}

func (s *httpSys) Where() string {
	return "HTTP.sys " + strings.Join(s.prefixes, " ")
}

// Serve receives each request from the request queue, serves it with the handler and sends the
// response, until Close.
func (s *httpSys) Serve() error {
	buf := make([]byte, 16<<10)
	for {
		var n uint32
		r, _, _ := procReceiveHTTPRequest.Call(uintptr(s.queue), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
		if uint32(r) == errMoreData && n <= maxRequest {
			id := (*httpRequestHead)(unsafe.Pointer(&buf[0])).RequestID
			buf = make([]byte, n)
			r, _, _ = procReceiveHTTPRequest.Call(uintptr(s.queue), uintptr(id), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
		}
		if s.closed.Load() {
			return nil
		}
		if e := uint32(r); e == errOperationAborted {
			return nil
		} else if e != 0 {
			s.log.Warn("receiving a request from HTTP.sys", "err", windows.Errno(e))
			continue
		}
		s.serve((*httpRequestHead)(unsafe.Pointer(&buf[0])))
	}
}

// serve hands one request to the handler and sends what it wrote.
func (s *httpSys) serve(req *httpRequestHead) {
	method := verbs[req.Verb]
	if method == "" && req.UnknownVerb != nil {
		method = string(unsafe.Slice(req.UnknownVerb, req.UnknownVerbLength))
	}
	host := utf16String(req.Host, req.HostLength)
	path := utf16String(req.AbsPath, req.AbsPathLength)
	query := strings.TrimPrefix(utf16String(req.QueryString, req.QueryStringLength), "?")
	hr := &http.Request{
		Method:     method,
		URL:        &url.URL{Path: path, RawQuery: query},
		Host:       host,
		Header:     http.Header{},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	rec := &recorder{header: http.Header{}, code: http.StatusOK}
	s.handler.ServeHTTP(rec, hr)
	s.respond(req.RequestID, rec, method == http.MethodHead)
}

// respond sends the response that rec recorded as the answer to the request id.
func (s *httpSys) respond(id uint64, rec *recorder, head bool) {
	resp := httpResponse{VersionMajor: 1, VersionMinor: 1, StatusCode: uint16(rec.code)}
	if reason := []byte(http.StatusText(rec.code)); len(reason) > 0 {
		resp.Reason, resp.ReasonLength = &reason[0], uint16(len(reason))
	}
	body := rec.body.Bytes()
	rec.header.Set("Content-Length", strconv.Itoa(len(body)))
	var unknown []httpUnknownHeader
	for name, values := range rec.header {
		value := []byte(strings.Join(values, ", "))
		if i, ok := knownResponseHeaders[name]; ok {
			resp.KnownHeaders[i] = httpKnownHeader{RawValueLength: uint16(len(value)), RawValue: first(value)}
			continue
		}
		n := []byte(name)
		unknown = append(unknown, httpUnknownHeader{NameLength: uint16(len(n)), RawValueLength: uint16(len(value)), Name: first(n), RawValue: first(value)})
	}
	if len(unknown) > 0 {
		resp.UnknownHeaderCount, resp.UnknownHeaders = uint16(len(unknown)), &unknown[0]
	}
	if len(body) > 0 && !head {
		resp.EntityChunkCount, resp.EntityChunks = 1, &httpDataChunk{Buffer: &body[0], Length: uint32(len(body))}
	}
	var sent uint32
	r, _, _ := procSendHTTPResponse.Call(uintptr(s.queue), uintptr(id), 0, uintptr(unsafe.Pointer(&resp)), 0, uintptr(unsafe.Pointer(&sent)), 0, 0, 0, 0)
	if err := apiError("HttpSendHttpResponse", r); err != nil {
		s.log.Debug("sending a response through HTTP.sys", "err", err)
	}
}

// Close shuts the request queue down, which ends Serve, and frees the HTTP.sys objects.
func (s *httpSys) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		if s.queue != 0 {
			procShutdownRequestQueue.Call(uintptr(s.queue))
		}
		if s.group != 0 {
			procCloseURLGroup.Call(uintptr(s.group))
		}
		if s.queue != 0 {
			procCloseRequestQueue.Call(uintptr(s.queue))
		}
		if s.session != 0 {
			procCloseServerSession.Call(uintptr(s.session))
		}
		if s.initialized {
			procTerminate.Call(initializeServer, 0)
		}
	})
	return nil
}

// Reserve makes a URL reservation (an HTTP.sys URL ACL) of prefix with the security descriptor
// sddl, as `netsh http add urlacl` does. created is false when a reservation of prefix exists
// already; it is left as it is.
func Reserve(prefix, sddl string) (created bool, err error) {
	r, _, _ := procInitialize.Call(httpAPIVersion2, initializeConfig, 0)
	if err := apiError("HttpInitialize", r); err != nil {
		return false, err
	}
	defer procTerminate.Call(initializeConfig, 0)
	set := urlACLSet{URLPrefix: utf16z(prefix), SDDL: utf16z(sddl)}
	r, _, _ = procSetServiceConfiguration.Call(0, serviceConfigURLACL, uintptr(unsafe.Pointer(&set)), unsafe.Sizeof(set), 0)
	if uint32(r) == errAlreadyExists {
		return false, nil
	}
	if err := apiError("HttpSetServiceConfiguration "+prefix, r); err != nil {
		return false, err
	}
	return true, nil
}

// Unreserve removes the URL reservation of prefix, as `netsh http delete urlacl` does; a
// reservation that does not exist is no error.
func Unreserve(prefix string) error {
	r, _, _ := procInitialize.Call(httpAPIVersion2, initializeConfig, 0)
	if err := apiError("HttpInitialize", r); err != nil {
		return err
	}
	defer procTerminate.Call(initializeConfig, 0)
	set := urlACLSet{URLPrefix: utf16z(prefix)}
	r, _, _ = procDeleteServiceConfiguration.Call(0, serviceConfigURLACL, uintptr(unsafe.Pointer(&set)), unsafe.Sizeof(set), 0)
	if uint32(r) == errFileNotFound {
		return nil
	}
	return apiError("HttpDeleteServiceConfiguration "+prefix, r)
}

// recorder is the http.ResponseWriter of one request on HTTP.sys.
type recorder struct {
	header http.Header
	code   int
	wrote  bool
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header {
	return r.header
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.code, r.wrote = code, true
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}

func utf16String(p *uint16, size uint16) string {
	if p == nil || size == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(p, size/2))
}

func first(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
