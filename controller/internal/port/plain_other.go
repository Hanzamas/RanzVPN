//go:build !windows

package port

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ListenPlain opens the plain-HTTP port on the TCP address addr with a listener of its own and
// serves h on it.
func ListenPlain(addr string, h http.Handler, log *slog.Logger) (Plain, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if log != nil {
		srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	}
	return &netPlain{ln: ln, srv: srv}, nil
}

type netPlain struct {
	ln  net.Listener
	srv *http.Server
}

func (p *netPlain) Serve() error {
	if err := p.srv.Serve(p.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *netPlain) Close() error {
	return p.srv.Close()
}

func (p *netPlain) Where() string {
	return p.ln.Addr().String()
}
