package api

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// certificatePath is the certificate that the controller serves on its TLS port, for the web UI, the
// API and the control streams of the nodes (SDN-92, #397).
const certificatePath = "/api/v1/controller-certificate"

// maxCertificateBody bounds the body of a change of the certificate: the setting is a few lines.
const maxCertificateBody = 64 << 10

// The certificate of the controller (SDN-92, #397), beside the calls of Handler:
//
//	GET    /api/v1/controller-certificate  the servercert.Info of the certificate that the TLS port serves:
//	                                       its subject, names, thumbprint, TLS fingerprint, expiry and
//	                                       source, and never a key                                       viewer
//	PUT    /api/v1/controller-certificate  a servercert.Setting, which becomes the one in force; a
//	                                       controller.CertificateChange                                  operator
//	                                       ?force=true: go on although a node did not take the new fingerprint
//	DELETE /api/v1/controller-certificate  removes the setting, so that the controller serves its own
//	                                       self-signed certificate again; a controller.CertificateChange operator
//
// A setting that cannot be served is answered with 400 Bad Request and the reason, and the certificate
// in use stays. A change that would strand a node that pinned the fingerprint of the certificate in
// use, because the node is not connected to take the new one, is answered with 409 Conflict and the
// names of the nodes, unless force says to go on.
func init() {
	register(
		route{http.MethodGet, certificatePath, rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			info, err := d.Controller.Certificate()
			if err != nil {
				replyCertificate(w, err)
				return
			}
			reply(w, http.StatusOK, info)
		}},
		route{http.MethodPut, certificatePath, rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCertificateBody))
			if err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a certificate setting: " + err.Error()})
				return
			}
			s, err := servercert.ParseSetting(b)
			if err != nil {
				replyCertificate(w, err)
				return
			}
			tok, _ := Caller(r.Context())
			res, err := d.Controller.SetCertificate(r.Context(), s, r.URL.Query().Get("force") == "true", tok.Name)
			if err != nil {
				replyCertificate(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
		route{http.MethodDelete, certificatePath, rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tok, _ := Caller(r.Context())
			res, err := d.Controller.ClearCertificate(r.Context(), r.URL.Query().Get("force") == "true", tok.Name)
			if err != nil {
				replyCertificate(w, err)
				return
			}
			reply(w, http.StatusOK, res)
		}},
	)
}

// replyCertificate answers a call of the certificate with the status that its error asks for: 400 for a
// setting or a certificate that is refused, 409 for nodes that did not take the new fingerprint, 501
// for a controller that serves one fixed certificate, and what replyError says for the rest.
func replyCertificate(w http.ResponseWriter, err error) {
	var refused *servercert.RefusedError
	var pinned *controller.NodesNotPinnedError
	switch {
	case errors.As(err, &refused):
		reply(w, http.StatusBadRequest, Problem{Error: err.Error()})
	case errors.As(err, &pinned):
		reply(w, http.StatusConflict, Problem{Error: err.Error()})
	case errors.Is(err, servercert.ErrNoManager):
		reply(w, http.StatusNotImplemented, Problem{Error: err.Error()})
	default:
		replyError(w, err)
	}
}

// ControllerCertificate returns the certificate that the controller serves on its TLS port.
func (c *Client) ControllerCertificate(ctx context.Context) (servercert.Info, error) {
	var info servercert.Info
	err := c.do(ctx, http.MethodGet, certificatePath, nil, &info)
	return info, err
}

// SetControllerCertificate makes the certificate of the setting s the one that the controller serves.
// With force it goes on although a node that is not connected did not take the new fingerprint.
func (c *Client) SetControllerCertificate(ctx context.Context, s servercert.Setting, force bool) (controller.CertificateChange, error) {
	var res controller.CertificateChange
	err := c.do(ctx, http.MethodPut, certificatePath+forceQuery(force), s, &res)
	return res, err
}

// ClearControllerCertificate removes the setting of the certificate, so that the controller serves its
// own self-signed certificate again.
func (c *Client) ClearControllerCertificate(ctx context.Context, force bool) (controller.CertificateChange, error) {
	var res controller.CertificateChange
	err := c.do(ctx, http.MethodDelete, certificatePath+forceQuery(force), nil, &res)
	return res, err
}

// forceQuery is the query of a call that goes on although a node did not take the new fingerprint.
func forceQuery(force bool) string {
	if force {
		return "?force=true"
	}
	return ""
}
