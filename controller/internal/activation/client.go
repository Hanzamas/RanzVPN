package activation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client talks to the activation service. On install the node or the controller uses it to activate
// a Licence key, to re-validate on a heartbeat, to fetch the Enterprise feature key and to pull the
// revocation list (ADR-0036 amendment of 2026-10-22).
type Client struct {
	// BaseURL is the service origin, for example https://licence.hanzcodes.example.
	BaseURL string
	// HTTP is the client to send with; http.DefaultClient when nil.
	HTTP *http.Client
}

// Activate sends the Licence key and the machine fingerprint and returns a signed, node-locked,
// time-limited activation token.
func (c *Client) Activate(ctx context.Context, key, fingerprint string) (string, error) {
	var resp TokenResponse
	err := c.post(ctx, "/activation/v1/activate", ActivateRequest{Key: key, Fingerprint: fingerprint}, &resp)
	return resp.Token, err
}

// Heartbeat re-validates the token and returns the renewed one.
func (c *Client) Heartbeat(ctx context.Context, token, fingerprint string) (string, error) {
	var resp TokenResponse
	err := c.post(ctx, "/activation/v1/heartbeat", HeartbeatRequest{Token: token, Fingerprint: fingerprint}, &resp)
	return resp.Token, err
}

// FeatureKey returns the Enterprise feature key, released only against an Enterprise token.
func (c *Client) FeatureKey(ctx context.Context, token, fingerprint string) ([]byte, error) {
	var resp FeatureKeyResponse
	if err := c.post(ctx, "/activation/v1/feature-key", FeatureKeyRequest{Token: token, Fingerprint: fingerprint}, &resp); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("activation: the feature key is not base64: %w", err)
	}
	return key, nil
}

// Revocations fetches the signed revocation list and its vendor signature.
func (c *Client) Revocations(ctx context.Context) (RevocationList, []byte, error) {
	var resp RevocationsResponse
	if err := c.do(ctx, http.MethodGet, "/activation/v1/revocations", nil, &resp); err != nil {
		return RevocationList{}, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return RevocationList{}, nil, fmt.Errorf("activation: the revocation signature is not base64: %w", err)
	}
	return resp.RevocationList, sig, nil
}

// post sends body as JSON to path and decodes the reply into out.
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

// do sends one request and decodes the reply, turning a non-2xx into the service's error message.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var p problem
		if json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&p) == nil && p.Error != "" {
			return fmt.Errorf("activation: %s: %s", resp.Status, p.Error)
		}
		return fmt.Errorf("activation: %s", resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
			return fmt.Errorf("activation: decoding the reply: %w", err)
		}
	}
	return nil
}
