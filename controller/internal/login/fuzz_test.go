package login

import (
	"net/url"
	"testing"
)

// FuzzParse runs the parsers of what a caller of the logins sends on any query or form: the request of
// the authorization page (ParseAuthorize), the request of the device authorization endpoint
// (ParseDeviceRequest), the user code of the device page (NormalizeUserCode) and the code verifier of
// the token endpoint (VerifyChallenge). None may panic; a request that ParseAuthorize takes it takes
// again from its own parameters, with a loopback redirect URI; a device has a static key of 32 bytes;
// and a user code that NormalizeUserCode takes is its own normal form.
func FuzzParse(f *testing.F) {
	_, challenge := NewVerifier()
	f.Add(Request{RedirectURI: "http://127.0.0.1:8080/cb", State: "s", Challenge: challenge, Device: &Device{Key: make([]byte, 32), Name: "pc-1"}}.Values().Encode())
	f.Add(Request{RedirectURI: "http://127.0.0.1:1/", Challenge: challenge}.Values().Encode())
	f.Add("client_id=ranz&node_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&node_name=pc")
	f.Add("user_code=bcdf-ghjk&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	f.Add("redirect_uri=http%3A%2F%2F127.0.0.1%3A80%40example.com%2F&response_type=code&client_id=ranz")
	f.Fuzz(func(t *testing.T, query string) {
		v, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		if req, err := ParseAuthorize(v); err == nil {
			if err := checkRedirect(req.RedirectURI); err != nil {
				t.Fatalf("ParseAuthorize took the redirect URI %q: %v", req.RedirectURI, err)
			}
			again, err := ParseAuthorize(req.Values())
			if err != nil || again.RedirectURI != req.RedirectURI || again.State != req.State || again.Challenge != req.Challenge || (again.Device == nil) != (req.Device == nil) {
				t.Fatalf("ParseAuthorize(%v) = %+v, and its own parameters give %+v, %v", v, req, again, err)
			}
		}
		if d, err := ParseDeviceRequest(v); err == nil && d != nil && len(d.Key) != 32 {
			t.Fatalf("ParseDeviceRequest(%v) gave a key of %d bytes", v, len(d.Key))
		}
		if c, ok := NormalizeUserCode(v.Get("user_code")); ok {
			if again, ok := NormalizeUserCode(c); !ok || again != c {
				t.Fatalf("the user code %q normalizes to %q, and that to %q, %v", v.Get("user_code"), c, again, ok)
			}
		}
		_ = VerifyChallenge(v.Get("code_verifier"), v.Get("code_challenge"))
	})
}
