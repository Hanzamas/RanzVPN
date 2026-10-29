package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// The keys of the finished configuration in these tests: 32 bytes of one value each, in base64.
var (
	privateKey   = bytes.Repeat([]byte{0x22}, 32)
	gatewayKey   = bytes.Repeat([]byte{0x11}, 32)
	presharedKey = bytes.Repeat([]byte{0x33}, 32)
	b64          = base64.StdEncoding.EncodeToString
)

// finished returns the finished configuration of a Device as `ranz device create` prints it (SDN-82, #377):
// the private key of the Device in its [Interface], and the PresharedKey in its [Peer].
func finished() string {
	return fmt.Sprintf(`# Ranz VPN: the WireGuard configuration of Device phone, of Network lab-net in VRF lab
[Interface]
PrivateKey = %s
Address = 10.70.0.3/32, fd07:7:7:1::3/128
MTU = 1280

[Peer]
# The gateway, Node gw
PublicKey = %s
PresharedKey = %s
Endpoint = gw.example.net:51820
AllowedIPs = 10.70.0.0/24, fd07:7:7:1::/64
PersistentKeepalive = 25
`, b64(privateKey), b64(gatewayKey), b64(presharedKey))
}

// TestParseTheFinishedConfiguration: a client takes the private key of the Device and the PresharedKey of its
// gateway from the finished configuration, as a stock client does.
func TestParseTheFinishedConfiguration(t *testing.T) {
	c, err := parseConfig(strings.NewReader(finished()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.privateKey, privateKey) {
		t.Errorf("the private key is %x, want %x", c.privateKey, privateKey)
	}
	if !bytes.Equal(c.presharedKey, presharedKey) {
		t.Errorf("the PresharedKey is %x, want %x", c.presharedKey, presharedKey)
	}
	if !bytes.Equal(c.gatewayKey, gatewayKey) {
		t.Errorf("the key of the gateway is %x, want %x", c.gatewayKey, gatewayKey)
	}
	if len(c.addresses) != 2 || c.mtu != 1280 || c.endpoint != "gw.example.net:51820" || len(c.allowedIPs) != 2 || c.keepalive != 25 {
		t.Errorf("the configuration is %+v", c)
	}
}

// TestParseTheConfigurationThatIsShownLater: the configuration that the controller renders later says where
// the keys go in comments, so a client of it has neither key and takes the private key from the file of -key.
func TestParseTheConfigurationThatIsShownLater(t *testing.T) {
	later := strings.Replace(finished(), "PrivateKey = "+b64(privateKey), "# PrivateKey = the private key of this Device, which only the Device holds", 1)
	later = strings.Replace(later, "PresharedKey = "+b64(presharedKey), "# PresharedKey = the PresharedKey of this Device, which the controller showed once when it made the Device", 1)
	c, err := parseConfig(strings.NewReader(later))
	if err != nil {
		t.Fatal(err)
	}
	if c.privateKey != nil || c.presharedKey != nil {
		t.Errorf("the private key is %x and the PresharedKey %x, want none of them", c.privateKey, c.presharedKey)
	}
}

// TestParseRefuses: a key that is not 32 bytes, a field that a stock client does not know, a second gateway
// and a configuration with no Address are errors that name their line.
func TestParseRefuses(t *testing.T) {
	short := b64(make([]byte, 31))
	for _, c := range []struct{ name, config, want string }{
		{"a PresharedKey of 31 bytes", strings.Replace(finished(), b64(presharedKey), short, 1), "presharedkey: a key of 31 bytes"},
		{"a private key that is no base64", strings.Replace(finished(), b64(privateKey), "not base64!", 1), "privatekey"},
		{"a field that is not one", strings.Replace(finished(), "MTU = 1280", "Table = off", 1), "not a field of [interface]"},
		{"a second gateway", finished() + "\n[Peer]\nPublicKey = " + b64(gatewayKey) + "\n", "2 [Peer] sections"},
		{"no Address", strings.Replace(finished(), "Address = 10.70.0.3/32, fd07:7:7:1::3/128\n", "", 1), "no Address"},
		{"no Endpoint", strings.Replace(finished(), "Endpoint = gw.example.net:51820\n", "", 1), "needs a PublicKey, an Endpoint and AllowedIPs"},
		{"a line that is no assignment", strings.Replace(finished(), "MTU = 1280", "MTU 1280", 1), "no key = value"},
	} {
		if _, err := parseConfig(strings.NewReader(c.config)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.want)
		}
	}
}
