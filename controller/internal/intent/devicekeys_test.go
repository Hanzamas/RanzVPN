package intent

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// The configuration of a Device that the controller made the keys of (SDN-82, #377) is the finished one: the
// PrivateKey of its [Interface] and the PresharedKey of its [Peer], each where a stock client reads it. A
// Device whose public key was supplied has a line that says where the private key goes instead, and the
// configuration that is shown later says where each key goes.
func TestDeviceConfigWithKeys(t *testing.T) {
	in := deviceLab(t)
	gateway := bytes.Repeat([]byte{0x11}, KeySize)
	private := bytes.Repeat([]byte{0x22}, KeySize)
	psk := bytes.Repeat([]byte{0x33}, KeySize)
	b64 := base64.StdEncoding.EncodeToString

	got, err := in.DeviceConfigWith("phone", gateway, DeviceKeys{Private: private, Preshared: psk})
	if err != nil {
		t.Fatal(err)
	}
	// The order of a configuration that a stock client reads: the private key opens [Interface], the
	// PresharedKey follows the key of the gateway in [Peer]
	var at []int
	for _, line := range []string{"[Interface]\n", "PrivateKey = " + b64(private) + "\n", "Address = ", "MTU = ", "[Peer]\n", "PublicKey = " + b64(gateway) + "\n",
		"PresharedKey = " + b64(psk) + "\n", "Endpoint = ", "AllowedIPs = ", "PersistentKeepalive = "} {
		i := strings.Index(got, line)
		if i < 0 {
			t.Fatalf("the finished configuration has no line %q:\n%s", line, got)
		}
		at = append(at, i)
	}
	for i := 1; i < len(at); i++ {
		if at[i] <= at[i-1] {
			t.Errorf("the lines of the finished configuration are out of order:\n%s", got)
			break
		}
	}
	if strings.Contains(got, "# PrivateKey") || strings.Contains(got, "# PresharedKey") {
		t.Errorf("the finished configuration says where a key goes, which it holds:\n%s", got)
	}

	// A public key that was supplied: the PresharedKey is there, the private key stays with the Device
	got, err = in.DeviceConfigWith("phone", gateway, DeviceKeys{Preshared: psk})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# PrivateKey = the private key of this Device, which only the Device holds\n", "\nPresharedKey = " + b64(psk) + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the configuration of a Device with a public key of its own has no %q:\n%s", strings.TrimSpace(want), got)
		}
	}
	if strings.Contains(got, "\nPrivateKey = ") {
		t.Errorf("the configuration of a Device with a public key of its own has a private key:\n%s", got)
	}

	// Shown later: no key, and the line that says where the PresharedKey goes only for a Device that has one
	got, err = in.DeviceConfigWith("phone", gateway, DeviceKeys{HasPreshared: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# PrivateKey = the private key of this Device, which only the Device holds\n",
		"# PresharedKey = the PresharedKey of this Device, which the controller showed once when it made the Device\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the configuration that is shown later has no %q:\n%s", strings.TrimSpace(want), got)
		}
	}
	if strings.Contains(got, "\nPresharedKey = ") || strings.Contains(got, "\nPrivateKey = ") {
		t.Errorf("the configuration that is shown later holds a key:\n%s", got)
	}
	if got, err = in.DeviceConfigWith("phone", gateway, DeviceKeys{}); err != nil || strings.Contains(got, "PresharedKey") {
		t.Errorf("the configuration of a Device with no PresharedKey says something of one (%v):\n%s", err, got)
	}
	plain, err := in.DeviceConfig("phone", gateway)
	if err != nil || plain != got {
		t.Errorf("DeviceConfig is %q (%v), want what DeviceConfigWith gives for no keys, %q", plain, err, got)
	}

	// A key that is not of the size of a key is not written: it would be an invalid configuration
	got, err = in.DeviceConfigWith("phone", gateway, DeviceKeys{Private: private[:KeySize-1], Preshared: psk[:KeySize-1]})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "\nPrivateKey = ") || strings.Contains(got, "\nPresharedKey = ") {
		t.Errorf("a key of %d bytes was written into the configuration:\n%s", KeySize-1, got)
	}
}

// The configuration that is shown later of a Device whose PresharedKey does not open with the key of the
// controller says so in the place of the key (SDN-82-R1), so that nobody takes the gateway for one that holds it.
func TestDeviceConfigOfAPresharedKeyThatDoesNotOpen(t *testing.T) {
	in := deviceLab(t)
	got, err := in.DeviceConfigWith("phone", bytes.Repeat([]byte{0x11}, KeySize), DeviceKeys{HasPreshared: true, PresharedDoesNotOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "\n# PresharedKey = the PresharedKey of this Device does not open with the key of the controller, so the gateway terminates the Device without it until it opens, or until the Device is made again\n"
	if !strings.Contains(got, want) {
		t.Errorf("the configuration of a Device whose PresharedKey does not open has no %q:\n%s", strings.TrimSpace(want), got)
	}
	if strings.Contains(got, "\nPresharedKey = ") || strings.Contains(got, "showed once") {
		t.Errorf("the configuration of a Device whose PresharedKey does not open holds a key, or says that the key is in place:\n%s", got)
	}
}
