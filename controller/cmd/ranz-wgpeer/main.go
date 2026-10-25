// Command ranz-wgpeer is a stock WireGuard client for the tests of the WireGuard Devices of a
// gateway Node (SDN-80 #375): wireguard-go with its netstack, a TCP/IP stack in the process, so it
// needs no adapter and no administrator rights and holds no address of the machine. It reads the
// configuration that the Controller renders for a Device (`ranz get device-config NAME`) and the
// private key that only the Device holds, as a stock client imports them. It is a test tool:
// ranz.yml and windows.yml build it, and nothing ships it.
//
// Usage:
//
//	ranz-wgpeer -genkey FILE
//	ranz-wgpeer -config FILE -key FILE [-ping ADDRESS] [-tcp ADDRESS:PORT] [-blocked] [-timeout DURATION]
//
// The first form writes a new private key into FILE, in base64 as wg genkey writes it, and prints
// its public key, the publicKey of the Device resource. The second brings the Device up and waits
// for its handshake with the gateway, pings the IPv4 ADDRESS of an overlay host and opens a TCP
// connection to ADDRESS:PORT, through which one line goes to the host and comes back. With
// -blocked the ping must get no reply, because policy denies it, and -tcp is not used. Each step
// prints one line that starts with WGPEER; the exit code is 0 only when every step passed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// The text that the echo request and the TCP connection carry
const probe = "ranz device tracer"

// blockedTries is how many echo requests the ping that policy denies sends, each waiting its own
// share of the timeout for a reply that must not come.
const blockedTries = 3

func main() {
	genkey := flag.String("genkey", "", "write a new private key into this file and print its public key")
	config := flag.String("config", "", "the WireGuard configuration of the Device, as `ranz get device-config` prints it")
	keyFile := flag.String("key", "", "the file of the private key of the Device, in base64")
	ping := flag.String("ping", "", "the IPv4 address of the overlay host to ping")
	tcp := flag.String("tcp", "", "the address and the port of the overlay host to open a TCP connection to")
	blocked := flag.Bool("blocked", false, "the ping must get no reply: policy denies it")
	timeout := flag.Duration("timeout", 30*time.Second, "how long the handshake and each step may take")
	flag.Parse()

	var err error
	if *genkey != "" {
		err = genKey(*genkey, os.Stdout)
	} else {
		err = run(*config, *keyFile, *ping, *tcp, *blocked, *timeout, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ranz-wgpeer:", err)
		os.Exit(1)
	}
}

// genKey writes a new private key into path, clamped as wg genkey writes one, and prints its public
// key to out.
func genKey(path string, out io.Writer) error {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return err
	}
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv[:])+"\n"), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()))
	return err
}

// deviceConfig is what a stock client takes from the configuration of a Device: its [Interface]
// and its one [Peer], the gateway.
type deviceConfig struct {
	addresses  []netip.Prefix
	mtu        int
	gatewayKey []byte
	endpoint   string
	allowedIPs []netip.Prefix
	keepalive  int
}

// parseConfig reads the configuration of a Device. A field that a stock client does not know fails
// it, and so does a second [Peer]: a Device has one gateway.
func parseConfig(r io.Reader) (deviceConfig, error) {
	c := deviceConfig{mtu: device.DefaultMTU}
	section, peers := "", 0
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			if section == "peer" {
				peers++
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("line %d: no key = value", n)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		var err error
		switch section + "." + key {
		case "interface.address":
			c.addresses, err = prefixes(value)
		case "interface.mtu":
			c.mtu, err = strconv.Atoi(value)
		case "interface.dns", "interface.privatekey", "interface.listenport":
			// The servers of overlay DNS, which the tests resolve no name with, and the key and the port
			// that the flags and the system give
		case "peer.publickey":
			c.gatewayKey, err = base64.StdEncoding.DecodeString(value)
			if err == nil && len(c.gatewayKey) != 32 {
				err = fmt.Errorf("a key of %d bytes, not 32", len(c.gatewayKey))
			}
		case "peer.endpoint":
			c.endpoint = value
		case "peer.allowedips":
			c.allowedIPs, err = prefixes(value)
		case "peer.persistentkeepalive":
			c.keepalive, err = strconv.Atoi(value)
		default:
			err = fmt.Errorf("not a field of [%s]", section)
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %s: %w", n, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	switch {
	case peers != 1:
		return c, fmt.Errorf("%d [Peer] sections, and a Device has one gateway", peers)
	case len(c.addresses) == 0:
		return c, errors.New("no Address in [Interface]")
	case c.gatewayKey == nil || c.endpoint == "" || len(c.allowedIPs) == 0:
		return c, errors.New("the [Peer] needs a PublicKey, an Endpoint and AllowedIPs")
	}
	return c, nil
}

// prefixes parses a list of prefixes separated by commas.
func prefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// readKey reads a private key in base64 from path.
func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s: not a private key of 32 bytes in base64", path)
	}
	return k, nil
}

// run brings the Device of the configuration up and runs the steps that the flags ask for.
func run(configFile, keyFile, ping, tcp string, blocked bool, timeout time.Duration, out io.Writer) error {
	f, err := os.Open(configFile)
	if err != nil {
		return err
	}
	cfg, err := parseConfig(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	priv, err := readKey(keyFile)
	if err != nil {
		return err
	}
	var target netip.Addr
	if ping != "" {
		if target, err = netip.ParseAddr(ping); err != nil || !target.Is4() {
			return fmt.Errorf("-ping %q is not an IPv4 address", ping)
		}
	}
	// The DNS name of the gateway, resolved as a stock client resolves it: IPv4 first
	ep, err := net.ResolveUDPAddr("udp4", cfg.endpoint)
	if err != nil {
		if ep, err = net.ResolveUDPAddr("udp", cfg.endpoint); err != nil {
			return fmt.Errorf("the Endpoint %s: %w", cfg.endpoint, err)
		}
	}
	endpoint := netip.AddrPortFrom(ep.AddrPort().Addr().Unmap(), ep.AddrPort().Port())

	var local []netip.Addr
	for _, p := range cfg.addresses {
		local = append(local, p.Addr())
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, nil, cfg.mtu)
	if err != nil {
		return err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "ranz-wgpeer: "))
	defer dev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n",
		hex.EncodeToString(priv), hex.EncodeToString(cfg.gatewayKey), endpoint, cfg.keepalive)
	for _, p := range cfg.allowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", p)
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		return fmt.Errorf("the configuration of wireguard-go: %w", err)
	}
	if err := dev.Up(); err != nil {
		return err
	}
	fmt.Fprintf(out, "WGPEER UP addresses %v gateway %s at %s (%s)\n", local, base64.StdEncoding.EncodeToString(cfg.gatewayKey), cfg.endpoint, endpoint)

	// The handshake: the persistent keepalive starts it as the Device comes up, and an echo request
	// to the overlay host starts it without one
	end := time.Now().Add(timeout)
	for {
		hs, err := lastHandshake(dev)
		if err != nil {
			return err
		}
		if !hs.IsZero() {
			fmt.Fprintf(out, "WGPEER HANDSHAKE OK %s\n", hs.UTC().Format(time.RFC3339))
			break
		}
		if time.Now().After(end) {
			return fmt.Errorf("no handshake with the gateway at %s within %s", endpoint, timeout)
		}
		if cfg.keepalive == 0 && target.IsValid() {
			// The reply, if any, goes with the socket
			_, _ = echo(tnet, target, 0, time.Second)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if target.IsValid() && blocked {
		for i := 1; i <= blockedTries; i++ {
			rtt, err := echo(tnet, target, i, timeout/blockedTries)
			if err == nil {
				return fmt.Errorf("echo request %d to %s got a reply after %s, and policy denies the Device", i, target, rtt)
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return fmt.Errorf("echo request %d to %s: %w", i, target, err)
			}
		}
		fmt.Fprintf(out, "WGPEER PING BLOCKED %s: %d echo requests, no reply within %s\n", target, blockedTries, timeout)
	} else if target.IsValid() {
		rtt, err := echo(tnet, target, 1, timeout)
		if err != nil {
			return fmt.Errorf("echo request to %s: %w", target, err)
		}
		fmt.Fprintf(out, "WGPEER PING OK %s in %s\n", target, rtt)
	}

	if tcp != "" && !blocked {
		if err := echoTCP(tnet, tcp, timeout); err != nil {
			return fmt.Errorf("the TCP connection to %s: %w", tcp, err)
		}
		fmt.Fprintf(out, "WGPEER TCP OK %s\n", tcp)
	}

	tx, rx, err := counters(dev)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "WGPEER COUNTERS tx %d rx %d\n", tx, rx)
	return nil
}

// ipc returns the values of the one peer that the UAPI of dev lists, by key.
func ipc(dev *device.Device) (map[string]string, error) {
	get, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(get, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out, nil
}

// lastHandshake returns the time of the last handshake with the gateway, zero before the first.
func lastHandshake(dev *device.Device) (time.Time, error) {
	v, err := ipc(dev)
	if err != nil {
		return time.Time{}, err
	}
	sec, _ := strconv.ParseInt(v["last_handshake_time_sec"], 10, 64)
	nsec, _ := strconv.ParseInt(v["last_handshake_time_nsec"], 10, 64)
	if sec == 0 && nsec == 0 {
		return time.Time{}, nil
	}
	return time.Unix(sec, nsec), nil
}

// counters returns the bytes that the Device sent to the gateway and received from it.
func counters(dev *device.Device) (tx, rx uint64, err error) {
	v, err := ipc(dev)
	if err != nil {
		return 0, 0, err
	}
	tx, _ = strconv.ParseUint(v["tx_bytes"], 10, 64)
	rx, _ = strconv.ParseUint(v["rx_bytes"], 10, 64)
	return tx, rx, nil
}

// echo sends one ICMP echo request with the sequence number seq to target and waits for its reply
// at most timeout: the round trip, or an error that wraps os.ErrDeadlineExceeded when no reply came.
func echo(tnet *netstack.Net, target netip.Addr, seq int, timeout time.Duration) (time.Duration, error) {
	c, err := tnet.Dial("ping4", target.String())
	if err != nil {
		return 0, err
	}
	defer c.Close()
	req := &icmp.Echo{Seq: seq, Data: []byte(probe)}
	msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: req}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := c.Write(msg); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return 0, err
		}
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if e, ok := reply.Body.(*icmp.Echo); ok && e.Seq == req.Seq && bytes.Equal(e.Data, req.Data) {
			return time.Since(start), nil
		}
	}
}

// echoTCP opens a TCP connection to address through the tunnel, sends one line on it and reads it
// back: the overlay host of the tests echoes what it receives.
func echoTCP(tnet *netstack.Net, address string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := tnet.DialContext(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	line := []byte(probe + "\n")
	if _, err := c.Write(line); err != nil {
		return err
	}
	got := make([]byte, len(line))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, line) {
		return fmt.Errorf("the overlay host sent back %q, not %q", got, line)
	}
	return nil
}
