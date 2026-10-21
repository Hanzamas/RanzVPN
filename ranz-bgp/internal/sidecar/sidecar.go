package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// The policy objects of the sidecar in GoBGP. The global RIB's policies apply to every peer.
const (
	globalRIB      = "global"
	exportPolicy   = "ranz-export"
	exportLocal    = "ranz-export-local"
	importPolicy   = "ranz-import"
	importLocal    = "ranz-import-local"
	acceptSetV4    = "ranz-accept-v4"
	acceptSetV6    = "ranz-accept-v6"
	acceptStmtV4   = "ranz-import-v4"
	acceptStmtV6   = "ranz-import-v6"
	defaultBGPPort = 179
)

// stateNames are the session states of a peer message.
var stateNames = map[bgp.FSMState]string{
	bgp.BGP_FSM_IDLE:        StateIdle,
	bgp.BGP_FSM_CONNECT:     StateConnect,
	bgp.BGP_FSM_ACTIVE:      StateActive,
	bgp.BGP_FSM_OPENSENT:    StateOpenSent,
	bgp.BGP_FSM_OPENCONFIRM: StateOpenConfirm,
	bgp.BGP_FSM_ESTABLISHED: StateEstablished,
}

// Options are the options of a session.
type Options struct {
	Logger   *slog.Logger   // the log of the sidecar and of GoBGP; none when nil
	LogLevel *slog.LevelVar // the level of Logger, which GoBGP may change; may be nil
}

// Version names ranz-bgp and the GoBGP it embeds.
func Version() string {
	v := "ranz-bgp"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/osrg/gobgp/v4" {
				return v + ", GoBGP " + d.Version
			}
		}
	}
	return v
}

// config is a start message, checked.
type config struct {
	asn             uint32
	routerID        netip.Addr
	listenPort      int32
	listenAddresses []string
	peers           []peerConfig
	accept          []netip.Prefix
}

type peerConfig struct {
	address netip.Addr
	asn     uint32
	port    uint32
	passive bool
}

// learnedRoute is the route of a learned prefix that the node was told about.
type learnedRoute struct {
	nextHop string
	peer    string
}

// session is BGP for one node.
type session struct {
	bgp       *server.BgpServer
	w         *Writer
	log       *slog.Logger
	cancel    context.CancelFunc
	announced map[netip.Prefix]uuid.UUID    // the read loop only
	learned   map[netip.Prefix]learnedRoute // the watch goroutine only
}

// Run serves one node on conn until the node closes it or ctx ends: it reads start, runs BGP with
// those settings, tells the node about its peers and the routes it learns, and applies the node's
// announce and withdraw messages. It returns nil when the node closed the pipe or ctx ended, and
// the error that ended the session otherwise.
func Run(ctx context.Context, conn io.ReadWriteCloser, opts Options) error {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := NewReader(conn)
	w := NewWriter(conn)
	defer conn.Close()

	// The end of ctx closes the pipe, which ends the read loop.
	stopClose := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopClose()

	first, err := r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the node closed the pipe before start")
		}
		return err
	}
	if first.Type != TypeStart {
		err := fmt.Errorf("the first message is %q, not %q", first.Type, TypeStart)
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}
	cfg, err := parseStart(first)
	if err != nil {
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}

	s, err := startSession(ctx, cfg, w, log, opts.LogLevel)
	if err != nil {
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}
	defer s.stop()

	if err := w.Write(Message{Type: TypeReady, Version: Version(), Protocol: ProtocolVersion}); err != nil {
		return err
	}
	log.Info("BGP started", "asn", cfg.asn, "routerID", cfg.routerID, "listenPort", cfg.listenPort, "peers", len(cfg.peers), "accept", len(cfg.accept))

	// The peers come after ready, so that the node reads ready before the first peer message.
	for _, p := range cfg.peers {
		if err := s.bgp.AddPeer(ctx, &api.AddPeerRequest{Peer: peerRequest(p)}); err != nil {
			s.send(Message{Type: TypeError, Peer: p.address.String(), Error: fmt.Sprintf("peer %s: %v", p.address, err)})
			continue
		}
		log.Info("peer added", "address", p.address, "asn", p.asn, "passive", p.passive)
	}

	for {
		m, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch m.Type {
		case TypeAnnounce:
			err = s.announce(m)
		case TypeWithdraw:
			err = s.withdraw(m)
		case TypeStart:
			err = errors.New("BGP runs already: start comes once")
		default:
			err = fmt.Errorf("unknown message type %q", m.Type)
		}
		if err != nil {
			log.Warn("message not applied", "type", m.Type, "prefix", m.Prefix, "err", err)
			s.send(Message{Type: TypeError, Prefix: m.Prefix, Error: err.Error()})
		}
	}
}

// parseStart checks the settings of a start message.
func parseStart(m Message) (config, error) {
	var cfg config
	if m.ASN == 0 {
		return cfg, errors.New("start: asn is missing")
	}
	cfg.asn = m.ASN
	id, err := netip.ParseAddr(m.RouterID)
	if err != nil || !id.Is4() {
		return cfg, fmt.Errorf("start: router_id %q is not an IPv4 address", m.RouterID)
	}
	cfg.routerID = id
	switch {
	case m.ListenPort == 0:
		cfg.listenPort = defaultBGPPort
	case m.ListenPort == -1 || (m.ListenPort > 0 && m.ListenPort <= 65535):
		cfg.listenPort = m.ListenPort
	default:
		return cfg, fmt.Errorf("start: listen_port %d is not a TCP port, 0 or -1", m.ListenPort)
	}
	for _, a := range m.ListenAddresses {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return cfg, fmt.Errorf("start: listen address %q: %v", a, err)
		}
		cfg.listenAddresses = append(cfg.listenAddresses, addr.String())
	}
	if len(m.Peers) == 0 {
		return cfg, errors.New("start: no peers")
	}
	seen := make(map[netip.Addr]bool)
	for _, p := range m.Peers {
		addr, err := netip.ParseAddr(p.Address)
		if err != nil {
			return cfg, fmt.Errorf("start: peer address %q: %v", p.Address, err)
		}
		if seen[addr] {
			return cfg, fmt.Errorf("start: peer %s comes twice", addr)
		}
		seen[addr] = true
		if p.ASN == 0 {
			return cfg, fmt.Errorf("start: peer %s has no asn", addr)
		}
		if p.Port > 65535 {
			return cfg, fmt.Errorf("start: peer %s: port %d is not a TCP port", addr, p.Port)
		}
		cfg.peers = append(cfg.peers, peerConfig{address: addr, asn: p.ASN, port: p.Port, passive: p.Passive})
	}
	for _, a := range m.Accept {
		prefix, err := parsePrefix(a)
		if err != nil {
			return cfg, fmt.Errorf("start: accept: %v", err)
		}
		cfg.accept = append(cfg.accept, prefix)
	}
	return cfg, nil
}

// parsePrefix parses an IPv4 or IPv6 prefix without host bits.
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("prefix %q: %v", s, err)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("prefix %q: an IPv4-mapped IPv6 prefix", s)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("prefix %q has host bits set (%s)", s, p.Masked())
	}
	return p, nil
}

// startSession starts GoBGP with cfg, without its peers: the global settings, the policies and
// the watch of the best paths and the peers.
func startSession(ctx context.Context, cfg config, w *Writer, log *slog.Logger, level *slog.LevelVar) (*session, error) {
	b := server.NewBgpServer(server.LoggerOption(log, level))
	go b.Serve()

	sctx, cancel := context.WithCancel(context.Background())
	s := &session{
		bgp:       b,
		w:         w,
		log:       log,
		cancel:    cancel,
		announced: make(map[netip.Prefix]uuid.UUID),
		learned:   make(map[netip.Prefix]learnedRoute),
	}

	err := b.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             cfg.asn,
		RouterId:        cfg.routerID.String(),
		ListenPort:      cfg.listenPort,
		ListenAddresses: cfg.listenAddresses,
	}})
	if err == nil {
		err = s.setPolicies(ctx, cfg.accept)
	}
	if err == nil {
		err = b.WatchEvent(sctx, server.WatchEventMessageCallbacks{
			OnBestPath:   s.onBestPath,
			OnPeerUpdate: s.onPeer,
		}, server.WatchBestPath(true), server.WatchPeer())
	}
	if err != nil {
		s.stop()
		return nil, fmt.Errorf("BGP did not start: %w", err)
	}
	return s, nil
}

// stop stops the watch and BGP, which sends a Cease notification to every peer.
func (s *session) stop() {
	s.cancel()
	s.bgp.Stop()
}

// setPolicies sets the filters of both sides: the peers get the node's own prefixes only, so the
// node never carries traffic from one router of the operator to another, and the sidecar takes
// from the peers only what accept covers. GoBGP applies the import policy of the global RIB to the
// node's own paths too, so its first statement takes them.
func (s *session) setPolicies(ctx context.Context, accept []netip.Prefix) error {
	accepted := api.RouteAction_ROUTE_ACTION_ACCEPT
	rejected := api.RouteAction_ROUTE_ACTION_REJECT

	err := s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: exportPolicy,
		Statements: []*api.Statement{{
			Name:       exportLocal,
			Conditions: &api.Conditions{RouteType: api.Conditions_ROUTE_TYPE_LOCAL},
			Actions:    &api.Actions{RouteAction: accepted},
		}},
	}})
	if err != nil {
		return err
	}
	err = s.bgp.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          globalRIB,
		Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
		Policies:      []*api.Policy{{Name: exportPolicy}},
		DefaultAction: rejected,
	}})
	if err != nil {
		return err
	}

	// A prefix set holds one address family: one set and one statement for each.
	var v4, v6 []*api.Prefix
	for _, p := range accept {
		e := &api.Prefix{
			IpPrefix:      p.String(),
			MaskLengthMin: uint32(p.Bits()),
			MaskLengthMax: uint32(p.Addr().BitLen()),
		}
		if p.Addr().Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	sets := []struct {
		set, statement string
		prefixes       []*api.Prefix
	}{
		{acceptSetV4, acceptStmtV4, v4},
		{acceptSetV6, acceptStmtV6, v6},
	}
	statements := []*api.Statement{{
		Name:       importLocal,
		Conditions: &api.Conditions{RouteType: api.Conditions_ROUTE_TYPE_LOCAL},
		Actions:    &api.Actions{RouteAction: accepted},
	}}
	for _, set := range sets {
		if len(set.prefixes) == 0 {
			continue
		}
		err := s.bgp.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        set.set,
			Prefixes:    set.prefixes,
		}})
		if err != nil {
			return err
		}
		statements = append(statements, &api.Statement{
			Name:       set.statement,
			Conditions: &api.Conditions{PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: set.set}},
			Actions:    &api.Actions{RouteAction: accepted},
		})
	}
	err = s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{Name: importPolicy, Statements: statements}})
	if err != nil {
		return err
	}
	return s.bgp.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          globalRIB,
		Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		Policies:      []*api.Policy{{Name: importPolicy}},
		DefaultAction: rejected,
	}})
}

// peerRequest is the GoBGP peer of a router of the operator, with IPv4 and IPv6 unicast.
func peerRequest(p peerConfig) *api.Peer {
	return &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.address.String(),
			PeerAsn:         p.asn,
		},
		Transport: &api.Transport{
			PassiveMode: p.passive,
			RemotePort:  p.port,
		},
		AfiSafis: []*api.AfiSafi{unicast(api.Family_AFI_IP), unicast(api.Family_AFI_IP6)},
	}
}

func unicast(afi api.Family_Afi) *api.AfiSafi {
	return &api.AfiSafi{Config: &api.AfiSafiConfig{
		Family:  &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST},
		Enabled: true,
	}}
}

// send writes a message to the node; a node that went away ends the read loop, so the error is
// only logged.
func (s *session) send(m Message) {
	if err := s.w.Write(m); err != nil {
		s.log.Warn("message to the node not sent", "type", m.Type, "err", err)
	}
}

// announce applies an announce message: the prefix goes to the peers as a path of the node.
func (s *session) announce(m Message) error {
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	family := bgp.RF_IPv4_UC
	nextHop := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
		nextHop = netip.IPv6Unspecified()
	}
	// An unspecified next hop becomes the address of each session (GoBGP's next-hop-self).
	if m.NextHop != "" {
		nextHop, err = netip.ParseAddr(m.NextHop)
		if err != nil {
			return fmt.Errorf("next hop %q: %v", m.NextHop, err)
		}
		if nextHop.Is4() != prefix.Addr().Is4() {
			return fmt.Errorf("next hop %s is not of the address family of %s", nextHop, prefix)
		}
	}
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return err
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)}
	if family == bgp.RF_IPv4_UC {
		a, err := bgp.NewPathAttributeNextHop(nextHop)
		if err != nil {
			return err
		}
		attrs = append(attrs, a)
	} else {
		a, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return err
		}
		attrs = append(attrs, a)
	}
	resp, err := s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: family,
		Nlri:   nlri,
		Attrs:  attrs,
		Age:    time.Now().Unix(),
	}}})
	if err != nil {
		return err
	}
	// A prefix announced again replaces its path, under a new UUID.
	s.announced[prefix] = resp[0].UUID
	s.log.Info("prefix announced", "prefix", prefix, "nextHop", nextHop)
	return nil
}

// withdraw applies a withdraw message.
func (s *session) withdraw(m Message) error {
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	id, ok := s.announced[prefix]
	if !ok {
		return fmt.Errorf("prefix %s is not announced", prefix)
	}
	if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return err
	}
	delete(s.announced, prefix)
	s.log.Info("prefix withdrawn", "prefix", prefix)
	return nil
}

// onPeer tells the node about a session state of a peer.
func (s *session) onPeer(ev *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
	if ev.Type != apiutil.PEER_EVENT_STATE {
		return
	}
	state, ok := stateNames[ev.Peer.State.SessionState]
	if !ok {
		return
	}
	addr := ev.Peer.Conf.NeighborAddress.String()
	s.log.Info("peer state", "peer", addr, "state", state)
	s.send(Message{Type: TypePeer, Peer: addr, ASN: ev.Peer.Conf.PeerASN, State: state})
}

// onBestPath tells the node about the best paths that changed: a best path learned from a peer
// is a learned route, and a prefix whose best path is withdrawn, or is now the node's own, is
// withdrawn. The paths of one call are applied in order, so a best path that moves from one
// peer to another ends as the later one, without a withdrawn message between.
func (s *session) onBestPath(paths []*apiutil.Path, _ time.Time) {
	next := make(map[netip.Prefix]*learnedRoute)
	var order []netip.Prefix
	for _, p := range paths {
		n, ok := p.Nlri.(*bgp.IPAddrPrefix)
		if !ok || (p.Family != bgp.RF_IPv4_UC && p.Family != bgp.RF_IPv6_UC) {
			continue
		}
		prefix := n.Prefix
		if _, ok := next[prefix]; !ok {
			order = append(order, prefix)
		}
		if p.Withdrawal || !p.PeerAddress.IsValid() {
			next[prefix] = nil
			continue
		}
		nh := pathNextHop(p)
		if !nh.IsValid() {
			s.log.Warn("learned path without a next hop", "prefix", prefix, "peer", p.PeerAddress)
			next[prefix] = nil
			continue
		}
		next[prefix] = &learnedRoute{nextHop: nh.String(), peer: p.PeerAddress.String()}
	}
	for _, prefix := range order {
		old, had := s.learned[prefix]
		r := next[prefix]
		switch {
		case r == nil && had:
			delete(s.learned, prefix)
			s.send(Message{Type: TypeWithdrawn, Prefix: prefix.String(), Peer: old.peer})
		case r != nil && (!had || old != *r):
			s.learned[prefix] = *r
			s.send(Message{Type: TypeLearned, Prefix: prefix.String(), NextHop: r.nextHop, Peer: r.peer})
		}
	}
}

// pathNextHop is the next hop of a unicast path: its NEXT_HOP, or the next hop of its
// MP_REACH_NLRI.
func pathNextHop(p *apiutil.Path) netip.Addr {
	for _, a := range p.Attrs {
		switch a := a.(type) {
		case *bgp.PathAttributeNextHop:
			return a.Value
		case *bgp.PathAttributeMpReachNLRI:
			return a.Nexthop
		}
	}
	return netip.Addr{}
}
