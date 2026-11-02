package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"sync"
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

	// started, when set, gets GoBGP once BGP runs, before ready; the tests look into its RIB.
	started func(*server.BgpServer)
}

// Version names ranz bgp, the program that runs the sidecar, and the GoBGP it embeds.
func Version() string {
	v := "ranz bgp"
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
	// address is the node's own address in the peering of the standard mode (peering.go), the zero
	// Addr for a sidecar that peers with the routers of the operator
	address netip.Addr
}

type peerConfig struct {
	address netip.Addr
	asn     uint32
	port    uint32
	passive bool
	// holdTime and vrfs are of a Ranz node in the peering of the standard mode: the BGP hold time in
	// seconds, 0 for the default, and the prefixes that it may announce in each VRF that it shares
	// with the node, by VRF id; vrfs is nil for a router of the operator
	holdTime uint32
	vrfs     map[uint32][]netip.Prefix
	// roles is the role of the peer in each of those VRFs whose nodes peer through route reflectors
	// (reflector.go), by VRF id; a VRF of a full mesh has none
	roles map[uint32]string
}

// learnedRoute is the route of a learned prefix that the node was told about.
type learnedRoute struct {
	nextHop string
	peer    string
}

// session is BGP for one node.
type session struct {
	bgp *server.BgpServer
	// The EVPN of a gateway (evpn.go; SDN-25 #201), nil for none
	evpn *evpnState
	// The route reflector of the peering of the standard mode (reflector.go; SDN-79 #359), nil outside the peering
	reflector *reflector
	w         *Writer
	log       *slog.Logger
	cancel    context.CancelFunc
	address   netip.Addr                // the node's own address in the peering of the standard mode, as in config
	announced map[routeKey]uuid.UUID    // the read loop only
	pending   []Peer                    // the read loop only: the peers of the peers messages with more so far
	learned   map[routeKey]learnedRoute // the watch goroutine, and in the peering the routes goroutine (peerfilter.go)

	// The Ranz nodes among the peers in the peering of the standard mode, by address, which the read
	// loop sets and the watch goroutine reads (peering.go)
	mu    sync.Mutex
	nodes map[netip.Addr]peerConfig

	// The filters of the peering (peerfilter.go): the generation of the last import policy and what it holds in GoBGP, both the
	// read loop's; the channel that kicks the routes goroutine, nil outside the peering; the peers whose session GoBGP closed
	// for the number of their paths, the watch goroutine's; and the paths that the last read of the table did not take, the
	// routes goroutine's
	generation uint32
	imported   *importState
	resync     chan struct{}
	capped     map[netip.Addr]bool
	notTaken   int
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
	// The EVPN of a gateway (evpn.go; SDN-25 #201), whose peers are the routers of a fabric, not Ranz nodes
	ev, err := parseEVPN(first.EVPN, cfg.routerID)
	if err == nil && ev != nil && cfg.address.IsValid() {
		err = errors.New("start: evpn is of a gateway, whose peers are the routers of a fabric, and an address runs the peering of the standard mode with Ranz nodes: a start has one of them")
	}
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
	// ... before the peers, which take its family
	if err := s.startEVPN(ctx, ev); err != nil {
		w.Write(Message{Type: TypeError, Error: err.Error()})
		return err
	}
	if opts.started != nil {
		opts.started(s.bgp)
	}

	if err := w.Write(Message{Type: TypeReady, Version: Version(), Protocol: ProtocolVersion}); err != nil {
		return err
	}
	log.Info("BGP started", "asn", cfg.asn, "routerID", cfg.routerID, "listenPort", cfg.listenPort, "peers", len(cfg.peers), "accept", len(cfg.accept))

	// The peers come after ready, so that the node reads ready before the first peer message.
	for _, p := range cfg.peers {
		if err := s.bgp.AddPeer(ctx, &api.AddPeerRequest{Peer: s.withEVPN(s.peerRequest(p))}); err != nil {
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
		case TypePeers:
			err = s.setPeers(ctx, m)
		case TypePing:
			err = s.ping(ctx)
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
	// The node's own address in the peering of the standard mode (peering.go)
	if m.Address != "" {
		addr, err := parsePeeringAddress(m)
		if err != nil {
			return cfg, err
		}
		cfg.address = addr
	}
	for _, a := range m.ListenAddresses {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return cfg, fmt.Errorf("start: listen address %q: %v", a, err)
		}
		cfg.listenAddresses = append(cfg.listenAddresses, addr.String())
	}
	// A node of the peering of the standard mode may be alone in its VRFs for now: a peers message brings its peers
	if len(m.Peers) == 0 && !cfg.address.IsValid() {
		return cfg, errors.New("start: no peers")
	}
	seen := make(map[netip.Addr]bool)
	for _, p := range m.Peers {
		pc, err := parsePeer(p, cfg.address)
		if err != nil {
			return cfg, fmt.Errorf("start: %w", err)
		}
		if seen[pc.address] {
			return cfg, fmt.Errorf("start: peer %s comes twice", pc.address)
		}
		// The roles of the route reflector come with the peers messages, which set its export policy first (reflector.go)
		if len(pc.roles) > 0 {
			return cfg, fmt.Errorf("start: peer %s has roles of a route reflector, which only a peers message gives", pc.address)
		}
		seen[pc.address] = true
		cfg.peers = append(cfg.peers, pc)
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
	sctx, cancel := context.WithCancel(context.Background())
	s := &session{
		w:         w,
		log:       log,
		cancel:    cancel,
		address:   cfg.address,
		announced: make(map[routeKey]uuid.UUID),
		learned:   make(map[routeKey]learnedRoute),
		nodes:     make(map[netip.Addr]peerConfig),
		capped:    make(map[netip.Addr]bool),
	}
	if cfg.address.IsValid() {
		s.resync = make(chan struct{}, 1)
	}
	for _, p := range cfg.peers {
		if p.vrfs != nil {
			s.nodes[p.address] = p
		}
	}

	// GoBGP logs into the log of the sidecar, and a session that it refuses goes to the node too (peering.go)
	b := server.NewBgpServer(server.LoggerOption(slog.New(refusalHandler{Handler: log.Handler(), refused: s.refused}), level))
	s.bgp = b
	go b.Serve()

	// The peering of the standard mode listens on the node's own address only
	listen := cfg.listenAddresses
	if cfg.address.IsValid() {
		listen = []string{cfg.address.String()}
	}
	err := b.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             cfg.asn,
		RouterId:        cfg.routerID.String(),
		ListenPort:      cfg.listenPort,
		ListenAddresses: listen,
	}})
	// The route reflector of the peering of the standard mode (reflector.go; SDN-79 #359)
	if err == nil && cfg.address.IsValid() {
		err = s.startReflector(sctx, cfg.asn, cfg.routerID)
	}
	if err == nil {
		err = s.setPolicies(ctx, cfg.accept)
	}
	if err == nil {
		callbacks := server.WatchEventMessageCallbacks{OnBestPath: s.onBestPath, OnPeerUpdate: s.onPeer}
		opts := []server.WatchOption{server.WatchBestPath(true), server.WatchPeer()}
		if s.resync != nil {
			// The peering reads the table whenever a path that the import policy took changes, besides the best paths and the
			// sessions (peerfilter.go)
			callbacks.OnPathUpdate = s.onUpdate
			opts = append(opts, server.WatchPostUpdate(false, "", ""))
			go s.watchRoutes(sctx)
		}
		err = b.WatchEvent(sctx, callbacks, opts...)
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

	// The peering of the standard mode takes the paths of each Ranz node whose exact prefix its accept lists hold, and
	// reports to the node only the ones that the peer may announce in the VRF of the path (setImport, syncRoutes and accepts in
	// peerfilter.go and peering.go; SDN-77-R3 #570)
	if s.address.IsValid() {
		return s.setImport(ctx, s.nodes)
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

// peerRequest is the GoBGP peer of a router of the operator, with IPv4 and IPv6 unicast, or of a Ranz
// node in the peering of the standard mode (nodePeer in peering.go).
func (s *session) peerRequest(p peerConfig) *api.Peer {
	if p.vrfs != nil {
		// ... with its roles in the VRFs of a route reflector (reflector.go)
		return s.reflectorPeer(nodePeer(p, s.address), p)
	}
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

// ping answers the node that the sidecar runs: pong, once GoBGP answered a question too, so that a
// sidecar whose BGP hangs answers nothing and the node ends it (SDN-77-R1 #531).
func (s *session) ping(ctx context.Context) error {
	if _, err := s.bgp.GetBgp(ctx, &api.GetBgpRequest{}); err != nil {
		return fmt.Errorf("ping: GoBGP does not answer: %w", err)
	}
	s.send(Message{Type: TypePong})
	return nil
}

// announce applies an announce message: the prefix goes to the peers as a path of the node, a
// unicast path, or a VPN path of its VRF in the peering of the standard mode.
func (s *session) announce(m Message) error {
	// A prefix of an EVPN VRF goes to the fabric as an IP prefix route, one of another VRF nowhere (evpn.go; SDN-25 #201)
	if m.VRF != 0 && s.evpn != nil {
		return s.announceEVPN(m)
	}
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	var path *apiutil.Path
	switch {
	case m.VRF != 0:
		path, err = s.vpnPath(m.VRF, prefix, m.NextHop)
	case s.address.IsValid():
		err = fmt.Errorf("prefix %s: an announce of the peering of the standard mode names its vrf", prefix)
	default:
		path, err = unicastPath(prefix, m.NextHop)
	}
	if err != nil {
		return err
	}
	resp, err := s.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	if err != nil {
		return err
	}
	// A prefix announced again replaces its path, under a new UUID.
	s.announced[routeKey{vrf: m.VRF, prefix: prefix}] = resp[0].UUID
	s.log.Info("prefix announced", "vrf", m.VRF, "prefix", prefix, "nextHop", pathNextHop(path))
	// A prefix that the node announces is none that it learns (peerfilter.go)
	s.kick()
	return nil
}

// unicastPath is the unicast path of an announce message without a VRF: prefix via next, the address
// of each session when it is empty (GoBGP's next-hop-self).
func unicastPath(prefix netip.Prefix, next string) (*apiutil.Path, error) {
	family := bgp.RF_IPv4_UC
	nextHop := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
		nextHop = netip.IPv6Unspecified()
	}
	if next != "" {
		var err error
		nextHop, err = netip.ParseAddr(next)
		if err != nil {
			return nil, fmt.Errorf("next hop %q: %v", next, err)
		}
		if nextHop.Is4() != prefix.Addr().Is4() {
			return nil, fmt.Errorf("next hop %s is not of the address family of %s", nextHop, prefix)
		}
	}
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, err
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)}
	if family == bgp.RF_IPv4_UC {
		a, err := bgp.NewPathAttributeNextHop(nextHop)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	} else {
		a, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs, Age: time.Now().Unix()}, nil
}

// withdraw applies a withdraw message.
func (s *session) withdraw(m Message) error {
	// ... and leaves it (evpn.go)
	if m.VRF != 0 && s.evpn != nil {
		return s.withdrawEVPN(m)
	}
	prefix, err := parsePrefix(m.Prefix)
	if err != nil {
		return err
	}
	key := routeKey{vrf: m.VRF, prefix: prefix}
	id, ok := s.announced[key]
	if !ok {
		if m.VRF != 0 {
			return fmt.Errorf("prefix %s is not announced in VRF %d", prefix, m.VRF)
		}
		return fmt.Errorf("prefix %s is not announced", prefix)
	}
	if err := s.bgp.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return err
	}
	delete(s.announced, key)
	s.log.Info("prefix withdrawn", "vrf", m.VRF, "prefix", prefix)
	s.kick()
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
	s.noteCapped(ev.Peer)
	s.send(Message{Type: TypePeer, Peer: addr, ASN: ev.Peer.Conf.PeerASN, State: state})
	// The routes of a session that ended go, and those of one that came may arrive (peerfilter.go)
	s.kick()
}

// onBestPath tells the node about the best paths that changed: a best path learned from a peer
// is a learned route, and a prefix whose best path is withdrawn, or is now the node's own, is
// withdrawn. The paths of one call are applied in order, so a best path that moves from one
// peer to another ends as the later one, without a withdrawn message between. The peering of the
// standard mode does not take the best path: it may be one that its peer may not announce, so
// the routes goroutine reads the table itself (syncRoutes in peerfilter.go), and a best path only
// asks it to.
func (s *session) onBestPath(paths []*apiutil.Path, _ time.Time) {
	if s.resync != nil {
		s.kick()
		return
	}
	next := make(map[routeKey]*learnedRoute)
	var order []routeKey
	for _, p := range paths {
		key, ok := pathKey(p)
		if !ok {
			continue
		}
		if _, ok := next[key]; !ok {
			order = append(order, key)
		}
		if p.Withdrawal || !p.PeerAddress.IsValid() {
			next[key] = nil
			continue
		}
		nh := pathNextHop(p)
		if !nh.IsValid() {
			s.log.Warn("learned path without a next hop", "vrf", key.vrf, "prefix", key.prefix, "peer", p.PeerAddress)
			next[key] = nil
			continue
		}
		next[key] = &learnedRoute{nextHop: nh.String(), peer: p.PeerAddress.Unmap().String()}
	}
	for _, key := range order {
		old, had := s.learned[key]
		r := next[key]
		switch {
		case r == nil && had:
			delete(s.learned, key)
			s.send(Message{Type: TypeWithdrawn, VRF: key.vrf, Prefix: key.prefix.String(), Peer: old.peer})
		case r != nil && (!had || old != *r):
			s.learned[key] = *r
			s.send(Message{Type: TypeLearned, VRF: key.vrf, Prefix: key.prefix.String(), NextHop: r.nextHop, Peer: r.peer})
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
