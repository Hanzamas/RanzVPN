package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// The tray without its window (SDN-55, #248): what it asks the Node service on the pipe of the logged-in
// user, what it shows for each answer, and the sign-in that it runs for the user. The window of the
// tray (trayui_windows.go) shows a trayView and sends the actions below; `ranz tray status`, `login`,
// `up`, `down` and `exit` run the same code with no window, which is also how the tests and the
// tracer of the CI drive it.

// clientPipe is the pipe of the logged-in user of the Node service as the tray reaches it: one command
// line, and the one JSON line of the answer. The Node answers status, up, down, exit, key and enrol
// (NodeClient.c).
type clientPipe interface {
	ask(command string) ([]byte, error)
}

// The errors of the pipe that the tray tells the user in words
var (
	errClientPipeMissing = errors.New("the pipe of the logged-in user of the Node service is not there")
	errClientPipeDenied  = errors.New("this account may not open the pipe of the logged-in user of the Node service")
)

// nodeRefusal is the reason that the Node service gave for a command that it refused
type nodeRefusal string

func (e nodeRefusal) Error() string { return string(e) }

// serviceState is what the Service Control Manager says of the Node service
type serviceState int

const (
	serviceUnknown  serviceState = iota // it could not be asked
	serviceMissing                      // no service of that name: Ranz is not installed
	serviceStopped                      // it is stopped or stopping
	serviceStarting                     // it is starting
	serviceRunning                      // it runs
)

// trayRestartGrace is how long a pipe that is not there counts as a service that starts or restarts, from the
// start of the tray and from the last answer of the pipe: a sign-in makes the Node join its Controller
// with a restart of its client role
const trayRestartGrace = 20 * time.Second

// clientStatus is the answer of the Node service to status, up, down and exit: the status of its client
// role as one JSON object (NodeClientStatusJson of NodeClient.c). A field that an older Node leaves out
// is its zero value. Error is the reason of a command that the Node refused.
type clientStatus struct {
	State      string            `json:"state"` // connected, connecting, down or asleep
	Transport  string            `json:"transport"`
	Peers      int               `json:"peers"`
	Sessions   int               `json:"sessions"`
	Addresses  []string          `json:"addresses"`
	Name       string            `json:"name"` // the Node resource of this PC, once the Controller sent its state
	Controller *clientController `json:"controller"`
	Exit       *clientExit       `json:"exit"` // the exit node that the user chose, null for none
	Exits      []clientExit      `json:"exits"`
	Error      string            `json:"error"`
}

// clientController is what the Node has of its Controller: the Controller settings and the control
// stream
type clientController struct {
	Set            bool   `json:"set"`
	Address        string `json:"address"`
	PublicKey      string `json:"publicKey"`
	TLSFingerprint string `json:"tlsFingerprint"`
	Connected      bool   `json:"connected"`
	Generation     uint64 `json:"generation"`
	Why            string `json:"why"`
}

// clientExit is an exit node: a peer that has the default route of a VRF, which the Node lists, and the
// one that the user chose. Active says that the default routes of both families go through the adapter
// of its VRF, and Available that the peer holds the default route still.
type clientExit struct {
	Name      string `json:"name"`
	VRF       uint32 `json:"vrf"`
	VRFName   string `json:"vrfName"`
	IPv4      bool   `json:"ipv4"`
	IPv6      bool   `json:"ipv6"`
	Active    bool   `json:"active"`
	Available bool   `json:"available"`
}

// trayExit is an exit node in the menu of the tray
type trayExit struct {
	Name   string
	VRF    uint32
	Label  string // what the menu says
	Chosen bool
}

// trayView is what the tray shows for one answer of the Node service: its icon, its tooltip, the lines at the
// top of its menu and the items below them
type trayView struct {
	Kind       trayKind
	Title      string   // the first line of the menu, in the tooltip too
	Detail     []string // the lines under it
	SignIn     string   // the words of the sign-in item, "" for none
	Toggle     string   // up or down, the command of the item that turns Ranz on or off, "" for no item
	ToggleText string   // the words of that item
	ExitMenu   bool     // the menu has the exit nodes
	Exits      []trayExit
	Reachable  bool // the Node service answered
}

// tooltip is the text of the icon: the name of the product and the title of the view
func (v trayView) tooltip() string {
	return trayText("title") + ": " + v.Title
}

// trayApp is the tray without its window: the pipe of the logged-in user, the Service Control Manager and the
// settings of the sign-in
type trayApp struct {
	pipe          clientPipe
	service       func() serviceState
	server        string // the Controller to sign in at, "" for the one of the settings of the Node
	fingerprint   string // the TLS fingerprint that the certificate of that Controller has, "" for the one of the Node's settings
	controllerDir string // the data directory of the Controller of this host, for the check of a loopback address

	mu       sync.Mutex
	started  time.Time // when the tray started
	lastGood time.Time // when the pipe answered last
	signing  bool      // a sign-in runs
}

// newTrayApp returns the tray that asks pipe, and the Service Control Manager through service, which may
// be nil
func newTrayApp(pipe clientPipe, service func() serviceState) *trayApp {
	if service == nil {
		service = func() serviceState { return serviceUnknown }
	}
	return &trayApp{pipe: pipe, service: service, started: time.Now()}
}

// ask sends command to the Node service and decodes its answer into out
func (a *trayApp) ask(command string, out any) error {
	b, err := a.pipe.ask(command)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.lastGood = time.Now()
	a.mu.Unlock()
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the Node service answered something that is not JSON: %w", err)
	}
	return nil
}

// command sends one of status, up, down and exit, and returns the status that the Node answers; the
// reason of a command that it refused is a nodeRefusal
func (a *trayApp) command(line string) (clientStatus, error) {
	var st clientStatus
	if err := a.ask(line, &st); err != nil {
		return clientStatus{}, err
	}
	if st.Error != "" {
		return st, nodeRefusal(st.Error)
	}
	return st, nil
}

// refresh asks for the status and returns what the tray shows for it
func (a *trayApp) refresh() trayView {
	st, err := a.command("status")
	v := a.viewOf(st, err)
	if a.isSigning() && v.Reachable {
		v.Kind, v.Title, v.Detail = trayAmber, trayText("signingin"), []string{trayText("signingin.how")}
		v.SignIn = ""
	}
	return v
}

// viewOf returns what the tray shows for the answer st of the Node service, or for err, the reason that it gave none
func (a *trayApp) viewOf(st clientStatus, err error) trayView {
	switch {
	case err == nil:
		return statusView(st)
	case errors.Is(err, errClientPipeMissing):
		return a.missingView()
	case errors.Is(err, errClientPipeDenied):
		return trayView{Kind: trayRed, Title: trayText("denied")}
	}
	return trayView{Kind: trayRed, Title: trayText("unreadable", err.Error())}
}

// missingView is what the tray shows while the pipe of the Node service is not there: why not, as far as the
// Service Control Manager tells
func (a *trayApp) missingView() trayView {
	a.mu.Lock()
	since := a.lastGood
	if since.Before(a.started) {
		since = a.started
	}
	a.mu.Unlock()
	switch a.service() {
	case serviceMissing:
		return trayView{Kind: trayGrey, Title: trayText("notinstalled")}
	case serviceStopped:
		return trayView{Kind: trayRed, Title: trayText("stopped"), Detail: []string{trayText("stopped.how", install.NodeServiceName)}}
	case serviceStarting:
		return trayView{Kind: trayAmber, Title: trayText("starting")}
	case serviceRunning:
		if time.Since(since) < trayRestartGrace {
			return trayView{Kind: trayAmber, Title: trayText("starting")}
		}
		return trayView{Kind: trayRed, Title: trayText("noclient"), Detail: []string{trayText("noclient.how")}}
	}
	return trayView{Kind: trayRed, Title: trayText("unknown")}
}

// statusView is what the tray shows for the status st of the client role
func statusView(st clientStatus) trayView {
	v := trayView{Reachable: true, ExitMenu: true, Exits: exitsOf(st)}
	c := st.Controller
	switch {
	case c == nil || !c.Set:
		v.Kind, v.Title, v.Detail = trayGrey, trayText("nocontroller"), []string{trayText("nocontroller.how")}
		v.SignIn = trayText("signin")
		v.ExitMenu, v.Exits = false, nil
		return v
	case st.State == "down":
		v.Kind, v.Title = trayGrey, trayText("off")
		v.Toggle, v.ToggleText = "up", trayText("turnon")
	case st.State == "asleep":
		v.Kind, v.Title = trayGrey, trayText("asleep")
	case st.State == "connected":
		v.Kind, v.Title = trayGreen, trayText("connected")
		v.Toggle, v.ToggleText = "down", trayText("turnoff")
	default:
		v.Kind, v.Title = trayAmber, trayText("connecting")
		v.Toggle, v.ToggleText = "down", trayText("turnoff")
		if !c.Connected && c.Why != "" {
			v.Detail = append(v.Detail, trayText("controller.why", c.Why))
		}
	}
	v.SignIn = trayText("signinagain")
	if st.Name != "" {
		v.Detail = append(v.Detail, trayText("as", st.Name))
	}
	if len(st.Addresses) > 0 {
		v.Detail = append(v.Detail, trayText("addresses", strings.Join(st.Addresses, ", ")))
	}
	if st.State == "connected" && st.Transport != "" {
		v.Detail = append(v.Detail, trayText("over", st.Transport))
	}
	if st.Exit != nil {
		v.Detail = append(v.Detail, trayText("exitnode", st.Exit.Name))
	}
	return v
}

// exitsOf is the exit nodes of the menu for the status st: each that the Node lists, which holds the default
// route of its VRF, and the one that the user chose when the Node lists it no more, marked as not available. A
// name that more than one entry has shows its VRF too, and an exit that carries no IPv6 says so.
func exitsOf(st clientStatus) []trayExit {
	list := append([]clientExit(nil), st.Exits...)
	for i := range list {
		list[i].Available = true
	}
	if st.Exit != nil && !slices.ContainsFunc(list, st.Exit.sameAs) {
		gone := *st.Exit
		gone.Available = false
		list = append(list, gone)
	}
	out := make([]trayExit, 0, len(list))
	for _, e := range list {
		var notes []string
		if slices.ContainsFunc(list, func(other clientExit) bool { return other.Name == e.Name && other.VRF != e.VRF }) {
			notes = append(notes, e.vrfLabel())
		}
		if e.Available && !e.IPv6 {
			notes = append(notes, trayText("ipv4only"))
		}
		if !e.Available {
			notes = append(notes, trayText("notavailable"))
		}
		label := e.Name
		if len(notes) > 0 {
			label += " (" + strings.Join(notes, ", ") + ")"
		}
		out = append(out, trayExit{Name: e.Name, VRF: e.VRF, Label: label, Chosen: st.Exit != nil && st.Exit.sameAs(e)})
	}
	return out
}

// sameAs reports whether other is the same exit as e: the same peer in the same VRF
func (e clientExit) sameAs(other clientExit) bool {
	return e.Name == other.Name && e.VRF == other.VRF
}

// vrfLabel is the VRF of an exit as the menu names it: its name, or its id when the Node sent none
func (e clientExit) vrfLabel() string {
	if e.VRFName != "" {
		return e.VRFName
	}
	return "VRF " + strconv.FormatUint(uint64(e.VRF), 10)
}

// isSigning reports whether a sign-in runs
func (a *trayApp) isSigning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signing
}

// beginSignIn marks a sign-in as running, and reports false when one runs already
func (a *trayApp) beginSignIn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signing {
		return false
	}
	a.signing = true
	return true
}

// endSignIn marks the sign-in as over
func (a *trayApp) endSignIn() {
	a.mu.Lock()
	a.signing = false
	a.mu.Unlock()
}

// chooseExit sends the exit command for the exit node e, or for none when e is nil, and returns the status that
// the Node answers
func (a *trayApp) chooseExit(e *trayExit) (clientStatus, error) {
	if e == nil {
		return a.command("exit none")
	}
	return a.command("exit " + e.Name + " " + strconv.FormatUint(uint64(e.VRF), 10))
}

// trayLogin is what a sign-in gave: the User, the Node resource of this PC, and whether the Node took new Controller
// settings (a Node that is enrolled has them already)
type trayLogin struct {
	User    string
	Node    string
	Changed bool
}

// message is the words that tell the user how the sign-in went
func (l trayLogin) message() string {
	if l.Changed {
		return trayText("signedin", l.User, l.Node)
	}
	return trayText("signedin.same", l.User, l.Node)
}

// enrolAnswer is the answer of the Node service to enrol: the Controller settings that it holds now, and whether
// this command gave it them
type enrolAnswer struct {
	Controller *nodeControllerSettings `json:"controller"`
	Changed    bool                    `json:"changed"`
	Error      string                  `json:"error"`
}

// loginTarget returns the Controller to sign in at and the TLS fingerprint to pin: the -server of the tray, else
// the Controller of the settings of the Node
func (a *trayApp) loginTarget(st clientStatus) (server, fingerprint string, err error) {
	switch {
	case a.server != "":
		return a.server, a.fingerprint, nil
	case st.Controller != nil && st.Controller.Set && st.Controller.Address != "":
		fingerprint = a.fingerprint
		if fingerprint == "" {
			fingerprint = st.Controller.TLSFingerprint
		}
		return "https://" + st.Controller.Address, fingerprint, nil
	}
	return "", "", errors.New(trayText("err.nocontroller"))
}

// signIn signs the user in at the Controller, in the browser or with a device code, enrolling this Node as a device of
// the user, and gives the Node the Controller settings that the login brought (enrol). What the user has to know
// goes to out, as it does for ranz login.
func (a *trayApp) signIn(ctx context.Context, device bool, out io.Writer) (trayLogin, error) {
	st, err := a.command("status")
	if err != nil {
		return trayLogin{}, err
	}
	server, fingerprint, err := a.loginTarget(st)
	if err != nil {
		return trayLogin{}, err
	}
	address, err := controlAddress(server)
	if err != nil {
		return trayLogin{}, err
	}
	var k nodeKeyAnswer
	if err := a.ask("key", &k); err != nil {
		return trayLogin{}, err
	}
	key, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if k.Error != "" || err != nil || len(key) != nodecontroller.KeySize {
		if k.Error != "" {
			return trayLogin{}, errors.New(trayText("err.key", k.Error))
		}
		return trayLogin{}, errors.New(trayText("err.keyshape", k.PublicKey))
	}
	lc, err := loginClient(server, fingerprint, a.controllerDir)
	if err != nil {
		return trayLogin{}, err
	}
	d := &login.Device{Key: key}
	var res login.Result
	if device {
		res, err = deviceLogin(ctx, lc, d, out)
	} else {
		res, err = browserLogin(ctx, lc, d, out)
	}
	if err != nil {
		return trayLogin{}, err
	}
	if res.Controller == nil {
		return trayLogin{}, errors.New(trayText("err.nokeys", res.Node))
	}
	pinned := res.Controller.TLSFingerprint
	if pinned == "" {
		pinned = fingerprint
	}
	s, err := nodecontroller.Parse(address, res.Controller.PublicKey, pinned)
	if err != nil {
		return trayLogin{}, errors.New(trayText("err.settings", res.Node, err))
	}
	var ans enrolAnswer
	if err := a.ask("enrol "+s.Address+" "+s.PublicKey+" "+s.TLSFingerprint, &ans); err != nil {
		return trayLogin{}, errors.New(trayText("err.enrol", res.Node, err))
	}
	if ans.Error != "" {
		return trayLogin{}, errors.New(trayText("err.refused", res.Node, ans.Error))
	}
	return trayLogin{User: res.User, Node: res.Node, Changed: ans.Changed}, nil
}
