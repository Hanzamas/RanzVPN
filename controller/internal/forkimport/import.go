package forkimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The mapping (ADR-0031 decision 11, SDN-27 #203). Each Virtual Hub is a VRF with one Network, both named after it, but for
// the name default, which the VRF and the Network of a first install have (ADR-0034): the Virtual Hub DEFAULT, which every
// server has, is VRF default-2, so that the import never replaces them. Every Virtual Hub of the file is named, the ones
// that an import does not take too, so a name is the same whichever hubs are taken. Each group of the hub is a Group,
// whose name is a tag of policy, and each user is a User that belongs to the Group of its group: the Node of a user carries
// the tags of its Groups (ADR-0031 amendment of 2026-10-25). The access list of the hub
// is the Policies of its VRF (access.go), and one more Policy lets through what no entry matches, as the fork does where
// the engine of a Node denies it. A user whom an entry names gets a Group of its own, the tag of that entry, unless the
// hub has a group of that name, which the user then joins: the fork matches the name of an entry against the user and
// the group of a session. The passwords are left out, as the SHA-0 hashes of the fork are left out of the import into the
// configuration store of a Node (ADR-0022 amendment of 2026-10-19): a User has none until an operator sets one.

// kindHub is the kind of the one name that the VRF and the Network of a Virtual Hub share, and that its rules start with.
const kindHub = "hub"

// ruleBase is how many characters of the name of a VRF start the names of its Policies, which end in the number of an
// entry and of a rule of it.
const ruleBase = 40

// expireOffset is what the fork subtracts from the milliseconds since 1970 of the time that it stores, 9 hours
// (TIME_ENCODE_OFFSET_MS of Kernel.c).
const expireOffset = 32400000

// maxExpire is the largest ExpireTime that stands for a year that an RFC 3339 time holds: 9999-12-31T23:59:59Z.
const maxExpire = 253402300799000 - expireOffset

// ErrNotConfig marks a tree that is no Config file of a server: it has no folder ServerConfiguration, which the start of
// the fork requires.
var ErrNotConfig = errors.New("the file is no Config file of a server: it has no folder ServerConfiguration")

// Options says which Virtual Hubs Import takes and how it makes their Networks.
type Options struct {
	// Hubs are the Virtual Hubs to take, by name without regard to case. The old server runs on until every Virtual Hub
	// has moved (ADR-0031 decision 11), so an operator moves them one at a time: the names of the resources are those that
	// the import of every Virtual Hub makes, so two imports of one file never make a name twice. Left out, every Virtual Hub.
	Hubs []string
	// Mode is the mode of the Networks, intent.ModeL3 or intent.ModeL2 in either case. Left out, intent.ModeL3.
	Mode string
	// Pools are the IPv4 pools of the Networks by name of the Virtual Hub, each a prefix such as 10.0.0.0/24. A Virtual
	// Hub of the fork has no pool, so a Network that Pools leaves out has none, and no Node gets an address in it until
	// the operator gives it one.
	Pools map[string]string
}

// Result is what Import makes of a Config file.
type Result struct {
	// Document holds, for each Virtual Hub, its VRF and Network, its Groups and Users, and its Policies. It applies to
	// an intent that has no resource of these names (intent.Apply).
	Document intent.Document
	// Hubs says what each Virtual Hub became, in the order of their names.
	Hubs []Hub
}

// Hub says what one Virtual Hub became.
type Hub struct {
	// Name is the Virtual Hub as the Config file has it, VRF and Network what it became.
	Name    string
	VRF     string
	Network string
	// Groups and Users count the Groups and the Users made for it, Entries the entries of its access list that the fork
	// loads, and Policies the Policies made of them, with the one that lets through what no entry matches.
	Groups   int
	Users    int
	Entries  int
	Policies int
	// Notes say what was left out and what was carried in another way, one line each.
	Notes []string
}

// Import turns the Virtual Hubs of the Config file root, which Parse returned, into an intent document. It fails for
// a tree that is no Config file of a server, a name of a Virtual Hub that the file does not have, a pool that is no
// IPv4 prefix and a mode that is none. Every document that it makes applies to an empty intent.
func Import(root *Folder, opts Options) (Result, error) {
	if root.Child("ServerConfiguration") == nil {
		return Result{}, ErrNotConfig
	}
	mode, err := opts.mode()
	if err != nil {
		return Result{}, err
	}
	hubs := root.Child("VirtualHUB").Sorted()
	chosen, err := opts.choose(hubs)
	if err != nil {
		return Result{}, err
	}
	pools, err := opts.pools(chosen)
	if err != nil {
		return Result{}, err
	}
	im := &importer{mode: mode, names: newNamer()}
	// The VRF and the Network of a first install and its starter rule are in the intent that the document applies to, and
	// the document must not replace them: the Virtual Hub DEFAULT, which every server has, is not VRF default
	im.names.reserve(kindHub, intent.DefaultVRF)
	im.names.reserve(kindHub, intent.DefaultNetwork)
	im.names.reserve(intent.KindPolicy, intent.StarterRule)
	var res Result
	// Every Virtual Hub is named, the ones that Options leaves out too, so that a name is the same whichever hubs an import
	// takes: hubs that move in several imports never make one name twice
	for _, f := range hubs {
		start := len(im.resources)
		hub := im.hub(f, pools[strings.ToLower(f.Name)])
		if !slices.Contains(chosen, f) {
			im.resources = im.resources[:start]
			continue
		}
		res.Hubs = append(res.Hubs, hub)
	}
	res.Document = intent.Document{Resources: im.resources}
	return res, nil
}

// mode returns the mode of the Networks.
func (o Options) mode() (string, error) {
	switch strings.ToUpper(o.Mode) {
	case "", intent.ModeL3:
		return intent.ModeL3, nil
	case intent.ModeL2:
		return intent.ModeL2, nil
	}
	return "", fmt.Errorf("the mode of a Network is %s or %s, not %q", intent.ModeL3, intent.ModeL2, o.Mode)
}

// choose returns the Virtual Hubs of hubs that o takes.
func (o Options) choose(hubs []*Folder) ([]*Folder, error) {
	if len(hubs) == 0 {
		return nil, errors.New("the Config file has no Virtual Hub")
	}
	if len(o.Hubs) == 0 {
		return hubs, nil
	}
	for _, name := range o.Hubs {
		if !slices.ContainsFunc(hubs, func(f *Folder) bool { return strings.EqualFold(f.Name, name) }) {
			return nil, fmt.Errorf("the Config file has no Virtual Hub %q", name)
		}
	}
	var out []*Folder
	for _, f := range hubs {
		if slices.ContainsFunc(o.Hubs, func(name string) bool { return strings.EqualFold(f.Name, name) }) {
			out = append(out, f)
		}
	}
	return out, nil
}

// pools checks the pools of o against the Virtual Hubs that it takes, and returns them by lower-case name.
func (o Options) pools(chosen []*Folder) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(o.Pools)) {
		if !slices.ContainsFunc(chosen, func(f *Folder) bool { return strings.EqualFold(f.Name, name) }) {
			return nil, fmt.Errorf("the pool of Virtual Hub %q: the import does not take that Virtual Hub", name)
		}
		p, err := intent.ParsePool(o.Pools[name], 4)
		if err != nil {
			return nil, fmt.Errorf("the pool of Virtual Hub %q: %w", name, err)
		}
		out[strings.ToLower(name)] = p.String()
	}
	return out, nil
}

// importer is the import of one Config file: the mode of its Networks, the names that it has given out and the
// resources that it has made.
type importer struct {
	mode      string
	names     *namer
	resources []intent.Resource
}

// add adds the resource of the kind and the name, with the spec spec.
func (im *importer) add(kind, name string, spec any) {
	// The specs hold strings, numbers, booleans, a time and slices of them, so Marshal cannot fail
	b, _ := json.Marshal(spec)
	im.resources = append(im.resources, intent.Resource{Kind: kind, Name: name, Spec: b})
}

// madeGroup is a Group that an entry of an access list made, for a user whom it names and the hub has no group of.
type madeGroup struct {
	name    string
	display string
}

// account is a user of a Virtual Hub and the User that it became.
type account struct {
	key    string
	name   string
	folder *Folder
}

// hubImport is the import of one Virtual Hub.
type hubImport struct {
	im *importer
	// vrf is the name of its VRF and of its Network.
	vrf string
	// prefix starts the names of its Policies: vrf, cut short to leave room for the rest.
	prefix string
	// pool is the IPv4 pool of its Network, empty for none.
	pool string
	// groups are the Groups that its groups became, by lower-case name, and folders the folders of those groups.
	groups  map[string]string
	folders map[string]*Folder
	// users are the folders of its users, by lower-case name.
	users map[string]*Folder
	// tags are the Groups that name a tag, by lower-case name: those of its groups and the ones that entries made.
	tags map[string]string
	// used are the names that the Policies made of its entries give, by lower-case name.
	used map[string]bool
	// made are the Groups that entries made, in the order that they were made.
	made []madeGroup
	// notes say what was left out and what was carried in another way.
	notes []string
	// prefixes are the IPv4 prefixes that its Policies match, which the pool of its Network should hold.
	prefixes []netip.Prefix
}

// say adds a line to the notes of the Virtual Hub.
func (h *hubImport) say(format string, args ...any) {
	h.notes = append(h.notes, fmt.Sprintf(format, args...))
}

// renamed says what a name of the Config file became when it is more than the same name in lower case.
func (h *hubImport) renamed(what, kind, raw, name string) {
	if name != strings.ToLower(raw) {
		h.say("%s %q is %s %q", what, raw, kind, name)
	}
}

// hub imports the Virtual Hub f, whose Network gets the IPv4 pool pool, empty for none.
func (im *importer) hub(f *Folder, pool string) Hub {
	base := slug(f.Name, "hub")
	vrf := im.names.take(kindHub, base)
	h := &hubImport{im: im, vrf: vrf, prefix: vrf, pool: pool}
	if len(h.prefix) > ruleBase {
		h.prefix = strings.TrimRight(h.prefix[:ruleBase], "-")
	}
	h.groups, h.folders, h.users = map[string]string{}, map[string]*Folder{}, map[string]*Folder{}
	h.tags, h.used = map[string]string{}, map[string]bool{}
	out := Hub{Name: f.Name, VRF: vrf, Network: vrf}
	if vrf != base {
		h.say("the VRF and the Network are %q and not %q, which is taken: by another Virtual Hub, or by the VRF default and the Network default that a first install makes", vrf, base)
	}
	im.add(intent.KindVRF, vrf, intent.VRF{})
	im.add(intent.KindNetwork, vrf, intent.Network{VRF: vrf, Mode: im.mode, IPv4Pool: pool})

	db := f.Child("SecurityAccountDatabase")
	for _, g := range db.Child("GroupList").Sorted() {
		key := strings.ToLower(g.Name)
		name := im.names.take(intent.KindGroup, slug(g.Name, "group"))
		h.groups[key], h.tags[key], h.folders[key] = name, name, g
		h.renamed("group", intent.KindGroup, g.Name, name)
		im.add(intent.KindGroup, name, intent.Group{DisplayName: displayName(g.Str("RealName"))})
		out.Groups++
	}
	var accounts []account
	for _, u := range db.Child("UserList").Sorted() {
		if u.Name == "*" {
			h.say("the user \"*\", whom the fork logs in by RADIUS or an NT domain, has no User: the controller has no such login yet")
			continue
		}
		key := strings.ToLower(u.Name)
		name := im.names.take(intent.KindUser, slug(u.Name, "user"))
		h.users[key] = u
		h.renamed("user", intent.KindUser, u.Name, name)
		accounts = append(accounts, account{key: key, name: name, folder: u})
	}

	// The tags that the entries name come first: a user joins the Group of a name that an entry gave
	out.Entries, out.Policies = h.accessList(f.Child("AccessList"))
	for _, m := range h.made {
		im.add(intent.KindGroup, m.name, intent.Group{DisplayName: m.display})
	}
	out.Groups += len(h.made)
	for _, a := range accounts {
		im.add(intent.KindUser, a.name, h.user(a))
	}
	out.Users = len(accounts)
	h.checkPool()
	out.Notes = h.notes
	return out
}

// tagOf returns the Group that is the tag of the name that an entry gave, which is the name of a user or of a group
// (the fork matches it against both): the Group of the hub's group of that name, else the Group of that user alone,
// which the user joins.
func (h *hubImport) tagOf(name string) string {
	key := strings.ToLower(name)
	h.used[key] = true
	if tag, ok := h.tags[key]; ok {
		return tag
	}
	tag := h.im.names.take(intent.KindGroup, slug(name, "group"))
	h.tags[key] = tag
	made := madeGroup{name: tag}
	if u := h.users[key]; u != nil {
		made.display = displayName(u.Str("RealName"))
	} else {
		h.say("an entry names %q, which is no user or group of the hub: Group %q has no member until a User joins it", name, tag)
	}
	h.made = append(h.made, made)
	return tag
}

// user returns the User of the account a: its display name, the Groups that give it its tags, its expiry and the two
// flags of its policy that a User has, FixPassword and NoSavePassword (ADR-0031 amendment of 2026-10-25).
func (h *hubImport) user(a account) intent.User {
	spec := intent.User{DisplayName: displayName(a.folder.Str("RealName"))}
	groupKey := strings.ToLower(strings.TrimSpace(a.folder.Str("GroupName")))
	var groups []string
	if g, ok := h.groups[groupKey]; ok {
		groups = append(groups, g)
	} else if groupKey != "" {
		h.say("the user %q is in the group %q, which the hub does not have", a.folder.Name, groupKey)
	}
	if h.used[a.key] {
		groups = append(groups, h.tags[a.key])
	}
	slices.Sort(groups)
	spec.Groups = slices.Compact(groups)
	spec.Expires = expiry(a.folder.Uint64("ExpireTime"))
	// The policy of a session is the one of its user, else the one of its group
	policy := a.folder.Child("Policy")
	if policy == nil {
		policy = h.folders[groupKey].Child("Policy")
	}
	if policy.Bool("FixPassword") {
		no := false
		spec.MayChangePassword = &no
	}
	spec.NoSavedPassword = policy.Bool("NoSavePassword")
	return spec
}

// expiry returns the instant that ExpireTime t of the fork stands for: its own encoding of a time in milliseconds, the
// UTC time of the Unix epoch less 9 hours. It returns the zero time, which is no expiry, for 0 and for a time past the
// year 9999.
func expiry(t uint64) time.Time {
	if t == 0 || t > maxExpire {
		return time.Time{}
	}
	return time.UnixMilli(int64(t + expireOffset)).UTC()
}

// displayName returns s as the display name of a User or a Group: valid UTF-8 without a control character, at most
// intent.MaxDisplayName characters long.
func displayName(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > intent.MaxDisplayName {
		s = string(r[:intent.MaxDisplayName])
	}
	return s
}

// checkPool says what the pool of the Network of the hub means for its Policies: that a Network of mode L3 without
// one gives no Node an address, and which prefixes that the Policies match its pool does not hold.
func (h *hubImport) checkPool() {
	if h.im.mode == intent.ModeL3 && h.pool == "" {
		h.say("Network %s has no IPv4 pool: give it one (ranz import-config -pool) before Nodes join, or none of them gets an address", h.vrf)
	}
	pool, err := netip.ParsePrefix(h.pool)
	if err != nil {
		return
	}
	var outside []string
	for _, p := range h.prefixes {
		if text := p.String(); !p.Overlaps(pool) && !slices.Contains(outside, text) {
			outside = append(outside, text)
		}
	}
	if len(outside) > 0 {
		h.say("the Policies match %s, which the pool %s of Network %s does not hold: no Node has an address there", strings.Join(outside, ", "), h.pool, h.vrf)
	}
}

// notImported says what no Virtual Hub carries over.
const notImported = "Not imported: the password of a user, which a User has none of until ranz user password sets one, " +
	"the login by certificate, RADIUS or NT domain, the limits and options of a user, a group and a Virtual Hub, " +
	"except the expiry of a user and its flags FixPassword and NoSavePassword, " +
	"and the Cascades, the Local Bridges, the listeners, the certificates and the administrators of the server.\n"

// Report says in text what Import made and what it left out: a line for each Virtual Hub with its notes under it, and
// what no Virtual Hub carries over.
func (r Result) Report() string {
	var b strings.Builder
	for _, h := range r.Hubs {
		fmt.Fprintf(&b, "Virtual Hub %q: VRF %s and Network %s, %d Groups, %d Users, %d Policies of %d access list entries\n",
			h.Name, h.VRF, h.Network, h.Groups, h.Users, h.Policies, h.Entries)
		for _, n := range h.Notes {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	b.WriteString(notImported)
	return b.String()
}
