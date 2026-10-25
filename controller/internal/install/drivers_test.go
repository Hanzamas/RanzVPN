package install

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

func fakePackage(names ...string) []payload.Payload {
	var files []payload.Payload
	for _, name := range names {
		files = append(files, payload.New(name, []byte(name)))
	}
	return files
}

// On x64 the drivers are SeLow first, then the XDP runtime, each with the files of its package.
func TestSelectDriversInstallsSeLowThenXDP(t *testing.T) {
	selow := fakePackage("SeLow_x64.sys", "SeLow_x64.inf")
	xdp := fakePackage("xdp.sys", "xdp.inf")

	got := selectDrivers(selow, xdp, false)
	if len(got) != 2 || got[0].record != "SeLow" || got[1].record != "xdp" {
		t.Fatalf("selectDrivers chose %+v, want SeLow and then xdp", got)
	}
	if len(got[0].files) != 2 || got[0].files[0].Name != "SeLow_x64.sys" {
		t.Errorf("the files of SeLow are %v", got[0].files)
	}
	if len(got[1].files) != 2 || got[1].files[0].Name != "xdp.sys" {
		t.Errorf("the files of the XDP runtime are %v", got[1].files)
	}
}

// ranz install --no-xdp leaves the XDP runtime out and keeps SeLow, the fallback of the Node.
func TestSelectDriversLeavesTheXDPRuntimeOutWithNoXDP(t *testing.T) {
	got := selectDrivers(fakePackage("SeLow_x64.sys"), fakePackage("xdp.sys"), true)
	if len(got) != 1 || got[0].record != "SeLow" {
		t.Fatalf("selectDrivers with noXDP chose %+v, want SeLow only", got)
	}
}

// arm64 has Wintun only: a build with no SeLow package and no XDP runtime has no driver to install,
// whatever the flags say (the third criterion of ONE-3).
func TestSelectDriversHasNothingWhereThereIsNoPackage(t *testing.T) {
	for _, noXDP := range []bool{false, true} {
		if got := selectDrivers(nil, nil, noXDP); len(got) != 0 {
			t.Errorf("selectDrivers(nil, nil, %v) chose %+v, want none", noXDP, got)
		}
	}
}

// A package that this build carries and the other that it does not: only the first is chosen.
func TestSelectDriversLeavesOutAPackageThatIsNotThere(t *testing.T) {
	if got := selectDrivers(nil, fakePackage("xdp.sys"), false); len(got) != 1 || got[0].record != "xdp" {
		t.Errorf("selectDrivers with no SeLow package chose %+v, want the XDP runtime only", got)
	}
	if got := selectDrivers(fakePackage("SeLow_x64.sys"), nil, false); len(got) != 1 || got[0].record != "SeLow" {
		t.Errorf("selectDrivers with no XDP package chose %+v, want SeLow only", got)
	}
}

// selectDrivers copies the driver tables, so the files of one install never stay in them.
func TestSelectDriversDoesNotChangeTheDriverTables(t *testing.T) {
	if got := selectDrivers(fakePackage("SeLow_x64.sys"), fakePackage("xdp.sys"), false); len(got) != 2 {
		t.Fatalf("selectDrivers chose %d drivers, want 2", len(got))
	}
	if seLowDriver.files != nil || xdpDriver.files != nil {
		t.Errorf("selectDrivers left files in the tables: %v, %v", seLowDriver.files, xdpDriver.files)
	}
}

// Uninstall looks at every driver that an earlier install may have put on the machine, whatever
// this build carries, and the names that tell them apart are unique: the install record, the
// folder under drivers, the service and the component.
func TestEveryDriverHasItsOwnNames(t *testing.T) {
	all := everyDriver()
	if len(all) != 2 {
		t.Fatalf("everyDriver returned %d drivers, want SeLow and the XDP runtime", len(all))
	}
	seen := map[string]string{}
	for _, d := range all {
		for kind, name := range map[string]string{"record": d.record, "service": d.service, "component": d.component, "INF": d.inf} {
			if name == "" {
				t.Errorf("%s has no %s", d.label, kind)
			}
			if other, dup := seen[kind+" "+name]; dup {
				t.Errorf("%s and %s have the same %s %q", d.label, other, kind, name)
			}
			seen[kind+" "+name] = d.label
		}
		if d.class != "p" && d.class != "s" {
			t.Errorf("%s has the class %q, not one of the protocol and service classes of netcfg (p, s)", d.label, d.class)
		}
	}
}

// The XDP runtime gets a receive ring that takes a send() of UDP segmentation offload in one pass:
// XdpRxRingSize is a power of two that XDP takes (up to 8192), above the 44 segments of a send() of
// 64 KB in frames of 1514 bytes (#72, risk R1). SeLow has no setting.
func TestXDPRuntimeGetsAReceiveRingForUSO(t *testing.T) {
	var ring uint32
	for _, s := range xdpDriver.settings {
		if s.name == "XdpRxRingSize" {
			ring = s.value
		}
	}
	if ring < 64 || ring > 8192 || ring&(ring-1) != 0 {
		t.Errorf("the XDP runtime is set up with XdpRxRingSize %d, want a power of two from 64 to 8192", ring)
	}
	if len(seLowDriver.settings) != 0 {
		t.Errorf("the SeLow driver has the settings %v, want none", seLowDriver.settings)
	}
}

// The SeLow driver of this file is what the INF of its package installs: a component of the class
// NetTrans (a protocol) with the id SeLow, and the service SeLow. The INF is the one that ranz
// carries (internal/payload/selow), so a new package fails here until the table follows it.
func TestSeLowDriverMatchesItsINF(t *testing.T) {
	inf, err := os.ReadFile(filepath.Join("..", "payload", "selow", seLowDriver.inf))
	if err != nil {
		t.Fatalf("reading the INF of the SeLow package: %v", err)
	}
	text := string(inf)
	checks := []struct{ what, pattern string }{
		{"the class NetTrans, which netcfg calls a protocol", `(?m)^Class\s*=\s*NetTrans\b`},
		{"the component " + seLowDriver.component, `(?m)^%\w+%\s*=\s*\w+,\s*` + regexp.QuoteMeta(seLowDriver.component) + `\s*$`},
		{"the service " + seLowDriver.service, `(?m)^AddService\s*=\s*` + regexp.QuoteMeta(seLowDriver.service) + `\s*,`},
	}
	for _, c := range checks {
		if !regexp.MustCompile(c.pattern).MatchString(text) {
			t.Errorf("the INF %s does not install %s", seLowDriver.inf, c.what)
		}
	}
	if seLowDriver.class != "p" {
		t.Errorf("the SeLow driver is installed with the class %q, not p (a protocol)", seLowDriver.class)
	}
}
