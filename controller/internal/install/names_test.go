package install

import (
	"strings"
	"testing"
)

// The SIDs that Windows gives the virtual accounts of the two services, as the rest of the tree
// has them: NODE_SERVICE_SID of src/Cedar/Node.h, which the nodesvc test of vpntest reads from the
// running service, and serviceSID of controller/service_windows.go, which controller-service.ps1
// reads from sc showsid.
func TestServiceSIDIsTheSIDWindowsGives(t *testing.T) {
	for name, want := range map[string]string{
		nodeServiceName:       "S-1-5-80-2319880895-1939077415-1550474732-530486738-250906376",
		controllerServiceName: "S-1-5-80-3572785604-795126647-2475823641-2319294638-1653438898",
	} {
		if got := serviceSID(name); got != want {
			t.Errorf("serviceSID(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestServiceSIDIgnoresTheCaseOfTheName(t *testing.T) {
	if lower, upper := serviceSID("ranzvpnserver"), serviceSID("RANZVPNSERVER"); lower != upper {
		t.Errorf("serviceSID differs by case: %s and %s", lower, upper)
	}
}

func TestFolderSDDLGrantsNothingToUsers(t *testing.T) {
	sddl := folderSDDL()
	if !strings.HasPrefix(sddl, "D:P(") {
		t.Errorf("%s is not a protected access list", sddl)
	}
	// Users, Everyone, Authenticated Users, and the interactive users
	for _, trustee := range []string{"BU", "WD", "AU", "IU"} {
		if strings.Contains(sddl, ";"+trustee+")") {
			t.Errorf("%s grants something to %s", sddl, trustee)
		}
	}
	for _, trustee := range []string{"SY", serviceSID(nodeServiceName), serviceSID(controllerServiceName)} {
		if !strings.Contains(sddl, ";"+trustee+")") {
			t.Errorf("%s names no %s", sddl, trustee)
		}
	}
}

func TestFolderSDDLGivesTheServicesNoMoreThanReadAndExecute(t *testing.T) {
	sddl := folderSDDL()
	for _, name := range []string{nodeServiceName, controllerServiceName} {
		want := "(A;OICI;FRFX;;;" + serviceSID(name) + ")"
		if !strings.Contains(sddl, want) {
			t.Errorf("%s has no %s", sddl, want)
		}
	}
	// Full control is for SYSTEM and the Administrators alone
	if got := strings.Count(sddl, ";FA;;;"); got != 2 {
		t.Errorf("%s gives full control to %d trustees, not 2", sddl, got)
	}
}
