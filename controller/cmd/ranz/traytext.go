package main

import "fmt"

// The words of the tray (SDN-55, #248), each under an id of its own. The Indonesian of the tray comes
// with SDN-60 (#253) as a second table of the same ids, so no word is spelled in the code that
// builds a menu or a message. A word with %s or %d takes its values in the order that the call
// names them.
var trayWords = map[string]string{
	"title": "Ranz VPN",

	// What the Node service says, and what is wrong when it does not
	"notinstalled": "Ranz is not installed on this PC",
	"stopped":      "The Ranz service is not running",
	"stopped.how":  "An administrator starts it with: Start-Service %s",
	"noclient":     "The Ranz service runs, but this PC has no client set up",
	"noclient.how": "The Client setting of the Node names the servers to join",
	"starting":     "The Ranz service is starting",
	"denied":       "This account may not use the Ranz service",
	"unreadable":   "The Ranz service gave no answer: %s",
	"unknown":      "The Ranz service is not running, or Ranz is not installed",

	// The state of the client role
	"nocontroller":     "Not signed in",
	"nocontroller.how": "Sign in to join your network",
	"signingin":        "Signing in...",
	"signingin.how":    "Finish the sign-in in your browser",
	"off":              "Ranz is turned off",
	"asleep":           "Waiting for this PC to wake up",
	"connecting":       "Connecting...",
	"connected":        "Connected",
	"as":               "This PC: %s",
	"addresses":        "Address: %s",
	"over":             "Over %s",
	"exitnode":         "Exit node: %s",
	"controller.why":   "The Controller: %s",

	// The items of the menu
	"signin":       "Sign in...",
	"signinagain":  "Sign in again...",
	"turnoff":      "Turn Ranz off",
	"turnon":       "Turn Ranz on",
	"exitmenu":     "Exit node",
	"exitnone":     "None (direct)",
	"noexits":      "No exit node is available",
	"notavailable": "not available",
	"ipv4only":     "IPv4 only",
	"quit":         "Quit",

	// The notices that pop up, and the messages of the verbs
	"signedin":      "Signed in as %s. This PC joins as %s.",
	"signedin.same": "Signed in as %s. This PC is %s already.",
	"signinfailed":  "The sign-in did not finish: %s",
	"signinbusy":    "A sign-in runs already: finish it in your browser",
	"actionfailed":  "Ranz refused: %s",
	"exitchosen":    "The traffic of this PC leaves through %s",
	"exitcleared":   "The traffic of this PC leaves directly again",

	"err.nocontroller": "no Controller to sign in at: start the tray with -server URL, or set RANZ_SERVER",
	"err.key":          "the Node gave no static key: %s",
	"err.keyshape":     "the Node answered a key that is not the base64 of 32 bytes: %q",
	"err.nokeys":       "the Controller enrolled the Node as %s, and gave none of its keys",
	"err.settings":     "the Node is enrolled as %s, and its Controller settings cannot be made: %v",
	"err.enrol":        "the Node is enrolled as %s, and it did not take its Controller settings: %v",
	"err.refused":      "the Node is enrolled as %s, and it refused its Controller settings: %s",
}

// trayText returns the words of id with the values args, or the id itself when no words are there, so
// that a missing word shows as its id and a check can find it.
func trayText(id string, args ...any) string {
	words, ok := trayWords[id]
	if !ok {
		return id
	}
	if len(args) == 0 {
		return words
	}
	return fmt.Sprintf(words, args...)
}
