package bundle

import (
	"context"
	"os"
	"runtime"
	"time"
)

// System is what a bundle says of the host and of the process that made it. It holds no
// environment variable and no argument of the command line, which is where a token goes.
type System struct {
	// Host is the name of the host.
	Host string `json:"host"`
	// OS is the operating system: windows or linux.
	OS string `json:"os"`
	// OSVersion is its version, on Windows major.minor.build.
	OSVersion string `json:"osVersion,omitempty"`
	// Arch is the processor architecture.
	Arch string `json:"arch"`
	// CPUs is the number of logical processors.
	CPUs int `json:"cpus"`
	// GoVersion is the version of Go that built the program.
	GoVersion string `json:"goVersion"`
	// Executable is the path of the program.
	Executable string `json:"executable,omitempty"`
	// ProcessID is its process id.
	ProcessID int `json:"processId"`
	// Time is the time of the host, in UTC.
	Time time.Time `json:"time"`
}

// SystemInfo returns what the bundle says of this host at now.
func SystemInfo(now time.Time) System {
	host, _ := os.Hostname()
	exe, _ := os.Executable()
	return System{Host: host, OS: runtime.GOOS, OSVersion: osVersion(), Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
		GoVersion: runtime.Version(), Executable: exe, ProcessID: os.Getpid(), Time: now.UTC()}
}

// SystemSource returns the source of system.json: SystemInfo at the time of the bundle.
func SystemSource() Source {
	return JSONSource("system", "system.json", func(context.Context) (any, error) {
		return SystemInfo(time.Now()), nil
	})
}

// Service is what a bundle says of a Windows service of Ranz.
type Service struct {
	// Name is the name of the service.
	Name string `json:"name"`
	// Installed is true when the service control manager knows the service.
	Installed bool `json:"installed"`
	// State is stopped, running or another state of the service.
	State string `json:"state,omitempty"`
	// ProcessID is the process of a running service.
	ProcessID uint32 `json:"processId,omitempty"`
	// ExitCode is the exit code of a service that stopped.
	ExitCode uint32 `json:"exitCode,omitempty"`
	// StartType is automatic, manual or disabled.
	StartType string `json:"startType,omitempty"`
	// Account is the account the service runs as.
	Account string `json:"account,omitempty"`
	// Command is its command line, as the service control manager holds it.
	Command string `json:"command,omitempty"`
}

// ServicesSource returns the source of services.json: the Windows services of Ranz, the Node's and
// the Controller's. It gives no part on a host that has no service control manager.
func ServicesSource() Source {
	return Source{Name: "services", Collect: func(context.Context) ([]Part, error) {
		list, err := Services()
		if err != nil || list == nil {
			return nil, err
		}
		p, err := JSON("services.json", list)
		if err != nil {
			return nil, err
		}
		return []Part{p}, nil
	}}
}
