package sidecar

import (
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// prepare does nothing: bind ties rqlited to the controller once it runs.
func prepare(*exec.Cmd) {}

// bind puts rqlited into a job object of its own that ends its processes when the last handle
// to the job closes (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE). The controller holds that handle until
// rqlited exits, and the system closes it when the controller exits in any way, a kill
// included. The returned function closes the handle once rqlited exited.
func bind(p *os.Process) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	runtime.KeepAlive(&info)
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return func() { windows.CloseHandle(job) }, nil
}
