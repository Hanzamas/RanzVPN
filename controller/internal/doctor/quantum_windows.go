package doctor

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The ML-KEM provider of CNG (BCRYPT_MLKEM_ALGORITHM), which Windows 11 24H2 and Windows Server 2025 have from their updates
// of 2025 on, and the calls that open and close a provider of bcrypt.dll.
var (
	bcrypt                   = windows.NewLazySystemDLL("bcrypt.dll")
	bcryptOpenProvider       = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
	bcryptCloseProvider      = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
	mlkemAlgorithm, mlkemErr = windows.UTF16PtrFromString("ML-KEM")
)

// thisHost reads what the report needs of this Windows host: whether CNG has ML-KEM, and the two TLS group lists.
func thisHost() host {
	h := host{windows: true, mlkem: hasMLKEM()}
	if list, ok, err := groupList(policyListKey); ok {
		h.policy = true
		if err == nil {
			h.policyList = list
		}
	}
	if list, ok, err := groupList(machineListKey); ok && err == nil {
		h.machine = list
	}
	return h
}

// hasMLKEM reports whether CNG opens its ML-KEM provider.
func hasMLKEM() bool {
	if mlkemErr != nil || bcrypt.Load() != nil || bcryptOpenProvider.Find() != nil || bcryptCloseProvider.Find() != nil {
		return false
	}
	var provider uintptr
	status, _, _ := bcryptOpenProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(mlkemAlgorithm)), 0, 0)
	if status != 0 {
		return false
	}
	bcryptCloseProvider.Call(provider, 0)
	return true
}

// groupList reads the list of the value EccCurves of the key under HKEY_LOCAL_MACHINE: ok says that the value is there,
// and err that it is no list.
func groupList(key string) (list []string, ok bool, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, err
	}
	defer k.Close()
	list, _, err = k.GetStringsValue(listValue)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, false, err
	}
	if list == nil && err == nil {
		list = []string{}
	}
	return list, true, err
}
