//go:build !(js && wasm)

package core

import (
	"fmt"
	"syscall"
)

// execve invokes the execve(2) system call.
func execve(argv0 string, argv []string, envv []string) error {
	var allowed = map[string]struct{}{"/usr/bin/mytool": {}} // TODO: Populate with actual allowed executables
	if _, ok := allowed[argv0]; !ok {
		return fmt.Errorf("disallowed executable")
	}
	return syscall.Exec(argv0, argv, envv)
}
