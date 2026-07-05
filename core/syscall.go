//go:build !(js && wasm)

package core

import (
	"fmt"
	"os"
	"syscall"
)

// execve invokes the execve(2) system call.
func execve(argv0 string, argv []string, envv []string) error {
	// verify that argv0 matches the current executable path
	// to prevent arbitrary code execution via syscall.Exec
	current, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current executable: %w", err)
	}
	if argv0 != current {
		return fmt.Errorf("execve: argv0 (%s) does not match the current executable (%s)", argv0, current)
	}
	return syscall.Exec(argv0, argv, envv)
}
