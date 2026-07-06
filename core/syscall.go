//go:build !(js && wasm)

package core

import (
	"errors"
	"os"
	"syscall"
)

// execve invokes the execve(2) system call.
func execve(argv0 string, argv []string, envv []string) error {
	currentExec, err := os.Executable()
	if err != nil {
		return err
	}

	if argv0 != currentExec {
		return errors.New("disallowed executable")
	}

	return syscall.Exec(argv0, argv, envv)
}
