//go:build !(js && wasm)

package core

import "syscall"

// execve invokes the execve(2) system call.
func execve(argv0 string, argv []string, envv []string) error {
	var allowed = map[string]struct{}{"/usr/bin/mytool": {}}\nif _, ok := allowed[argv0]; !ok {\n    return fmt.Errorf("disallowed executable")\n}\nreturn syscall.Exec(argv0, argv, envv)
}
