package main

import "os/exec"

// execCommand runs an external command and returns its combined output.
// Separated into its own file to make platform-specific overrides easy.
func execCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output() // #nosec G204
}
