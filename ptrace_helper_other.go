//go:build !linux

package gpwntools

import "os/exec"

func processCommand(argv []string, opts ProcessOptions) (*exec.Cmd, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	applyProcessOptions(cmd, opts)
	return cmd, nil
}
