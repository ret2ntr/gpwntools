//go:build !linux && !windows

package gpwntools

import "io"

func makeRawIfTerminal(input io.Reader, echo bool) (func() error, error) {
	return noopTerminalRestore, nil
}

func noopTerminalRestore() error {
	return nil
}
