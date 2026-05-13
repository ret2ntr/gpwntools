//go:build !linux

package gpwntools

import "io"

func makeRawIfTerminal(input io.Reader) (func() error, error) {
	return noopTerminalRestore, nil
}

func noopTerminalRestore() error {
	return nil
}
