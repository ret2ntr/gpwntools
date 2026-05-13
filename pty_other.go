//go:build !linux

package gpwntools

import (
	"errors"
	"os"
)

func openProcessPTY() (processOutput, *os.File, error) {
	return nil, nil, errors.New("process PTY is only implemented on linux")
}
