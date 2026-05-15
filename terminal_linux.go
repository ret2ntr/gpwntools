//go:build linux

package gpwntools

import (
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func makeRawIfTerminal(input io.Reader, echo bool) (func() error, error) {
	file, ok := input.(*os.File)
	if !ok {
		return noopTerminalRestore, nil
	}

	fd := int(file.Fd())
	oldState, err := getTermios(fd)
	if err != nil {
		if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EINVAL) {
			return noopTerminalRestore, nil
		}
		return noopTerminalRestore, err
	}

	cbreakState := *oldState
	cbreakState.Lflag &^= syscall.ICANON | syscall.ECHOCTL
	if echo {
		cbreakState.Lflag |= syscall.ECHO
	} else {
		cbreakState.Lflag &^= syscall.ECHO
	}
	cbreakState.Cc[syscall.VMIN] = 1
	cbreakState.Cc[syscall.VTIME] = 0

	if err := setTermios(fd, &cbreakState); err != nil {
		return noopTerminalRestore, err
	}

	return func() error {
		return setTermios(fd, oldState)
	}, nil
}

func getTermios(fd int) (*syscall.Termios, error) {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	if errno != 0 {
		return nil, errno
	}
	return &termios, nil
}

func setTermios(fd int, termios *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(termios)))
	if errno != 0 {
		return errno
	}
	return nil
}

func noopTerminalRestore() error {
	return nil
}
