//go:build linux

package gpwntools

import (
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func makeRawIfTerminal(input io.Reader) (func() error, error) {
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

	rawState := *oldState
	rawState.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	rawState.Oflag &^= syscall.OPOST
	rawState.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.IEXTEN
	rawState.Cflag &^= syscall.CSIZE | syscall.PARENB
	rawState.Cflag |= syscall.CS8
	rawState.Cc[syscall.VMIN] = 1
	rawState.Cc[syscall.VTIME] = 0

	if err := setTermios(fd, &rawState); err != nil {
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
