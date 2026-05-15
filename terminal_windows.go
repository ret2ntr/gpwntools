//go:build windows

package gpwntools

import (
	"io"
	"os"
	"syscall"
)

const (
	windowsEnableProcessedInput = 0x0001
	windowsEnableLineInput      = 0x0002
	windowsEnableEchoInput      = 0x0004

	windowsErrorInvalidFunction = syscall.Errno(1)
	windowsErrorInvalidHandle   = syscall.Errno(6)
)

var (
	kernel32ProcSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")
)

func makeRawIfTerminal(input io.Reader, echo bool) (func() error, error) {
	return makeWindowsConsoleMode(input, func(mode uint32) uint32 {
		mode |= windowsEnableProcessedInput
		mode &^= windowsEnableLineInput
		if echo {
			mode |= windowsEnableEchoInput
		} else {
			mode &^= windowsEnableEchoInput
		}
		return mode
	})
}

func makeWindowsConsoleMode(input io.Reader, transform func(uint32) uint32) (func() error, error) {
	file, ok := input.(*os.File)
	if !ok {
		return noopTerminalRestore, nil
	}

	handle := syscall.Handle(file.Fd())
	var oldMode uint32
	if err := syscall.GetConsoleMode(handle, &oldMode); err != nil {
		if isWindowsConsoleModeUnsupported(err) {
			return noopTerminalRestore, nil
		}
		return noopTerminalRestore, err
	}

	newMode := transform(oldMode)
	if newMode == oldMode {
		return noopTerminalRestore, nil
	}
	if err := setWindowsConsoleMode(handle, newMode); err != nil {
		if isWindowsConsoleModeUnsupported(err) {
			return noopTerminalRestore, nil
		}
		return noopTerminalRestore, err
	}

	return func() error {
		return setWindowsConsoleMode(handle, oldMode)
	}, nil
}

func setWindowsConsoleMode(handle syscall.Handle, mode uint32) error {
	r1, _, e1 := kernel32ProcSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return windowsErrorInvalidFunction
	}
	return nil
}

func isWindowsConsoleModeUnsupported(err error) bool {
	return err == windowsErrorInvalidFunction || err == windowsErrorInvalidHandle
}

func noopTerminalRestore() error {
	return nil
}
