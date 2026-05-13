//go:build linux

package gpwntools

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type ptyMaster struct {
	file *os.File
	fd   int

	readDeadline time.Time
}

func openProcessPTY() (processOutput, *os.File, error) {
	masterFD, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(masterFD), "/dev/ptmx")

	if err := unlockPTY(masterFD); err != nil {
		_ = master.Close()
		return nil, nil, err
	}

	slaveName, err := ptsName(masterFD)
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}

	slaveFD, err := syscall.Open(slaveName, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}

	if err := syscall.SetNonblock(masterFD, true); err != nil {
		_ = master.Close()
		_ = syscall.Close(slaveFD)
		return nil, nil, err
	}

	return &ptyMaster{file: master, fd: masterFD}, os.NewFile(uintptr(slaveFD), slaveName), nil
}

func (p *ptyMaster) Read(buf []byte) (int, error) {
	for {
		if err := waitReadable(p.fd, p.readDeadline); err != nil {
			return 0, err
		}

		n, err := p.file.Read(buf)
		if err == nil || n > 0 {
			return n, err
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			continue
		}
		return n, err
	}
}

func (p *ptyMaster) Close() error {
	return p.file.Close()
}

func (p *ptyMaster) SetReadDeadline(deadline time.Time) error {
	p.readDeadline = deadline
	return nil
}

func unlockPTY(fd int) error {
	var unlock int32
	return ioctl(fd, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock)))
}

func ptsName(fd int) (string, error) {
	var number uint32
	if err := ioctl(fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", number), nil
}

func ioctl(fd int, request uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func waitReadable(fd int, deadline time.Time) error {
	for {
		var timeout *syscall.Timeval
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return os.ErrDeadlineExceeded
			}
			tv := syscall.NsecToTimeval(remaining.Nanoseconds())
			timeout = &tv
		}

		var readfds syscall.FdSet
		if !fdSet(fd, &readfds) {
			return fmt.Errorf("file descriptor %d is too large for select", fd)
		}
		n, err := syscall.Select(fd+1, &readfds, nil, nil, timeout)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return os.ErrDeadlineExceeded
		}
		return nil
	}
}

func fdSet(fd int, set *syscall.FdSet) bool {
	if fd < 0 || fd/64 >= len(set.Bits) {
		return false
	}
	set.Bits[fd/64] |= 1 << (uint(fd) % 64)
	return true
}
