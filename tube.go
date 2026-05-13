package gpwntools

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"time"
)

// ErrTimeoutUnsupported is returned when a timeout is requested on a reader
// that does not support read deadlines.
var ErrTimeoutUnsupported = errors.New("reader does not support read deadlines")

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// Send writes all bytes to a target.
func Send(w io.Writer, data []byte) error {
	_, err := io.Copy(w, bytes.NewReader(data))
	return err
}

// SendLine writes all bytes to a target and appends a newline.
func SendLine(w io.Writer, data []byte) error {
	line := make([]byte, 0, len(data)+1)
	line = append(line, data...)
	line = append(line, '\n')
	return Send(w, line)
}

// SendAfter waits for delim, then writes all bytes to a target.
func SendAfter(r io.Reader, w io.Writer, delim []byte, data []byte) ([]byte, error) {
	received, err := RecvUntil(r, delim)
	if err != nil {
		return received, err
	}
	return received, Send(w, data)
}

// SendLineAfter waits for delim, then writes all bytes plus a newline.
func SendLineAfter(r io.Reader, w io.Writer, delim []byte, data []byte) ([]byte, error) {
	received, err := RecvUntil(r, delim)
	if err != nil {
		return received, err
	}
	return received, SendLine(w, data)
}

// Recv reads up to n bytes from a target.
func Recv(r io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("recv size must be non-negative")
	}
	if n == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, n)
	read, err := r.Read(buf)
	return buf[:read], err
}

// RecvTimeout reads up to n bytes from a deadline-capable target.
func RecvTimeout(r io.Reader, n int, timeout time.Duration) ([]byte, error) {
	var out []byte
	err := withReadDeadline(r, timeout, func() error {
		var err error
		out, err = Recv(r, n)
		return err
	})
	return out, err
}

// RecvLine reads until a newline is seen. The returned data includes the newline.
func RecvLine(r io.Reader) ([]byte, error) {
	return RecvUntil(r, []byte("\n"))
}

// RecvLineTimeout reads until a newline is seen from a deadline-capable target.
func RecvLineTimeout(r io.Reader, timeout time.Duration) ([]byte, error) {
	return RecvUntilTimeout(r, []byte("\n"), timeout)
}

// RecvUntil reads until delim is seen. The returned data includes delim.
func RecvUntil(r io.Reader, delim []byte) ([]byte, error) {
	if len(delim) == 0 {
		return nil, errors.New("recvuntil delimiter must not be empty")
	}

	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(r)
	}

	out := make([]byte, 0, len(delim))
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return out, err
		}

		out = append(out, b)
		if bytes.HasSuffix(out, delim) {
			return out, nil
		}
	}
}

// RecvUntilTimeout reads until delim is seen from a deadline-capable target.
func RecvUntilTimeout(r io.Reader, delim []byte, timeout time.Duration) ([]byte, error) {
	var out []byte
	err := withReadDeadline(r, timeout, func() error {
		var err error
		out, err = RecvUntil(r, delim)
		return err
	})
	return out, err
}

func withReadDeadline(r io.Reader, timeout time.Duration, fn func() error) error {
	if timeout <= 0 {
		return fn()
	}

	deadliner, ok := r.(readDeadliner)
	if !ok {
		return ErrTimeoutUnsupported
	}

	if err := deadliner.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer deadliner.SetReadDeadline(time.Time{})

	return fn()
}
