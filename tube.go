package gpwntools

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
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
	n, err := io.Copy(w, bytes.NewReader(data))
	if n > 0 || err == nil {
		debugLogPacket("Sent", data[:int(n)])
	}
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

// Recv reads up to n bytes from a target. It keeps reading until n bytes are
// received, or until the underlying reader returns an error.
func Recv(r io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("recv size must be non-negative")
	}
	if n == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, n)
	read := 0
	for read < n {
		nread, err := r.Read(buf[read:])
		read += nread
		if err != nil {
			debugLogPacket("Received", buf[:read])
			return buf[:read], err
		}
		if nread == 0 {
			debugLogPacket("Received", buf[:read])
			return buf[:read], io.ErrNoProgress
		}
	}
	debugLogPacket("Received", buf)
	return buf, nil
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

// RecvUntil reads until delim is seen. The returned data includes delim unless drop is true.
func RecvUntil(r io.Reader, delim []byte, drop ...bool) ([]byte, error) {
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
			debugLogPacket("Received", out)
			return out, err
		}

		out = append(out, b)
		if bytes.HasSuffix(out, delim) {
			debugLogPacket("Received", out)
			if shouldDropDelimiter(drop) {
				return out[:len(out)-len(delim)], nil
			}
			return out, nil
		}
	}
}

// RecvUntilTimeout reads until delim is seen from a deadline-capable target.
func RecvUntilTimeout(r io.Reader, delim []byte, timeout time.Duration, drop ...bool) ([]byte, error) {
	var out []byte
	err := withReadDeadline(r, timeout, func() error {
		var err error
		out, err = RecvUntil(r, delim, drop...)
		return err
	})
	return out, err
}

func shouldDropDelimiter(drop []bool) bool {
	return len(drop) > 0 && drop[0]
}

func debugLogPacket(direction string, data []byte) {
	if !Log.Enabled(LogLevelDebug) {
		return
	}
	if len(data) == 0 {
		if direction == "Received" {
			return
		}
		Log.Debug("%s 0x0 bytes", direction)
		return
	}
	Log.Debug("%s 0x%x bytes:\n%s", direction, len(data), indentDebugDump(Hexdump(data)))
}

func indentDebugDump(dump string) string {
	if dump == "" {
		return ""
	}
	lines := strings.SplitAfter(dump, "\n")
	var out strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		out.WriteString("    ")
		out.WriteString(line)
	}
	return out.String()
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
