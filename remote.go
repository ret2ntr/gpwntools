package gpwntools

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// RemoteTube wraps a TCP connection.
type RemoteTube struct {
	conn    net.Conn
	reader  *bufio.Reader
	mu      sync.Mutex
	timeout time.Duration
}

func remote(host string, port int) (*RemoteTube, error) {
	return Remote(host, port)
}

// Remote connects to host:port over TCP.
func Remote(host string, port int) (*RemoteTube, error) {
	return RemoteAddress(net.JoinHostPort(host, strconv.Itoa(port)))
}

// RemoteAddress connects to a TCP address such as "127.0.0.1:31337".
func RemoteAddress(address string) (*RemoteTube, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return &RemoteTube{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		timeout: contextTimeout(),
	}, nil
}

func (r *RemoteTube) Read(p []byte) (int, error) {
	return r.bufferedReader().Read(p)
}

func (r *RemoteTube) Write(p []byte) (int, error) {
	return r.conn.Write(p)
}

func (r *RemoteTube) Close() error {
	return r.conn.Close()
}

// Send writes all bytes to the remote TCP connection.
func (r *RemoteTube) Send(data []byte) error {
	return Send(r.conn, data)
}

// SendLine writes all bytes plus a newline to the remote TCP connection.
func (r *RemoteTube) SendLine(data []byte) error {
	return SendLine(r.conn, data)
}

// SendAfter waits for delim, then writes all bytes to the remote TCP connection.
func (r *RemoteTube) SendAfter(delim []byte, data []byte) ([]byte, error) {
	received, err := r.RecvUntil(delim)
	if err != nil {
		return received, err
	}
	return received, r.Send(data)
}

// SendLineAfter waits for delim, then writes all bytes plus a newline.
func (r *RemoteTube) SendLineAfter(delim []byte, data []byte) ([]byte, error) {
	received, err := r.RecvUntil(delim)
	if err != nil {
		return received, err
	}
	return received, r.SendLine(data)
}

// Recv reads up to n bytes from the remote TCP connection.
func (r *RemoteTube) Recv(n int) ([]byte, error) {
	if r.timeout <= 0 {
		return Recv(r.bufferedReader(), n)
	}
	return r.RecvTimeout(n, r.timeout)
}

// RecvTimeout reads up to n bytes with a per-call timeout.
func (r *RemoteTube) RecvTimeout(n int, timeout time.Duration) ([]byte, error) {
	return recvWithDeadline(r.conn, timeout, func() ([]byte, error) {
		return Recv(r.bufferedReader(), n)
	})
}

// RecvLine reads from the remote TCP connection until a newline is seen.
func (r *RemoteTube) RecvLine() ([]byte, error) {
	if r.timeout <= 0 {
		return RecvLine(r.bufferedReader())
	}
	return r.RecvLineTimeout(r.timeout)
}

// RecvLineTimeout reads until a newline is seen with a per-call timeout.
func (r *RemoteTube) RecvLineTimeout(timeout time.Duration) ([]byte, error) {
	return r.RecvUntilTimeout([]byte("\n"), timeout)
}

// RecvUntil reads from the remote TCP connection until delim is seen.
func (r *RemoteTube) RecvUntil(delim []byte) ([]byte, error) {
	if r.timeout <= 0 {
		return RecvUntil(r.bufferedReader(), delim)
	}
	return r.RecvUntilTimeout(delim, r.timeout)
}

// RecvUntilTimeout reads until delim is seen with a per-call timeout.
func (r *RemoteTube) RecvUntilTimeout(delim []byte, timeout time.Duration) ([]byte, error) {
	return recvWithDeadline(r.conn, timeout, func() ([]byte, error) {
		return RecvUntil(r.bufferedReader(), delim)
	})
}

// SetTimeout sets the default timeout used by Recv, RecvLine, and RecvUntil.
func (r *RemoteTube) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
}

// Interactive connects stdin/stdout to the remote TCP connection.
func (r *RemoteTube) Interactive() error {
	return r.interactiveWithIO(os.Stdin, os.Stdout)
}

func (r *RemoteTube) interactiveWithIO(input io.Reader, output io.Writer) error {
	return interactiveWithIO(r, r, input, output, r.closeWrite)
}

func (r *RemoteTube) closeWrite() error {
	if conn, ok := r.conn.(*net.TCPConn); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (r *RemoteTube) bufferedReader() *bufio.Reader {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reader == nil {
		r.reader = bufio.NewReader(r.conn)
	}
	return r.reader
}

func recvWithDeadline(deadliner readDeadliner, timeout time.Duration, fn func() ([]byte, error)) ([]byte, error) {
	if timeout <= 0 {
		return fn()
	}
	if err := deadliner.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer deadliner.SetReadDeadline(time.Time{})
	return fn()
}
