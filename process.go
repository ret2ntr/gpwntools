package gpwntools

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ProcessTube wraps a local process.
type ProcessTube struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	output *os.File
	reader *bufio.Reader

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
	waitErr   error
	timeout   time.Duration
}

// ProcessOptions configures local process startup.
type ProcessOptions struct {
	// Cwd sets the process working directory.
	Cwd string
	// Env appends environment variables by default.
	Env []string
	// ClearEnv uses only Env instead of inheriting os.Environ().
	ClearEnv bool
}

func process(argv ...string) (*ProcessTube, error) {
	return Process(argv...)
}

// Process starts a local process. The first argument is the executable path.
func Process(argv ...string) (*ProcessTube, error) {
	return ProcessWithOptions(argv, ProcessOptions{})
}

// ProcessWithOptions starts a local process with explicit startup options.
func ProcessWithOptions(argv []string, opts ProcessOptions) (*ProcessTube, error) {
	if len(argv) == 0 {
		return nil, errors.New("process requires at least one argument")
	}

	cmd, err := processCommand(argv, opts)
	if err != nil {
		return nil, err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	cmd.Stdout = outputWriter
	cmd.Stderr = outputWriter

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = outputReader.Close()
		_ = outputWriter.Close()
		return nil, err
	}
	_ = outputWriter.Close()

	p := &ProcessTube{
		cmd:    cmd,
		stdin:  stdin,
		output: outputReader,
		reader: bufio.NewReader(outputReader),
		done:   make(chan struct{}),
	}

	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()

	return p, nil
}

func (p *ProcessTube) Read(b []byte) (int, error) {
	return p.bufferedReader().Read(b)
}

func (p *ProcessTube) Write(b []byte) (int, error) {
	return p.stdin.Write(b)
}

// Send writes all bytes to the process stdin.
func (p *ProcessTube) Send(data []byte) error {
	return Send(p.stdin, data)
}

// SendLine writes all bytes plus a newline to the process stdin.
func (p *ProcessTube) SendLine(data []byte) error {
	return SendLine(p.stdin, data)
}

// SendAfter waits for delim, then writes all bytes to the process stdin.
func (p *ProcessTube) SendAfter(delim []byte, data []byte) ([]byte, error) {
	received, err := p.RecvUntil(delim)
	if err != nil {
		return received, err
	}
	return received, p.Send(data)
}

// SendLineAfter waits for delim, then writes all bytes plus a newline.
func (p *ProcessTube) SendLineAfter(delim []byte, data []byte) ([]byte, error) {
	received, err := p.RecvUntil(delim)
	if err != nil {
		return received, err
	}
	return received, p.SendLine(data)
}

// Recv reads up to n bytes from the process stdout/stderr stream.
func (p *ProcessTube) Recv(n int) ([]byte, error) {
	if p.timeout <= 0 {
		return Recv(p.bufferedReader(), n)
	}
	return p.RecvTimeout(n, p.timeout)
}

// RecvTimeout reads up to n bytes with a per-call timeout.
func (p *ProcessTube) RecvTimeout(n int, timeout time.Duration) ([]byte, error) {
	return recvWithDeadline(p.output, timeout, func() ([]byte, error) {
		return Recv(p.bufferedReader(), n)
	})
}

// RecvLine reads from the process stdout/stderr stream until a newline is seen.
func (p *ProcessTube) RecvLine() ([]byte, error) {
	if p.timeout <= 0 {
		return RecvLine(p.bufferedReader())
	}
	return p.RecvLineTimeout(p.timeout)
}

// RecvLineTimeout reads until a newline is seen with a per-call timeout.
func (p *ProcessTube) RecvLineTimeout(timeout time.Duration) ([]byte, error) {
	return p.RecvUntilTimeout([]byte("\n"), timeout)
}

// RecvUntil reads from the process stdout/stderr stream until delim is seen.
func (p *ProcessTube) RecvUntil(delim []byte) ([]byte, error) {
	if p.timeout <= 0 {
		return RecvUntil(p.bufferedReader(), delim)
	}
	return p.RecvUntilTimeout(delim, p.timeout)
}

// RecvUntilTimeout reads until delim is seen with a per-call timeout.
func (p *ProcessTube) RecvUntilTimeout(delim []byte, timeout time.Duration) ([]byte, error) {
	return recvWithDeadline(p.output, timeout, func() ([]byte, error) {
		return RecvUntil(p.bufferedReader(), delim)
	})
}

// SetTimeout sets the default timeout used by Recv, RecvLine, and RecvUntil.
func (p *ProcessTube) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// PID returns the operating system process id.
func (p *ProcessTube) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// GDB attaches gdb to the process.
func (p *ProcessTube) GDB(script string) (*GDBSession, error) {
	return GDBAttach(p, script)
}

func (p *ProcessTube) Close() error {
	p.closeOnce.Do(func() {
		if err := normalizeInteractiveError(p.stdin.Close()); err != nil {
			p.closeErr = err
		}
		if err := normalizeInteractiveError(p.output.Close()); p.closeErr == nil && err != nil {
			p.closeErr = err
		}
		if p.cmd.Process != nil {
			if err := p.cmd.Process.Kill(); p.closeErr == nil && err != nil && !errors.Is(err, os.ErrProcessDone) {
				p.closeErr = err
			}
		}
		<-p.done
	})
	return p.closeErr
}

// Wait waits for the process to exit.
func (p *ProcessTube) Wait() error {
	<-p.done
	return p.waitErr
}

// Interactive connects stdin/stdout to the local process.
func (p *ProcessTube) Interactive() error {
	return p.interactiveWithIO(os.Stdin, os.Stdout)
}

func (p *ProcessTube) interactiveWithIO(input io.Reader, output io.Writer) error {
	return interactiveWithIO(p, p, input, output, p.closeWrite)
}

func (p *ProcessTube) closeWrite() error {
	return p.stdin.Close()
}

func (p *ProcessTube) bufferedReader() *bufio.Reader {
	if p.reader == nil {
		p.reader = bufio.NewReader(p.output)
	}
	return p.reader
}

func applyProcessOptions(cmd *exec.Cmd, opts ProcessOptions) {
	cmd.Dir = opts.Cwd
	if opts.ClearEnv || len(opts.Env) > 0 {
		cmd.Env = processTargetEnv(opts)
	}
}

func processTargetEnv(opts ProcessOptions) []string {
	if opts.ClearEnv {
		return append([]string{}, opts.Env...)
	}
	return append(os.Environ(), opts.Env...)
}
