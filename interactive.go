package gpwntools

import (
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// ErrInteractiveInterrupted is returned when interactive mode is interrupted by Ctrl+C.
var ErrInteractiveInterrupted = errors.New("interactive interrupted")

// Tube is the common interface shared by remote and process connections.
type Tube interface {
	io.Reader
	io.Writer
	io.Closer
	Interactive() error
}

// Interactive connects stdin/stdout to a tube in line mode, so terminal input
// is forwarded only after Enter.
func Interactive(t Tube) error {
	return interactive(t, false)
}

// InteractiveRaw connects stdin/stdout to a tube in cbreak mode, so each
// keystroke is forwarded immediately.
func InteractiveRaw(t Tube) error {
	return interactive(t, true)
}

// InteractiveLine is a compatibility alias for Interactive.
func InteractiveLine(t Tube) error {
	return Interactive(t)
}

func interactive(t Tube, rawInput bool) error {
	var closeWrite func() error
	if target, ok := t.(interface{ closeWrite() error }); ok {
		closeWrite = target.closeWrite
	}
	return interactiveWithIOMode(t, t, os.Stdin, os.Stdout, closeWrite, t.Close, rawInput)
}

func interactiveWithIO(targetReader io.Reader, targetWriter io.Writer, input io.Reader, output io.Writer, closeWrite func() error, closeTarget func() error) error {
	return interactiveWithIOMode(targetReader, targetWriter, input, output, closeWrite, closeTarget, false)
}

func interactiveRawWithIO(targetReader io.Reader, targetWriter io.Writer, input io.Reader, output io.Writer, closeWrite func() error, closeTarget func() error) error {
	return interactiveWithIOMode(targetReader, targetWriter, input, output, closeWrite, closeTarget, true)
}

func interactiveLineWithIO(targetReader io.Reader, targetWriter io.Writer, input io.Reader, output io.Writer, closeWrite func() error, closeTarget func() error) error {
	return interactiveWithIO(targetReader, targetWriter, input, output, closeWrite, closeTarget)
}

func interactiveWithIOMode(targetReader io.Reader, targetWriter io.Writer, input io.Reader, output io.Writer, closeWrite func() error, closeTarget func() error, rawInput bool) error {
	restoreTerminal := noopTerminalRestore
	display := &lockedWriter{w: output}
	lineEcho := Context.InteractiveLineEcho
	systemEcho := Context.InteractiveSystemEcho
	if rawInput {
		var err error
		restoreTerminal, err = makeRawIfTerminal(input, systemEcho)
		if err != nil {
			return err
		}
	} else if !systemEcho || lineEcho {
		var err error
		restoreTerminal, err = makeRawIfTerminal(input, systemEcho)
		if err != nil {
			return err
		}

		var echo io.Writer
		if lineEcho {
			echo = display
		}
		input = newInteractiveLineInput(input, echo)
	} else {
		input = newInteractiveInputNormalizer(input)
	}
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			_ = restoreTerminal()
		})
	}
	defer restore()

	inputDone := make(chan error, 1)
	interruptDone := make(chan error, 1)
	signalDone := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer func() {
		signal.Stop(sigCh)
		close(signalDone)
	}()

	go func() {
		select {
		case <-signalDone:
			return
		case <-sigCh:
		}
		restore()

		var err error
		if closeTarget != nil {
			err = normalizeInteractiveError(closeTarget())
		} else if closeWrite != nil {
			err = normalizeInteractiveError(closeWrite())
		}
		if err == nil {
			err = ErrInteractiveInterrupted
		}
		interruptDone <- err
	}()

	go func() {
		_, err := io.Copy(targetWriter, input)
		if closeWrite != nil {
			if closeErr := closeWrite(); err == nil {
				err = closeErr
			}
		}
		inputDone <- normalizeInteractiveError(err)
	}()

	_, outputErr := io.Copy(display, targetReader)
	outputErr = normalizeInteractiveError(outputErr)

	select {
	case interruptErr := <-interruptDone:
		return interruptErr
	case inputErr := <-inputDone:
		if outputErr == nil {
			return inputErr
		}
	default:
	}

	return outputErr
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type interactiveInputNormalizer struct {
	r          io.Reader
	pending    []byte
	previousCR bool
}

func newInteractiveInputNormalizer(r io.Reader) io.Reader {
	return &interactiveInputNormalizer{r: r}
}

func (n *interactiveInputNormalizer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(n.pending) == 0 {
		buf := make([]byte, len(p))
		nread, err := n.r.Read(buf)
		if nread > 0 {
			n.pending = append(n.pending, normalizeInteractiveInput(buf[:nread], &n.previousCR)...)
		}
		if err != nil {
			if len(n.pending) == 0 {
				return 0, err
			}
			break
		}
	}

	nread := copy(p, n.pending)
	n.pending = n.pending[nread:]
	return nread, nil
}

func normalizeInteractiveInput(b []byte, previousCR *bool) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if *previousCR && c == '\n' {
			*previousCR = false
			continue
		}
		*previousCR = false

		if c == '\r' {
			out = append(out, '\n')
			*previousCR = true
			continue
		}
		out = append(out, c)
	}
	return out
}

type interactiveLineInput struct {
	r          io.Reader
	echo       io.Writer
	pending    []byte
	line       []byte
	previousCR bool
}

func newInteractiveLineInput(r io.Reader, echo io.Writer) io.Reader {
	return &interactiveLineInput{r: r, echo: echo}
}

func (n *interactiveLineInput) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(n.pending) == 0 {
		var buf [1]byte
		nread, err := n.r.Read(buf[:])
		if nread > 0 {
			if processErr := n.processByte(buf[0]); processErr != nil {
				return 0, processErr
			}
		}
		if err != nil {
			if len(n.pending) == 0 && len(n.line) > 0 {
				n.pending = append(n.pending, n.line...)
				n.line = nil
				break
			}
			if len(n.pending) == 0 {
				return 0, err
			}
			break
		}
	}

	nread := copy(p, n.pending)
	n.pending = n.pending[nread:]
	return nread, nil
}

func (n *interactiveLineInput) processByte(c byte) error {
	if n.previousCR && c == '\n' {
		n.previousCR = false
		return nil
	}
	n.previousCR = false

	switch c {
	case '\r', '\n':
		if c == '\r' {
			n.previousCR = true
		}
		if err := n.writeEcho([]byte("\r\n")); err != nil {
			return err
		}
		n.line = append(n.line, '\n')
		n.pending = append(n.pending, n.line...)
		n.line = nil
	case 0x7f, '\b':
		if len(n.line) == 0 {
			return nil
		}
		n.line = n.line[:len(n.line)-1]
		return n.writeEcho([]byte("\b \b"))
	case 0x04:
		if len(n.line) == 0 {
			return io.EOF
		}
	default:
		if err := n.writeEcho([]byte{c}); err != nil {
			return err
		}
		n.line = append(n.line, c)
	}
	return nil
}

func (n *interactiveLineInput) writeEcho(p []byte) error {
	if n.echo == nil {
		return nil
	}
	_, err := n.echo.Write(p)
	return err
}

func normalizeInteractiveError(err error) error {
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.EBADF) {
		return nil
	}
	return err
}
