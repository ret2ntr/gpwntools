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

// Interactive connects stdin/stdout to a tube without putting the terminal in
// cbreak mode, so terminal input is forwarded only after Enter.
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
	if rawInput {
		var err error
		restoreTerminal, err = makeRawIfTerminal(input)
		if err != nil {
			return err
		}
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

	_, outputErr := io.Copy(output, targetReader)
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
