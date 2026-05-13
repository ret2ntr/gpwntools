package gpwntools

import (
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
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

// Interactive connects stdin/stdout to a tube, like pwntools' interactive().
func Interactive(t Tube) error {
	var closeWrite func() error
	if target, ok := t.(interface{ closeWrite() error }); ok {
		closeWrite = target.closeWrite
	}
	return interactiveWithIO(t, t, os.Stdin, os.Stdout, closeWrite, t.Close)
}

func interactiveWithIO(targetReader io.Reader, targetWriter io.Writer, input io.Reader, output io.Writer, closeWrite func() error, closeTarget func() error) error {
	restoreTerminal, err := makeRawIfTerminal(input)
	if err != nil {
		return err
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
		errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
