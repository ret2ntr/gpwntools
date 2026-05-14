//go:build linux

package gpwntools

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestInteractiveWaitsForEnterOnTerminalInput(t *testing.T) {
	inputMaster, inputSlave, err := openProcessPTY()
	if err != nil {
		t.Fatalf("open input pty: %v", err)
	}
	t.Cleanup(func() {
		_ = inputMaster.Close()
		_ = inputSlave.Close()
	})

	targetOutputReader, targetOutputWriter := io.Pipe()
	targetInputReader, targetInputWriter := io.Pipe()
	t.Cleanup(func() {
		_ = targetOutputReader.Close()
		_ = targetOutputWriter.Close()
		_ = targetInputReader.Close()
		_ = targetInputWriter.Close()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- interactiveWithIO(
			targetOutputReader,
			targetInputWriter,
			inputSlave,
			io.Discard,
			targetInputWriter.Close,
			nil,
		)
	}()

	readCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := targetInputReader.Read(buf)
		if err == nil {
			readCh <- append([]byte(nil), buf[:n]...)
		}
	}()

	master := inputMaster.(*ptyMaster)
	if _, err := master.file.Write([]byte("n")); err != nil {
		t.Fatalf("write partial terminal input: %v", err)
	}

	select {
	case got := <-readCh:
		t.Fatalf("Interactive forwarded input before Enter: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := master.file.Write([]byte("\n")); err != nil {
		t.Fatalf("write terminal newline: %v", err)
	}

	select {
	case got := <-readCh:
		if !bytes.Equal(got, []byte("n\n")) {
			t.Fatalf("Interactive forwarded %q, want %q", got, "n\n")
		}
	case <-time.After(time.Second):
		t.Fatal("Interactive did not forward input after Enter")
	}

	_ = inputSlave.Close()
	_ = targetOutputWriter.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Interactive returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Interactive did not exit after input/output close")
	}
}

func TestInteractiveRawForwardsBeforeEnterOnTerminalInput(t *testing.T) {
	inputMaster, inputSlave, err := openProcessPTY()
	if err != nil {
		t.Fatalf("open input pty: %v", err)
	}
	t.Cleanup(func() {
		_ = inputMaster.Close()
		_ = inputSlave.Close()
	})

	targetOutputReader, targetOutputWriter := io.Pipe()
	targetInputReader, targetInputWriter := io.Pipe()
	t.Cleanup(func() {
		_ = targetOutputReader.Close()
		_ = targetOutputWriter.Close()
		_ = targetInputReader.Close()
		_ = targetInputWriter.Close()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- interactiveRawWithIO(
			targetOutputReader,
			targetInputWriter,
			inputSlave,
			io.Discard,
			targetInputWriter.Close,
			nil,
		)
	}()

	readCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := targetInputReader.Read(buf)
		if err == nil {
			readCh <- append([]byte(nil), buf[:n]...)
		}
	}()

	master := inputMaster.(*ptyMaster)
	if _, err := master.file.Write([]byte("n")); err != nil {
		t.Fatalf("write terminal input: %v", err)
	}

	select {
	case got := <-readCh:
		if !bytes.Equal(got, []byte("n")) {
			t.Fatalf("InteractiveRaw forwarded %q, want %q", got, "n")
		}
	case <-time.After(time.Second):
		t.Fatal("InteractiveRaw did not forward input before Enter")
	}

	_ = inputSlave.Close()
	_ = targetOutputWriter.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("InteractiveRaw returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("InteractiveRaw did not exit after input/output close")
	}
}
