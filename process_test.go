package gpwntools

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProcessPTYFlushesLineBufferedOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process PTY is only implemented on linux")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc not available: %v", err)
	}

	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })
	Context.PTY = true

	dir := t.TempDir()
	source := filepath.Join(dir, "prompt.c")
	binary := filepath.Join(dir, "prompt")
	if err := os.WriteFile(source, []byte(`
#include <stdio.h>

int main(void) {
	puts("please input");
	char buf[32];
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		return 1;
	}
	puts("ok");
	return 0;
}
`), 0600); err != nil {
		t.Fatalf("write C source: %v", err)
	}

	build := exec.Command("gcc", source, "-o", binary)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build C target: %v: %s", err, out)
	}

	p, err := Process(binary)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	got, err := p.RecvUntilTimeout([]byte("please input"), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("RecvUntilTimeout failed after %q: %v", got, err)
	}

	if !strings.Contains(string(got), "please input") {
		t.Fatalf("got %q, want prompt", got)
	}
}

func TestProcessPTYDoesNotTranslateNewline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process PTY is only implemented on linux")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc not available: %v", err)
	}

	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })
	Context.PTY = true

	dir := t.TempDir()
	source := filepath.Join(dir, "newline.c")
	binary := filepath.Join(dir, "newline")
	if err := os.WriteFile(source, []byte(`
#include <stdio.h>

int main(void) {
	puts("line");
	return 0;
}
`), 0600); err != nil {
		t.Fatalf("write C source: %v", err)
	}

	build := exec.Command("gcc", source, "-o", binary)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build C target: %v: %s", err, out)
	}

	p, err := Process(binary)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	got, err := p.RecvUntilTimeout([]byte("\n"), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("RecvUntilTimeout failed after %q: %v", got, err)
	}
	if strings.Contains(string(got), "\r\n") {
		t.Fatalf("got %q, want raw newline without CR translation", got)
	}
}

func TestProcessPTYStillBuffersTerminalInputUntilEnter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process PTY is only implemented on linux")
	}

	inputMaster, inputSlave, err := openProcessPTYWithRaw(false)
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
		t.Fatalf("write terminal input: %v", err)
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
