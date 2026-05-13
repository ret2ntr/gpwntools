package gpwntools

import (
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
