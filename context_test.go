package gpwntools

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestContextFlatUsesBitsAndEndian(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.SetArch("i386")
	Context.Endian = "big"

	got, err := Flat(int(0x11223344), uint32(0x55667788))
	if err != nil {
		t.Fatalf("Flat failed: %v", err)
	}

	want := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestContextAsmDefaultArch(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.SetArch("i386")
	Context.Syntax = "intel"

	got, err := Asm("xor eax, eax\nret")
	if err != nil {
		if isMissingAsmToolError(err) {
			t.Skip(err)
		}
		t.Fatalf("Asm failed: %v", err)
	}

	want := []byte{0x31, 0xc0, 0xc3}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestContextTimeoutAppliesToNewProcess(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.Timeout = 150 * time.Millisecond

	p, err := Process("cat")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.timeout != 150*time.Millisecond {
		t.Fatalf("timeout = %s, want %s", p.timeout, 150*time.Millisecond)
	}
}

func TestContextTimeoutAffectsProcessRecv(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.Timeout = 50 * time.Millisecond

	p, err := ProcessWithOptions([]string{"sh", "-c", "sleep 1"}, ProcessOptions{
		DisablePTY: true,
	})
	if err != nil {
		t.Fatalf("ProcessWithOptions failed: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	start := time.Now()
	got, err := p.Recv(1)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Recv succeeded with %q, want timeout", got)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Recv returned after %s, want context timeout to apply", elapsed)
	}
}

func TestContextTimeoutAffectsProcessSendLineAfter(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.Timeout = 50 * time.Millisecond

	p, err := ProcessWithOptions([]string{"sh", "-c", "sleep 1"}, ProcessOptions{
		DisablePTY: true,
	})
	if err != nil {
		t.Fatalf("ProcessWithOptions failed: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	start := time.Now()
	got, err := p.SendLineAfter([]byte("never printed"), []byte("input"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("SendLineAfter succeeded after receiving %q, want timeout", got)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("SendLineAfter returned after %s, want context timeout to apply", elapsed)
	}
}

func TestContextKillOnTimeoutKillsProcess(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.Timeout = 50 * time.Millisecond
	Context.KillOnTimeout = true

	p, err := ProcessWithOptions([]string{"sh", "-c", "sleep 1"}, ProcessOptions{
		DisablePTY: true,
	})
	if err != nil {
		t.Fatalf("ProcessWithOptions failed: %v", err)
	}

	start := time.Now()
	_, err = p.Recv(1)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Recv succeeded, want timeout")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Recv error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Recv returned after %s, want timeout", elapsed)
	}

	if waitErr := p.Wait(); waitErr == nil {
		t.Fatal("Wait succeeded, want process termination after timeout")
	}
}

func TestContextTerminalSelection(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.SetTerminal("tmux", "split-window", "-h")

	got := contextTerminal()
	want := []string{"tmux", "split-window", "-h"}
	if len(got) != len(want) {
		t.Fatalf("terminal len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("terminal[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestContextSetTerminalByName(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	if err := Context.SetTerminalByName("wezterm"); err != nil {
		t.Fatalf("SetTerminalByName failed: %v", err)
	}

	got := contextTerminal()
	want := []string{"wezterm", "start", "--", "sh", "-lc"}
	if len(got) != len(want) {
		t.Fatalf("terminal len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("terminal[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func isMissingAsmToolError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no assembler found") ||
		strings.Contains(msg, "no objcopy found") ||
		strings.Contains(msg, "not found")
}
