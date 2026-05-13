package gpwntools

import (
	"bytes"
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

func isMissingAsmToolError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no assembler found") ||
		strings.Contains(msg, "no objcopy found") ||
		strings.Contains(msg, "not found")
}
