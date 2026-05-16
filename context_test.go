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

func TestAsmBuiltinRetDoesNotRequireExternalAssembler(t *testing.T) {
	got, err := AsmWithOptions("ret", AsmOptions{
		Arch: "amd64",
		OS:   "linux",
		As:   "/definitely/missing/as",
	})
	if err != nil {
		t.Fatalf("AsmWithOptions(ret) failed: %v", err)
	}
	if !bytes.Equal(got, []byte{0xc3}) {
		t.Fatalf("AsmWithOptions(ret) = %#v, want %#v", got, []byte{0xc3})
	}
}

func TestAsmBuiltinSyscallConstant(t *testing.T) {
	got, err := AsmWithOptions("mov eax, SYS_select\nret", AsmOptions{
		Arch: "i386",
		OS:   "linux",
		As:   "/definitely/missing/as",
	})
	if err != nil {
		t.Fatalf("AsmWithOptions(SYS_select) failed: %v", err)
	}
	want := []byte{0xb8, 0x52, 0x00, 0x00, 0x00, 0xc3}
	if !bytes.Equal(got, want) {
		t.Fatalf("AsmWithOptions(SYS_select) = %#v, want %#v", got, want)
	}
}

func TestAsmBuiltinFreeBSDSyscallConstant(t *testing.T) {
	got, err := AsmWithOptions("mov eax, SYS_select", AsmOptions{
		Arch: "i386",
		OS:   "freebsd",
		As:   "/definitely/missing/as",
	})
	if err != nil {
		t.Fatalf("AsmWithOptions(freebsd SYS_select) failed: %v", err)
	}
	want := []byte{0xb8, 0x5d, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("AsmWithOptions(freebsd SYS_select) = %#v, want %#v", got, want)
	}
}

func TestAsmFallbackExpandsSyscallConstants(t *testing.T) {
	got, err := AsmWithOptions("lea rdi, [rsp]\nmov eax, SYS_open\nsyscall", AsmOptions{
		Arch: "amd64",
		OS:   "linux",
	})
	if err != nil {
		if isMissingAsmToolError(err) {
			t.Skip(err)
		}
		t.Fatalf("AsmWithOptions fallback failed: %v", err)
	}
	want := []byte{0xb8, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Contains(got, want) {
		t.Fatalf("fallback asm did not expand SYS_open: got %#v, want bytes %#v", got, want)
	}
}

func TestAsmExpandSyscallConstantsSkipsCommentsAndStrings(t *testing.T) {
	got, err := asmExpandSyscallConstants("mov eax, SYS_open # SYS_missing\n.ascii \"SYS_write\"\n", "amd64", "linux")
	if err != nil {
		t.Fatalf("asmExpandSyscallConstants failed: %v", err)
	}
	want := "mov eax, 2 # SYS_missing\n.ascii \"SYS_write\"\n"
	if got != want {
		t.Fatalf("expanded asm = %q, want %q", got, want)
	}
}

func TestAsmExpandSyscallConstantsKeepsAArch64ImmediatePrefix(t *testing.T) {
	got, err := asmExpandSyscallConstants("mov x8, #SYS_mmap\nsvc #0\n", "aarch64", "linux")
	if err != nil {
		t.Fatalf("asmExpandSyscallConstants failed: %v", err)
	}
	want := "mov x8, #222\nsvc #0\n"
	if got != want {
		t.Fatalf("expanded aarch64 asm = %q, want %q", got, want)
	}
}

func TestAsmSyscallNumbersAdditionalLinuxArchitectures(t *testing.T) {
	cases := []struct {
		arch string
		name string
		want uint64
	}{
		{"arm", "SYS_open", 5},
		{"aarch64", "SYS_openat", 56},
		{"mips", "SYS_open", 4005},
		{"mipsel", "SYS_open", 4005},
		{"mips64", "SYS_execve", 5057},
		{"mips64el", "SYS_execve", 5057},
		{"amd64", "SYS_bpf", 321},
		{"i386", "SYS_mmap2", 192},
		{"arm", "SYS_execveat", 387},
		{"aarch64", "SYS_mmap", 222},
		{"mips", "SYS_mmap2", 4210},
		{"mips64", "SYS_mmap", 5009},
		{"amd64", "SYS_sendfile", 40},
		{"arm", "SYS_sendfile", 187},
		{"aarch64", "SYS_sendfile", 71},
		{"mips", "SYS_sendfile", 4207},
		{"mips64", "SYS_sendfile", 5039},
	}

	for _, tc := range cases {
		t.Run(tc.arch+"/"+tc.name, func(t *testing.T) {
			got, err := asmSyscallNumber(tc.name, tc.arch, "linux")
			if err != nil {
				t.Fatalf("asmSyscallNumber failed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("asmSyscallNumber(%q, %q) = %d, want %d", tc.name, tc.arch, got, tc.want)
			}
		})
	}
}

func TestAsmBuiltinRespectsI386Registers(t *testing.T) {
	got, err := AsmWithOptions("pop edi", AsmOptions{
		Arch: "i386",
		OS:   "linux",
		As:   "/definitely/missing/as",
	})
	if err != nil {
		t.Fatalf("AsmWithOptions(pop edi) failed: %v", err)
	}
	if !bytes.Equal(got, []byte{0x5f}) {
		t.Fatalf("AsmWithOptions(pop edi) = %#v, want %#v", got, []byte{0x5f})
	}

	if got, err := AsmWithOptions("pop rdi", AsmOptions{
		Arch: "i386",
		OS:   "linux",
		As:   "/definitely/missing/as",
	}); err == nil {
		t.Fatalf("AsmWithOptions(pop rdi) = %#v, want error", got)
	}
}

func TestAsmOptionsUseContextOS(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.SetArch("i386")
	Context.SetOS("freebsd")

	if got := asmOS(AsmOptions{}); got != "freebsd" {
		t.Fatalf("asmOS = %q, want %q", got, "freebsd")
	}
	if got := asmClangTarget("i386", asmOS(AsmOptions{})); got != "i386-unknown-freebsd" {
		t.Fatalf("asm clang target = %q, want %q", got, "i386-unknown-freebsd")
	}
	if got := asmClangTarget("x86_64", asmOS(AsmOptions{OS: "linux"})); got != "x86_64-linux-gnu" {
		t.Fatalf("asm override target = %q, want %q", got, "x86_64-linux-gnu")
	}
}

func TestWindowsAsmTargetDoesNotUseHostAssembler(t *testing.T) {
	cfg, err := asmToolchainConfigForArch("amd64", "windows")
	if err != nil {
		t.Fatalf("asmToolchainConfigForArch failed: %v", err)
	}
	if cfg.allowHostTools {
		t.Fatal("windows asm target allowed host GNU as")
	}
	if cfg.clangTarget != "x86_64-w64-windows-gnu" {
		t.Fatalf("clang target = %q, want %q", cfg.clangTarget, "x86_64-w64-windows-gnu")
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

func TestDefaultContextInteractiveEcho(t *testing.T) {
	defaults := DefaultContext()
	if !defaults.InteractiveSystemEcho {
		t.Fatal("InteractiveSystemEcho default is false, want true")
	}
	if defaults.InteractiveLineEcho {
		t.Fatal("InteractiveLineEcho default is true, want false")
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
