package gpwntools

import (
	"strings"
	"testing"
)

func TestShellcraftShAmd64(t *testing.T) {
	sc := Shellcraft.WithArch("amd64").WithOS("linux")
	code := sc.Sh()

	for _, want := range []string{
		"sub rsp, 0xa",
		"mov rdi, rsp",
		"xor rsi, rsi",
		"xor rdx, rdx",
		"mov rax, 0x3b",
		"syscall",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("Shellcraft.Sh() missing %q:\n%s", want, code)
		}
	}

	payload, err := sc.Asm(code)
	if err != nil {
		if isMissingAsmToolError(err) {
			t.Skip(err)
		}
		t.Fatalf("assembling Shellcraft.Sh failed: %v\n%s", err, code)
	}
	if len(payload) == 0 {
		t.Fatal("assembling Shellcraft.Sh returned empty payload")
	}
}

func TestShellcraftI386OpenRegister(t *testing.T) {
	code := Shellcraft.WithArch("i386").WithOS("linux").Open("esp")

	for _, want := range []string{
		"mov ebx, esp",
		"xor ecx, ecx",
		"xor edx, edx",
		"mov eax, 0x5",
		"int 0x80",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("Shellcraft.Open(\"esp\") missing %q:\n%s", want, code)
		}
	}
}

func TestShellcraftORWUsesReadResultForWriteSize(t *testing.T) {
	code := Shellcraft.WithArch("amd64").WithOS("linux").ORW("/flag", 0x40)

	for _, want := range []string{
		"mov rax, 0x2",
		"mov rdi, rax",
		"mov rdx, 0x40",
		"xor rax, rax",
		"mov rdi, 0x1",
		"mov rdx, rax",
		"mov rax, 0x1",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("Shellcraft.ORW missing %q:\n%s", want, code)
		}
	}
}

func TestShellcraftAdditionalLinuxArchitectures(t *testing.T) {
	cases := []struct {
		arch string
		want []string
	}{
		{"arm", []string{"mov r0, sp", "movw r7, #0xb", "svc 0"}},
		{"aarch64", []string{"mov x0, sp", "movz x8, #0xdd", "svc #0"}},
		{"mips", []string{"move $a0, $sp", "li $v0, 0xfab", "syscall"}},
		{"mipsel", []string{"move $a0, $sp", "li $v0, 0xfab", "syscall"}},
		{"mips64", []string{"move $a0, $sp", "li $v0, 0x13c1", "syscall"}},
		{"mips64el", []string{"move $a0, $sp", "li $v0, 0x13c1", "syscall"}},
	}

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			code := Shellcraft.WithArch(tc.arch).WithOS("linux").Sh()
			for _, want := range tc.want {
				if !strings.Contains(code, want) {
					t.Fatalf("Shellcraft.Sh(%s) missing %q:\n%s", tc.arch, want, code)
				}
			}
		})
	}
}

func TestShellcraftAArch64OpenUsesOpenAt(t *testing.T) {
	code := Shellcraft.WithArch("aarch64").WithOS("linux").Open("sp")

	for _, want := range []string{
		"movz x0, #0xff9c",
		"mov x1, sp",
		"movz x8, #0x38",
		"svc #0",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("Shellcraft.Open(aarch64) missing %q:\n%s", want, code)
		}
	}
}

func TestShellcraftMIPSEndianPushString(t *testing.T) {
	mips := Shellcraft.WithArch("mips").WithOS("linux").PushString("ABCD")
	if !strings.Contains(mips, "li $t9, 0x41424344") {
		t.Fatalf("mips PushString did not store big-endian word:\n%s", mips)
	}

	mipsel := Shellcraft.WithArch("mipsel").WithOS("linux").PushString("ABCD")
	if !strings.Contains(mipsel, "li $t9, 0x44434241") {
		t.Fatalf("mipsel PushString did not store little-endian word:\n%s", mipsel)
	}
}

func TestShellcraftMmap(t *testing.T) {
	cases := []struct {
		arch string
		want []string
	}{
		{"amd64", []string{"mov rax, 0x9", "syscall"}},
		{"i386", []string{"mov eax, 0xc0", "int 0x80"}},
		{"arm", []string{"movw r7, #0xc0", "svc 0"}},
		{"aarch64", []string{"movz x8, #0xde", "svc #0"}},
		{"mips", []string{"li $v0, 0x1072", "sw $t9, 16($sp)", "sw $t9, 20($sp)", "syscall"}},
		{"mips64", []string{"li $v0, 0x1391", "syscall"}},
	}

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			code := Shellcraft.WithArch(tc.arch).WithOS("linux").Mmap(0, 0x1000, 7, 0x22, -1, 0)
			for _, want := range tc.want {
				if !strings.Contains(code, want) {
					t.Fatalf("Shellcraft.Mmap(%s) missing %q:\n%s", tc.arch, want, code)
				}
			}
		})
	}
}

func TestShellcraftSendfile(t *testing.T) {
	cases := []struct {
		arch string
		want []string
	}{
		{"amd64", []string{"mov rdi, 0x1", "mov rsi, 0x3", "xor rdx, rdx", "mov r10, 0x100", "mov rax, 0x28", "syscall"}},
		{"i386", []string{"mov ebx, 0x1", "mov ecx, 0x3", "xor edx, edx", "mov esi, 0x100", "mov eax, 0xbb", "int 0x80"}},
		{"arm", []string{"movw r7, #0xbb", "svc 0"}},
		{"aarch64", []string{"movz x8, #0x47", "svc #0"}},
		{"mips", []string{"li $v0, 0x106f", "syscall"}},
		{"mips64", []string{"li $v0, 0x13af", "syscall"}},
	}

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			code := Shellcraft.WithArch(tc.arch).WithOS("linux").Sendfile(1, 3, 0, 0x100)
			for _, want := range tc.want {
				if !strings.Contains(code, want) {
					t.Fatalf("Shellcraft.Sendfile(%s) missing %q:\n%s", tc.arch, want, code)
				}
			}
		})
	}
}

func TestShellcraftSyscallFullLinuxTable(t *testing.T) {
	code := Shellcraft.WithArch("amd64").WithOS("linux").Syscall("bpf", 0, 0, 0)
	if !strings.Contains(code, "mov rax, 0x141") {
		t.Fatalf("Shellcraft.Syscall(bpf) did not use full syscall table:\n%s", code)
	}
}
