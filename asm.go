package gpwntools

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultAsmArch     = "amd64"
	defaultAssembler   = "as"
	defaultObjcopyPath = "objcopy"
)

// AsmOptions configures assembly. Simple x86 snippets may be assembled by the
// built-in encoder; other code uses GNU as or clang plus objcopy.
type AsmOptions struct {
	// Arch is the target architecture. Supported values include amd64, i386, arm,
	// thumb, arm64/aarch64, mips, mipsel, mips64, and mips64el.
	Arch string
	// OS is the target operating system. It defaults to Context.OS.
	OS string
	// Syntax is "intel" or "att" for x86/x86_64. It defaults to "intel".
	Syntax string
	// As is the GNU assembler executable. It defaults to "as".
	// For non-native architectures, gpwntools searches common cross assemblers
	// and falls back to clang's integrated assembler when available.
	As string
	// Objcopy is the objcopy executable. It defaults to "objcopy" or
	// "llvm-objcopy" depending on the selected assembler backend.
	Objcopy string
	// Args are extra arguments passed to the assembler.
	Args []string
}

// Asm assembles code to raw machine bytes using Context defaults.
func Asm(code string) ([]byte, error) {
	return AsmWithOptions(code, AsmOptions{})
}

// MustAsm is Asm but panics on assembly errors.
func MustAsm(code string) []byte {
	out, err := Asm(code)
	if err != nil {
		panic(err)
	}
	return out
}

// AsmArch assembles code for a specific architecture.
//
// Deprecated: use AsmWithOptions with AsmOptions{Arch: "..."} when overriding
// context defaults.
func AsmArch(code string, arch string) ([]byte, error) {
	return AsmWithOptions(code, AsmOptions{Arch: arch})
}

// AsmWithOptions assembles code to raw machine bytes.
func AsmWithOptions(code string, opts AsmOptions) ([]byte, error) {
	if strings.TrimSpace(code) == "" {
		return []byte{}, nil
	}

	arch := asmArch(opts)
	osName := asmOS(opts)
	if out, ok, err := asmBuiltin(code, arch, osName, asmSyntax(arch, opts)); ok || err != nil {
		return out, err
	}

	toolchain, err := asmToolchain(arch, osName, opts)
	if err != nil {
		return nil, err
	}
	source, err := asmSource(code, arch, asmSyntax(arch, opts))
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "gpwntools-asm-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	asmPath := filepath.Join(dir, "input.s")
	objPath := filepath.Join(dir, "output.o")
	binPath := filepath.Join(dir, "output.bin")

	if err := os.WriteFile(asmPath, []byte(source), 0600); err != nil {
		return nil, err
	}

	args := append([]string{}, toolchain.assemblerArgs...)
	args = append(args, opts.Args...)
	args = append(args, "-o", objPath, asmPath)
	if out, err := exec.Command(toolchain.assembler, args...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("assemble failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	objcopyArgs := []string{"-O", "binary", "-j", ".text", objPath, binPath}
	if out, err := exec.Command(toolchain.objcopy, objcopyArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("objcopy failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return os.ReadFile(binPath)
}

func asmArch(opts AsmOptions) string {
	if opts.Arch == "" {
		return contextArch()
	}
	return strings.ToLower(opts.Arch)
}

func asmOS(opts AsmOptions) string {
	if opts.OS == "" {
		return contextOS()
	}
	return normalizeContextOS(opts.OS)
}

func asmSyntax(arch string, opts AsmOptions) string {
	if opts.Syntax != "" {
		return opts.Syntax
	}
	if normalizedAsmFamily(arch) == "x86" {
		return contextSyntax()
	}
	return ""
}

type asmToolchainConfig struct {
	gnuArgs           []string
	gnuAssemblers     []string
	clangTarget       string
	objcopies         []string
	allowHostTools    bool
	preferLLVMObjcopy bool
}

type asmToolchainPlan struct {
	assembler     string
	assemblerArgs []string
	objcopy       string
}

func asmToolchain(arch string, osName string, opts AsmOptions) (asmToolchainPlan, error) {
	cfg, err := asmToolchainConfigForArch(arch, osName)
	if err != nil {
		return asmToolchainPlan{}, err
	}

	assembler, assemblerArgs, usingClang, err := selectAssembler(cfg, opts)
	if err != nil {
		return asmToolchainPlan{}, err
	}

	objcopy, err := selectObjcopy(cfg, opts, usingClang)
	if err != nil {
		return asmToolchainPlan{}, err
	}

	return asmToolchainPlan{
		assembler:     assembler,
		assemblerArgs: assemblerArgs,
		objcopy:       objcopy,
	}, nil
}

func asmToolchainConfigForArch(arch string, osName string) (asmToolchainConfig, error) {
	switch arch {
	case "amd64", "x86_64", "x64":
		return asmToolchainConfig{
			gnuArgs:           []string{"--64"},
			gnuAssemblers:     []string{defaultAssembler},
			clangTarget:       asmClangTarget("x86_64", osName),
			objcopies:         []string{defaultObjcopyPath, "llvm-objcopy"},
			allowHostTools:    asmHostToolsAllowed(osName),
			preferLLVMObjcopy: false,
		}, nil
	case "i386", "x86", "386":
		return asmToolchainConfig{
			gnuArgs:           []string{"--32"},
			gnuAssemblers:     []string{defaultAssembler},
			clangTarget:       asmClangTarget("i386", osName),
			objcopies:         []string{defaultObjcopyPath, "llvm-objcopy"},
			allowHostTools:    asmHostToolsAllowed(osName),
			preferLLVMObjcopy: false,
		}, nil
	case "arm", "arm32":
		return asmCrossToolchain(asmClangTarget("arm", osName), []string{
			"arm-linux-gnueabi-as",
			"arm-linux-gnueabihf-as",
			"arm-none-eabi-as",
		}, []string{
			"arm-linux-gnueabi-objcopy",
			"arm-linux-gnueabihf-objcopy",
			"arm-none-eabi-objcopy",
		}), nil
	case "thumb", "thumb32":
		return asmCrossToolchain(asmClangTarget("arm", osName), []string{
			"arm-linux-gnueabi-as",
			"arm-linux-gnueabihf-as",
			"arm-none-eabi-as",
		}, []string{
			"arm-linux-gnueabi-objcopy",
			"arm-linux-gnueabihf-objcopy",
			"arm-none-eabi-objcopy",
		}), nil
	case "arm64", "aarch64":
		return asmCrossToolchain(asmClangTarget("aarch64", osName), []string{
			"aarch64-linux-gnu-as",
			"aarch64-none-elf-as",
		}, []string{
			"aarch64-linux-gnu-objcopy",
			"aarch64-none-elf-objcopy",
		}), nil
	case "mips":
		return asmCrossToolchain(asmClangTarget("mips", osName), []string{
			"mips-linux-gnu-as",
			"mips-linux-musl-as",
		}, []string{
			"mips-linux-gnu-objcopy",
			"mips-linux-musl-objcopy",
		}), nil
	case "mipsel", "mipsle":
		return asmCrossToolchain(asmClangTarget("mipsel", osName), []string{
			"mipsel-linux-gnu-as",
			"mipsel-linux-musl-as",
		}, []string{
			"mipsel-linux-gnu-objcopy",
			"mipsel-linux-musl-objcopy",
		}), nil
	case "mips64":
		return asmCrossToolchain(asmClangTarget("mips64", osName), []string{
			"mips64-linux-gnuabi64-as",
		}, []string{
			"mips64-linux-gnuabi64-objcopy",
		}), nil
	case "mips64el", "mips64le":
		return asmCrossToolchain(asmClangTarget("mips64el", osName), []string{
			"mips64el-linux-gnuabi64-as",
		}, []string{
			"mips64el-linux-gnuabi64-objcopy",
		}), nil
	default:
		return asmToolchainConfig{}, fmt.Errorf("unsupported asm arch %q", arch)
	}
}

func asmCrossToolchain(clangTarget string, assemblers []string, objcopies []string) asmToolchainConfig {
	cfg := asmToolchainConfig{
		gnuAssemblers:     assemblers,
		clangTarget:       clangTarget,
		objcopies:         append(append([]string{}, objcopies...), "llvm-objcopy"),
		preferLLVMObjcopy: true,
	}
	if asmHostMatchesTarget(clangTarget) {
		cfg.gnuAssemblers = append(cfg.gnuAssemblers, defaultAssembler)
		cfg.objcopies = append(cfg.objcopies, defaultObjcopyPath)
		cfg.allowHostTools = true
	}
	return cfg
}

func asmHostToolsAllowed(osName string) bool {
	return runtime.GOOS == "linux" && normalizeContextOS(osName) == "linux"
}

func asmClangTarget(arch string, osName string) string {
	osName = normalizeContextOS(osName)
	if osName == "" {
		osName = "linux"
	}

	switch osName {
	case "linux":
		switch arch {
		case "x86_64":
			return "x86_64-linux-gnu"
		case "i386":
			return "i386-linux-gnu"
		case "arm":
			return "arm-linux-gnueabi"
		case "aarch64":
			return "aarch64-linux-gnu"
		case "mips":
			return "mips-linux-gnu"
		case "mipsel":
			return "mipsel-linux-gnu"
		case "mips64":
			return "mips64-linux-gnuabi64"
		case "mips64el":
			return "mips64el-linux-gnuabi64"
		}
	case "freebsd":
		return arch + "-unknown-freebsd"
	case "openbsd":
		return arch + "-unknown-openbsd"
	case "netbsd":
		return arch + "-unknown-netbsd"
	case "darwin":
		return arch + "-apple-darwin"
	case "windows":
		if arch == "i386" {
			return "i686-w64-windows-gnu"
		}
		return arch + "-w64-windows-gnu"
	}
	return arch + "-unknown-" + osName
}

func selectAssembler(cfg asmToolchainConfig, opts AsmOptions) (string, []string, bool, error) {
	if opts.As != "" {
		path, err := exec.LookPath(opts.As)
		if err != nil {
			return "", nil, false, fmt.Errorf("assembler %q not found", opts.As)
		}
		if isClang(path) {
			return path, []string{"-target", cfg.clangTarget, "-c"}, true, nil
		}
		return path, cfg.gnuArgs, false, nil
	}

	if cfg.allowHostTools {
		if path, ok := firstExecutable(cfg.gnuAssemblers); ok {
			return path, cfg.gnuArgs, false, nil
		}
	}

	if path, ok := firstExecutable([]string{"clang"}); ok {
		return path, []string{"-target", cfg.clangTarget, "-c"}, true, nil
	}

	return "", nil, false, fmt.Errorf("no assembler found for target %q; install one of %s or clang in the process runtime environment", cfg.clangTarget, strings.Join(cfg.gnuAssemblers, ", "))
}

func selectObjcopy(cfg asmToolchainConfig, opts AsmOptions, usingClang bool) (string, error) {
	if opts.Objcopy != "" {
		path, err := exec.LookPath(opts.Objcopy)
		if err != nil {
			return "", fmt.Errorf("objcopy %q not found", opts.Objcopy)
		}
		return path, nil
	}

	candidates := cfg.objcopies
	if usingClang || cfg.preferLLVMObjcopy {
		candidates = preferTool(candidates, "llvm-objcopy")
	}

	if path, ok := firstExecutable(candidates); ok {
		return path, nil
	}
	return "", fmt.Errorf("no objcopy found; install one of %s", strings.Join(candidates, ", "))
}

func firstExecutable(candidates []string) (string, bool) {
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path, true
		}
	}
	return "", false
}

func preferTool(candidates []string, tool string) []string {
	out := []string{tool}
	for _, candidate := range candidates {
		if candidate != tool {
			out = append(out, candidate)
		}
	}
	return out
}

func isClang(path string) bool {
	base := filepath.Base(path)
	return strings.Contains(base, "clang")
}

func asmHostMatchesTarget(target string) bool {
	if runtime.GOOS != "linux" || !strings.Contains(target, "-linux-") {
		return false
	}
	switch runtime.GOARCH {
	case "arm":
		return strings.HasPrefix(target, "arm-")
	case "arm64":
		return strings.HasPrefix(target, "aarch64-")
	case "mips":
		return strings.HasPrefix(target, "mips-") && !strings.HasPrefix(target, "mipsel-")
	case "mipsle":
		return strings.HasPrefix(target, "mipsel-")
	case "mips64":
		return strings.HasPrefix(target, "mips64-") && !strings.HasPrefix(target, "mips64el-")
	case "mips64le":
		return strings.HasPrefix(target, "mips64el-")
	default:
		return false
	}
}

func asmBuiltin(code string, arch string, osName string, syntax string) ([]byte, bool, error) {
	if normalizedAsmFamily(arch) != "x86" {
		return nil, false, nil
	}
	if syntax != "" {
		switch strings.ToLower(strings.TrimSpace(syntax)) {
		case "intel", "default":
		default:
			return nil, false, nil
		}
	}

	instructions := asmBuiltinInstructions(code)
	if len(instructions) == 0 {
		return []byte{}, true, nil
	}

	out := make([]byte, 0, len(instructions)*4)
	for _, inst := range instructions {
		chunk, ok, err := asmBuiltinX86Instruction(inst, arch, osName)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		out = append(out, chunk...)
	}
	return out, true, nil
}

func asmBuiltinInstructions(code string) []string {
	var out []string
	for _, line := range strings.Split(code, "\n") {
		line = strings.TrimSpace(stripAsmBuiltinComment(line))
		if line == "" {
			continue
		}
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func stripAsmBuiltinComment(line string) string {
	for _, marker := range []string{"//", "#"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			line = line[:idx]
		}
	}
	return line
}

func asmBuiltinX86Instruction(inst string, arch string, osName string) ([]byte, bool, error) {
	normalized := normalizeAsmBuiltinInstruction(inst)
	switch normalized {
	case "nop":
		return []byte{0x90}, true, nil
	case "ret":
		return []byte{0xc3}, true, nil
	case "leave":
		return []byte{0xc9}, true, nil
	case "syscall":
		return []byte{0x0f, 0x05}, true, nil
	case "int 0x80", "int 80h":
		return []byte{0xcd, 0x80}, true, nil
	case "xor eax,eax":
		return []byte{0x31, 0xc0}, true, nil
	case "xor rax,rax":
		if !asmBuiltinX86Is64Bit(arch) {
			return nil, false, nil
		}
		return []byte{0x48, 0x31, 0xc0}, true, nil
	}

	if strings.HasPrefix(normalized, "mov ") {
		chunk, ok, err := asmBuiltinX86MovImmediate(strings.TrimSpace(normalized[len("mov "):]), arch, osName)
		return chunk, ok, err
	}

	if strings.HasPrefix(normalized, "pop ") {
		chunk, ok := asmBuiltinX86Pop(strings.TrimSpace(normalized[len("pop "):]), arch)
		return chunk, ok, nil
	}

	return nil, false, nil
}

func normalizeAsmBuiltinInstruction(inst string) string {
	inst = strings.ToLower(strings.TrimSpace(inst))
	inst = strings.ReplaceAll(inst, "\t", " ")
	for strings.Contains(inst, "  ") {
		inst = strings.ReplaceAll(inst, "  ", " ")
	}
	inst = strings.ReplaceAll(inst, ", ", ",")
	inst = strings.ReplaceAll(inst, " ,", ",")
	return inst
}

func asmBuiltinX86MovImmediate(operands string, arch string, osName string) ([]byte, bool, error) {
	parts := strings.SplitN(operands, ",", 2)
	if len(parts) != 2 {
		return nil, false, nil
	}
	reg := strings.TrimSpace(parts[0])
	imm, err := parseAsmBuiltinImmediate(parts[1], arch, osName)
	if err != nil {
		return nil, false, err
	}

	if code, ok := asmBuiltinX86Reg8(reg); ok {
		return []byte{0xb0 + code, byte(imm)}, true, nil
	}
	if code, ok := asmBuiltinX86Reg32(reg); ok {
		out := make([]byte, 5)
		out[0] = 0xb8 + code
		binary.LittleEndian.PutUint32(out[1:], uint32(imm))
		return out, true, nil
	}
	if asmBuiltinX86Is64Bit(arch) {
		if code, ok := asmBuiltinX86Reg64(reg); ok {
			out := make([]byte, 10)
			if code >= 8 {
				out[0] = 0x49
				out[1] = 0xb8 + (code - 8)
			} else {
				out[0] = 0x48
				out[1] = 0xb8 + code
			}
			binary.LittleEndian.PutUint64(out[2:], imm)
			return out, true, nil
		}
	}
	return nil, false, nil
}

func asmBuiltinX86Pop(reg string, arch string) ([]byte, bool) {
	if asmBuiltinX86Is64Bit(arch) {
		if code, ok := asmBuiltinX86Reg64(reg); ok {
			if code >= 8 {
				return []byte{0x41, 0x58 + (code - 8)}, true
			}
			return []byte{0x58 + code}, true
		}
	}
	if code, ok := asmBuiltinX86Reg32(reg); ok {
		return []byte{0x58 + code}, true
	}
	return nil, false
}

func asmBuiltinX86Is64Bit(arch string) bool {
	switch arch {
	case "amd64", "x86_64", "x64":
		return true
	default:
		return false
	}
}

func asmBuiltinX86Reg8(reg string) (byte, bool) {
	switch reg {
	case "al":
		return 0, true
	case "cl":
		return 1, true
	case "dl":
		return 2, true
	case "bl":
		return 3, true
	default:
		return 0, false
	}
}

func asmBuiltinX86Reg32(reg string) (byte, bool) {
	switch reg {
	case "eax":
		return 0, true
	case "ecx":
		return 1, true
	case "edx":
		return 2, true
	case "ebx":
		return 3, true
	case "esp":
		return 4, true
	case "ebp":
		return 5, true
	case "esi":
		return 6, true
	case "edi":
		return 7, true
	default:
		return 0, false
	}
}

func asmBuiltinX86Reg64(reg string) (byte, bool) {
	switch reg {
	case "rax":
		return 0, true
	case "rcx":
		return 1, true
	case "rdx":
		return 2, true
	case "rbx":
		return 3, true
	case "rsp":
		return 4, true
	case "rbp":
		return 5, true
	case "rsi":
		return 6, true
	case "rdi":
		return 7, true
	case "r8":
		return 8, true
	case "r9":
		return 9, true
	case "r10":
		return 10, true
	case "r11":
		return 11, true
	case "r12":
		return 12, true
	case "r13":
		return 13, true
	case "r14":
		return 14, true
	case "r15":
		return 15, true
	default:
		return 0, false
	}
}

func parseAsmBuiltinImmediate(raw string, arch string, osName string) (uint64, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "$")
	if strings.HasPrefix(strings.ToUpper(value), "SYS_") || strings.HasPrefix(strings.ToUpper(value), "__NR_") {
		return asmSyscallNumber(value, arch, osName)
	}
	if strings.HasSuffix(strings.ToLower(value), "h") {
		return strconv.ParseUint(strings.TrimSuffix(strings.ToLower(value), "h"), 16, 64)
	}
	return strconv.ParseUint(value, 0, 64)
}

func asmSyscallNumber(name string, arch string, osName string) (uint64, error) {
	original := strings.TrimSpace(name)
	name = original
	upper := strings.ToUpper(name)
	switch {
	case strings.HasPrefix(upper, "SYS_"):
		name = name[4:]
	case strings.HasPrefix(upper, "__NR_"):
		name = name[5:]
	}
	key := strings.ToLower(name)
	table := map[string]map[string]uint64{
		"linux/amd64": {
			"read": 0, "write": 1, "open": 2, "close": 3, "select": 23, "execve": 59, "exit": 60,
		},
		"linux/i386": {
			"exit": 1, "read": 3, "write": 4, "open": 5, "close": 6, "execve": 11, "select": 82,
		},
		"freebsd/amd64": {
			"read": 3, "write": 4, "open": 5, "close": 6, "execve": 59, "select": 93, "exit": 1,
		},
		"freebsd/i386": {
			"read": 3, "write": 4, "open": 5, "close": 6, "execve": 59, "select": 93, "exit": 1,
		},
	}
	tableKey := normalizeContextOS(osName) + "/" + canonicalAsmSyscallArch(arch)
	if syscalls, ok := table[tableKey]; ok {
		if number, ok := syscalls[key]; ok {
			return number, nil
		}
	}
	return 0, fmt.Errorf("unsupported syscall constant %q for %s", original, tableKey)
}

func canonicalAsmSyscallArch(arch string) string {
	switch arch {
	case "amd64", "x86_64", "x64":
		return "amd64"
	case "i386", "x86", "386":
		return "i386"
	default:
		return arch
	}
}

func asmSource(code string, arch string, syntax string) (string, error) {
	var b strings.Builder
	switch normalizedAsmFamily(arch) {
	case "x86":
		if syntax == "" {
			syntax = "intel"
		}
		switch strings.ToLower(syntax) {
		case "intel":
			b.WriteString(".intel_syntax noprefix\n")
		case "att", "at&t":
			b.WriteString(".att_syntax prefix\n")
		default:
			return "", fmt.Errorf("unsupported asm syntax %q", syntax)
		}
	case "arm":
		if syntax != "" && syntax != "default" {
			return "", fmt.Errorf("asm syntax %q is only supported for x86", syntax)
		}
		b.WriteString(".syntax unified\n")
		if arch == "thumb" || arch == "thumb32" {
			b.WriteString(".thumb\n")
		} else {
			b.WriteString(".arm\n")
		}
	case "aarch64":
		if syntax != "" && syntax != "default" {
			return "", fmt.Errorf("asm syntax %q is only supported for x86", syntax)
		}
	case "mips":
		if syntax != "" && syntax != "default" {
			return "", fmt.Errorf("asm syntax %q is only supported for x86", syntax)
		}
		b.WriteString(".set noreorder\n")
	default:
		return "", fmt.Errorf("unsupported asm arch %q", arch)
	}

	b.WriteString(".section .text\n")
	b.WriteString(".global _start\n")
	b.WriteString("_start:\n")
	b.WriteString(code)
	if !strings.HasSuffix(code, "\n") {
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func normalizedAsmFamily(arch string) string {
	switch arch {
	case "amd64", "x86_64", "x64", "i386", "x86", "386":
		return "x86"
	case "arm", "arm32", "thumb", "thumb32":
		return "arm"
	case "arm64", "aarch64":
		return "aarch64"
	case "mips", "mipsel", "mipsle", "mips64", "mips64el", "mips64le":
		return "mips"
	default:
		return ""
	}
}
