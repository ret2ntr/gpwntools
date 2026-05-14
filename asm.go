package gpwntools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	defaultAsmArch     = "amd64"
	defaultAssembler   = "as"
	defaultObjcopyPath = "objcopy"
)

// AsmOptions configures assembly through GNU as and objcopy.
type AsmOptions struct {
	// Arch is the target architecture. Supported values include amd64, i386, arm,
	// thumb, arm64/aarch64, mips, mipsel, mips64, and mips64el.
	Arch string
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

// Asm assembles code to raw machine bytes. It defaults to amd64 Intel syntax.
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
func AsmArch(code string, arch string) ([]byte, error) {
	return AsmWithOptions(code, AsmOptions{Arch: arch})
}

// AsmWithOptions assembles code to raw machine bytes using GNU as and objcopy.
func AsmWithOptions(code string, opts AsmOptions) ([]byte, error) {
	if strings.TrimSpace(code) == "" {
		return []byte{}, nil
	}

	arch := asmArch(opts)
	toolchain, err := asmToolchain(arch, opts)
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

func asmToolchain(arch string, opts AsmOptions) (asmToolchainPlan, error) {
	cfg, err := asmToolchainConfigForArch(arch)
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

func asmToolchainConfigForArch(arch string) (asmToolchainConfig, error) {
	switch arch {
	case "amd64", "x86_64", "x64":
		return asmToolchainConfig{
			gnuArgs:           []string{"--64"},
			gnuAssemblers:     []string{defaultAssembler},
			clangTarget:       "x86_64-linux-gnu",
			objcopies:         []string{defaultObjcopyPath, "llvm-objcopy"},
			allowHostTools:    true,
			preferLLVMObjcopy: false,
		}, nil
	case "i386", "x86", "386":
		return asmToolchainConfig{
			gnuArgs:           []string{"--32"},
			gnuAssemblers:     []string{defaultAssembler},
			clangTarget:       "i386-linux-gnu",
			objcopies:         []string{defaultObjcopyPath, "llvm-objcopy"},
			allowHostTools:    true,
			preferLLVMObjcopy: false,
		}, nil
	case "arm", "arm32":
		return asmCrossToolchain("arm-linux-gnueabi", []string{
			"arm-linux-gnueabi-as",
			"arm-linux-gnueabihf-as",
			"arm-none-eabi-as",
		}, []string{
			"arm-linux-gnueabi-objcopy",
			"arm-linux-gnueabihf-objcopy",
			"arm-none-eabi-objcopy",
		}), nil
	case "thumb", "thumb32":
		return asmCrossToolchain("arm-linux-gnueabi", []string{
			"arm-linux-gnueabi-as",
			"arm-linux-gnueabihf-as",
			"arm-none-eabi-as",
		}, []string{
			"arm-linux-gnueabi-objcopy",
			"arm-linux-gnueabihf-objcopy",
			"arm-none-eabi-objcopy",
		}), nil
	case "arm64", "aarch64":
		return asmCrossToolchain("aarch64-linux-gnu", []string{
			"aarch64-linux-gnu-as",
			"aarch64-none-elf-as",
		}, []string{
			"aarch64-linux-gnu-objcopy",
			"aarch64-none-elf-objcopy",
		}), nil
	case "mips":
		return asmCrossToolchain("mips-linux-gnu", []string{
			"mips-linux-gnu-as",
			"mips-linux-musl-as",
		}, []string{
			"mips-linux-gnu-objcopy",
			"mips-linux-musl-objcopy",
		}), nil
	case "mipsel", "mipsle":
		return asmCrossToolchain("mipsel-linux-gnu", []string{
			"mipsel-linux-gnu-as",
			"mipsel-linux-musl-as",
		}, []string{
			"mipsel-linux-gnu-objcopy",
			"mipsel-linux-musl-objcopy",
		}), nil
	case "mips64":
		return asmCrossToolchain("mips64-linux-gnuabi64", []string{
			"mips64-linux-gnuabi64-as",
		}, []string{
			"mips64-linux-gnuabi64-objcopy",
		}), nil
	case "mips64el", "mips64le":
		return asmCrossToolchain("mips64el-linux-gnuabi64", []string{
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

	if path, ok := firstExecutable(cfg.gnuAssemblers); ok {
		return path, cfg.gnuArgs, false, nil
	}

	if path, ok := firstExecutable([]string{"clang"}); ok {
		return path, []string{"-target", cfg.clangTarget, "-c"}, true, nil
	}

	return "", nil, false, fmt.Errorf("no assembler found for arch %q; install one of %s or clang", cfg.clangTarget, strings.Join(cfg.gnuAssemblers, ", "))
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
