package gpwntools

import (
	"runtime"
	"strings"
	"time"
)

// ContextConfig holds pwntools-style global defaults.
type ContextConfig struct {
	// Arch is the default architecture, such as amd64, i386, arm, aarch64, mips, or mipsel.
	Arch string
	// Bits overrides the default word size. When zero, it is derived from Arch.
	Bits int
	// Endian is "little" or "big". When empty, it is derived from Arch.
	Endian string
	// OS is the target operating system name.
	OS string
	// Syntax is the default assembly syntax. x86 accepts "intel" or "att".
	Syntax string
	// Terminal is the terminal command prefix used by GDB helpers. The complete
	// shell-escaped GDB command is appended as the final argument. If empty,
	// gpwntools auto-detects one.
	Terminal []string
	// Timeout is copied into newly-created tubes as their default recv timeout.
	Timeout time.Duration
	// KillOnTimeout makes newly-created process tubes terminate the child process when a recv timeout occurs.
	KillOnTimeout bool
	// PTY makes local Process stdout/stderr use a pseudo-terminal by default.
	PTY bool
}

// Context stores package-wide defaults, similar to pwntools' context object.
var Context = ContextConfig{
	Arch:   defaultContextArch(),
	OS:     runtime.GOOS,
	Syntax: "intel",
	PTY:    defaultContextPTY(),
}

// DefaultContext returns a fresh copy of the built-in defaults.
func DefaultContext() ContextConfig {
	return ContextConfig{
		Arch:   defaultContextArch(),
		OS:     runtime.GOOS,
		Syntax: "intel",
		PTY:    defaultContextPTY(),
	}
}

// Clone returns a copy of the context.
func (c ContextConfig) Clone() ContextConfig {
	out := c
	out.Terminal = append([]string{}, c.Terminal...)
	return out
}

// Apply copies src into c.
func (c *ContextConfig) Apply(src ContextConfig) {
	*c = src.Clone()
}

// ResetContext restores package-wide defaults.
func ResetContext() {
	Context = DefaultContext()
}

// SetArch changes the default architecture and lets Bits/Endian be derived from it again.
func (c *ContextConfig) SetArch(arch string) {
	c.Arch = strings.ToLower(strings.TrimSpace(arch))
	c.Bits = 0
	c.Endian = ""
}

// SetTerminal changes the terminal command used by GDB helpers.
func (c *ContextConfig) SetTerminal(command ...string) {
	c.Terminal = append([]string{}, command...)
}

// SetTerminalByName selects a built-in terminal launcher by name.
func (c *ContextConfig) SetTerminalByName(name string) error {
	terminal, err := GDBTerminalByName(name)
	if err != nil {
		return err
	}
	c.Terminal = terminal
	return nil
}

func contextArch() string {
	arch := strings.ToLower(strings.TrimSpace(Context.Arch))
	if arch == "" {
		return defaultContextArch()
	}
	return arch
}

func contextSyntax() string {
	syntax := strings.TrimSpace(Context.Syntax)
	if syntax == "" {
		return "intel"
	}
	return syntax
}

func contextBits() int {
	if Context.Bits > 0 {
		return Context.Bits
	}
	if bits := bitsForArch(contextArch()); bits != 0 {
		return bits
	}
	return 64
}

func contextEndian() string {
	endian := normalizeEndian(Context.Endian)
	if endian != "" {
		return endian
	}
	switch contextArch() {
	case "mips", "mips64":
		return "big"
	default:
		return "little"
	}
}

func contextTimeout() time.Duration {
	return Context.Timeout
}

func contextTerminal() []string {
	if len(Context.Terminal) > 0 {
		return append([]string{}, Context.Terminal...)
	}
	return GDBTerminalDefault()
}

func bitsForArch(arch string) int {
	switch arch {
	case "amd64", "x86_64", "x64", "arm64", "aarch64", "mips64", "mips64el", "mips64le":
		return 64
	case "i386", "x86", "386", "arm", "arm32", "thumb", "thumb32", "mips", "mipsel", "mipsle":
		return 32
	default:
		return 0
	}
}

func normalizeEndian(endian string) string {
	switch strings.ToLower(strings.TrimSpace(endian)) {
	case "little", "le", "l":
		return "little"
	case "big", "be", "b":
		return "big"
	default:
		return ""
	}
}

func defaultContextArch() string {
	switch runtime.GOARCH {
	case "386":
		return "i386"
	case "arm":
		return "arm"
	case "arm64":
		return "aarch64"
	case "mips":
		return "mips"
	case "mipsle":
		return "mipsel"
	case "mips64":
		return "mips64"
	case "mips64le":
		return "mips64el"
	case "amd64":
		return "amd64"
	default:
		return defaultAsmArch
	}
}

func defaultContextPTY() bool {
	return runtime.GOOS == "linux"
}
