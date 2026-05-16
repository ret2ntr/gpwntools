package gpwntools

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SigreturnFrameOptions configures a Linux sigreturn frame.
type SigreturnFrameOptions struct {
	// Arch defaults to Context.Arch. Supported layouts match pwntools:
	// amd64, i386, arm, aarch64, mips, and mipsel.
	Arch string
	// Endian defaults to Context.Endian when set, otherwise the natural endian
	// for Arch. It mainly selects mips vs mipsel layouts.
	Endian string
	// Kernel controls i386 segment selector defaults. Use "amd64" for a 32-bit
	// process running on a 64-bit kernel. Empty defaults to "i386".
	Kernel string
}

// SigreturnFrameOption mutates SigreturnFrameOptions.
type SigreturnFrameOption func(*SigreturnFrameOptions)

// WithSigreturnFrameArch selects the sigreturn frame architecture.
func WithSigreturnFrameArch(arch string) SigreturnFrameOption {
	return func(opts *SigreturnFrameOptions) {
		opts.Arch = arch
	}
}

// WithSigreturnFrameEndian selects the sigreturn frame endian.
func WithSigreturnFrameEndian(endian string) SigreturnFrameOption {
	return func(opts *SigreturnFrameOptions) {
		opts.Endian = endian
	}
}

// WithSigreturnFrameKernel selects the kernel architecture for i386 frames.
func WithSigreturnFrameKernel(kernel string) SigreturnFrameOption {
	return func(opts *SigreturnFrameOptions) {
		opts.Kernel = kernel
	}
}

// SigreturnFrame creates a pwntools-style Linux sigreturn frame.
func SigreturnFrame(opts ...SigreturnFrameOption) (*SROPFrame, error) {
	return SigreturnFrameWithOptions(SigreturnFrameOptions{}, opts...)
}

// NewSigreturnFrame is an alias for SigreturnFrame.
func NewSigreturnFrame(opts ...SigreturnFrameOption) (*SROPFrame, error) {
	return SigreturnFrame(opts...)
}

// MustSigreturnFrame is SigreturnFrame but panics on construction errors.
func MustSigreturnFrame(opts ...SigreturnFrameOption) *SROPFrame {
	frame, err := SigreturnFrame(opts...)
	if err != nil {
		panic(err)
	}
	return frame
}

// SigreturnFrameWithOptions creates a sigreturn frame from explicit options.
func SigreturnFrameWithOptions(options SigreturnFrameOptions, opts ...SigreturnFrameOption) (*SROPFrame, error) {
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	layout, arch, endian, kernel, err := sropLayoutForOptions(options)
	if err != nil {
		return nil, err
	}

	frame := &SROPFrame{
		Arch:    arch,
		Endian:  endian,
		Kernel:  kernel,
		layout:  layout,
		values:  make(map[string]uint64, len(layout.regs)),
		aliases: make(map[string]string, len(layout.regs)*2),
	}
	for _, reg := range layout.regs {
		frame.values[reg.name] = 0
		frame.aliases[sropNormalizeRegister(reg.name)] = reg.name
	}
	for name, value := range layout.defaults {
		if reg, ok := frame.registerName(name); ok {
			frame.values[reg] = value
		}
	}
	return frame, nil
}

// SROPFrame holds register values for a sigreturn frame.
type SROPFrame struct {
	Arch   string
	Endian string
	Kernel string

	layout  sropLayout
	values  map[string]uint64
	aliases map[string]string
}

// Set updates one register or sigcontext field in the frame.
func (f *SROPFrame) Set(register string, value uint64) error {
	if f == nil {
		return fmt.Errorf("nil sigreturn frame")
	}
	reg, ok := f.registerName(register)
	if !ok {
		return fmt.Errorf("unknown sigreturn frame register %q for arch %q", register, f.Arch)
	}
	if f.Arch == "arm" && reg == "sp" && value&0x7 != 0 {
		Warn("ARM SROP sp should be 8-byte aligned")
	}
	if f.Arch == "aarch64" && reg == "sp" && value&0xf != 0 {
		Warn("AArch64 SROP sp should be 16-byte aligned")
	}
	f.values[reg] = value
	return nil
}

// MustSet is Set but panics on invalid register names.
func (f *SROPFrame) MustSet(register string, value uint64) *SROPFrame {
	if err := f.Set(register, value); err != nil {
		panic(err)
	}
	return f
}

// Get returns a register or sigcontext field value.
func (f *SROPFrame) Get(register string) (uint64, bool) {
	reg, ok := f.registerName(register)
	if !ok {
		return 0, false
	}
	return f.values[reg], true
}

// SetPC updates the architecture's instruction pointer register.
func (f *SROPFrame) SetPC(value uint64) error {
	return f.Set(f.layout.pc, value)
}

// SetSP updates the architecture's stack pointer register.
func (f *SROPFrame) SetSP(value uint64) error {
	return f.Set(f.layout.sp, value)
}

// SetSyscall updates the architecture's syscall-number register.
func (f *SROPFrame) SetSyscall(value uint64) error {
	return f.Set(f.layout.syscall, value)
}

// SetSyscallName resolves a Linux syscall name such as "mprotect" or
// "SYS_mprotect" and writes the architecture's syscall-number register.
func (f *SROPFrame) SetSyscallName(name string) error {
	number, err := asmSyscallNumber(name, f.Arch, "linux")
	if err != nil {
		return err
	}
	return f.SetSyscall(number)
}

// SetArguments updates syscall argument registers in ABI order.
func (f *SROPFrame) SetArguments(args ...uint64) error {
	if len(args) > len(f.layout.args) {
		return fmt.Errorf("too many SROP syscall arguments for arch %q: got %d, max %d", f.Arch, len(args), len(f.layout.args))
	}
	for i, value := range args {
		if err := f.Set(f.layout.args[i], value); err != nil {
			return err
		}
	}
	return nil
}

// PCRegister returns the frame field used as the instruction pointer.
func (f *SROPFrame) PCRegister() string {
	return f.layout.pc
}

// SPRegister returns the frame field used as the stack pointer.
func (f *SROPFrame) SPRegister() string {
	return f.layout.sp
}

// SyscallRegister returns the frame field used as the syscall number.
func (f *SROPFrame) SyscallRegister() string {
	return f.layout.syscall
}

// ArgumentRegisters returns syscall argument registers in ABI order.
func (f *SROPFrame) ArgumentRegisters() []string {
	return append([]string(nil), f.layout.args...)
}

// Registers returns all writable fields in frame order.
func (f *SROPFrame) Registers() []string {
	out := make([]string, 0, len(f.layout.regs))
	for _, reg := range f.layout.regs {
		out = append(out, reg.name)
	}
	return out
}

// Len returns the serialized frame length.
func (f *SROPFrame) Len() int {
	return f.layout.size
}

// Bytes serializes the sigreturn frame.
func (f *SROPFrame) Bytes() []byte {
	out := make([]byte, f.layout.size)
	for _, reg := range f.layout.regs {
		sropPutUint(out[reg.offset:reg.offset+f.layout.wordSize], f.layout.wordSize, f.Endian, f.values[reg.name])
	}
	return out
}

// MustBytes returns Bytes. It exists for symmetry with other Must helpers.
func (f *SROPFrame) MustBytes() []byte {
	return f.Bytes()
}

func (f *SROPFrame) registerName(name string) (string, bool) {
	if f == nil {
		return "", false
	}
	reg, ok := f.aliases[sropNormalizeRegister(name)]
	return reg, ok
}

type sropRegister struct {
	offset int
	name   string
}

type sropLayout struct {
	regs     []sropRegister
	defaults map[string]uint64
	wordSize int
	size     int
	pc       string
	sp       string
	syscall  string
	args     []string
}

func sropLayoutForOptions(opts SigreturnFrameOptions) (sropLayout, string, string, string, error) {
	arch := strings.ToLower(strings.TrimSpace(opts.Arch))
	if arch == "" {
		arch = contextArch()
	}

	canonicalArch, err := sropCanonicalArch(arch)
	if err != nil {
		return sropLayout{}, "", "", "", err
	}

	endian := normalizeEndian(opts.Endian)
	if endian == "" {
		endian = normalizeEndian(Context.Endian)
	}
	if endian == "" {
		endian = sropDefaultEndian(canonicalArch)
	}
	if canonicalArch == "mipsel" {
		endian = "little"
	}

	layoutKey := canonicalArch
	if canonicalArch == "mips" && endian == "little" {
		layoutKey = "mipsel"
	}
	if layoutKey == "mipsel" {
		canonicalArch = "mipsel"
		endian = "little"
	}

	layout, ok := sropLayouts[layoutKey]
	if !ok {
		return sropLayout{}, "", "", "", fmt.Errorf("unsupported sigreturn frame arch %q (supported: amd64, i386, arm, aarch64, mips, mipsel)", arch)
	}

	kernel := strings.ToLower(strings.TrimSpace(opts.Kernel))
	if kernel == "" {
		kernel = contextKernel()
	}
	if canonicalArch == "i386" {
		if kernel == "" {
			kernel = "i386"
		}
		if sropIsAmd64Kernel(kernel) {
			layout.defaults = sropI386OnAmd64Defaults
			kernel = "amd64"
		} else {
			layout.defaults = sropI386Defaults
			kernel = "i386"
		}
	}

	return layout, canonicalArch, endian, kernel, nil
}

func sropCanonicalArch(arch string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x86_64", "x64":
		return "amd64", nil
	case "i386", "x86", "386":
		return "i386", nil
	case "arm", "arm32", "thumb", "thumb32":
		return "arm", nil
	case "arm64", "aarch64":
		return "aarch64", nil
	case "mips":
		return "mips", nil
	case "mipsel", "mipsle":
		return "mipsel", nil
	default:
		return "", fmt.Errorf("unsupported sigreturn frame arch %q (supported: amd64, i386, arm, aarch64, mips, mipsel)", arch)
	}
}

func sropDefaultEndian(arch string) string {
	switch arch {
	case "mips":
		return "big"
	default:
		return "little"
	}
}

func sropIsAmd64Kernel(kernel string) bool {
	switch strings.ToLower(strings.TrimSpace(kernel)) {
	case "amd64", "x86_64", "x64":
		return true
	default:
		return false
	}
}

func sropNormalizeRegister(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "$")
	return name
}

func sropPutUint(out []byte, width int, endian string, value uint64) {
	if endian == "big" {
		switch width {
		case 8:
			binary.BigEndian.PutUint64(out, value)
		case 4:
			binary.BigEndian.PutUint32(out, uint32(value))
		default:
			for i := 0; i < width; i++ {
				out[i] = byte(value >> uint((width-1-i)*8))
			}
		}
		return
	}

	switch width {
	case 8:
		binary.LittleEndian.PutUint64(out, value)
	case 4:
		binary.LittleEndian.PutUint32(out, uint32(value))
	default:
		for i := 0; i < width; i++ {
			out[i] = byte(value >> uint(i*8))
		}
	}
}

var sropI386Defaults = map[string]uint64{"cs": 0x73, "ss": 0x7b}
var sropI386OnAmd64Defaults = map[string]uint64{"cs": 0x23, "ss": 0x2b}

var sropLayouts = map[string]sropLayout{
	"i386": {
		regs: []sropRegister{
			{0, "gs"}, {4, "fs"}, {8, "es"}, {12, "ds"},
			{16, "edi"}, {20, "esi"}, {24, "ebp"}, {28, "esp"},
			{32, "ebx"}, {36, "edx"}, {40, "ecx"}, {44, "eax"},
			{48, "trapno"}, {52, "err"}, {56, "eip"}, {60, "cs"},
			{64, "eflags"}, {68, "esp_at_signal"}, {72, "ss"}, {76, "fpstate"},
		},
		defaults: sropI386Defaults,
		wordSize: 4,
		size:     80,
		pc:       "eip",
		sp:       "esp",
		syscall:  "eax",
		args:     []string{"ebx", "ecx", "edx", "esi", "edi", "ebp"},
	},
	"amd64": {
		regs: []sropRegister{
			{0, "uc_flags"}, {8, "&uc"}, {16, "uc_stack.ss_sp"}, {24, "uc_stack.ss_flags"},
			{32, "uc_stack.ss_size"}, {40, "r8"}, {48, "r9"}, {56, "r10"},
			{64, "r11"}, {72, "r12"}, {80, "r13"}, {88, "r14"},
			{96, "r15"}, {104, "rdi"}, {112, "rsi"}, {120, "rbp"},
			{128, "rbx"}, {136, "rdx"}, {144, "rax"}, {152, "rcx"},
			{160, "rsp"}, {168, "rip"}, {176, "eflags"}, {184, "csgsfs"},
			{192, "err"}, {200, "trapno"}, {208, "oldmask"}, {216, "cr2"},
			{224, "&fpstate"}, {232, "__reserved"}, {240, "sigmask"},
		},
		defaults: map[string]uint64{"csgsfs": 0x33},
		wordSize: 8,
		size:     248,
		pc:       "rip",
		sp:       "rsp",
		syscall:  "rax",
		args:     []string{"rdi", "rsi", "rdx", "r10", "r8", "r9"},
	},
	"arm": {
		regs: []sropRegister{
			{0, "uc_flags"}, {4, "uc_link"}, {8, "uc_stack.ss_sp"}, {12, "uc_stack.ss_flags"},
			{16, "uc_stack.ss_size"}, {20, "trap_no"}, {24, "error_code"}, {28, "oldmask"},
			{32, "r0"}, {36, "r1"}, {40, "r2"}, {44, "r3"},
			{48, "r4"}, {52, "r5"}, {56, "r6"}, {60, "r7"},
			{64, "r8"}, {68, "r9"}, {72, "r10"}, {76, "fp"},
			{80, "ip"}, {84, "sp"}, {88, "lr"}, {92, "pc"},
			{96, "cpsr"}, {100, "fault_address"}, {104, "uc_sigmask"}, {108, "__unused"},
			{112, "uc_regspace"}, {232, "VFPU-magic"}, {236, "VFPU-size"},
		},
		defaults: map[string]uint64{
			"trap_no":    0x6,
			"cpsr":       0x40000010,
			"VFPU-magic": 0x56465001,
			"VFPU-size":  0x120,
		},
		wordSize: 4,
		size:     240,
		pc:       "pc",
		sp:       "sp",
		syscall:  "r7",
		args:     []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6"},
	},
	"mips": {
		regs: []sropRegister{
			{0, "sf_ass0"}, {4, "sf_ass1"}, {8, "sf_ass2"}, {12, "sf_ass3"},
			{16, "sf_ass4"}, {20, "sf_pad0"}, {24, "sf_pad1"}, {28, "sc_regmask"},
			{32, "sc_status"}, {36, "pc"}, {44, "padding"}, {52, "at"},
			{60, "v0"}, {68, "v1"}, {76, "a0"}, {84, "a1"},
			{92, "a2"}, {100, "a3"}, {108, "t0"}, {116, "t1"},
			{124, "t2"}, {132, "t3"}, {140, "t4"}, {148, "t5"},
			{156, "t6"}, {164, "t7"}, {172, "s0"}, {180, "s1"},
			{188, "s2"}, {196, "s3"}, {204, "s4"}, {212, "s5"},
			{220, "s6"}, {228, "s7"}, {236, "t8"}, {244, "t9"},
			{252, "k0"}, {260, "k1"}, {268, "gp"}, {276, "sp"},
			{284, "s8"}, {292, "ra"},
		},
		defaults: map[string]uint64{},
		wordSize: 4,
		size:     296,
		pc:       "pc",
		sp:       "sp",
		syscall:  "v0",
		args:     []string{"a0", "a1", "a2", "a3"},
	},
	"mipsel": {
		regs: []sropRegister{
			{0, "sf_ass0"}, {4, "sf_ass1"}, {8, "sf_ass2"}, {12, "sf_ass3"},
			{16, "sf_ass4"}, {20, "sc_regmask"}, {24, "sc_status"}, {32, "pc"},
			{40, "padding"}, {48, "at"}, {56, "v0"}, {64, "v1"},
			{72, "a0"}, {80, "a1"}, {88, "a2"}, {96, "a3"},
			{104, "t0"}, {112, "t1"}, {120, "t2"}, {128, "t3"},
			{136, "t4"}, {144, "t5"}, {152, "t6"}, {160, "t7"},
			{168, "s0"}, {176, "s1"}, {184, "s2"}, {192, "s3"},
			{200, "s4"}, {208, "s5"}, {216, "s6"}, {224, "s7"},
			{232, "t8"}, {240, "t9"}, {248, "k0"}, {256, "k1"},
			{264, "gp"}, {272, "sp"}, {280, "s8"}, {288, "ra"},
		},
		defaults: map[string]uint64{},
		wordSize: 4,
		size:     292,
		pc:       "pc",
		sp:       "sp",
		syscall:  "v0",
		args:     []string{"a0", "a1", "a2", "a3"},
	},
	"aarch64": {
		regs: []sropRegister{
			{312, "x0"}, {320, "x1"}, {328, "x2"}, {336, "x3"},
			{344, "x4"}, {352, "x5"}, {360, "x6"}, {368, "x7"},
			{376, "x8"}, {384, "x9"}, {392, "x10"}, {400, "x11"},
			{408, "x12"}, {416, "x13"}, {424, "x14"}, {432, "x15"},
			{440, "x16"}, {448, "x17"}, {456, "x18"}, {464, "x19"},
			{472, "x20"}, {480, "x21"}, {488, "x22"}, {496, "x23"},
			{504, "x24"}, {512, "x25"}, {520, "x26"}, {528, "x27"},
			{536, "x28"}, {544, "x29"}, {552, "x30"}, {560, "sp"},
			{568, "pc"}, {592, "magic"},
		},
		defaults: map[string]uint64{"magic": 0x0000021046508001},
		wordSize: 8,
		size:     600,
		pc:       "pc",
		sp:       "sp",
		syscall:  "x8",
		args:     []string{"x0", "x1", "x2", "x3", "x4", "x5"},
	},
}
