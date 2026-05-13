package gpwntools

import (
	"debug/elf"
	"errors"
)

const (
	RELROFull    = "Full RELRO"
	RELROPartial = "Partial RELRO"
	RELRONone    = "No RELRO"
)

// ChecksecInfo summarizes common ELF hardening properties.
type ChecksecInfo struct {
	Arch   string
	Bits   int
	Endian string
	PIE    bool
	NX     bool
	Canary bool
	RELRO  string
}

// Checksec parses an ELF binary and returns common hardening properties.
func Checksec(path string) (ChecksecInfo, error) {
	e, err := ELF(path)
	if err != nil {
		return ChecksecInfo{}, err
	}
	defer e.Close()
	return e.Checksec()
}

// Checksec returns common hardening properties for this ELF.
func (e *ELFFile) Checksec() (ChecksecInfo, error) {
	if e == nil || e.file == nil {
		return ChecksecInfo{}, errors.New("ELF file is closed")
	}

	info := ChecksecInfo{
		Arch:   e.file.Machine.String(),
		Bits:   elfBits(e.file.Class),
		Endian: elfEndian(e.file.Data),
		PIE:    e.file.Type == elf.ET_DYN,
		NX:     elfNX(e.file),
		Canary: elfHasCanary(e.file),
		RELRO:  elfRELRO(e.file),
	}
	return info, nil
}

func elfBits(class elf.Class) int {
	switch class {
	case elf.ELFCLASS32:
		return 32
	case elf.ELFCLASS64:
		return 64
	default:
		return 0
	}
}

func elfEndian(data elf.Data) string {
	switch data {
	case elf.ELFDATA2LSB:
		return "little"
	case elf.ELFDATA2MSB:
		return "big"
	default:
		return "unknown"
	}
}

func elfNX(f *elf.File) bool {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			return prog.Flags&elf.PF_X == 0
		}
	}
	return true
}

func elfHasCanary(f *elf.File) bool {
	has := func(symbols []elf.Symbol) bool {
		for _, symbol := range symbols {
			if symbol.Name == "__stack_chk_fail" || symbol.Name == "__stack_chk_guard" {
				return true
			}
		}
		return false
	}

	if symbols, err := f.DynamicSymbols(); err == nil && has(symbols) {
		return true
	}
	if symbols, err := f.Symbols(); err == nil && has(symbols) {
		return true
	}
	return false
}

func elfRELRO(f *elf.File) string {
	hasRelro := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	if !hasRelro {
		return RELRONone
	}
	if elfBindNow(f) {
		return RELROFull
	}
	return RELROPartial
}

func elfBindNow(f *elf.File) bool {
	if values, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(values) > 0 {
		return true
	}
	if values, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, value := range values {
			if value&uint64(elf.DF_BIND_NOW) != 0 {
				return true
			}
		}
	}
	if values, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, value := range values {
			if value&uint64(elf.DF_1_NOW) != 0 {
				return true
			}
		}
	}
	return false
}
