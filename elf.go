package gpwntools

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
)

// ELFFile stores useful addresses parsed from an ELF binary.
type ELFFile struct {
	Path     string
	Base     uint64
	Entry    uint64
	Symbols  map[string]uint64
	GOT      map[string]uint64
	PLT      map[string]uint64
	Sections map[string]uint64
	file     *elf.File
}

// ELF parses an ELF binary and returns common symbol, GOT, PLT, and section addresses.
func ELF(path string) (*ELFFile, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	out := &ELFFile{
		Path:     path,
		Entry:    f.Entry,
		Symbols:  make(map[string]uint64),
		GOT:      make(map[string]uint64),
		PLT:      make(map[string]uint64),
		Sections: make(map[string]uint64),
		file:     f,
	}

	for _, section := range f.Sections {
		if section.Name != "" {
			out.Sections[section.Name] = section.Addr
		}
	}

	out.loadSymbols(f)
	if err := out.loadRelocations(f); err != nil {
		return nil, err
	}
	return out, nil
}

// SetBase sets the runtime base address used by Resolve and Search.
func (e *ELFFile) SetBase(base uint64) {
	e.Base = base
}

// Resolve returns the runtime address for a symbol, GOT/PLT entry, or section.
func (e *ELFFile) Resolve(name string) (uint64, bool) {
	if addr, ok := e.Symbols[name]; ok {
		return e.Base + addr, true
	}
	if addr, ok := e.GOT[name]; ok {
		return e.Base + addr, true
	}
	if addr, ok := e.PLT[name]; ok {
		return e.Base + addr, true
	}
	if addr, ok := e.Sections[name]; ok {
		return e.Base + addr, true
	}
	return 0, false
}

// ResolveAddr returns Base + addr.
func (e *ELFFile) ResolveAddr(addr uint64) uint64 {
	return e.Base + addr
}

// Close closes the underlying ELF file.
func (e *ELFFile) Close() error {
	if e == nil || e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	return err
}

// Symbol returns the address of a named ELF symbol.
func (e *ELFFile) Symbol(name string) (uint64, bool) {
	addr, ok := e.Symbols[name]
	return addr, ok
}

// GOTAddr returns the address of a GOT entry for a symbol.
func (e *ELFFile) GOTAddr(name string) (uint64, bool) {
	addr, ok := e.GOT[name]
	return addr, ok
}

// PLTAddr returns the address of a PLT stub for a symbol.
func (e *ELFFile) PLTAddr(name string) (uint64, bool) {
	addr, ok := e.PLT[name]
	return addr, ok
}

// SectionAddr returns the address of a section by name, such as ".text".
func (e *ELFFile) SectionAddr(name string) (uint64, bool) {
	addr, ok := e.Sections[name]
	return addr, ok
}

// Search returns virtual addresses where needle appears in loadable segments.
func (e *ELFFile) Search(needle []byte) ([]uint64, error) {
	if len(needle) == 0 {
		return nil, errors.New("search needle must not be empty")
	}
	if e == nil || e.file == nil {
		return nil, errors.New("ELF file is closed")
	}

	var addrs []uint64
	for _, prog := range e.file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Filesz == 0 {
			continue
		}
		data := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(data, 0); err != nil {
			return nil, fmt.Errorf("read program segment %#x: %w", prog.Vaddr, err)
		}

		base := 0
		for {
			idx := bytes.Index(data[base:], needle)
			if idx < 0 {
				break
			}
			offset := base + idx
			addrs = append(addrs, e.Base+prog.Vaddr+uint64(offset))
			base = offset + 1
		}
	}
	return addrs, nil
}

func (e *ELFFile) loadSymbols(f *elf.File) {
	load := func(symbols []elf.Symbol) {
		for _, symbol := range symbols {
			if symbol.Name == "" || symbol.Value == 0 {
				continue
			}
			e.Symbols[symbol.Name] = symbol.Value
		}
	}

	if symbols, err := f.DynamicSymbols(); err == nil {
		load(symbols)
	}
	if symbols, err := f.Symbols(); err == nil {
		load(symbols)
	}
}

func (e *ELFFile) loadRelocations(f *elf.File) error {
	for _, section := range f.Sections {
		if section.Type != elf.SHT_RELA && section.Type != elf.SHT_REL {
			continue
		}

		relocs, err := readRelocations(f, section)
		if err != nil {
			return err
		}
		symbols, err := symbolsForRelocationSection(f, section)
		if err != nil {
			return err
		}

		pltIndex := 0
		for _, reloc := range relocs {
			name := relocationSymbolName(symbols, reloc.symbolIndex)
			if name == "" {
				continue
			}

			if isGOTRelocation(f.Machine, reloc.relType) {
				e.GOT[name] = reloc.offset
				e.Symbols["got."+name] = reloc.offset
			}
			if isPLTRelocationSection(section.Name) && isPLTRelocation(f.Machine, reloc.relType) {
				if plt, ok := pltEntryAddress(f, pltIndex, len(relocs)); ok {
					e.PLT[name] = plt
					e.Symbols["plt."+name] = plt
				}
				pltIndex++
			}
		}
	}
	return nil
}

type relocation struct {
	offset      uint64
	info        uint64
	relType     uint64
	symbolIndex uint64
}

func readRelocations(f *elf.File, section *elf.Section) ([]relocation, error) {
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read relocation section %s: %w", section.Name, err)
	}

	entrySize, err := relocationEntrySize(f, section)
	if err != nil {
		return nil, err
	}
	if len(data)%entrySize != 0 {
		return nil, fmt.Errorf("relocation section %s has invalid size", section.Name)
	}

	relocs := make([]relocation, 0, len(data)/entrySize)
	for len(data) > 0 {
		reloc := relocation{}
		switch f.Class {
		case elf.ELFCLASS64:
			reloc.offset = f.ByteOrder.Uint64(data[0:8])
			reloc.info = f.ByteOrder.Uint64(data[8:16])
			reloc.symbolIndex = reloc.info >> 32
			reloc.relType = reloc.info & 0xffffffff
		case elf.ELFCLASS32:
			reloc.offset = uint64(f.ByteOrder.Uint32(data[0:4]))
			reloc.info = uint64(f.ByteOrder.Uint32(data[4:8]))
			reloc.symbolIndex = reloc.info >> 8
			reloc.relType = reloc.info & 0xff
		default:
			return nil, fmt.Errorf("unsupported ELF class %s", f.Class)
		}
		relocs = append(relocs, reloc)
		data = data[entrySize:]
	}
	return relocs, nil
}

func relocationEntrySize(f *elf.File, section *elf.Section) (int, error) {
	if section.Entsize != 0 {
		return int(section.Entsize), nil
	}

	switch f.Class {
	case elf.ELFCLASS64:
		if section.Type == elf.SHT_RELA {
			return 24, nil
		}
		return 16, nil
	case elf.ELFCLASS32:
		if section.Type == elf.SHT_RELA {
			return 12, nil
		}
		return 8, nil
	default:
		return 0, fmt.Errorf("unsupported ELF class %s", f.Class)
	}
}

func symbolsForRelocationSection(f *elf.File, section *elf.Section) ([]elf.Symbol, error) {
	if section.Link == 0 || int(section.Link) >= len(f.Sections) {
		return nil, fmt.Errorf("relocation section %s has invalid symbol table link", section.Name)
	}

	symbolSection := f.Sections[section.Link]
	switch symbolSection.Type {
	case elf.SHT_DYNSYM:
		symbols, err := f.DynamicSymbols()
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, nil
		}
		return symbols, err
	case elf.SHT_SYMTAB:
		symbols, err := f.Symbols()
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, nil
		}
		return symbols, err
	default:
		return nil, fmt.Errorf("relocation section %s links to unsupported symbol section %s", section.Name, symbolSection.Name)
	}
}

func relocationSymbolName(symbols []elf.Symbol, index uint64) string {
	if index == 0 || index > uint64(len(symbols)) {
		return ""
	}
	return symbols[index-1].Name
}

func isGOTRelocation(machine elf.Machine, relType uint64) bool {
	switch machine {
	case elf.EM_X86_64:
		return relType == uint64(elf.R_X86_64_GLOB_DAT) || relType == uint64(elf.R_X86_64_JMP_SLOT)
	case elf.EM_386:
		return relType == uint64(elf.R_386_GLOB_DAT) || relType == uint64(elf.R_386_JMP_SLOT)
	case elf.EM_AARCH64:
		return relType == uint64(elf.R_AARCH64_GLOB_DAT) || relType == uint64(elf.R_AARCH64_JUMP_SLOT)
	case elf.EM_ARM:
		return relType == uint64(elf.R_ARM_GLOB_DAT) || relType == uint64(elf.R_ARM_JUMP_SLOT)
	default:
		return false
	}
}

func isPLTRelocation(machine elf.Machine, relType uint64) bool {
	switch machine {
	case elf.EM_X86_64:
		return relType == uint64(elf.R_X86_64_JMP_SLOT)
	case elf.EM_386:
		return relType == uint64(elf.R_386_JMP_SLOT)
	case elf.EM_AARCH64:
		return relType == uint64(elf.R_AARCH64_JUMP_SLOT)
	case elf.EM_ARM:
		return relType == uint64(elf.R_ARM_JUMP_SLOT)
	default:
		return false
	}
}

func isPLTRelocationSection(name string) bool {
	return name == ".rel.plt" || name == ".rela.plt" || name == ".rela.plt.sec" || name == ".rel.plt.sec"
}

func pltEntryAddress(f *elf.File, index int, count int) (uint64, bool) {
	if section := f.Section(".plt.sec"); section != nil {
		if entrySize, ok := pltEntrySize(f.Machine); ok && section.Size >= uint64(count)*entrySize {
			return section.Addr + uint64(index)*entrySize, true
		}
	}

	section := f.Section(".plt")
	if section == nil {
		return 0, false
	}

	headerSize, entrySize, ok := pltLayout(f.Machine)
	if !ok {
		return 0, false
	}
	return section.Addr + headerSize + uint64(index)*entrySize, true
}

func pltEntrySize(machine elf.Machine) (uint64, bool) {
	switch machine {
	case elf.EM_X86_64, elf.EM_386, elf.EM_AARCH64:
		return 16, true
	case elf.EM_ARM:
		return 12, true
	default:
		return 0, false
	}
}

func pltLayout(machine elf.Machine) (uint64, uint64, bool) {
	switch machine {
	case elf.EM_X86_64, elf.EM_386:
		return 16, 16, true
	case elf.EM_AARCH64:
		return 32, 16, true
	case elf.EM_ARM:
		return 20, 12, true
	default:
		return 0, 0, false
	}
}
