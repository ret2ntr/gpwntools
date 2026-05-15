package gpwntools

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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

// ELFSearchOptions controls where SearchWithOptions looks for bytes.
type ELFSearchOptions struct {
	// Section restricts the search to one named ELF section, such as ".text".
	Section string
	// Readable, Writable, and Executable restrict program segment searches by
	// PT_LOAD permissions. For section searches, they are matched against the
	// closest section flags available in the ELF metadata.
	Readable   bool
	Writable   bool
	Executable bool
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
	out.applyContextDefaults(f)
	return out, nil
}

// SetBase sets the runtime base address and rebases public address fields/maps.
func (e *ELFFile) SetBase(base uint64) {
	if e == nil || e.Base == base {
		return
	}
	oldBase := e.Base
	if e.Entry != 0 {
		e.Entry = rebaseAddress(e.Entry, oldBase, base)
	}
	rebaseAddressMap(e.Symbols, oldBase, base)
	rebaseAddressMap(e.GOT, oldBase, base)
	rebaseAddressMap(e.PLT, oldBase, base)
	rebaseAddressMap(e.Sections, oldBase, base)
	e.Base = base
}

// Resolve returns the runtime address for a symbol, GOT/PLT entry, or section.
func (e *ELFFile) Resolve(name string) (uint64, bool) {
	if addr, ok := e.Symbols[name]; ok {
		return addr, true
	}
	if addr, ok := e.GOT[name]; ok {
		return addr, true
	}
	if addr, ok := e.PLT[name]; ok {
		return addr, true
	}
	if addr, ok := e.Sections[name]; ok {
		return addr, true
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
	return e.SearchWithOptions(needle, ELFSearchOptions{})
}

// SearchExecutable returns virtual addresses where needle appears in executable loadable segments.
func (e *ELFFile) SearchExecutable(needle []byte) ([]uint64, error) {
	return e.SearchWithOptions(needle, ELFSearchOptions{Executable: true})
}

// SearchSection returns virtual addresses where needle appears in a named ELF section.
func (e *ELFFile) SearchSection(section string, needle []byte) ([]uint64, error) {
	return e.SearchWithOptions(needle, ELFSearchOptions{Section: section})
}

// SearchOne returns the first Search result.
func (e *ELFFile) SearchOne(needle []byte) (uint64, error) {
	return firstSearchResult(e.Search(needle))
}

// SearchExecutableOne returns the first SearchExecutable result.
func (e *ELFFile) SearchExecutableOne(needle []byte) (uint64, error) {
	return firstSearchResult(e.SearchExecutable(needle))
}

// SearchSectionOne returns the first SearchSection result.
func (e *ELFFile) SearchSectionOne(section string, needle []byte) (uint64, error) {
	return firstSearchResult(e.SearchSection(section, needle))
}

// SearchWithOptions returns virtual addresses where needle appears in matching ELF areas.
func (e *ELFFile) SearchWithOptions(needle []byte, opts ELFSearchOptions) ([]uint64, error) {
	if len(needle) == 0 {
		return nil, errors.New("search needle must not be empty")
	}
	if e == nil || e.file == nil {
		return nil, errors.New("ELF file is closed")
	}
	if opts.Section != "" {
		return e.searchSection(opts.Section, needle, opts)
	}

	var addrs []uint64
	for _, prog := range e.file.Progs {
		if prog.Type != elf.PT_LOAD || prog.Filesz == 0 {
			continue
		}
		if !programMatchesSearchOptions(prog, opts) {
			continue
		}
		data := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(data, 0); err != nil {
			return nil, fmt.Errorf("read program segment %#x: %w", prog.Vaddr, err)
		}

		addrs = append(addrs, searchBytes(data, needle, e.Base+prog.Vaddr)...)
	}
	return addrs, nil
}

func (e *ELFFile) searchSection(name string, needle []byte, opts ELFSearchOptions) ([]uint64, error) {
	section := e.file.Section(name)
	if section == nil {
		return nil, fmt.Errorf("ELF section %q not found", name)
	}
	if !sectionMatchesSearchOptions(section, opts) {
		return nil, nil
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read section %q: %w", name, err)
	}
	return searchBytes(data, needle, e.Base+section.Addr), nil
}

func searchBytes(data []byte, needle []byte, baseAddr uint64) []uint64 {
	var addrs []uint64
	base := 0
	for {
		idx := bytes.Index(data[base:], needle)
		if idx < 0 {
			break
		}
		offset := base + idx
		addrs = append(addrs, baseAddr+uint64(offset))
		base = offset + 1
	}
	return addrs
}

func programMatchesSearchOptions(prog *elf.Prog, opts ELFSearchOptions) bool {
	if opts.Readable && prog.Flags&elf.PF_R == 0 {
		return false
	}
	if opts.Writable && prog.Flags&elf.PF_W == 0 {
		return false
	}
	if opts.Executable && prog.Flags&elf.PF_X == 0 {
		return false
	}
	return true
}

func sectionMatchesSearchOptions(section *elf.Section, opts ELFSearchOptions) bool {
	if opts.Readable && section.Flags&elf.SHF_ALLOC == 0 {
		return false
	}
	if opts.Writable && section.Flags&elf.SHF_WRITE == 0 {
		return false
	}
	if opts.Executable && section.Flags&elf.SHF_EXECINSTR == 0 {
		return false
	}
	return true
}

func firstSearchResult(addrs []uint64, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	if len(addrs) == 0 {
		return 0, errors.New("search needle not found")
	}
	return addrs[0], nil
}

func rebaseAddressMap(addrs map[string]uint64, oldBase uint64, newBase uint64) {
	for name, addr := range addrs {
		addrs[name] = rebaseAddress(addr, oldBase, newBase)
	}
}

func rebaseAddress(addr uint64, oldBase uint64, newBase uint64) uint64 {
	if oldBase == 0 {
		return addr + newBase
	}
	if addr >= oldBase {
		return addr - oldBase + newBase
	}
	return addr + newBase
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

func (e *ELFFile) applyContextDefaults(f *elf.File) {
	if arch := contextArchForELF(f); arch != "" {
		Context.SetArch(arch)
	}
	if osName := contextOSForELF(f); osName != "" {
		Context.SetOS(osName)
	}
}

func contextArchForELF(f *elf.File) string {
	switch f.Machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_386:
		return "i386"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_MIPS, elf.EM_MIPS_RS3_LE:
		if f.Class == elf.ELFCLASS64 {
			if f.ByteOrder == binary.LittleEndian {
				return "mips64el"
			}
			return "mips64"
		}
		if f.ByteOrder == binary.LittleEndian {
			return "mipsel"
		}
		return "mips"
	default:
		return ""
	}
}

func contextOSForELF(f *elf.File) string {
	switch f.OSABI {
	case elf.ELFOSABI_LINUX, elf.ELFOSABI_NONE:
		return "linux"
	case elf.ELFOSABI_FREEBSD:
		return "freebsd"
	case elf.ELFOSABI_OPENBSD:
		return "openbsd"
	case elf.ELFOSABI_NETBSD:
		return "netbsd"
	default:
		return ""
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
