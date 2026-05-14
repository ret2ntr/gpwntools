package gpwntools

import (
	"debug/elf"
	"testing"
)

func TestSearchBytesFindsOverlappingMatches(t *testing.T) {
	got := searchBytes([]byte("aaaa"), []byte("aa"), 0x400000)
	want := []uint64{0x400000, 0x400001, 0x400002}
	if len(got) != len(want) {
		t.Fatalf("searchBytes found %d matches, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("searchBytes[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestProgramMatchesSearchOptions(t *testing.T) {
	prog := &elf.Prog{ProgHeader: elf.ProgHeader{Flags: elf.PF_R | elf.PF_X}}
	if !programMatchesSearchOptions(prog, ELFSearchOptions{Executable: true}) {
		t.Fatal("executable program was not matched")
	}
	if programMatchesSearchOptions(prog, ELFSearchOptions{Writable: true}) {
		t.Fatal("non-writable program matched writable search")
	}
}

func TestSectionMatchesSearchOptions(t *testing.T) {
	section := &elf.Section{SectionHeader: elf.SectionHeader{Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR}}
	if !sectionMatchesSearchOptions(section, ELFSearchOptions{Executable: true}) {
		t.Fatal("executable section was not matched")
	}
	if sectionMatchesSearchOptions(section, ELFSearchOptions{Writable: true}) {
		t.Fatal("non-writable section matched writable search")
	}
}

func TestSetBaseRebasesAddressMaps(t *testing.T) {
	e := &ELFFile{
		Entry:    0x1000,
		Symbols:  map[string]uint64{"backdoor": 0x1234},
		GOT:      map[string]uint64{"puts": 0x3000},
		PLT:      map[string]uint64{"puts": 0x1030},
		Sections: map[string]uint64{".text": 0x1000},
	}

	e.SetBase(0x55555000)
	if e.Entry != 0x55556000 {
		t.Fatalf("Entry = %#x, want %#x", e.Entry, uint64(0x55556000))
	}
	if e.Symbols["backdoor"] != 0x55556234 {
		t.Fatalf("symbol = %#x, want %#x", e.Symbols["backdoor"], uint64(0x55556234))
	}
	if got, ok := e.Resolve("backdoor"); !ok || got != 0x55556234 {
		t.Fatalf("Resolve(backdoor) = %#x, %v", got, ok)
	}

	e.SetBase(0x66666000)
	if e.Symbols["backdoor"] != 0x66667234 {
		t.Fatalf("rebased symbol = %#x, want %#x", e.Symbols["backdoor"], uint64(0x66667234))
	}
}
