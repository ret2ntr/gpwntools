package gpwntools

import (
	"encoding/binary"
	"testing"
)

func TestSigreturnFrameAmd64(t *testing.T) {
	frame, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "amd64"})
	if err != nil {
		t.Fatalf("SigreturnFrame failed: %v", err)
	}
	if frame.Len() != 248 {
		t.Fatalf("amd64 frame len = %d, want 248", frame.Len())
	}
	if got := sropTestU64(frame.Bytes(), 184, "little"); got != 0x33 {
		t.Fatalf("amd64 csgsfs = %#x, want 0x33", got)
	}

	if err := frame.SetSyscallName("mprotect"); err != nil {
		t.Fatalf("SetSyscallName failed: %v", err)
	}
	if err := frame.SetArguments(0x601000, 0x1000, 7); err != nil {
		t.Fatalf("SetArguments failed: %v", err)
	}
	if err := frame.SetSP(0xdeadbeef); err != nil {
		t.Fatalf("SetSP failed: %v", err)
	}
	if err := frame.SetPC(0x400123); err != nil {
		t.Fatalf("SetPC failed: %v", err)
	}

	data := frame.Bytes()
	checks := map[int]uint64{
		104: 0x601000,
		112: 0x1000,
		136: 7,
		144: 10,
		160: 0xdeadbeef,
		168: 0x400123,
	}
	for offset, want := range checks {
		if got := sropTestU64(data, offset, "little"); got != want {
			t.Fatalf("amd64 offset %d = %#x, want %#x", offset, got, want)
		}
	}

	payload, err := Flat([]byte("A"), frame)
	if err != nil {
		t.Fatalf("Flat(frame) failed: %v", err)
	}
	if len(payload) != 1+frame.Len() {
		t.Fatalf("Flat(frame) len = %d, want %d", len(payload), 1+frame.Len())
	}
}

func TestSigreturnFrameI386KernelDefaults(t *testing.T) {
	frame, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "i386"})
	if err != nil {
		t.Fatalf("SigreturnFrame failed: %v", err)
	}
	if frame.Len() != 80 {
		t.Fatalf("i386 frame len = %d, want 80", frame.Len())
	}
	data := frame.Bytes()
	if got := sropTestU32(data, 60, "little"); got != 0x73 {
		t.Fatalf("i386 cs = %#x, want 0x73", got)
	}
	if got := sropTestU32(data, 72, "little"); got != 0x7b {
		t.Fatalf("i386 ss = %#x, want 0x7b", got)
	}

	frame64Kernel, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "i386", Kernel: "amd64"})
	if err != nil {
		t.Fatalf("SigreturnFrame kernel=amd64 failed: %v", err)
	}
	data = frame64Kernel.Bytes()
	if got := sropTestU32(data, 60, "little"); got != 0x23 {
		t.Fatalf("i386-on-amd64 cs = %#x, want 0x23", got)
	}
	if got := sropTestU32(data, 72, "little"); got != 0x2b {
		t.Fatalf("i386-on-amd64 ss = %#x, want 0x2b", got)
	}

	if err := frame.SetSyscallName("mprotect"); err != nil {
		t.Fatalf("SetSyscallName failed: %v", err)
	}
	if err := frame.SetArguments(0x601000, 0x1000, 7); err != nil {
		t.Fatalf("SetArguments failed: %v", err)
	}
	data = frame.Bytes()
	checks := map[int]uint64{
		32: 0x601000,
		36: 7,
		40: 0x1000,
		44: 125,
	}
	for offset, want := range checks {
		if got := sropTestU32(data, offset, "little"); uint64(got) != want {
			t.Fatalf("i386 offset %d = %#x, want %#x", offset, got, want)
		}
	}
}

func TestSigreturnFrameArmAndAArch64(t *testing.T) {
	arm, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "arm"})
	if err != nil {
		t.Fatalf("SigreturnFrame arm failed: %v", err)
	}
	if arm.Len() != 240 {
		t.Fatalf("arm frame len = %d, want 240", arm.Len())
	}
	armData := arm.Bytes()
	for offset, want := range map[int]uint32{
		20:  0x6,
		96:  0x40000010,
		232: 0x56465001,
		236: 0x120,
	} {
		if got := sropTestU32(armData, offset, "little"); got != want {
			t.Fatalf("arm offset %d = %#x, want %#x", offset, got, want)
		}
	}

	aarch64, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "aarch64"})
	if err != nil {
		t.Fatalf("SigreturnFrame aarch64 failed: %v", err)
	}
	if aarch64.Len() != 600 {
		t.Fatalf("aarch64 frame len = %d, want 600", aarch64.Len())
	}
	if err := aarch64.SetSyscallName("mprotect"); err != nil {
		t.Fatalf("SetSyscallName failed: %v", err)
	}
	if err := aarch64.SetArguments(0x4000, 0x1000, 7); err != nil {
		t.Fatalf("SetArguments failed: %v", err)
	}
	aarch64Data := aarch64.Bytes()
	checks := map[int]uint64{
		312: 0x4000,
		320: 0x1000,
		328: 7,
		376: 226,
		592: 0x0000021046508001,
	}
	for offset, want := range checks {
		if got := sropTestU64(aarch64Data, offset, "little"); got != want {
			t.Fatalf("aarch64 offset %d = %#x, want %#x", offset, got, want)
		}
	}
}

func TestSigreturnFrameMIPSLayouts(t *testing.T) {
	mips, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "mips"})
	if err != nil {
		t.Fatalf("SigreturnFrame mips failed: %v", err)
	}
	if mips.Len() != 296 {
		t.Fatalf("mips frame len = %d, want 296", mips.Len())
	}
	if mips.Endian != "big" {
		t.Fatalf("mips endian = %q, want big", mips.Endian)
	}
	if err := mips.Set("$v0", 0x101d); err != nil {
		t.Fatalf("Set($v0) failed: %v", err)
	}
	if err := mips.SetArguments(0x601000, 0x1000, 7); err != nil {
		t.Fatalf("SetArguments failed: %v", err)
	}
	data := mips.Bytes()
	checks := map[int]uint32{
		60: 0x101d,
		76: 0x601000,
		84: 0x1000,
		92: 7,
	}
	for offset, want := range checks {
		if got := sropTestU32(data, offset, "big"); got != want {
			t.Fatalf("mips offset %d = %#x, want %#x", offset, got, want)
		}
	}

	mipsel, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "mipsel"})
	if err != nil {
		t.Fatalf("SigreturnFrame mipsel failed: %v", err)
	}
	if mipsel.Len() != 292 {
		t.Fatalf("mipsel frame len = %d, want 292", mipsel.Len())
	}
	if mipsel.Endian != "little" {
		t.Fatalf("mipsel endian = %q, want little", mipsel.Endian)
	}
	if err := mipsel.Set("$v0", 0x101d); err != nil {
		t.Fatalf("Set($v0) failed: %v", err)
	}
	if err := mipsel.SetArguments(0x601000, 0x1000, 7); err != nil {
		t.Fatalf("SetArguments failed: %v", err)
	}
	data = mipsel.Bytes()
	checks = map[int]uint32{
		56: 0x101d,
		72: 0x601000,
		80: 0x1000,
		88: 7,
	}
	for offset, want := range checks {
		if got := sropTestU32(data, offset, "little"); got != want {
			t.Fatalf("mipsel offset %d = %#x, want %#x", offset, got, want)
		}
	}
}

func TestSigreturnFrameUsesContextEndianForMIPS(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	Context.SetArch("mips")
	Context.Endian = "little"

	frame, err := SigreturnFrame()
	if err != nil {
		t.Fatalf("SigreturnFrame failed: %v", err)
	}
	if frame.Arch != "mipsel" {
		t.Fatalf("context mips little frame arch = %q, want mipsel", frame.Arch)
	}
	if frame.Len() != 292 {
		t.Fatalf("context mips little frame len = %d, want 292", frame.Len())
	}
}

func TestSigreturnFrameRejectsUnknownRegister(t *testing.T) {
	frame, err := SigreturnFrameWithOptions(SigreturnFrameOptions{Arch: "amd64"})
	if err != nil {
		t.Fatalf("SigreturnFrame failed: %v", err)
	}
	if err := frame.Set("not_a_register", 1); err == nil {
		t.Fatal("Set(not_a_register) succeeded, want error")
	}
}

func sropTestU64(data []byte, offset int, endian string) uint64 {
	if endian == "big" {
		return binary.BigEndian.Uint64(data[offset : offset+8])
	}
	return binary.LittleEndian.Uint64(data[offset : offset+8])
}

func sropTestU32(data []byte, offset int, endian string) uint32 {
	if endian == "big" {
		return binary.BigEndian.Uint32(data[offset : offset+4])
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}
