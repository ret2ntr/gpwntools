package gpwntools

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestShellcraftIoUring(t *testing.T) {
	sc := Shellcraft.WithArch("amd64").WithOS("linux")
	setup := sc.IoUringSetup(8, "rsp")
	for _, want := range []string{
		"mov rdi, 0x8",
		"mov rsi, rsp",
		"mov rax, 0x1a9",
		"syscall",
	} {
		if !strings.Contains(setup, want) {
			t.Fatalf("IoUringSetup missing %q:\n%s", want, setup)
		}
	}

	enter := sc.IoUringEnter(3, 1, 1, IORING_ENTER_GETEVENTS, 0, 8)
	for _, want := range []string{
		"mov rdi, 0x3",
		"mov rsi, 0x1",
		"mov rdx, 0x1",
		"mov r10, 0x1",
		"xor r8, r8",
		"mov r9, 0x8",
		"mov rax, 0x1aa",
	} {
		if !strings.Contains(enter, want) {
			t.Fatalf("IoUringEnter missing %q:\n%s", want, enter)
		}
	}

	register := sc.IoUringRegister(3, IORING_REGISTER_FILES, "rsp", 1)
	for _, want := range []string{
		"mov rdi, 0x3",
		"mov rsi, 0x2",
		"mov rdx, rsp",
		"mov r10, 0x1",
		"mov rax, 0x1ab",
	} {
		if !strings.Contains(register, want) {
			t.Fatalf("IoUringRegister missing %q:\n%s", want, register)
		}
	}
}

func TestShellcraftIoUringORW(t *testing.T) {
	sc := Shellcraft.WithArch("amd64").WithOS("linux")
	code := sc.IoUringORW("/flag", 0x40)

	for _, want := range []string{
		"SYS_io_uring_setup",
		"SYS_io_uring_enter",
		"SYS_mmap",
		"SYS_write",
		"mov byte ptr [rdi + 0], 0x12",
		"mov byte ptr [rdi + 0], 0x16",
		"mov byte ptr [rdi + 0], 0x17",
		"mov dword ptr [rdi + 24], 0x40",
		".asciz \"/flag\"",
		"ret",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("IoUringORW missing %q:\n%s", want, code)
		}
	}
	if strings.Contains(code, "SYS_exit") {
		t.Fatalf("IoUringORW should return instead of exit:\n%s", code)
	}

	payload, err := sc.Asm(code)
	if err != nil {
		if isMissingAsmToolError(err) {
			t.Skip(err)
		}
		t.Fatalf("assembling IoUringORW failed: %v\n%s", err, code)
	}
	if len(payload) == 0 {
		t.Fatal("assembling IoUringORW returned empty payload")
	}
}

func TestShellcraftIoUringORWArchitectures(t *testing.T) {
	cases := []struct {
		arch string
		want []string
	}{
		{"i386", []string{
			"SYS_io_uring_setup",
			"SYS_mmap2",
			"int 0x80",
			"mov byte ptr [edi + 0], 0x12",
			".asciz \"/flag\"",
		}},
		{"arm", []string{
			"movw r7, #SYS_io_uring_setup",
			"movw r7, #SYS_mmap2",
			"svc 0",
			"strb r1, [r0]",
			".asciz \"/flag\"",
		}},
		{"aarch64", []string{
			"mov x8, #SYS_io_uring_setup",
			"mov x8, #SYS_mmap",
			"svc #0",
			"strb w1, [x0]",
			".asciz \"/flag\"",
		}},
		{"mips", []string{
			"bal base_anchor",
			"li $v0, SYS_io_uring_setup",
			"li $v0, SYS_mmap2",
			"sw $t0, 20($v0)",
			"syscall",
			".asciz \"/flag\"",
		}},
		{"mipsel", []string{
			"bal base_anchor",
			"li $v0, SYS_io_uring_setup",
			"li $v0, SYS_mmap2",
			"sw $t0, 16($v0)",
			"syscall",
			".asciz \"/flag\"",
		}},
		{"mips64", []string{
			"bal base_anchor",
			"li $v0, SYS_io_uring_setup",
			"li $v0, SYS_mmap",
			"sd $t0, 16($v0)",
			"syscall",
			".asciz \"/flag\"",
		}},
		{"mips64el", []string{
			"bal base_anchor",
			"li $v0, SYS_io_uring_setup",
			"li $v0, SYS_mmap",
			"sd $t0, 16($v0)",
			"syscall",
			".asciz \"/flag\"",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			sc := Shellcraft.WithArch(tc.arch).WithOS("linux")
			code := sc.IoUringORW("/flag", 0x40)
			for _, want := range tc.want {
				if !strings.Contains(code, want) {
					t.Fatalf("IoUringORW(%s) missing %q:\n%s", tc.arch, want, code)
				}
			}
			if strings.Contains(code, "SYS_exit") {
				t.Fatalf("IoUringORW(%s) should return instead of exit:\n%s", tc.arch, code)
			}

			payload, err := sc.Asm(code)
			if err != nil {
				if isMissingAsmToolError(err) {
					t.Skip(err)
				}
				t.Fatalf("assembling IoUringORW(%s) failed: %v\n%s", tc.arch, err, code)
			}
			if len(payload) == 0 {
				t.Fatalf("assembling IoUringORW(%s) returned empty payload", tc.arch)
			}
		})
	}
}

func TestShellcraftIoUringArchitectures(t *testing.T) {
	cases := []struct {
		arch string
		want []string
	}{
		{"i386", []string{"mov eax, 0x1a9", "int 0x80"}},
		{"arm", []string{"movw r7, #0x1a9", "svc 0"}},
		{"aarch64", []string{"movz x8, #0x1a9", "svc #0"}},
		{"mips", []string{"li $v0, 0x1149", "syscall"}},
		{"mips64", []string{"li $v0, 0x1531", "syscall"}},
	}

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			code := Shellcraft.WithArch(tc.arch).WithOS("linux").IoUringSetup(8, 0)
			for _, want := range tc.want {
				if !strings.Contains(code, want) {
					t.Fatalf("IoUringSetup(%s) missing %q:\n%s", tc.arch, want, code)
				}
			}
		})
	}
}

func TestIoUringSQEBytes(t *testing.T) {
	sqe := IoUringSQE{
		Opcode:      IORING_OP_WRITE,
		Flags:       IOSQE_IO_LINK,
		Ioprio:      0x1234,
		FD:          -1,
		Off:         0x0102030405060708,
		Addr:        0x1122334455667788,
		Len:         0x40,
		OpFlags:     0x99,
		UserData:    0xdeadbeefcafebabe,
		BufIndex:    2,
		Personality: 3,
		FileIndex:   IORING_FILE_INDEX_ALLOC,
		Addr3:       0x8877665544332211,
		Pad2:        0xaabbccddeeff0011,
	}
	got := sqe.BytesEndian("little")
	if len(got) != IoUringSQESize {
		t.Fatalf("SQE len = %d, want %d", len(got), IoUringSQESize)
	}
	if got[0] != IORING_OP_WRITE || got[1] != IOSQE_IO_LINK {
		t.Fatalf("SQE opcode/flags = %#x/%#x", got[0], got[1])
	}
	checkU16LE(t, got[2:4], 0x1234)
	checkU32LE(t, got[4:8], 0xffffffff)
	checkU64LE(t, got[8:16], 0x0102030405060708)
	checkU64LE(t, got[16:24], 0x1122334455667788)
	checkU32LE(t, got[24:28], 0x40)
	checkU32LE(t, got[28:32], 0x99)
	checkU64LE(t, got[32:40], 0xdeadbeefcafebabe)
	checkU16LE(t, got[40:42], 2)
	checkU16LE(t, got[42:44], 3)
	checkU32LE(t, got[44:48], 0xffffffff)
	checkU64LE(t, got[48:56], 0x8877665544332211)
	checkU64LE(t, got[56:64], 0xaabbccddeeff0011)

	big := sqe.BytesEndian("big")
	if !bytes.Equal(big[8:16], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("SQE big-endian off = %#v", big[8:16])
	}
}

func TestIoUringParamsAndCQEBytes(t *testing.T) {
	params := IoUringParams{
		SQEntries:    8,
		CQEntries:    16,
		Flags:        IORING_SETUP_CQSIZE,
		SQThreadCPU:  1,
		SQThreadIdle: 2,
		Features:     IORING_FEAT_SINGLE_MMAP,
		WqFD:         3,
		Resv:         [3]uint32{4, 5, 6},
		SQOff: IoUringSQOffsets{
			Head: 1, Tail: 2, RingMask: 3, RingEntries: 4,
			Flags: 5, Dropped: 6, Array: 7, Resv1: 8, UserAddr: 0x1111111122222222,
		},
		CQOff: IoUringCQOffsets{
			Head: 9, Tail: 10, RingMask: 11, RingEntries: 12,
			Overflow: 13, CQEs: 14, Flags: 15, Resv1: 16, UserAddr: 0x3333333344444444,
		},
	}
	got := params.BytesEndian("little")
	if len(got) != IoUringParamsSize {
		t.Fatalf("params len = %d, want %d", len(got), IoUringParamsSize)
	}
	checkU32LE(t, got[0:4], 8)
	checkU32LE(t, got[4:8], 16)
	checkU32LE(t, got[8:12], IORING_SETUP_CQSIZE)
	checkU32LE(t, got[40:44], 1)
	checkU64LE(t, got[72:80], 0x1111111122222222)
	checkU32LE(t, got[100:104], 14)
	checkU64LE(t, got[112:120], 0x3333333344444444)

	cqe := IoUringCQE{UserData: 0x1122334455667788, Res: -2, Flags: IORING_CQE_F_MORE}
	cqeBytes := cqe.BytesEndian("little")
	if len(cqeBytes) != IoUringCQESize {
		t.Fatalf("CQE len = %d, want %d", len(cqeBytes), IoUringCQESize)
	}
	checkU64LE(t, cqeBytes[0:8], 0x1122334455667788)
	checkU32LE(t, cqeBytes[8:12], 0xfffffffe)
	checkU32LE(t, cqeBytes[12:16], IORING_CQE_F_MORE)

	flat, err := Flat([]byte("A"), sqeForFlat(), params, cqe)
	if err != nil {
		t.Fatalf("Flat io_uring values failed: %v", err)
	}
	wantLen := 1 + IoUringSQESize + IoUringParamsSize + IoUringCQESize
	if len(flat) != wantLen {
		t.Fatalf("Flat io_uring len = %d, want %d", len(flat), wantLen)
	}
}

func sqeForFlat() IoUringSQE {
	return IoUringSQE{Opcode: IORING_OP_NOP}
}

func checkU16LE(t *testing.T, got []byte, want uint16) {
	t.Helper()
	if value := binary.LittleEndian.Uint16(got); value != want {
		t.Fatalf("got %#x, want %#x", value, want)
	}
}

func checkU32LE(t *testing.T, got []byte, want uint32) {
	t.Helper()
	if value := binary.LittleEndian.Uint32(got); value != want {
		t.Fatalf("got %#x, want %#x", value, want)
	}
}

func checkU64LE(t *testing.T, got []byte, want uint64) {
	t.Helper()
	if value := binary.LittleEndian.Uint64(got); value != want {
		t.Fatalf("got %#x, want %#x", value, want)
	}
}
