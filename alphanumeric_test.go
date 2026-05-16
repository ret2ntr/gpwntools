package gpwntools

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAlphanumericEncodeFast(t *testing.T) {
	encoded, err := Alphanumeric.Encode([]byte{0xeb, 0xfe})
	if err != nil {
		t.Fatalf("Alphanumeric.Encode failed: %v", err)
	}
	if !IsAlphanumeric(encoded) {
		t.Fatalf("encoded shellcode contains non-alphanumeric bytes: % x", encoded)
	}
	if len(encoded) != 78 {
		t.Fatalf("encoded length = %d, want 78", len(encoded))
	}
	if !bytes.HasSuffix(encoded, []byte("k6")) {
		t.Fatalf("encoded shellcode tail = %q, want suffix %q", encoded[len(encoded)-2:], "k6")
	}
	wantHex := "575459483339596a335459666939576d575a6a3854596669394a425741586a4b54596669396b435741596a435459666939336957415a6a4254596669394e36307438315241505a307438305a6b36"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded shellcode changed:\ngot  %x\nwant %x", encoded, want)
	}
}

func TestAlphanumericEncodeRegisterAndOffset(t *testing.T) {
	encoded, err := Alphanumeric.
		WithRegister("r13").
		WithOffset(0x30).
		Encode([]byte{0x48, 0x31, 0xc0, 0xc3})
	if err != nil {
		t.Fatalf("Alphanumeric.Encode(r13, offset) failed: %v", err)
	}
	if !IsAlphanumeric(encoded) {
		t.Fatalf("encoded shellcode contains non-alphanumeric bytes: % x", encoded)
	}
	if !bytes.HasPrefix(encoded, []byte("AUX")) {
		t.Fatalf("r13 prologue prefix = %q, want %q", encoded[:3], "AUX")
	}
}

func TestAlphanumericInvalidOptions(t *testing.T) {
	if _, err := Alphanumeric.Encode([]byte{0xcc}, WithAlphanumericRegister("rip")); err == nil {
		t.Fatal("invalid register succeeded, want error")
	}
	if _, err := Alphanumeric.Encode([]byte{0xcc}, WithAlphanumericOffset(-1)); err == nil {
		t.Fatal("negative offset succeeded, want error")
	}
	_, err := Alphanumeric.Encode([]byte{0xcc}, WithAlphanumericStrategy(AlphanumericStrategySmall))
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("small strategy error = %v, want not implemented", err)
	}
}

func TestAlphanumericInstructionBytes(t *testing.T) {
	if got := alphaIMULDI(0x6d57); !bytes.Equal(got, []byte("fi9Wm")) {
		t.Fatalf("alphaIMULDI = %q", got)
	}
	if got := alphaXorRAXRDI('A', true); !bytes.Equal(got, []byte("0T8A")) {
		t.Fatalf("alphaXorRAXRDI low = %q", got)
	}
	if got := alphaXorRAXRDI('A', false); !bytes.Equal(got, []byte("0t8A")) {
		t.Fatalf("alphaXorRAXRDI high = %q", got)
	}
	push, err := alphaPushRegister("r13")
	if err != nil {
		t.Fatalf("alphaPushRegister(r13) failed: %v", err)
	}
	if !bytes.Equal(push, []byte("AU")) {
		t.Fatalf("alphaPushRegister(r13) = %q", push)
	}
}
