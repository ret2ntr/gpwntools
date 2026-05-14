package gpwntools

import (
	"io"
	"testing"
)

func TestParseHexUintVariants(t *testing.T) {
	if got, err := ParseHexUint64([]byte("0x12345678")); err != nil || got != 0x12345678 {
		t.Fatalf("ParseHexUint64 = %#x, %v", got, err)
	}
	if got, err := ParseHexUint32([]byte("12345678")); err != nil || got != 0x12345678 {
		t.Fatalf("ParseHexUint32 = %#x, %v", got, err)
	}
	if got, err := ParseHexUint16([]byte("0x1234")); err != nil || got != 0x1234 {
		t.Fatalf("ParseHexUint16 = %#x, %v", got, err)
	}
	if got, err := ParseHexUint8([]byte("0x7f")); err != nil || got != 0x7f {
		t.Fatalf("ParseHexUint8 = %#x, %v", got, err)
	}
}

type oneByteReader struct {
	data []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestRecvReadsRequestedSizeAcrossShortReads(t *testing.T) {
	got, err := Recv(&oneByteReader{data: []byte("abc")}, 3)
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("Recv = %q, want %q", got, "abc")
	}
}
