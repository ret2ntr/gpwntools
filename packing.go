package gpwntools

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func Gp64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

func Gp32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf
}

func Gp16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, v)
	return buf
}

func Gp8(v uint8) []byte {
	return GP8(v)
}

// GP64 packs a 64-bit unsigned integer in big-endian byte order.
func GP64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// GP32 packs a 32-bit unsigned integer in big-endian byte order.
func GP32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// GP16 packs a 16-bit unsigned integer in big-endian byte order.
func GP16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

// GP8 packs an 8-bit unsigned integer.
func GP8(v uint8) []byte {
	return []byte{v}
}

// Gu64 unpacks a 64-bit unsigned integer from little-endian byte order.
func Gu64(data []byte) (uint64, error) {
	if err := requirePackedBytes(data, 8); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:8]), nil
}

// Gu32 unpacks a 32-bit unsigned integer from little-endian byte order.
func Gu32(data []byte) (uint32, error) {
	if err := requirePackedBytes(data, 4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data[:4]), nil
}

// Gu16 unpacks a 16-bit unsigned integer from little-endian byte order.
func Gu16(data []byte) (uint16, error) {
	if err := requirePackedBytes(data, 2); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data[:2]), nil
}

// Gu8 unpacks an 8-bit unsigned integer.
func Gu8(data []byte) (uint8, error) {
	if err := requirePackedBytes(data, 1); err != nil {
		return 0, err
	}
	return data[0], nil
}

// GU64 unpacks a 64-bit unsigned integer from big-endian byte order.
func GU64(data []byte) (uint64, error) {
	if err := requirePackedBytes(data, 8); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data[:8]), nil
}

// GU32 unpacks a 32-bit unsigned integer from big-endian byte order.
func GU32(data []byte) (uint32, error) {
	if err := requirePackedBytes(data, 4); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data[:4]), nil
}

// GU16 unpacks a 16-bit unsigned integer from big-endian byte order.
func GU16(data []byte) (uint16, error) {
	if err := requirePackedBytes(data, 2); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data[:2]), nil
}

// GU8 unpacks an 8-bit unsigned integer.
func GU8(data []byte) (uint8, error) {
	return Gu8(data)
}

// ParseHexUint64 parses an ASCII hex string such as "0x7fff..." or "7fff...".
func ParseHexUint64(data []byte) (uint64, error) {
	s := strings.TrimSpace(string(data))
	s = strings.TrimPrefix(s, "0x")
	return strconv.ParseUint(s, 16, 64)
}

// ParseHexUint32 parses an ASCII hex string as uint32.
func ParseHexUint32(data []byte) (uint32, error) {
	value, err := ParseHexUint64(data)
	return uint32(value), err
}

// ParseHexUint16 parses an ASCII hex string as uint16.
func ParseHexUint16(data []byte) (uint16, error) {
	value, err := ParseHexUint64(data)
	return uint16(value), err
}

// ParseHexUint8 parses an ASCII hex string as uint8.
func ParseHexUint8(data []byte) (uint8, error) {
	value, err := ParseHexUint64(data)
	return uint8(value), err
}

// RecvHexUint64 reads until delim and parses the received ASCII hex value.
func RecvHexUint64(r io.Reader, delim []byte) (uint64, []byte, error) {
	data, err := RecvUntil(r, delim)
	if err != nil {
		return 0, data, err
	}
	value, err := ParseHexUint64(data)
	return value, data, err
}

// RecvHexUint32 reads until delim and parses the received ASCII hex value as uint32.
func RecvHexUint32(r io.Reader, delim []byte) (uint32, []byte, error) {
	value, data, err := RecvHexUint64(r, delim)
	return uint32(value), data, err
}

// RecvHexUint16 reads until delim and parses the received ASCII hex value as uint16.
func RecvHexUint16(r io.Reader, delim []byte) (uint16, []byte, error) {
	value, data, err := RecvHexUint64(r, delim)
	return uint16(value), data, err
}

// RecvHexUint8 reads until delim and parses the received ASCII hex value as uint8.
func RecvHexUint8(r io.Reader, delim []byte) (uint8, []byte, error) {
	value, data, err := RecvHexUint64(r, delim)
	return uint8(value), data, err
}

// RecvHex reads until delim and parses the received ASCII hex value as uint64.
func RecvHex(r io.Reader, delim []byte) (uint64, []byte, error) {
	return RecvHexUint64(r, delim)
}

func requirePackedBytes(data []byte, n int) error {
	if len(data) < n {
		return fmt.Errorf("need at least %d bytes, got %d", n, len(data))
	}
	return nil
}
