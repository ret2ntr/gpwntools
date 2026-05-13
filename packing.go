package gpwntools

import (
	"encoding/binary"
	"fmt"
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

func requirePackedBytes(data []byte, n int) error {
	if len(data) < n {
		return fmt.Errorf("need at least %d bytes, got %d", n, len(data))
	}
	return nil
}
