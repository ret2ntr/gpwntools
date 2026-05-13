package gpwntools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const cyclicAlphabet = "abcdefghijklmnopqrstuvwxyz"

// Flat concatenates common payload fragments into one byte slice.
func Flat(parts ...any) ([]byte, error) {
	var out []byte
	for _, part := range parts {
		chunk, err := flatPart(part)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// MustFlat is Flat but panics on invalid input.
func MustFlat(parts ...any) []byte {
	out, err := Flat(parts...)
	if err != nil {
		panic(err)
	}
	return out
}

// Fit places fragments at explicit offsets and fills gaps with filler.
func Fit(fragments map[int]any, filler byte) ([]byte, error) {
	offsets := make([]int, 0, len(fragments))
	for offset := range fragments {
		if offset < 0 {
			return nil, fmt.Errorf("negative fit offset %d", offset)
		}
		offsets = append(offsets, offset)
	}
	sort.Ints(offsets)

	var out []byte
	for _, offset := range offsets {
		part, err := flatPart(fragments[offset])
		if err != nil {
			return nil, err
		}
		end := offset + len(part)
		if len(out) < end {
			out = append(out, bytes.Repeat([]byte{filler}, end-len(out))...)
		}
		copy(out[offset:end], part)
	}
	return out, nil
}

// MustFit is Fit but panics on invalid input.
func MustFit(fragments map[int]any, filler byte) []byte {
	out, err := Fit(fragments, filler)
	if err != nil {
		panic(err)
	}
	return out
}

// Cyclic generates a de Bruijn-like pattern for finding overflow offsets.
func Cyclic(n int) []byte {
	if n <= 0 {
		return []byte{}
	}

	pattern := make([]byte, 0, n)
	alphabet := []byte(cyclicAlphabet)
	for _, a := range alphabet {
		for _, b := range alphabet {
			for _, c := range alphabet {
				pattern = append(pattern, a, b, c)
				if len(pattern) >= n {
					return pattern[:n]
				}
			}
		}
	}
	return pattern[:n]
}

// CyclicFind returns the first offset of needle in the generated cyclic pattern.
func CyclicFind(needle any) int {
	target, err := cyclicNeedle(needle)
	if err != nil || len(target) == 0 {
		return -1
	}
	return bytes.Index(Cyclic(len(cyclicAlphabet)*len(cyclicAlphabet)*len(cyclicAlphabet)*3), target)
}

func flatPart(part any) ([]byte, error) {
	switch v := part.(type) {
	case nil:
		return []byte{}, nil
	case []byte:
		return append([]byte(nil), v...), nil
	case string:
		return []byte(v), nil
	case uint8:
		return []byte{v}, nil
	case uint16:
		return Gp16(v), nil
	case uint32:
		return Gp32(v), nil
	case uint64:
		return Gp64(v), nil
	case uint:
		return Gp64(uint64(v)), nil
	case int:
		return Gp64(uint64(v)), nil
	case int8:
		return []byte{byte(v)}, nil
	case int16:
		return Gp16(uint16(v)), nil
	case int32:
		return Gp32(uint32(v)), nil
	case int64:
		return Gp64(uint64(v)), nil
	default:
		return nil, fmt.Errorf("unsupported flat part %T", part)
	}
}

func cyclicNeedle(needle any) ([]byte, error) {
	switch v := needle.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case uint32:
		return Gp32(v), nil
	case uint64:
		return Gp64(v), nil
	case int:
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(v))
		return buf, nil
	default:
		return nil, fmt.Errorf("unsupported cyclic needle %T", needle)
	}
}
