package gpwntools

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	AlphanumericStrategyFast  = "fast"
	AlphanumericStrategySmall = "small"

	alphanumericCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	// Alphanumeric provides amd64 alphanumeric shellcode encoding helpers.
	Alphanumeric = AlphanumericEncoder{}

	alphaClearRDI    = []byte{0x57, 0x54, 0x59, 0x48, 0x33, 0x39, 0x59}
	alphaInitDecoder = []byte{
		0x6a, 0x33, 0x54, 0x59, 0x66, 0x69, 0x39, 0x57, 0x6d, 0x57, 0x5a,
		0x6a, 0x38, 0x54, 0x59, 0x66, 0x69, 0x39, 0x4a, 0x42, 0x57, 0x41, 0x58,
		0x6a, 0x4b, 0x54, 0x59, 0x66, 0x69, 0x39, 0x6b, 0x43, 0x57, 0x41, 0x59,
		0x6a, 0x43, 0x54, 0x59, 0x66, 0x69, 0x39, 0x33, 0x69, 0x57, 0x41, 0x5a,
	}
	alphaNop  = []byte{0x51}
	alphaNop2 = []byte{0x51, 0x59}
)

// AlphanumericOptions configures amd64 alphanumeric shellcode encoding.
type AlphanumericOptions struct {
	// Register is the register that points at the encoded shellcode. It
	// defaults to rax, matching ae64.
	Register string
	// Offset is added to the shellcode pointer while building decoder offsets.
	Offset int
	// Strategy selects the encoder strategy. "fast" is implemented without
	// external dependencies. "small" is reserved for a future solver-backed
	// encoder and currently returns an error.
	Strategy string
}

// AlphanumericOption updates AlphanumericOptions.
type AlphanumericOption func(*AlphanumericOptions)

// AlphanumericEncoder carries default options for alphanumeric shellcode
// encoding.
type AlphanumericEncoder struct {
	opts AlphanumericOptions
}

// WithAlphanumericRegister sets the register containing the shellcode pointer.
func WithAlphanumericRegister(register string) AlphanumericOption {
	return func(opts *AlphanumericOptions) {
		opts.Register = register
	}
}

// WithAlphanumericOffset sets the pointer offset used by the decoder.
func WithAlphanumericOffset(offset int) AlphanumericOption {
	return func(opts *AlphanumericOptions) {
		opts.Offset = offset
	}
}

// WithAlphanumericStrategy sets the encoder strategy.
func WithAlphanumericStrategy(strategy string) AlphanumericOption {
	return func(opts *AlphanumericOptions) {
		opts.Strategy = strategy
	}
}

// WithRegister returns a copy of the encoder with a default pointer register.
func (e AlphanumericEncoder) WithRegister(register string) AlphanumericEncoder {
	e.opts.Register = register
	return e
}

// WithOffset returns a copy of the encoder with a default pointer offset.
func (e AlphanumericEncoder) WithOffset(offset int) AlphanumericEncoder {
	e.opts.Offset = offset
	return e
}

// WithStrategy returns a copy of the encoder with a default strategy.
func (e AlphanumericEncoder) WithStrategy(strategy string) AlphanumericEncoder {
	e.opts.Strategy = strategy
	return e
}

// Encode transforms amd64 shellcode into alphanumeric shellcode. The generated
// decoder self-modifies the encoded bytes, so the target memory page must be
// writable.
func (e AlphanumericEncoder) Encode(shellcode []byte, options ...AlphanumericOption) ([]byte, error) {
	opts := e.options(options...)
	switch opts.Strategy {
	case "", AlphanumericStrategyFast:
		return alphaEncodeFast(shellcode, opts.Register, opts.Offset)
	case AlphanumericStrategySmall:
		return nil, fmt.Errorf("alphanumeric strategy %q is not implemented; use %q", opts.Strategy, AlphanumericStrategyFast)
	default:
		return nil, fmt.Errorf("unsupported alphanumeric strategy %q", opts.Strategy)
	}
}

// MustEncode is Encode but panics on invalid input.
func (e AlphanumericEncoder) MustEncode(shellcode []byte, options ...AlphanumericOption) []byte {
	out, err := e.Encode(shellcode, options...)
	if err != nil {
		panic(err)
	}
	return out
}

// EncodeFast is the ae64-style fast amd64 alphanumeric encoder.
func (e AlphanumericEncoder) EncodeFast(shellcode []byte, register string, offset int) ([]byte, error) {
	return alphaEncodeFast(shellcode, register, offset)
}

// AlphanumericEncode transforms amd64 shellcode into alphanumeric shellcode
// using the package-level Alphanumeric encoder.
func AlphanumericEncode(shellcode []byte, options ...AlphanumericOption) ([]byte, error) {
	return Alphanumeric.Encode(shellcode, options...)
}

// MustAlphanumericEncode is AlphanumericEncode but panics on invalid input.
func MustAlphanumericEncode(shellcode []byte, options ...AlphanumericOption) []byte {
	out, err := AlphanumericEncode(shellcode, options...)
	if err != nil {
		panic(err)
	}
	return out
}

// IsAlphanumericByte reports whether b is ASCII [0-9A-Za-z].
func IsAlphanumericByte(b byte) bool {
	return ('0' <= b && b <= '9') || ('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z')
}

// IsAlphanumeric reports whether every byte in data is ASCII [0-9A-Za-z].
func IsAlphanumeric(data []byte) bool {
	for _, b := range data {
		if !IsAlphanumericByte(b) {
			return false
		}
	}
	return true
}

func (e AlphanumericEncoder) options(options ...AlphanumericOption) AlphanumericOptions {
	opts := e.opts
	if opts.Register == "" {
		opts.Register = "rax"
	}
	if opts.Strategy == "" {
		opts.Strategy = AlphanumericStrategyFast
	}
	opts.Register = strings.ToLower(strings.TrimSpace(opts.Register))
	opts.Strategy = strings.ToLower(strings.TrimSpace(opts.Strategy))
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	if opts.Register == "" {
		opts.Register = "rax"
	}
	if opts.Strategy == "" {
		opts.Strategy = AlphanumericStrategyFast
	}
	opts.Register = strings.ToLower(strings.TrimSpace(opts.Register))
	opts.Strategy = strings.ToLower(strings.TrimSpace(opts.Strategy))
	return opts
}

type alphaMulCache struct {
	word uint16
	b    byte
}

type alphaMulGadget struct {
	mul    alphaMulCache
	offset int
}

type alphaEncodeInfo struct {
	idx        int
	reg        string
	useLowByte bool
}

type alphaEncodeInfoPlus struct {
	info           alphaEncodeInfo
	gadget         alphaMulGadget
	needPushByte   bool
	needChangeRDI  bool
	needChangeRDX  bool
	needRecoverRDX bool
}

func alphaEncodeFast(shellcode []byte, register string, offset int) ([]byte, error) {
	register = strings.ToLower(strings.TrimSpace(register))
	if register == "" {
		register = "rax"
	}
	if !alphaValidRegister(register) {
		return nil, fmt.Errorf("invalid alphanumeric register %q", register)
	}
	if offset < 0 {
		return nil, fmt.Errorf("alphanumeric offset must be non-negative, got %d", offset)
	}

	prologue, err := alphaPrologue(register)
	if err != nil {
		return nil, err
	}
	encodedShellcode, infos, err := alphaEncodePayload(shellcode)
	if err != nil {
		return nil, err
	}

	totalSpace := len(prologue)
	if totalSpace < 0x20 {
		totalSpace = 0x20
	}

	var decoder []byte
	nopLength := 0
	for attempt := 0; attempt < 256; attempt++ {
		infosPlus, err := alphaOptimizeEncoderInfo(infos, offset+totalSpace)
		if err != nil {
			return nil, err
		}
		decoder, err = alphaDecoder(infosPlus)
		if err != nil {
			return nil, err
		}
		trueLength := len(prologue) + len(decoder)
		if totalSpace >= trueLength && totalSpace-trueLength <= 100 {
			nopLength = totalSpace - trueLength
			break
		}
		totalSpace = trueLength
		if attempt == 255 {
			return nil, fmt.Errorf("alphanumeric decoder layout did not converge")
		}
	}

	out := make([]byte, 0, len(prologue)+len(decoder)+nopLength+len(encodedShellcode))
	out = append(out, prologue...)
	out = append(out, decoder...)
	out = append(out, bytes.Repeat(alphaNop2, nopLength/2)...)
	if nopLength%2 != 0 {
		out = append(out, alphaNop...)
	}
	out = append(out, encodedShellcode...)

	if !IsAlphanumeric(out) {
		return nil, fmt.Errorf("internal alphanumeric encoder error: generated non-alphanumeric byte")
	}
	return out, nil
}

func alphaPrologue(register string) ([]byte, error) {
	var out []byte
	if register != "rax" {
		push, err := alphaPushRegister(register)
		if err != nil {
			return nil, err
		}
		out = append(out, push...)
		out = append(out, 0x58) // pop rax
	}
	out = append(out, alphaClearRDI...)
	out = append(out, alphaInitDecoder...)
	return out, nil
}

func alphaEncodePayload(shellcode []byte) ([]byte, []alphaEncodeInfo, error) {
	regs := []string{"rdx", "r8", "r9", "r10"}
	lowBytes := []byte{0x55, 0x30, 0x59, 0x59}
	highBytes := []byte{0xc8, 0x80, 0xc0, 0x88}

	out := append([]byte(nil), shellcode...)
	var infos []alphaEncodeInfo
	for i, b := range shellcode {
		if IsAlphanumericByte(b) {
			continue
		}
		info := alphaEncodeInfo{idx: i}
		found := false
		if b < 0x80 {
			info.useLowByte = true
			for j, xorByte := range lowBytes {
				if IsAlphanumericByte(xorByte ^ b) {
					info.reg = regs[j]
					out[i] ^= xorByte
					found = true
					break
				}
			}
		} else {
			info.useLowByte = false
			for j, xorByte := range highBytes {
				if IsAlphanumericByte(xorByte ^ b) {
					info.reg = regs[j]
					out[i] ^= xorByte
					found = true
					break
				}
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("cannot alphanumeric-encode byte %#x at offset %d", b, i)
		}
		infos = append(infos, info)
	}
	return out, infos, nil
}

func alphaOptimizeEncoderInfo(infos []alphaEncodeInfo, offset int) ([]alphaEncodeInfoPlus, error) {
	count := len(infos)
	book := make([]bool, count)
	lastUpdate := 0

	cacheRDI := 0
	var cacheStackByte byte
	var cacheMulWord uint16
	var out []alphaEncodeInfoPlus

	for {
		noUpdate := true
		needCalcNewRDI := true
		needPushByte := true
		var useRDX, useR8, useR9, useR10 []alphaEncodeInfoPlus

		for i := lastUpdate; i < count; i++ {
			if book[i] {
				continue
			}
			if needCalcNewRDI {
				needCalcNewRDI = false
				lastUpdate = i
				gadget, pushByte, err := alphaFindMulGadget(infos[i].idx+offset, cacheStackByte)
				if err != nil {
					return nil, err
				}
				cacheRDI = (int(gadget.mul.word) * int(gadget.mul.b)) & 0xffff
				cacheStackByte = gadget.mul.b
				cacheMulWord = gadget.mul.word
				needPushByte = pushByte
			}

			disp := infos[i].idx + offset - cacheRDI
			if !alphaIntIsByte(disp) {
				continue
			}
			noUpdate = false
			book[i] = true
			info := alphaEncodeInfoPlus{
				info: infos[i],
				gadget: alphaMulGadget{
					mul:    alphaMulCache{word: cacheMulWord, b: cacheStackByte},
					offset: disp,
				},
			}

			switch infos[i].reg {
			case "rdx":
				useRDX = append(useRDX, info)
			case "r8":
				useR8 = append(useR8, info)
			case "r9":
				useR9 = append(useR9, info)
			case "r10":
				useR10 = append(useR10, info)
			default:
				return nil, fmt.Errorf("internal alphanumeric encoder error: unsupported xor register %q", infos[i].reg)
			}
		}

		alphaMarkRDXChange(useRDX)
		alphaMarkRDXChange(useR8)
		alphaMarkRDXChange(useR9)
		alphaMarkRDXChange(useR10)

		combined := append(useRDX, useR8...)
		combined = append(combined, useR9...)
		combined = append(combined, useR10...)
		if len(combined) > 0 {
			combined[0].needChangeRDI = true
			combined[0].needPushByte = needPushByte
			out = append(out, combined...)
		}
		if noUpdate {
			break
		}
	}
	return out, nil
}

func alphaMarkRDXChange(values []alphaEncodeInfoPlus) {
	if len(values) == 0 {
		return
	}
	values[0].needChangeRDX = true
	values[len(values)-1].needRecoverRDX = true
}

func alphaFindMulGadget(target int, cacheStackByte byte) (alphaMulGadget, bool, error) {
	charset := []byte(alphanumericCharset)
	for _, off := range charset {
		if cacheStackByte != 0 {
			for _, high := range charset {
				for _, low := range charset {
					word := uint16(high)<<8 | uint16(low)
					ans := (int(word) * int(cacheStackByte)) & 0xffff
					if ans+int(off) == target {
						return alphaMulGadget{
							mul:    alphaMulCache{word: word, b: cacheStackByte},
							offset: int(off),
						}, false, nil
					}
				}
			}
		}

		for _, high := range charset {
			for _, low := range charset {
				word := uint16(high)<<8 | uint16(low)
				for _, b := range charset {
					ans := (int(word) * int(b)) & 0xffff
					if ans+int(off) == target {
						return alphaMulGadget{
							mul:    alphaMulCache{word: word, b: b},
							offset: int(off),
						}, true, nil
					}
				}
			}
		}
	}
	return alphaMulGadget{}, false, fmt.Errorf("cannot build alphanumeric decoder offset for target %#x", target)
}

func alphaDecoder(infos []alphaEncodeInfoPlus) ([]byte, error) {
	var out []byte
	for _, info := range infos {
		if info.needChangeRDI {
			if info.needPushByte {
				if !IsAlphanumericByte(info.gadget.mul.b) {
					return nil, fmt.Errorf("internal alphanumeric encoder error: non-alphanumeric multiplier byte")
				}
				out = append(out, 0x6a, info.gadget.mul.b, 0x54, 0x59) // push imm8; push rsp; pop rcx
			}
			out = append(out, alphaIMULDI(info.gadget.mul.word)...)
		}

		if info.info.reg != "rdx" && info.needChangeRDX {
			push, err := alphaPushRegister("rdx")
			if err != nil {
				return nil, err
			}
			out = append(out, push...)
			push, err = alphaPushRegister(info.info.reg)
			if err != nil {
				return nil, err
			}
			out = append(out, push...)
			out = append(out, 0x5a) // pop rdx
		}

		if !alphaIntIsByte(info.gadget.offset) {
			return nil, fmt.Errorf("internal alphanumeric encoder error: non-alphanumeric decoder displacement %#x", info.gadget.offset)
		}
		out = append(out, alphaXorRAXRDI(byte(info.gadget.offset), info.info.useLowByte)...)

		if info.info.reg != "rdx" && info.needRecoverRDX {
			out = append(out, 0x5a) // pop rdx
		}
	}
	return out, nil
}

func alphaIMULDI(word uint16) []byte {
	return []byte{0x66, 0x69, 0x39, byte(word), byte(word >> 8)}
}

func alphaXorRAXRDI(disp byte, useLowByte bool) []byte {
	if useLowByte {
		return []byte{0x30, 0x54, 0x38, disp} // xor byte ptr [rax+rdi+disp], dl
	}
	return []byte{0x30, 0x74, 0x38, disp} // xor byte ptr [rax+rdi+disp], dh
}

func alphaPushRegister(register string) ([]byte, error) {
	switch register {
	case "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi":
		code := map[string]byte{
			"rax": 0x50, "rcx": 0x51, "rdx": 0x52, "rbx": 0x53,
			"rsp": 0x54, "rbp": 0x55, "rsi": 0x56, "rdi": 0x57,
		}
		return []byte{code[register]}, nil
	case "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
		n := map[string]byte{
			"r8": 0x50, "r9": 0x51, "r10": 0x52, "r11": 0x53,
			"r12": 0x54, "r13": 0x55, "r14": 0x56, "r15": 0x57,
		}
		return []byte{0x41, n[register]}, nil
	default:
		return nil, fmt.Errorf("invalid alphanumeric register %q", register)
	}
}

func alphaValidRegister(register string) bool {
	switch register {
	case "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
		return true
	default:
		return false
	}
}

func alphaIntIsByte(value int) bool {
	return 0 <= value && value <= 0xff && IsAlphanumericByte(byte(value))
}
