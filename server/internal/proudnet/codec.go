package proudnet

import (
	"encoding/binary"
	"errors"
)

// Goley's native ProudNet TCP payload codec, mirrored from client VA 0xA69F20
// plus the small expansion wrapper at 0xA69C10. The outer PN32 header's fourth
// byte is the rolling codec channel used by this transform.

var codecPackCounts = [...]int{0, 1, 2, 3, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 8, 9, 10}

var codecPackLens = [17][10]int{
	{},
	{1},
	{1, 4},
	{1, 4, 4},
	{4, 4, 6},
	{8, 4, 11},
	{7, 8, 9, 11},
	{4, 7, 14, 13, 6},
	{3, 15, 9, 16, 5, 7},
	{6, 14, 12, 14, 7, 10},
	{9, 2, 12, 14, 11, 16, 13},
	{11, 4, 21, 12, 14, 12, 11},
	{4, 24, 19, 6, 24, 16, 4, 10},
	{8, 4, 11, 17, 26, 18, 19, 26},
	{3, 17, 15, 19, 27, 11, 32, 34},
	{4, 16, 33, 26, 23, 22, 32, 15, 23},
	{14, 8, 21, 29, 39, 35, 17, 32, 37, 24},
}

var codecPackSkips = [17][10]int{
	{},
	{3},
	{3, 3},
	{3, 1, 2},
	{2, 3, 3},
	{3, 2, 3},
	{3, 3, 3, 2},
	{2, 2, 2, 2, 3},
	{2, 2, 2, 3, 2, 2},
	{2, 3, 2, 2, 2, 2},
	{2, 3, 2, 3, 3, 3, 2},
	{3, 2, 3, 2, 2, 3, 3},
	{1, 3, 3, 3, 3, 2, 3, 1},
	{3, 3, 1, 3, 2, 3, 3, 1},
	{2, 1, 3, 3, 3, 2, 3, 3},
	{1, 3, 2, 3, 3, 2, 3, 2, 1},
	{3, 3, 3, 2, 2, 3, 2, 2, 2, 3},
}

func codecGroupForPlainLen(n int) int {
	switch {
	case n == 0:
		return 0
	case n < 0x0b:
		if n >= 6 {
			return 2
		}
		return 1
	case n < 0x1a:
		if n >= 0x10 {
			return 4
		}
		return 3
	case n < 0x42:
		if n < 0x2e {
			if n >= 0x24 {
				return 6
			}
			return 5
		}
		if n >= 0x38 {
			return 8
		}
		return 7
	case n < 0x83:
		if n < 0x60 {
			if n >= 0x51 {
				return 10
			}
			return 9
		}
		if n >= 0x6f {
			return 12
		}
		return 11
	case n < 0xc9:
		if n >= 0xa1 {
			return 14
		}
		return 13
	default:
		if n >= 0x100 {
			return 16
		}
		return 15
	}
}

func codecGroupForPackedLen(n int) int {
	switch {
	case n == 0:
		return 0
	case n < 0x11:
		if n >= 0x0c {
			return 2
		}
		return 1
	case n < 0x22:
		if n >= 0x18 {
			return 4
		}
		return 3
	case n < 0x4f:
		if n < 0x39 {
			if n >= 0x2f {
				return 6
			}
			return 5
		}
		if n >= 0x45 {
			return 8
		}
		return 7
	case n < 0x96:
		if n < 0x72 {
			if n >= 0x63 {
				return 10
			}
			return 9
		}
		if n >= 0x82 {
			return 12
		}
		return 11
	case n < 0xdd:
		if n >= 0xb5 {
			return 14
		}
		return 13
	default:
		if n >= 0x119 {
			return 16
		}
		return 15
	}
}

func codecKey10Word(i int) uint32 {
	var b [4]byte
	for j := range b {
		b[j] = byte('0' + ((i*4 + j) % 10))
	}
	return binary.LittleEndian.Uint32(b[:])
}

func codecTableWord(i int) uint32 {
	v := byte(0xff - (i & 0xff))
	return uint32(v) | uint32(v)<<8 | uint32(v)<<16 | uint32(v)<<24
}

func xorWordsInPlace(data []byte, keyWord func(int) uint32, keyLen int) {
	words := len(data) / 4
	for i := 0; i < words; i++ {
		v := binary.LittleEndian.Uint32(data[i*4:]) ^ keyWord(i%keyLen)
		binary.LittleEndian.PutUint32(data[i*4:], v)
	}
	if rem := len(data) & 3; rem != 0 {
		kw := keyWord(words % keyLen)
		off := words * 4
		for i := 0; i < rem; i++ {
			data[off+i] ^= byte(kw >> (8 * i))
		}
	}
}

// CodecTransform mirrors VA 0xA69F20. It is symmetric: applying it twice with
// the same channel returns the original payload.
func CodecTransform(payload []byte, channel byte) []byte {
	out := append([]byte(nil), payload...)
	xorWordsInPlace(out, codecKey10Word, 10)

	blocks := len(out) / 10
	rem := len(out) % 10
	for i := 0; i < blocks; i++ {
		if int(channel) == i {
			continue
		}
		xorWordsInPlace(out[i*10:i*10+10], func(int) uint32 { return codecTableWord(i) }, 1)
	}
	if rem != 0 && int(channel) != blocks {
		xorWordsInPlace(out[blocks*10:], func(int) uint32 { return codecTableWord(blocks) }, 1)
	}
	xorWordsInPlace(out, func(int) uint32 { return codecTableWord(int(channel)) }, 1)
	return out
}

// CodecPack expands the transformed payload using the client's 0xA69C10 shape.
// The inserted bytes are skipped by the decoder; the client does not depend on
// their values.
func CodecPack(payload []byte) []byte {
	g := codecGroupForPlainLen(len(payload))
	out := make([]byte, 0, len(payload)+32)
	pos := 0
	for i := 0; i < codecPackCounts[g]; i++ {
		n := codecPackLens[g][i]
		if pos+n > len(payload) {
			break
		}
		out = append(out, payload[pos:pos+n]...)
		pos += n
		for j := 0; j < codecPackSkips[g][i]; j++ {
			out = append(out, 0xff)
		}
	}
	out = append(out, payload[pos:]...)
	return out
}

// CodecUnpack reverses CodecPack / client VA 0xA69B70.
func CodecUnpack(packed []byte) ([]byte, error) {
	g := codecGroupForPackedLen(len(packed))
	out := make([]byte, 0, len(packed))
	pos := 0
	for i := 0; i < codecPackCounts[g]; i++ {
		n := codecPackLens[g][i]
		skip := codecPackSkips[g][i]
		if pos+n > len(packed) {
			return nil, errors.New("proudnet: packed payload too short")
		}
		out = append(out, packed[pos:pos+n]...)
		pos += n + skip
		if pos > len(packed) {
			return nil, errors.New("proudnet: packed payload skip past end")
		}
	}
	out = append(out, packed[pos:]...)
	return out, nil
}

func EncodeCodecFrameBody(channel byte, plain []byte) []byte {
	return CodecPack(CodecTransform(plain, channel))
}

func DecodeCodecFrameBody(channel byte, packed []byte) ([]byte, error) {
	unpacked, err := CodecUnpack(packed)
	if err != nil {
		return nil, err
	}
	return CodecTransform(unpacked, channel), nil
}
