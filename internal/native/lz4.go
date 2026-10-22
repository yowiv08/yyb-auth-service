package native

import (
	"encoding/binary"
	"fmt"
)

func lz4CompressBlock(src []byte) []byte {
	srcLen := len(src)
	if srcLen == 0 {
		return []byte{}
	}

	out := make([]byte, 0, srcLen)
	hashTable := make([]int, 16384)
	for i := range hashTable {
		hashTable[i] = -1
	}

	hash4 := func(index int) int {
		if index+4 > srcLen {
			return -1
		}
		return int((binary.LittleEndian.Uint32(src[index:index+4]) * 0x9e3779b1 >> 16) & 0x3fff)
	}

	writeLen := func(length int) {
		for length >= 255 {
			out = append(out, 255)
			length -= 255
		}
		out = append(out, byte(length))
	}

	rememberRange := func(start int, end int) {
		for index := start; index < end && index+4 <= srcLen; index++ {
			hashTable[hash4(index)] = index
		}
	}

	anchor := 0
	for pos := 0; pos+4 <= srcLen; {
		hash := hash4(pos)
		candidate := hashTable[hash]
		hashTable[hash] = pos

		if candidate >= 0 &&
			candidate < pos &&
			pos-candidate <= 65535 &&
			candidate+4 <= srcLen &&
			binary.LittleEndian.Uint32(src[candidate:candidate+4]) == binary.LittleEndian.Uint32(src[pos:pos+4]) {
			matchLen := 4
			for pos+matchLen < srcLen && src[candidate+matchLen] == src[pos+matchLen] {
				matchLen++
			}

			litLen := pos - anchor
			tokenPos := len(out)
			out = append(out, 0)
			if litLen < 15 {
				out[tokenPos] = byte(litLen << 4)
			} else {
				out[tokenPos] = 0xf0
				writeLen(litLen - 15)
			}

			out = append(out, src[anchor:pos]...)
			offset := pos - candidate
			out = append(out, byte(offset&0xff), byte((offset>>8)&0xff))

			matchNibble := matchLen - 4
			if matchNibble < 15 {
				out[tokenPos] |= byte(matchNibble)
			} else {
				out[tokenPos] |= 15
				writeLen(matchNibble - 15)
			}

			matchStart := pos
			pos += matchLen
			rememberRange(matchStart+1, pos)
			anchor = pos
			continue
		}

		pos++
	}

	litLen := srcLen - anchor
	tokenPos := len(out)
	out = append(out, 0)
	if litLen < 15 {
		out[tokenPos] = byte(litLen << 4)
	} else {
		out[tokenPos] = 0xf0
		writeLen(litLen - 15)
	}
	out = append(out, src[anchor:]...)

	return out
}

func lz4DecompressBlock(src []byte) ([]byte, error) {
	return lz4DecompressBlockLimit(src, 16<<20)
}

func lz4DecompressBlockLimit(src []byte, maxOutput int) ([]byte, error) {
	capacity := maxOutput
	if len(src) <= maxOutput/4 {
		capacity = len(src) * 4
	}
	out := make([]byte, 0, capacity)
	readLength := func(pos *int, length int) (int, error) {
		if length == 15 {
			for {
				if *pos >= len(src) {
					return 0, fmt.Errorf("lz4 length extension truncated")
				}
				current := int(src[*pos])
				(*pos)++
				if current > maxOutput-length {
					return 0, fmt.Errorf("lz4 output exceeds %d bytes", maxOutput)
				}
				length += current
				if current != 255 {
					break
				}
			}
		}
		return length, nil
	}
	for pos := 0; pos < len(src); {
		token := src[pos]
		pos++

		litLen, err := readLength(&pos, int(token>>4))
		if err != nil {
			return nil, err
		}

		if litLen > len(src)-pos {
			return nil, fmt.Errorf("lz4 literal truncated")
		}
		if litLen > maxOutput-len(out) {
			return nil, fmt.Errorf("lz4 output exceeds %d bytes", maxOutput)
		}
		out = append(out, src[pos:pos+litLen]...)
		pos += litLen

		if pos >= len(src) {
			break
		}
		if pos+1 >= len(src) {
			return nil, fmt.Errorf("lz4 offset truncated")
		}

		offset := int(src[pos]) | int(src[pos+1])<<8
		pos += 2
		if offset <= 0 || offset > len(out) {
			return nil, fmt.Errorf("lz4 invalid offset")
		}

		matchLen, err := readLength(&pos, int(token&0x0f))
		if err != nil {
			return nil, err
		}
		if matchLen > maxOutput-len(out)-4 {
			return nil, fmt.Errorf("lz4 output exceeds %d bytes", maxOutput)
		}
		matchLen += 4

		start := len(out) - offset
		for index := 0; index < matchLen; index++ {
			out = append(out, out[start+index])
		}
	}

	return out, nil
}
