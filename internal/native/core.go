package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

type PBValue struct {
	WireType int
	Bytes    []byte
	Varint   uint64
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func hmacSha256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func hkdfExpand(prk []byte, info []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	prev := []byte{}
	for counter := byte(1); len(out) < outLen; counter++ {
		buf := make([]byte, 0, len(prev)+len(info)+1)
		buf = append(buf, prev...)
		buf = append(buf, info...)
		buf = append(buf, counter)
		prev = hmacSha256(prk, buf)
		out = append(out, prev...)
	}
	return out[:outLen]
}

func gcmNonce(iv []byte, seq uint64) ([]byte, error) {
	if len(iv) != 12 {
		return nil, fmt.Errorf("aes-gcm iv must be 12B")
	}

	nonce := append([]byte{}, iv...)
	high := uint32(seq >> 32)
	low := uint32(seq)
	binary.BigEndian.PutUint32(
		nonce[4:8],
		binary.BigEndian.Uint32(nonce[4:8])^high,
	)
	binary.BigEndian.PutUint32(
		nonce[8:12],
		binary.BigEndian.Uint32(nonce[8:12])^low,
	)
	return nonce, nil
}

func aesGCMEncrypt(key []byte, nonce []byte, plain []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm: %w", err)
	}
	return aead.Seal(nil, nonce, plain, aad), nil
}

func aesGCMDecrypt(key []byte, nonce []byte, payload []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm: %w", err)
	}
	plain, err := aead.Open(nil, nonce, payload, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes-gcm: %w", err)
	}
	return plain, nil
}

func aesGCMEncrypt192Packed(
	key []byte,
	plain []byte,
	nonce []byte,
	aad []byte,
) ([]byte, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("aes-192-gcm key must be 24B")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("aes-192-gcm nonce must be 12B")
	}

	payload, err := aesGCMEncrypt(key, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(payload)+12)
	out = append(out, payload[:len(payload)-16]...)
	out = append(out, nonce...)
	out = append(out, payload[len(payload)-16:]...)
	return out, nil
}

func aesGCMDecrypt192Packed(
	key []byte,
	blob []byte,
	aad []byte,
) ([]byte, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("aes-192-gcm key must be 24B")
	}
	if len(blob) <= 28 {
		return nil, fmt.Errorf("aes-192-gcm blob too short")
	}

	ciphertext := blob[:len(blob)-28]
	nonce := blob[len(blob)-28 : len(blob)-16]
	tag := blob[len(blob)-16:]
	payload := append(append([]byte{}, ciphertext...), tag...)
	return aesGCMDecrypt(key, nonce, payload, aad)
}

func writeVarint(v uint64) []byte {
	out := make([]byte, 0, 10)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			out = append(out, b)
			return out
		}
		out = append(out, b|0x80)
	}
}

func writeSignedVarint(v int64) []byte {
	return writeVarint(uint64(v))
}

func readVarint(buf []byte, offset int) (uint64, int, error) {
	if offset < 0 || offset > len(buf) {
		return 0, 0, fmt.Errorf("invalid varint offset %d", offset)
	}
	var (
		value uint64
		shift uint
	)
	cursor := offset
	for cursor < len(buf) {
		current := buf[cursor]
		cursor++
		if shift == 63 && current > 1 {
			return 0, 0, fmt.Errorf("varint overflow")
		}
		value |= uint64(current&0x7f) << shift
		if current < 0x80 {
			return value, cursor, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, fmt.Errorf("varint too long")
		}
	}
	return 0, 0, fmt.Errorf("truncated varint")
}

func pbFieldBytes(field int, payload []byte) []byte {
	tag := writeVarint(uint64((field << 3) | 2))
	length := writeVarint(uint64(len(payload)))
	out := make([]byte, 0, len(tag)+len(length)+len(payload))
	out = append(out, tag...)
	out = append(out, length...)
	out = append(out, payload...)
	return out
}

func pbFieldVarint(field int, value uint64) []byte {
	tag := writeVarint(uint64(field << 3))
	encoded := writeVarint(value)
	out := make([]byte, 0, len(tag)+len(encoded))
	out = append(out, tag...)
	out = append(out, encoded...)
	return out
}

func pbFieldFixed32(field int, value uint32) []byte {
	tag := writeVarint(uint64((field << 3) | 5))
	out := make([]byte, 0, len(tag)+4)
	out = append(out, tag...)
	return binary.LittleEndian.AppendUint32(out, value)
}

func pbFieldFixed64(field int, value uint64) []byte {
	tag := writeVarint(uint64((field << 3) | 1))
	out := make([]byte, 0, len(tag)+8)
	out = append(out, tag...)
	return binary.LittleEndian.AppendUint64(out, value)
}

func pbDecode(buf []byte) (map[int][]PBValue, error) {
	fields := map[int][]PBValue{}
	for offset := 0; offset < len(buf); {
		tag, next, err := readVarint(buf, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		field := int(tag >> 3)
		wireType := int(tag & 0x7)
		if tag>>3 == 0 || tag>>3 > 536870911 {
			return nil, fmt.Errorf("invalid protobuf field number %d", tag>>3)
		}

		value := PBValue{WireType: wireType}
		switch wireType {
		case 0:
			decoded, cursor, err := readVarint(buf, offset)
			if err != nil {
				return nil, err
			}
			value.Varint = decoded
			offset = cursor
		case 1:
			if offset+8 > len(buf) {
				return nil, fmt.Errorf("fixed64 field %d truncated", field)
			}
			value.Bytes = append([]byte{}, buf[offset:offset+8]...)
			offset += 8
		case 2:
			length, cursor, err := readVarint(buf, offset)
			if err != nil {
				return nil, err
			}
			offset = cursor
			if length > uint64(len(buf)-offset) {
				return nil, fmt.Errorf("bytes field %d truncated", field)
			}
			end := offset + int(length)
			value.Bytes = append([]byte{}, buf[offset:end]...)
			offset = end
		case 5:
			if offset+4 > len(buf) {
				return nil, fmt.Errorf("fixed32 field %d truncated", field)
			}
			value.Bytes = append([]byte{}, buf[offset:offset+4]...)
			offset += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wireType)
		}

		fields[field] = append(fields[field], value)
	}
	return fields, nil
}

func firstBytes(fields map[int][]PBValue, field int) []byte {
	values := fields[field]
	if len(values) == 0 {
		return nil
	}
	return values[0].Bytes
}

func firstVarint(fields map[int][]PBValue, field int) (uint64, bool) {
	values := fields[field]
	if len(values) == 0 || values[0].WireType != 0 {
		return 0, false
	}
	return values[0].Varint, true
}

func signed64(value uint64) int64 {
	return int64(value)
}

func decodeBase64(raw string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
	}
	var firstErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil {
			return decoded, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}
