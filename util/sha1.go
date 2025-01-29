package util

import (
	"encoding/binary"
	"fmt"
)

const (
	blockSize = 64
)

func left_rotate(x uint32, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}

func SHA1_hasher(message string) string {

	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476
	var h4 uint32 = 0xC3D2E1F0

	messageBytes := []byte(message)
	ml := uint64(len(messageBytes) * 8)

	messageBytes = append(messageBytes, 0x80)

	paddingLength := (56 - (len(messageBytes) % 64)) % 64
	for i := 0; i < paddingLength; i++ {
		messageBytes = append(messageBytes, 0x00)
	}

	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, ml)
	messageBytes = append(messageBytes, lengthBytes...)

	for i := 0; i < len(messageBytes); i += 64 {
		var w [80]uint32

		for j := 0; j < 16; j++ {
			w[j] = binary.BigEndian.Uint32(messageBytes[i+j*4 : i+(j+1)*4])
		}

		for j := 16; j < 80; j++ {
			w[j] = left_rotate(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1)
		}

		a, b, c, d, e := h0, h1, h2, h3, h4
		for j := 0; j < 80; j++ {
			var f, k uint32
			switch {
			case j >= 0 && j <= 19:
				f = (b & c) | (^b & d)
				k = 0x5A827999
			case j >= 20 && j <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			case j >= 40 && j <= 59:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			case j >= 60 && j <= 79:
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			temp := left_rotate(a, 5) + f + e + k + w[j]
			e, d, c, b, a = d, c, left_rotate(b, 30), a, temp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}

	return fmt.Sprintf("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
}

func hmac_SHA1(key []byte, counter []byte) []byte {
	if len(key) > blockSize {
		hashedKey := SHA1_hasher(string(key))
		key = []byte(hashedKey)
	}

	if len(key) < blockSize {
		padding := make([]byte, blockSize-len(key))
		key = append(key, padding...)
	}

	oPad := make([]byte, blockSize)
	iPad := make([]byte, blockSize)

	for i := range key {
		oPad[i] = key[i] ^ 0x5C
		iPad[i] = key[i] ^ 0x36
	}

	innerHash := SHA1_hasher(string(append(iPad, counter...)))
	return []byte(SHA1_hasher(string(append(oPad, []byte(innerHash)...))))
}
