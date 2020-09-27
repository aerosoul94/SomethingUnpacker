package unpacker

import (
	"crypto/aes"
)

// XorBytes xors two byte strings
func XorBytes(dst, a, b []byte, n int) {
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func bytesToV(src []byte) (uint32, uint32) {
	r0 := uint32(src[0])<<0 | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
	r1 := uint32(src[4])<<0 | uint32(src[5])<<8 | uint32(src[6])<<16 | uint32(src[7])<<24
	return r0, r1
}

func bytesToKey(src []byte) []uint32 {
	result := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		result[i] |= uint32(src[(i*4)+0]) << 0
		result[i] |= uint32(src[(i*4)+1]) << 8
		result[i] |= uint32(src[(i*4)+2]) << 16
		result[i] |= uint32(src[(i*4)+3]) << 24
	}
	return result
}

func uint32ToBytes(v0, v1 uint32, dst []byte) {
	dst[0] = byte(v0)
	dst[1] = byte(v0 >> 8)
	dst[2] = byte(v0 >> 16)
	dst[3] = byte(v0 >> 24)
	dst[4] = byte(v1)
	dst[5] = byte(v1 >> 8)
	dst[6] = byte(v1 >> 16)
	dst[7] = byte(v1 >> 24)
}

const numRounds = 64

// XTEAEncrypt will encrypt a chunk using XTEA
func XTEAEncrypt(v, key []byte) []byte {
	v0, v1 := bytesToV(v)
	k := bytesToKey(key)
	var sum uint32 = 0
	var delta uint32 = 0x9e3779b9
	var mask uint32 = 0xffffffff

	for round := 0; round < numRounds; round++ {
		v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum&3]))) & mask
		sum = (sum + delta) & mask
		v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11&3]))) & mask
	}

	dst := make([]byte, 8)
	uint32ToBytes(v0, v1, dst)
	return dst
}

// AESDecrypt decrypts a chunk using AES-ECB
func AESDecrypt(encrypted []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(encrypted))
	cipher.Decrypt(decrypted, encrypted)
	return decrypted
}

// CryptoMethod is the method to use for decryption
type CryptoMethod int

const (
	// AES use AES-ECB for decryption
	AES CryptoMethod = iota
	// XTEA use XTEA for decryption
	XTEA
)