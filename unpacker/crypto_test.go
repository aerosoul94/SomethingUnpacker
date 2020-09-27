package unpacker

import (
	"bytes"
	"testing"
)

func TestAESDecrypt(t *testing.T) {
	key := []byte("\x22\xB4\xEF\xF0\x4F\xF0\xDA\xCE\xEF\x81\x37\x7A\x08\x78\x82\x36")
	encrypted := []byte("\x3F\xC6\x4A\x20\xDF\x8D\x31\x17\x33\xD2\x5C\xB8\x8F\x16\xEE\x51")
	decrypted := []byte("\x48\x89\x54\x24\x10\x4C\x89\x44\x24\x18\x4C\x89\x4C\x24\x20\x53")
	result := AESDecrypt(encrypted, key)
	if bytes.Compare(result, decrypted) != 0 {
		t.Errorf("Decrypt failed!")
	}
}

func TestXTEADecrypt(t *testing.T) {
	key := []byte("\xfe\x71\x68\xf1\x24\x6b\x9b\x68\xad\x7f\x9a\x03\x16\xd7\x23\x2c")
	v := []byte("\x39\x3c\x7d\x9d\x5a\x9f\xfe\xdc")
	encrypted := []byte("\xF7\xE1\xA4\x60\xF1\x85\x91\xE8")
	decrypted := []byte("\x4C\x8B\x1C\xCA\x48\x8B\x2C\xC2")
	result := XTEAEncrypt(v, key)
	XorBytes(result, encrypted, result, 8)
	if bytes.Compare(result, decrypted) != 0 {
		t.Errorf("Decrypt failed!")
	}
}
