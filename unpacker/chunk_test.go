package unpacker

import (
	"bytes"
	"testing"
)

func TestDecodeVLQ(t *testing.T) {
	r := bytes.NewReader([]byte("\x80\x20\x69"))
	offset := DecodeVLQ(r)
	length := DecodeVLQ(r)
	t.Logf("%x %x\n", offset, length)
	if offset != 0x1000 || length != 0x69 {
		t.Errorf("DecodeVLQ failed!")
	}
}

func TestDecodeInt32(t *testing.T) {
	r := bytes.NewReader([]byte("\x00\x10\x00\x00\x69\x00\x00\x00"))
	offset := DecodeInt32(r)
	length := DecodeInt32(r)
	t.Logf("%x %x\n", offset, length)
	if offset != 0x1000 || length != 0x69 {
		t.Errorf("DecodeInt32 failed!")
	}
}

func TestChunkDecodeEncoded(t *testing.T) {
	r := bytes.NewReader([]byte("\xFF\x87\xF3\xC6\x0D"))
	DecodeChunks = true
	chunk := Chunk{offset: 0x27233b26, length: 0xda}
	ChunkDecode(r, &chunk)
	t.Logf("%x %x\n", chunk.offset, chunk.length)
	if chunk.offset != 0xffffffff || chunk.length != 0xda {
		t.Errorf("ChunkDecode failed!")
	}
}

func TestChunkDecode(t *testing.T) {
	r := bytes.NewReader([]byte("\x01\x02\x03\x04\x05\x06\x07\x08"))
	DecodeChunks = false
	chunk := Chunk{offset: 0x27233b26, length: 0xda}
	ChunkDecode(r, &chunk)
	t.Logf("%x %x\n", chunk.offset, chunk.length)
	if chunk.offset != 0x04030201 || chunk.length != 0x08070605 {
		t.Errorf("ChunkDecode failed!")
	}
}