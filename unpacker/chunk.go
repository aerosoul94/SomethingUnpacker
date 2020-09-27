package unpacker

import (
	"bytes"
)

// Chunk contains information for a single encrypted block
type Chunk struct {
	offset int	// The offset to the chunk
	length int	// The length of the chunk
}

// DecodeVLQ decodes a single variable length quantity
func DecodeVLQ(buffer *bytes.Reader) int {
	val := 0
	shift := 0
	for {
		b, err := buffer.ReadByte()
		if err != nil {
			panic(err)
		}

		val += (int(b) & 0x7f) << shift
		shift += 7
		if (b & 0x80) == 0 {
			break
		}
	}
	return val
}

// DecodeInt32 decodes a single little endian int32 value
func DecodeInt32(buffer *bytes.Reader) int {
	tmp := make([]byte, 4)
	buffer.Read(tmp)
	var val uint32
	val |= uint32(tmp[0])
	val |= uint32(tmp[1]) << 8
	val |= uint32(tmp[2]) << 16
	val |= uint32(tmp[3]) << 24
	return int(val)
}

var DecodeChunks = false

// ChunkDecode decodes chunk information
func ChunkDecode(buffer *bytes.Reader, chunk *Chunk) {
	if DecodeChunks {
		chunk.offset = chunk.offset + DecodeVLQ(buffer) + chunk.length
		if chunk.offset == 0xffffffff {
			return
		}
		chunk.length = DecodeVLQ(buffer)
	} else {
		chunk.offset = DecodeInt32(buffer)
		if chunk.offset == 0xffffffff {
			return
		}
		chunk.length = DecodeInt32(buffer)
	}
}