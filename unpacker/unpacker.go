package unpacker

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
)


func getSectionByRVA(pefile *pe.File, rva uint32) *pe.Section {
	for _, section := range pefile.Sections {
		virtualAddr := section.VirtualAddress
		size := section.VirtualSize
		if section.Size > size {
			size = section.Size
		}
		end := virtualAddr + size
		if rva >= virtualAddr && rva < end {
			return section
		}
	}
	return nil
}

func getData(pefile *pe.File, base *bytes.Buffer, outBytes []byte,
	rva uint32) {
	section := getSectionByRVA(pefile, rva)
	if section == nil {
		log.Fatalf("Can't find section for RVA: %x", rva)
	}
	// Translate the rva to a file offset
	offset := (rva - section.VirtualAddress) + section.Offset
	length := len(outBytes)
	end := offset + uint32(length)
	copy(outBytes, base.Bytes()[offset:end])
}

// ReadData read's the next array of encrypted bytes
func ReadData(pefile *pe.File, base *bytes.Buffer, chunkTable *bytes.Reader, chunk *Chunk,
		outBuffer *bytes.Buffer, length int, bytesProcessed *int) {
	bytesToRead := length
	for {
		// Bytes remaining in this chunk
		bytesRemaining := chunk.length - *bytesProcessed
		rva := uint32(chunk.offset) + uint32(*bytesProcessed)
		if bytesToRead < bytesRemaining {
			// Just a plain old copy of length bytes
			var tmp = make([]byte, bytesToRead)
			getData(pefile, base, tmp, rva)
			outBuffer.Write(tmp)
			*bytesProcessed = bytesToRead + *bytesProcessed
		} else {
			// We are at the end of a chunk
			if bytesToRead == bytesRemaining {
				// The amount we need is the amount thats left
				var tmp = make([]byte, bytesRemaining)
				getData(pefile, base, tmp, rva)
				outBuffer.Write(tmp)
				ChunkDecode(chunkTable, chunk)
				if chunk.offset == 0xffffffff {
					return
				}
				*bytesProcessed = 0
			} else {
				// We need more than what remains
				var tmp = make([]byte, bytesRemaining)
				getData(pefile, base, tmp, rva)
				outBuffer.Write(tmp)
				*bytesProcessed = 0
				ChunkDecode(chunkTable, chunk)
				bytesToRead = bytesToRead - bytesRemaining
				if chunk.offset == 0xffffffff {
					var tmp = make([]byte, bytesToRead)
					outBuffer.Write(tmp)
					return
				}
				// We should continue on to copy the remaining bytes
			}
		}
		if outBuffer.Len() > length {
			log.Fatal("Something went wrong in ReadData()")
		}
		if outBuffer.Len() == length {
			break
		}
	}
}

func setData(pefile *pe.File, base *bytes.Buffer, inBytes []byte, rva uint32) {
	section := getSectionByRVA(pefile, rva)
	if section == nil {
		log.Fatalf("No section for rva: %x\n", rva)
	}
	// Translate the rva to a file offset
	offset := (rva - section.VirtualAddress) + section.Offset
	length := len(inBytes)
	end := offset + uint32(length)
	copy(base.Bytes()[offset:end], inBytes)
}

// WriteData back to the executable
func WriteData(pefile *pe.File, base *bytes.Buffer, chunkTable *bytes.Reader, chunk *Chunk,
		data []byte, length int, bytesProcessed *int) {
	// Total number of bytes written
	bytesWritten := 0
	for {
		// Bytes left in the current chunk
		bytesRemaining := chunk.length - *bytesProcessed
		// Number of bytes to write this round
		bytesToWrite := length - bytesWritten
		offset := uint32(chunk.offset) + uint32(*bytesProcessed)
		// If we're at the end of the chunk
		if bytesToWrite < bytesRemaining {
			setData(pefile, base, data[bytesWritten:bytesWritten+bytesToWrite], offset)
			*bytesProcessed = bytesToWrite + *bytesProcessed
			bytesWritten = length
		} else {
			setData(pefile, base, data[bytesWritten:bytesWritten+bytesRemaining], offset)
			bytesWritten += bytesRemaining
			ChunkDecode(chunkTable, chunk)
			if chunk.offset == 0xffffffff {
				return
			}
			*bytesProcessed = 0
		}
		if bytesWritten == length {
			break
		}
	}
}

// Unpack will unpack an executable
func Unpack(exepath string, method CryptoMethod, key []byte, iv []byte,
		chunkOffset int64, chunkEncoded bool) {
	file, err := os.Open(exepath)
	if err != nil {
		log.Fatal("Failed to open file!")
	}

	pefile, err := pe.NewFile(file)
	if err != nil {
		log.Fatal("Failed to read PE file")
	}

	// We need to get the file size
	fi, err := file.Stat()
	if err != nil {
		log.Fatal("Failed to obtain stat!")
	}

	// Allocate memory for the file
	fileLength := fi.Size()
	buffer := make([]byte, fileLength)
	file.Read(buffer)

	// Read the data into memory
	readChunkPointer := bytes.NewReader(buffer)
	readChunkPointer.Seek(chunkOffset, io.SeekStart)

	writeChunkPointer := bytes.NewReader(buffer)

	outputBuffer := bytes.NewBuffer(buffer)

	DecodeChunks = chunkEncoded

	// Get initial chunk
	var readChunk, writeChunk Chunk
	ChunkDecode(readChunkPointer, &readChunk)

	var bytesRead int
	var bytesWritten int
	var encryptedSize int
	if method == AES {
		encryptedSize = 0x10
	} else if method == XTEA {
		encryptedSize = 0x8
	}

	// The unpacker processes `encryptedSize` amount of bytes in each round
	// At the end of a chunk, ReadData will overwrite `readChunk` with the next
	// chunk's information. The loop ends when `readChunk`'s offset is 0xffffffff.
	var encryptedBuffer bytes.Buffer
	for readChunk.offset != 0xffffffff {
		position, _ := readChunkPointer.Seek(0, io.SeekCurrent)

		writeChunkPointer.Seek(position, io.SeekStart)
		writeChunk.offset = readChunk.offset
		writeChunk.length = readChunk.length

		bytesWritten = bytesRead
		
		// Read the encrypted data
		ReadData(pefile, outputBuffer, readChunkPointer, &readChunk, &encryptedBuffer, encryptedSize, &bytesRead)

		// Decrypt the data
		decryptedBytes := make([]byte, encryptedSize)
		if method == AES {
			decryptedBytes = AESDecrypt(encryptedBuffer.Bytes(), key)
		} else if method == XTEA {
			iv = XTEAEncrypt(iv, key)
			XorBytes(decryptedBytes, iv, encryptedBuffer.Bytes(), 8)
		}

		// Write decrypted data back to memory
		WriteData(pefile, outputBuffer, writeChunkPointer, &writeChunk, decryptedBytes, encryptedSize, &bytesWritten)

		encryptedBuffer.Reset()
	}

	fileName := strings.TrimSuffix(exepath, path.Ext(exepath))
	save, err := os.Create(fmt.Sprintf("%s_unpacked.exe", fileName))
	save.Write(outputBuffer.Bytes())

	log.Print("Finito.")
}
