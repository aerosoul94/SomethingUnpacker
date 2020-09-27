package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"./unpacker"
)

// Config stores information for unpacking a binary
type Config struct {
	Name              string `json:"name"`
	Key               string `json:"key"`
	IV                string `json:"iv"`
	Method            string `json:"method"`
	ChunkTableOffset  int64  `json:"chunkTableOffset"`
	ChunkTableEncoded bool   `json:"chunkTableEncoded"`
}

func printUsage() {
	log.Print("This unpacker unpacks stuff")
	log.Printf("Usage: %s <config> <exe path>", os.Args[0])
}

func main() {
	// TODO: One day we will automatically recover "configs" using the the binary alone
	if len(os.Args) != 3 {
		printUsage()
		log.Fatal("Incorrect number of parameters passed. See usage.")
	}

	jsonFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal("Cannot find config.json")
	}

	var configs []Config
	var config *Config
	js, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(js, &configs)

	for i := 0; i < len(configs); i++ {
		if os.Args[1] == configs[i].Name {
			config = &configs[i]
		}
	}

	if config == nil {
		log.Print("Available configurations:")
		for i := 0; i < len(configs); i++ {
			log.Printf("%s", configs[i].Name)
		}
		log.Fatalf("ERROR: No config named: %s", os.Args[1])
	}

	var method unpacker.CryptoMethod
	switch config.Method {
	case "aes":
		method = unpacker.AES
		break
	case "xtea":
		method = unpacker.XTEA
		break
	default:
		log.Fatalf("Unsupported crypto method %s", config.Method)
	}

	var key, iv []byte
	key, err = hex.DecodeString(config.Key)
	if err != nil {
		log.Fatalf("Unable to parse key string: %s", config.Key)
	}

	if config.IV != "" {
		iv, err = hex.DecodeString(config.IV)
		if err != nil {
			log.Fatalf("Unable to parse iv string: %s", config.IV)
		}
	}

	log.Printf("Decrypting: %s", os.Args[2])
	log.Printf("Config: %s", config.Name)
	log.Printf("Key: %s", config.Key)
	log.Printf("IV: %s", config.IV)
	log.Printf("Chunk Table Offset: %x", config.ChunkTableOffset)
	log.Printf("Chunk Table Encoded: %v", config.ChunkTableEncoded)

	unpacker.Unpack(os.Args[2], method, key, iv,
		config.ChunkTableOffset, config.ChunkTableEncoded)
}
