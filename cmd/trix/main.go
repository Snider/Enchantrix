package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/leaanthony/clir"
)

var availableSigils = []string{
	"reverse", "hex", "base64", "gzip", "json", "json-indent", "md4", "md5",
	"sha1", "sha224", "sha256", "sha384", "sha512", "ripemd160", "sha3-224",
	"sha3-256", "sha3-384", "sha3-512", "sha512-224", "sha512-256",
	"blake2s-256", "blake2b-256", "blake2b-384", "blake2b-512",
}

func main() {
	app := clir.NewCli("trix", "A tool for encoding and decoding .trix files", "v0.0.1")

	// Encode command
	encodeCmd := app.NewSubCommand("encode", "Encode a file to the .trix format")
	var encodeInput, encodeOutput, encodeMagic string
	encodeCmd.StringFlag("input", "Input file (or stdin)", &encodeInput)
	encodeCmd.StringFlag("output", "Output file", &encodeOutput)
	encodeCmd.StringFlag("magic", "Magic number (4 bytes)", &encodeMagic)
	encodeCmd.Action(func() error {
		sigils := encodeCmd.OtherArgs()
		return handleEncode(encodeInput, encodeOutput, encodeMagic, sigils)
	})

	// Decode command
	decodeCmd := app.NewSubCommand("decode", "Decode a .trix file")
	var decodeInput, decodeOutput, decodeMagic string
	decodeCmd.StringFlag("input", "Input file (or stdin)", &decodeInput)
	decodeCmd.StringFlag("output", "Output file", &decodeOutput)
	decodeCmd.StringFlag("magic", "Magic number (4 bytes)", &decodeMagic)
	decodeCmd.Action(func() error {
		sigils := decodeCmd.OtherArgs()
		return handleDecode(decodeInput, decodeOutput, decodeMagic, sigils)
	})

	// Hash command
	hashCmd := app.NewSubCommand("hash", "Hash a file using a specified algorithm")
	var hashInput string
	var hashAlgo string
	hashCmd.StringFlag("input", "Input file (or stdin)", &hashInput)
	hashCmd.Action(func() error {
		algo := hashCmd.OtherArgs()
		if len(algo) > 0 {
			hashAlgo = algo[0]
		}
		return handleHash(hashInput, hashAlgo)
	})

	// Sigil commands
	for _, sigil := range availableSigils {
		sigil := sigil // capture range variable
		sigilCmd := app.NewSubCommand(sigil, "Apply the "+sigil+" sigil")
		var input string
		sigilCmd.StringFlag("input", "Input file or string (or stdin)", &input)
		sigilCmd.Action(func() error {
			return handleSigil(sigil, input)
		})
	}

	if err := app.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func readInput(inputFile string) ([]byte, error) {
	if inputFile == "" {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(inputFile)
}

func handleSigil(sigilName, input string) error {
	s, err := enchantrix.NewSigil(sigilName)
	if err != nil {
		return err
	}
	var data []byte
	// check if input is a file or a string
	if _, err := os.Stat(input); err == nil {
		data, err = readInput(input)
		if err != nil {
			return err
		}
	} else {
		if input == "" {
			data, err = readInput("")
			if err != nil {
				return err
			}
		} else {
			data = []byte(input)
		}
	}

	out, err := s.In(data)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func handleHash(inputFile, algo string) error {
	if algo == "" {
		return fmt.Errorf("hash algorithm is required")
	}

	data, err := readInput(inputFile)
	if err != nil {
		return err
	}

	service := crypt.NewService()
	hash := service.Hash(crypt.HashType(algo), string(data))
	fmt.Println(hash)
	return nil
}

func handleEncode(inputFile, outputFile, magicNumber string, sigils []string) error {
	if outputFile == "" {
		return fmt.Errorf("output file is required")
	}
	if len(magicNumber) != 4 {
		return fmt.Errorf("magic number must be 4 bytes long")
	}

	payload, err := readInput(inputFile)
	if err != nil {
		return err
	}

	t := &trix.Trix{
		Header:   make(map[string]interface{}),
		Payload:  payload,
		InSigils: sigils,
	}

	if err := t.Pack(); err != nil {
		return err
	}

	encoded, err := trix.Encode(t, magicNumber, nil)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputFile, encoded, 0644)
}

func handleDecode(inputFile, outputFile, magicNumber string, sigils []string) error {
	if outputFile == "" {
		return fmt.Errorf("output file is required")
	}
	if len(magicNumber) != 4 {
		return fmt.Errorf("magic number must be 4 bytes long")
	}

	data, err := readInput(inputFile)
	if err != nil {
		return err
	}

	t, err := trix.Decode(data, magicNumber, nil)
	if err != nil {
		return err
	}

	t.OutSigils = sigils
	if err := t.Unpack(); err != nil {
		return err
	}

	return ioutil.WriteFile(outputFile, t.Payload, 0644)
}
