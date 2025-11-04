package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "trix",
		Short: "A tool for encoding and decoding .trix files",
		Long:  `trix is a command-line tool for working with the .trix file format, which is used for storing encrypted data.`,
	}

	encodeCmd = &cobra.Command{
		Use:   "encode",
		Short: "Encode a file to the .trix format",
		RunE:  runEncode,
	}

	decodeCmd = &cobra.Command{
		Use:   "decode",
		Short: "Decode a .trix file",
		RunE:  runDecode,
	}

	hashCmd = &cobra.Command{
		Use:   "hash [algorithm]",
		Short: "Hash a file using a specified algorithm",
		Args:  cobra.ExactArgs(1),
		RunE:  runHash,
	}
)

var availableSigils = []string{
	"reverse", "hex", "base64", "gzip", "json", "json-indent", "md4", "md5",
	"sha1", "sha224", "sha256", "sha384", "sha512", "ripemd160", "sha3-224",
	"sha3-256", "sha3-384", "sha3-512", "sha512-224", "sha512-256",
	"blake2s-256", "blake2b-256", "blake2b-384", "blake2b-512",
}

var exit = os.Exit

func init() {
	// Add flags to encode command
	encodeCmd.Flags().StringP("input", "i", "", "Input file (or stdin)")
	encodeCmd.Flags().StringP("output", "o", "", "Output file")
	encodeCmd.Flags().StringP("magic", "m", "", "Magic number (4 bytes)")

	// Add flags to decode command
	decodeCmd.Flags().StringP("input", "i", "", "Input file (or stdin)")
	decodeCmd.Flags().StringP("output", "o", "", "Output file")
	decodeCmd.Flags().StringP("magic", "m", "", "Magic number (4 bytes)")

	// Add flags to hash command
	hashCmd.Flags().StringP("input", "i", "", "Input file (or stdin)")

	rootCmd.AddCommand(encodeCmd, decodeCmd, hashCmd)

	// Add sigil commands
	for _, sigilName := range availableSigils {
		sigilCmd := &cobra.Command{
			Use:   sigilName,
			Short: "Apply the " + sigilName + " sigil",
			RunE:  createSigilRunE(sigilName),
		}
		sigilCmd.Flags().StringP("input", "i", "-", "Input file or string (or stdin)")
		rootCmd.AddCommand(sigilCmd)
	}
}

func createSigilRunE(sigilName string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		input, _ := cmd.Flags().GetString("input")
		return handleSigil(cmd, sigilName, input)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		exit(1)
	}
}

func runEncode(cmd *cobra.Command, args []string) error {
	input, _ := cmd.Flags().GetString("input")
	output, _ := cmd.Flags().GetString("output")
	magic, _ := cmd.Flags().GetString("magic")
	return handleEncode(cmd, input, output, magic, args)
}

func runDecode(cmd *cobra.Command, args []string) error {
	input, _ := cmd.Flags().GetString("input")
	output, _ := cmd.Flags().GetString("output")
	magic, _ := cmd.Flags().GetString("magic")
	return handleDecode(cmd, input, output, magic, args)
}

func runHash(cmd *cobra.Command, args []string) error {
	input, _ := cmd.Flags().GetString("input")
	return handleHash(cmd, input, args[0])
}

func handleSigil(cmd *cobra.Command, sigilName, input string) error {
	s, err := enchantrix.NewSigil(sigilName)
	if err != nil {
		return err
	}

	var data []byte
	if input == "-" {
		data, err = ioutil.ReadAll(cmd.InOrStdin())
	} else if _, err := os.Stat(input); err == nil {
		data, err = ioutil.ReadFile(input)
	} else {
		data = []byte(input)
	}

	if err != nil {
		return err
	}

	out, err := s.In(data)
	if err != nil {
		return err
	}
	cmd.OutOrStdout().Write(out)
	return nil
}

func handleHash(cmd *cobra.Command, inputFile, algo string) error {
	if algo == "" {
		return fmt.Errorf("hash algorithm is required")
	}
	service := crypt.NewService()
	if !service.IsHashAlgo(algo) {
		return fmt.Errorf("invalid hash algorithm: %s", algo)
	}

	var data []byte
	var err error
	if inputFile == "" || inputFile == "-" {
		data, err = ioutil.ReadAll(cmd.InOrStdin())
	} else {
		data, err = ioutil.ReadFile(inputFile)
	}
	if err != nil {
		return err
	}

	hash := service.Hash(crypt.HashType(algo), string(data))
	cmd.OutOrStdout().Write([]byte(hash))
	return nil
}

func handleEncode(cmd *cobra.Command, inputFile, outputFile, magicNumber string, sigils []string) error {
	if len(magicNumber) != 4 {
		return fmt.Errorf("magic number must be 4 bytes long")
	}
	var data []byte
	var err error
	if inputFile == "" || inputFile == "-" {
		data, err = ioutil.ReadAll(cmd.InOrStdin())
	} else {
		data, err = ioutil.ReadFile(inputFile)
	}
	if err != nil {
		return err
	}

	t := &trix.Trix{
		Header:   make(map[string]interface{}),
		Payload:  data,
		InSigils: sigils,
	}

	if err := t.Pack(); err != nil {
		return err
	}

	encoded, err := trix.Encode(t, magicNumber, nil)
	if err != nil {
		return err
	}

	if outputFile == "" || outputFile == "-" {
		_, err = cmd.OutOrStdout().Write(encoded)
		return err
	}
	return ioutil.WriteFile(outputFile, encoded, 0644)
}

func handleDecode(cmd *cobra.Command, inputFile, outputFile, magicNumber string, sigils []string) error {
	if len(magicNumber) != 4 {
		return fmt.Errorf("magic number must be 4 bytes long")
	}
	var data []byte
	var err error
	if inputFile == "" || inputFile == "-" {
		data, err = ioutil.ReadAll(cmd.InOrStdin())
	} else {
		data, err = ioutil.ReadFile(inputFile)
	}
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

	if outputFile == "" || outputFile == "-" {
		_, err = cmd.OutOrStdout().Write(t.Payload)
		return err
	}
	return ioutil.WriteFile(outputFile, t.Payload, 0644)
}
