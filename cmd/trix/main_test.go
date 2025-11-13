package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestMain_Good(t *testing.T) {
	// Redirect stdout to a buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run the main function
	main()

	// Restore stdout
	w.Close()
	os.Stdout = old

	// Read the output from the buffer
	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Check that the output contains the help message
	assert.Contains(t, buf.String(), "Usage:")
}

func TestMain_Bad(t *testing.T) {
	oldExit := exit
	defer func() { exit = oldExit }()
	var exitCode int
	exit = func(code int) {
		exitCode = code
	}
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return errors.New("test error")
	}
	// The rootCmd needs to be reset so that the test can be run again
	defer func() { rootCmd = &cobra.Command{
		Use:   "trix",
		Short: "A tool for encoding and decoding .trix files",
		Long:  `trix is a command-line tool for working with the .trix file format, which is used for storing encrypted data.`,
	}
	}()
	main()
	assert.Equal(t, 1, exitCode)
}

func TestHandleSigil_Good(t *testing.T) {
	// Create a dummy command
	cmd := &cobra.Command{}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	// Run the handleSigil function
	err := handleSigil(cmd, "base64", "hello")
	assert.NoError(t, err)

	// Check that the output is the base64 encoded string
	assert.Equal(t, "aGVsbG8=", strings.TrimSpace(buf.String()))
}

func TestHandleSigil_Bad(t *testing.T) {
	cmd := &cobra.Command{}
	err := handleSigil(cmd, "bad-sigil", "hello")
	assert.Error(t, err)
}

func TestRunEncodeAndDecode_Good(t *testing.T) {
	// Encode
	encodeCmd := &cobra.Command{}
	encodeBuf := new(bytes.Buffer)
	encodeCmd.SetOut(encodeBuf)
	encodeCmd.SetIn(strings.NewReader("hello"))
	encodeCmd.Flags().StringP("input", "i", "-", "Input file or string (or stdin)")
	encodeCmd.Flags().StringP("output", "o", "-", "Output file")
	encodeCmd.Flags().StringP("magic", "m", "TEST", "Magic number (4 bytes)")
	err := runEncode(encodeCmd, []string{"base64"})
	assert.NoError(t, err)
	assert.NotEmpty(t, encodeBuf.String())

	// Decode
	decodeCmd := &cobra.Command{}
	decodeBuf := new(bytes.Buffer)
	decodeCmd.SetOut(decodeBuf)
	decodeCmd.SetIn(encodeBuf) // Use the output of the encode as the input for the decode
	decodeCmd.Flags().StringP("input", "i", "-", "Input file or string (or stdin)")
	decodeCmd.Flags().StringP("output", "o", "-", "Output file")
	decodeCmd.Flags().StringP("magic", "m", "TEST", "Magic number (4 bytes)")
	err = runDecode(decodeCmd, []string{"base64"})
	assert.NoError(t, err)
	assert.Equal(t, "hello", strings.TrimSpace(decodeBuf.String()))
}

func TestRunEncode_Bad(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringP("magic", "m", "bad", "Magic number (4 bytes)")
	err := runEncode(cmd, []string{})
	assert.Error(t, err)
}

func TestRunDecode_Bad(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().StringP("magic", "m", "bad", "Magic number (4 bytes)")
	err := runDecode(cmd, []string{})
	assert.Error(t, err)
}

func TestRunHash_Good(t *testing.T) {
	cmd := &cobra.Command{}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetIn(strings.NewReader("hello"))
	cmd.Flags().StringP("input", "i", "-", "Input file or string (or stdin)")

	// Run the runHash function
	err := runHash(cmd, []string{"sha256"})
	assert.NoError(t, err)

	// Check that the output is not empty
	assert.NotEmpty(t, buf.String())
}

func TestRunHash_Bad(t *testing.T) {
	cmd := &cobra.Command{}
	err := runHash(cmd, []string{"bad-hash"})
	assert.Error(t, err)
}

func TestCreateSigilRunE_Good(t *testing.T) {
	cmd := &cobra.Command{}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetIn(strings.NewReader("hello"))
	cmd.Flags().StringP("input", "i", "-", "Input file or string (or stdin)")

	// Run the createSigilRunE function
	runE := createSigilRunE("base64")
	err := runE(cmd, []string{})
	assert.NoError(t, err)
}
