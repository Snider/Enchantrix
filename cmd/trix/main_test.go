package main

import (
	"bytes"
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

func TestHandleEncodeAndDecode_Good(t *testing.T) {
	// Encode
	encodeCmd := &cobra.Command{}
	encodeBuf := new(bytes.Buffer)
	encodeCmd.SetOut(encodeBuf)
	encodeCmd.SetIn(strings.NewReader("hello"))
	err := handleEncode(encodeCmd, "-", "-", "TEST", []string{"base64"})
	assert.NoError(t, err)
	assert.NotEmpty(t, encodeBuf.String())

	// Decode
	decodeCmd := &cobra.Command{}
	decodeBuf := new(bytes.Buffer)
	decodeCmd.SetOut(decodeBuf)
	decodeCmd.SetIn(encodeBuf) // Use the output of the encode as the input for the decode
	err = handleDecode(decodeCmd, "-", "-", "TEST", []string{"base64"})
	assert.NoError(t, err)
	assert.Equal(t, "hello", strings.TrimSpace(decodeBuf.String()))
}

func TestHandleHash_Good(t *testing.T) {
	cmd := &cobra.Command{}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetIn(strings.NewReader("hello"))

	// Run the handleHash function
	err := handleHash(cmd, "-", "sha256")
	assert.NoError(t, err)

	// Check that the output is not empty
	assert.NotEmpty(t, buf.String())
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
