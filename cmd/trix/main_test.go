package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// executeCommand executes the root command with the given arguments and returns the output.
func executeCommand(args ...string) (string, error) {
	b := new(bytes.Buffer)
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return b.String(), err
}

// executeCommandWithStdin executes the root command with the given arguments and stdin,
// and returns the output.
func executeCommandWithStdin(stdin string, args ...string) (string, error) {
	b := new(bytes.Buffer)
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	// reset stdin
	rootCmd.SetIn(os.Stdin)
	return b.String(), err
}

func TestRootCommand(t *testing.T) {
	output, err := executeCommand()
	assert.NoError(t, err)
	assert.Contains(t, output, "trix [command]")
}

func TestEncodeDecodeCommand(t *testing.T) {
	// 1. Create original payload
	originalPayload := "hello world"
	inputFile, _ := os.CreateTemp("", "input")
	defer os.Remove(inputFile.Name())
	inputFile.Write([]byte(originalPayload))
	inputFile.Close()

	// 2. Encode it to a file
	encodedFile, _ := os.CreateTemp("", "encoded")
	defer os.Remove(encodedFile.Name())
	_, err := executeCommand("encode", "-i", inputFile.Name(), "-o", encodedFile.Name(), "-m", "magc", "reverse")
	assert.NoError(t, err)

	// 3. Decode it back
	decodedFile, _ := os.CreateTemp("", "decoded")
	defer os.Remove(decodedFile.Name())
	_, err = executeCommand("decode", "-i", encodedFile.Name(), "-o", decodedFile.Name(), "-m", "magc", "reverse")
	assert.NoError(t, err)

	// 4. Verify content
	finalPayload, err := os.ReadFile(decodedFile.Name())
	assert.NoError(t, err)
	assert.Equal(t, originalPayload, string(finalPayload))
}

func TestHashCommand(t *testing.T) {
	// Test with input file
	inputFile, _ := os.CreateTemp("", "input")
	defer os.Remove(inputFile.Name())
	inputFile.Write([]byte("hello"))
	inputFile.Close()
	output, err := executeCommand("hash", "md5", "-i", inputFile.Name())
	assert.NoError(t, err)
	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", strings.TrimSpace(output))

	// Test with stdin
	output, err = executeCommandWithStdin("hello", "hash", "md5")
	assert.NoError(t, err)
	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", strings.TrimSpace(output))

	// Test error cases
	_, err = executeCommand("hash")
	assert.Error(t, err)
	_, err = executeCommand("hash", "invalid-algo")
	assert.Error(t, err)
	_, err = executeCommand("hash", "md5", "-i", "nonexistent-file")
	assert.Error(t, err)
}

func TestMainFunction(t *testing.T) {
	// This test is to ensure the main function is covered
	// We run it in a separate process to avoid os.Exit calls
	if os.Getenv("GO_TEST_MAIN") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMainFunction")
	cmd.Env = append(os.Environ(), "GO_TEST_MAIN=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		t.Fatalf("main function exited with error: %v", err)
	}
}
