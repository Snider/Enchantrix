package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := &cobra.Command{}
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd, out, errOut
}

func TestKeystoreInitAndList(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("test-master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err := runKeystoreInit(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Key store created")

	// List (empty)
	cmd, out, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("test-master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err = runKeystoreList(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No keys stored")
}

func TestKeystoreImportAndList(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Import - stdin provides master password then import password
	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\nmy-secret-password\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	cmd.Flags().StringP("label", "l", "test-key", "")
	cmd.Flags().StringP("type", "t", "chacha256", "")
	err := runKeystoreImport(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Imported key")
	assert.Contains(t, out.String(), "test-key")

	// List (should have 1 key)
	cmd, out, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err = runKeystoreList(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "test-key")
	assert.Contains(t, out.String(), "chacha256")
}

func TestKeystoreGenerate(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Generate x25519
	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	cmd.Flags().StringP("label", "l", "stmf-server", "")
	cmd.Flags().StringP("type", "t", "x25519", "")
	err := runKeystoreGenerate(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Generated x25519 key")
	assert.Contains(t, out.String(), "stmf-server")

	// List
	cmd, out, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err = runKeystoreList(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "stmf-server")
	assert.Contains(t, out.String(), "x25519")
}

func TestKeystoreDelete(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Import
	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\npassword\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	cmd.Flags().StringP("label", "l", "to-delete", "")
	cmd.Flags().StringP("type", "t", "chacha256", "")
	require.NoError(t, runKeystoreImport(cmd, nil))
	// Extract key ID from output
	keyID := ""
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "Imported key: ") {
			parts := strings.SplitN(line, " ", 3)
			keyID = strings.TrimSuffix(parts[2], " (label: to-delete)")
			break
		}
	}
	require.NotEmpty(t, keyID)

	// Delete
	cmd, out, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	cmd.Flags().StringP("id", "", keyID, "")
	err := runKeystoreDelete(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Deleted key")

	// List (should be empty)
	cmd, out, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err = runKeystoreList(cmd, nil)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No keys stored")
}

func TestKeystoreGenerateInvalidType(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Generate with invalid type
	cmd, _, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	cmd.Flags().StringP("label", "l", "bad", "")
	cmd.Flags().StringP("type", "t", "aes512", "")
	err := runKeystoreGenerate(cmd, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type")
}

func TestKeystoreInitDuplicate(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init first time
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Init second time — should fail
	cmd, _, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err := runKeystoreInit(cmd, nil)
	assert.Error(t, err)
}

func TestKeystoreWrongPassword(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "test.trix")

	// Init
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("correct-master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// List with wrong password
	cmd, _, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("wrong-master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	err := runKeystoreList(cmd, nil)
	assert.Error(t, err)
}
