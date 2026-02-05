package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyserverSessionCreate(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/keys.trix"

	// Init store
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Create session
	cmd, out, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("store", "s", storePath, "")
	cmd.Flags().StringP("caps", "c", "encrypt:key-abc,decrypt:key-abc", "")
	cmd.Flags().StringP("ttl", "", "1h", "")
	cmd.Flags().StringP("client", "", "test-agent", "")
	err := runKeyserverSessionCreate(cmd, nil)
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "Session ID:")
	assert.Contains(t, output, "ses_")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "encrypt:key-abc")
	assert.Contains(t, output, "decrypt:key-abc")
}

func TestKeyserverSessionCreateInvalidCaps(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/keys.trix"

	// Init store
	cmd, _, _ := newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("path", "p", storePath, "")
	require.NoError(t, runKeystoreInit(cmd, nil))

	// Create session with bad capabilities
	cmd, _, _ = newTestCmd()
	cmd.SetIn(strings.NewReader("master\n"))
	cmd.Flags().StringP("store", "s", storePath, "")
	cmd.Flags().StringP("caps", "c", "badop:key", "")
	cmd.Flags().StringP("ttl", "", "1h", "")
	cmd.Flags().StringP("client", "", "", "")
	err := runKeyserverSessionCreate(cmd, nil)
	assert.Error(t, err)
}

func TestKeyserverSessionCreateInvalidTTL(t *testing.T) {
	cmd, _, _ := newTestCmd()
	cmd.Flags().StringP("store", "s", "/dummy", "")
	cmd.Flags().StringP("caps", "c", "encrypt:key", "")
	cmd.Flags().StringP("ttl", "", "notaduration", "")
	cmd.Flags().StringP("client", "", "", "")
	err := runKeyserverSessionCreate(cmd, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TTL")
}
