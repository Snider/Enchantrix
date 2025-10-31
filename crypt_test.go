package crypt

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	payload := "hello"
	hash := Hash(LTHN, payload)
	assert.NotEmpty(t, hash)
}

func TestLuhn(t *testing.T) {
	assert.True(t, Luhn("79927398713"))
	assert.False(t, Luhn("79927398714"))
}

func TestFletcher16(t *testing.T) {
	assert.Equal(t, uint16(0xC8F0), Fletcher16("abcde"))
	assert.Equal(t, uint16(0x2057), Fletcher16("abcdef"))
	assert.Equal(t, uint16(0x0627), Fletcher16("abcdefgh"))
}

func TestFletcher32(t *testing.T) {
	expected := uint32(0xF04FC729)
	actual := Fletcher32("abcde")
	fmt.Printf("Fletcher32('abcde'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)

	expected = uint32(0x56502D2A)
	actual = Fletcher32("abcdef")
	fmt.Printf("Fletcher32('abcdef'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)

	expected = uint32(0xEBE19591)
	actual = Fletcher32("abcdefgh")
	fmt.Printf("Fletcher32('abcdefgh'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)
}

func TestFletcher64(t *testing.T) {
	assert.Equal(t, uint64(0xc8c6c527646362c6), Fletcher64("abcde"))
	assert.Equal(t, uint64(0xc8c72b276463c8c6), Fletcher64("abcdef"))
	assert.Equal(t, uint64(0x312e2b28cccac8c6), Fletcher64("abcdefgh"))
}

func TestRootFS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "enchantrix-crypt-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	fs := NewRootFS(tempDir, key)
	err = fs.Write("test.txt", []byte("hello"))
	assert.NoError(t, err)

	data, err := fs.Read("test.txt")
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)
}
