package crypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	service := NewService()
	payload := "hello"
	hash := service.Hash(LTHN, payload)
	assert.NotEmpty(t, hash)
}

func TestLuhn(t *testing.T) {
	service := NewService()
	assert.True(t, service.Luhn("79927398713"))
	assert.False(t, service.Luhn("79927398714"))
}

func TestFletcher16(t *testing.T) {
	service := NewService()
	assert.Equal(t, uint16(0xC8F0), service.Fletcher16("abcde"))
	assert.Equal(t, uint16(0x2057), service.Fletcher16("abcdef"))
	assert.Equal(t, uint16(0x0627), service.Fletcher16("abcdefgh"))
}

func TestFletcher32(t *testing.T) {
	service := NewService()
	expected := uint32(0xF04FC729)
	actual := service.Fletcher32("abcde")
	fmt.Printf("Fletcher32('abcde'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)

	expected = uint32(0x56502D2A)
	actual = service.Fletcher32("abcdef")
	fmt.Printf("Fletcher32('abcdef'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)

	expected = uint32(0xEBE19591)
	actual = service.Fletcher32("abcdefgh")
	fmt.Printf("Fletcher32('abcdefgh'): expected: %x, actual: %x\n", expected, actual)
	assert.Equal(t, expected, actual)
}

func TestFletcher64(t *testing.T) {
	service := NewService()
	assert.Equal(t, uint64(0xc8c6c527646362c6), service.Fletcher64("abcde"))
	assert.Equal(t, uint64(0xc8c72b276463c8c6), service.Fletcher64("abcdef"))
	assert.Equal(t, uint64(0x312e2b28cccac8c6), service.Fletcher64("abcdefgh"))
}
