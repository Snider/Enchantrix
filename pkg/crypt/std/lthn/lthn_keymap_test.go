package lthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetKeyMap(t *testing.T) {
	originalKeyMap := GetKeyMap()
	newKeyMap := map[rune]rune{
		'a': 'b',
	}
	SetKeyMap(newKeyMap)
	assert.Equal(t, newKeyMap, GetKeyMap())
	SetKeyMap(originalKeyMap)
}
