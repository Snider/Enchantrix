package lthn

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testKeyMapMu sync.Mutex

func TestSetKeyMap(t *testing.T) {
	testKeyMapMu.Lock()
	originalKeyMap := GetKeyMap()
	t.Cleanup(func() {
		SetKeyMap(originalKeyMap)
		testKeyMapMu.Unlock()
	})

	newKeyMap := map[rune]rune{
		'a': 'b',
	}
	SetKeyMap(newKeyMap)
	assert.Equal(t, newKeyMap, GetKeyMap())
}
