package pool

import (
	"github.com/Snider/Enchantrix/pkg/miner"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPoolClient(t *testing.T) {
	jq := miner.NewJobQueue()
	pc := New("test-url", "test-user", "test-pass", jq)
	pc.Start()
	time.Sleep(6 * time.Second)
	pc.Stop()

	assert.NotNil(t, jq.Get())
}
