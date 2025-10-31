package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProxy(t *testing.T) {
	proxy := New()
	proxy.Start()
	time.Sleep(6 * time.Second)
	proxy.Stop()

	summary := proxy.Summary()
	assert.NotNil(t, summary)

	workers := proxy.WorkersSummary()
	assert.NotNil(t, workers)
	assert.True(t, len(workers) > 0)
}
