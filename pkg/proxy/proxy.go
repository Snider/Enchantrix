package proxy

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type Proxy struct {
	mu          sync.RWMutex
	StartTime   time.Time
	Workers     []*Worker
	stopChannel chan struct{}
}

type Worker struct {
	ID        string
	Hashrate  float64
	Shares    int
	Connected time.Time
}

func New() *Proxy {
	return &Proxy{
		StartTime:   time.Now(),
		stopChannel: make(chan struct{}),
	}
}

func (p *Proxy) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.mu.Lock()
				// Simulate a worker connecting
				if len(p.Workers) < 10 {
					p.Workers = append(p.Workers, &Worker{
						ID:        fmt.Sprintf("worker-%d", len(p.Workers)),
						Hashrate:  100 + rand.Float64()*10-5,
						Connected: time.Now(),
					})
				}
				p.mu.Unlock()
			case <-p.stopChannel:
				return
			}
		}
	}()
}

func (p *Proxy) Stop() {
	close(p.stopChannel)
}

func (p *Proxy) Summary() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var totalHashrate float64
	for _, worker := range p.Workers {
		totalHashrate += worker.Hashrate
	}

	return map[string]interface{}{
		"id":           "enchantrix-proxy",
		"version":      "0.0.1",
		"kind":         "proxy",
		"uptime":       int64(time.Since(p.StartTime).Seconds()),
		"hashrate": map[string]interface{}{
			"total": []float64{totalHashrate, totalHashrate, totalHashrate},
		},
		"miners": map[string]interface{}{
			"now": len(p.Workers),
			"max": 10,
		},
	}
}

func (p *Proxy) WorkersSummary() []map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	summary := make([]map[string]interface{}, len(p.Workers))
	for i, worker := range p.Workers {
		summary[i] = map[string]interface{}{
			"id":       worker.ID,
			"hashrate": worker.Hashrate,
			"shares":   worker.Shares,
		}
	}
	return summary
}
