package pool

import (
	"github.com/Snider/Enchantrix/pkg/miner"
	"time"
)

type PoolClient struct {
	URL         string
	User        string
	Pass        string
	JobQueue    *miner.JobQueue
	stopChannel chan struct{}
}

func New(url, user, pass string, jobQueue *miner.JobQueue) *PoolClient {
	return &PoolClient{
		URL:         url,
		User:        user,
		Pass:        pass,
		JobQueue:    jobQueue,
		stopChannel: make(chan struct{}),
	}
}

func (p *PoolClient) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.JobQueue.Set(miner.NewMockJob())
			case <-p.stopChannel:
				return
			}
		}
	}()
}

func (p *PoolClient) Stop() {
	close(p.stopChannel)
}
