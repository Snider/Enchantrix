package crypt

import (
	"sync"
	"testing"
)

func TestServiceRace(t *testing.T) {
	s := &Service{}
	var wg sync.WaitGroup

	//These goroutines will race to initialize the pgp and rsa services.
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.ensurePGP()
		}()
		go func() {
			defer wg.Done()
			s.ensureRSA()
		}()
	}

	wg.Wait()
}
