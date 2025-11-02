package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
)

type Config struct {
	mu      sync.RWMutex
	API struct {
		ID       string `json:"id"`
		WorkerID string `json:"worker-id"`
	} `json:"api"`
	HTTP struct {
		Enabled     bool   `json:"enabled"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		AccessToken string `json:"access-token"`
		Restricted  bool   `json:"restricted"`
	} `json:"http"`
	Pools []struct {
		URL  string `json:"url"`
		User string `json:"user"`
		Pass string `json:"pass"`
	} `json:"pools"`
}

func New() *Config {
	cfg := &Config{}
	if _, err := os.Stat("config.json"); err == nil {
		cfg.Load("config.json")
	} else {
		cfg.API.ID = "enchantrix"
		cfg.HTTP.Enabled = true
		cfg.HTTP.Host = "127.0.0.1"
		cfg.HTTP.Port = 8080
		cfg.HTTP.Restricted = true
	}
	return cfg
}

func (c *Config) Load(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, c)
}

func (c *Config) Get() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// To avoid returning a pointer to the internal struct, we create a copy
	clone := *c
	return &clone
}

func (c *Config) Update(newConfig *Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.API = newConfig.API
	c.HTTP = newConfig.HTTP
	c.Pools = newConfig.Pools
}
