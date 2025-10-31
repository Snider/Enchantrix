package main

import (
	"fmt"
	"github.com/Snider/Enchantrix/pkg/config"
	"github.com/Snider/Enchantrix/pkg/miner"
	"github.com/Snider/Enchantrix/pkg/pool"
	"github.com/Snider/Enchantrix/pkg/proxy"
	"github.com/gin-gonic/gin"
	"github.com/leaanthony/clir"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
)

func main() {
	// Create a new cli application
	cli := clir.NewCli("Enchantrix Miner", "A miner for the Enchantrix project", "v0.0.1")

	// Create a new config
	cfg := config.New()

	// Create a start command
	startCmd := cli.NewSubCommand("start", "Starts the miner")

	// Define flags
	var configFile string
	startCmd.StringFlag("config", "Path to config file", &configFile)

	var logLevel string
	startCmd.StringFlag("log-level", "Log level (trace, debug, info, warn, error, fatal, panic)", &logLevel)

	var url string
	startCmd.StringFlag("url", "URL of mining pool", &url)

	var user string
	startCmd.StringFlag("user", "Username for mining pool", &user)

	var pass string
	startCmd.StringFlag("pass", "Password for mining pool", &pass)

	var numThreads int
	startCmd.IntFlag("threads", "Number of miner threads", &numThreads)


	startCmd.Action(func() error {
		// Set up logging
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			level = logrus.InfoLevel
		}
		logrus.SetLevel(level)

		// Load config from file if specified
		if configFile != "" {
			if err := cfg.Load(configFile); err != nil {
				return err
			}
		}

		logrus.Info("Starting the miner...")

		// Override config with flags
		if url != "" {
			cfg.Pools = []struct {
				URL  string `json:"url"`
				User string `json:"user"`
				Pass string `json:"pass"`
			}{{URL: url, User: user, Pass: pass}}
		}
		if numThreads == 0 {
			numThreads = 1
		}


		// Create a new miner
		algo := &miner.MockAlgo{}
		m := miner.New(algo, cfg.Pools[0].URL, cfg.Pools[0].User, cfg.Pools[0].Pass, numThreads)
		m.Start()
		defer m.Stop()

		// Create a new pool client
		p := pool.New(cfg.Pools[0].URL, cfg.Pools[0].User, cfg.Pools[0].Pass, m.JobQueue)
		p.Start()
		defer p.Stop()


		if cfg.Pools[0].URL != "" {
			logrus.Infof("Connecting to %s as %s", cfg.Pools[0].URL, cfg.Pools[0].User)
		}

		// Set up the Gin router
		router := gin.Default()
		router.GET("/1/miners", func(c *gin.Context) {
			c.JSON(http.StatusOK, []gin.H{
				{
					"id":      0,
					"status":  "running",
					"summary": m.StateManager.Summary(),
				},
			})
		})
		router.GET("/1/miner/:id/status", func(c *gin.Context) {
			id, err := strconv.Atoi(c.Param("id"))
			if err != nil || id != 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "miner not found"})
				return
			}
			c.JSON(http.StatusOK, m.StateManager.Summary())
		})
		router.GET("/1/config", func(c *gin.Context) {
			c.JSON(http.StatusOK, cfg.Get())
		})
		router.PUT("/1/config", func(c *gin.Context) {
			var newConfig config.Config
			if err := c.ShouldBindJSON(&newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			cfg.Update(&newConfig)
			c.JSON(http.StatusOK, cfg.Get())
		})
		router.GET("/1/threads", func(c *gin.Context) {
			c.JSON(http.StatusOK, m.StateManager.ThreadsSummary())
		})

		// Start the server
		logrus.Infof("Starting API server on http://%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
		return router.Run(fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port))
	})

	// Create a proxy command
	proxyCmd := cli.NewSubCommand("proxy", "Starts the proxy")

	// Define flags
	var proxyConfigFile string
	proxyCmd.StringFlag("config", "Path to config file", &proxyConfigFile)

	var proxyLogLevel string
	proxyCmd.StringFlag("log-level", "Log level (trace, debug, info, warn, error, fatal, panic)", &proxyLogLevel)

	proxyCmd.Action(func() error {
		// Set up logging
		level, err := logrus.ParseLevel(proxyLogLevel)
		if err != nil {
			level = logrus.InfoLevel
		}
		logrus.SetLevel(level)

		// Load config from file if specified
		if proxyConfigFile != "" {
			if err := cfg.Load(proxyConfigFile); err != nil {
				return err
			}
		}

		logrus.Info("Starting the proxy...")

		// Create a new proxy
		p := proxy.New()
		p.Start()
		defer p.Stop()

		// Set up the Gin router
		router := gin.Default()
		router.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, p.Summary())
		})
		router.GET("/workers.json", func(c *gin.Context) {
			c.JSON(http.StatusOK, p.WorkersSummary())
		})


		// Start the server
		logrus.Infof("Starting API server on http://%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
		return router.Run(fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port))
	})


	// Run the cli
	if err := cli.Run(); err != nil {
		logrus.Fatal(err)
	}
}
