package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/detector"
	"agent-cybersecurity-guardrails/engine"
	"agent-cybersecurity-guardrails/monitor"
	"agent-cybersecurity-guardrails/response"
	"agent-cybersecurity-guardrails/whitelist"
)

func main() {
	cfgPath := flag.String("config", "guardrail.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		// Try default config if file not found
		if os.IsNotExist(err) {
			log.Printf("[main] config not found, using defaults")
			cfg = config.DefaultConfig()
		} else {
			log.Fatalf("[main] load config: %v", err)
		}
	}

	// Initialize whitelist store
	wl := whitelist.New(cfg.Whitelist)
	log.Printf("[main] whitelist loaded with %d entries", wl.Count())

	// Initialize anomaly detector
	ad := detector.New(&cfg.Behaviour)

	// Initialize decision engine
	decEngine := engine.New(cfg, wl, ad)

	// Initialize response handler
	respHandler := response.New(&cfg.Response)

	// Create event channels
	processChan := make(chan monitor.ProcessEvent, 100)
	networkChan := make(chan monitor.NetworkEvent, 100)

	// Initialize process monitor
	pm := monitor.NewProcessMonitor(&cfg.Behaviour, processChan, os.Getpid())
	pm.Start()
	defer pm.Stop()

	// Initialize network monitor
	nm := monitor.NewNetworkMonitor(&cfg.Network, networkChan)
	nm.Start()
	defer nm.Stop()

	// Start event processing goroutines
	go processEvents(processChan, decEngine, respHandler)
	go networkEvents(networkChan, decEngine, respHandler)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ad.Cleanup()
		}
	}()

	log.Printf("[main] guardrails daemon started")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("[main] shutting down...")
}

// processEvents handles process events from the monitor.
func processEvents(ch <-chan monitor.ProcessEvent, decEngine *engine.Engine, respHandler *response.Handler) {
	for evt := range ch {
		verdict := decEngine.EvaluateProcess(evt)
		if err := respHandler.Handle(evt.Info.PID, evt.Info.Exe, evt.Info.Cmdline, verdict.Reason, verdict); err != nil {
			log.Printf("[main] handle process event: %v", err)
		}
	}
}

// networkEvents handles network events from the monitor.
func networkEvents(ch <-chan monitor.NetworkEvent, decEngine *engine.Engine, respHandler *response.Handler) {
	for evt := range ch {
		verdict := decEngine.EvaluateNetwork(evt)
		if err := respHandler.Handle(evt.Connection.PID, evt.Connection.RemoteAddr, "", evt.Reason, verdict); err != nil {
			log.Printf("[main] handle network event: %v", err)
		}
	}
}
