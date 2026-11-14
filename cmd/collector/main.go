package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/config"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/ebpf"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
	"github.com/coltonjacob24/ebpf-xdp-collector/processor"
)

func main() {
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Initialize eBPF collector
	collector, err := ebpf.NewCollector(cfg)
	if err != nil {
		log.Fatalf("Failed to create eBPF collector: %v", err)
	}

	// Initialize eBPF Loader
	loader, err := ebpf.NewLoader(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to create eBPF loader: %v", err)
	}
	defer loader.Close()

	/*// Initialize InfluxDB client
	influxClient, err := influx.NewClient(cfg.InfluxDB)
	if err != nil {
		log.Fatalf("Failed to create InfluxDB client: %v", err)
	}*/

	// Initialize InfluxDB Writer
	influxWriter, err := influx.NewWriter(cfg.Influx)
	if err != nil {
		log.Fatalf("Failed to create InfluxDB writer: %v", err)
	}
	defer influxWriter.Close()

	// Initialize processor
	proc := processor.New(influxWriter)

	// Start the collector
	log.Printf("Starting eBPF collector on interface %s ...", cfg.Interface)
	if err := loader.Run(ctx, proc.HandleEvent); err != nil {
		log.Fatalf("Collector stopped: %v", err)
	}

	// Start the processor
	if err := proc.Start(ctx); err != nil {
		log.Fatalf("Failed to start processor: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()
}
