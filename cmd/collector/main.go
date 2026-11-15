package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/config"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/ebpf"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/processor"
)

func run() error {
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	writer, err := influx.NewWriter(cfg.Influx)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := writer.Close(shutdownCtx); err != nil {
			log.Printf("flush/close InfluxDB writer: %v", err)
		}
	}()

	loader, err := ebpf.NewLoader(cfg.Interface)
	if err != nil {
		return err
	}
	defer func() {
		if err := loader.Close(); err != nil {
			log.Printf("close eBPF loader: %v", err)
		}
	}()

	proc := processor.New(writer)
	log.Printf("Starting metadata collector on interface %s", cfg.Interface)
	if err := loader.Start(ctx, proc.HandleEvent); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	events, parseErrors, writeErrors := proc.Counts()
	log.Printf("Collector stopped: events=%d parse_errors=%d write_errors=%d", events, parseErrors, writeErrors)
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Printf("collector: %v", err)
		os.Exit(1)
	}
}
