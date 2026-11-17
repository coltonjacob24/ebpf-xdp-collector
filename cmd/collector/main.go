package main

import (
	"context"
	"errors"
	"fmt"
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

func main() {
	if err := run(); err != nil {
		log.Printf("collector stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("internal/config/config.yaml")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stopSignal := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignal()

	loader, err := ebpf.NewLoader(cfg.Interface)
	if err != nil {
		return fmt.Errorf("create eBPF loader: %w", err)
	}

	writer, err := influx.NewWriter(cfg.Influx)
	if err != nil {
		if closeErr := loader.Close(); closeErr != nil {
			return errors.Join(
				fmt.Errorf("create InfluxDB writer: %w", err),
				fmt.Errorf("close eBPF loader: %w", closeErr),
			)
		}
		return fmt.Errorf("create InfluxDB writer: %w", err)
	}

	proc := processor.New(writer)

	log.Printf("starting metadata collector on interface %s", cfg.Interface)

	startDone := make(chan error, 1)
	go func() {
		startDone <- loader.Start(ctx, proc.HandleEvent)
	}()

	ticker := time.NewTicker(5 * time.Second)

	var startErr error

collection:
	for {
		select {
		case startErr = <-startDone:
			break collection

		case <-ticker.C:
			reportStats("periodic", loader, proc, writer)
		}
	}

	ticker.Stop()

	// Stop reading and detach XDP, but keep the maps open.
	stopErr := loader.Stop()

	// Read final kernel counters after XDP has detached.
	finalXDPStats, xdpStatsErr := loader.Stats()

	// Drain the queue and flush remaining InfluxDB batches.
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	writerCloseErr := writer.Close(shutdownCtx)
	cancel()

	// Read userspace counters after the writer has finished flushing.
	processorStats := proc.Stats()
	writerStats := writer.Stats()

	log.Printf(
		"shutdown: xdp_seen=%d xdp_parsed=%d ringbuf_reserve_failed=%d "+
			"events_submitted=%d events_received=%d parse_errors=%d "+
			"processor_write_errors=%d queued=%d queue_dropped=%d "+
			"influx_written=%d influx_write_dropped=%d influx_write_errors=%d",
		finalXDPStats.PacketsSeen,
		finalXDPStats.PacketsParsed,
		finalXDPStats.RingbufReserveFailed,
		finalXDPStats.EventsSubmitted,
		processorStats.Events,
		processorStats.ParseErrors,
		processorStats.WriteErrors,
		writerStats.Queued,
		writerStats.QueueDropped,
		writerStats.Written,
		writerStats.WriteDropped,
		writerStats.WriteErrors,
	)

	// The maps are no longer needed.
	loaderCloseErr := loader.Close()

	var shutdownErrors []error

	if startErr != nil {
		shutdownErrors = append(
			shutdownErrors,
			fmt.Errorf("run collector: %w", startErr),
		)
	}
	if stopErr != nil {
		shutdownErrors = append(shutdownErrors, stopErr)
	}
	if xdpStatsErr != nil {
		shutdownErrors = append(
			shutdownErrors,
			fmt.Errorf("read final XDP statistics: %w", xdpStatsErr),
		)
	}
	if writerCloseErr != nil {
		shutdownErrors = append(
			shutdownErrors,
			fmt.Errorf("close InfluxDB writer: %w", writerCloseErr),
		)
	}
	if loaderCloseErr != nil {
		shutdownErrors = append(shutdownErrors, loaderCloseErr)
	}

	return errors.Join(shutdownErrors...)
}

func reportStats(
	label string,
	loader *ebpf.Loader,
	proc *processor.Processor,
	writer *influx.Writer,
) {
	xdpStats, err := loader.Stats()
	if err != nil {
		log.Printf("%s: read XDP statistics: %v", label, err)
		return
	}

	processorStats := proc.Stats()
	writerStats := writer.Stats()

	log.Printf(
		"%s: xdp_seen=%d xdp_parsed=%d ringbuf_reserve_failed=%d "+
			"events_submitted=%d events_received=%d parse_errors=%d "+
			"processor_write_errors=%d queued=%d queue_dropped=%d "+
			"influx_written=%d influx_write_dropped=%d influx_write_errors=%d",
		label,
		xdpStats.PacketsSeen,
		xdpStats.PacketsParsed,
		xdpStats.RingbufReserveFailed,
		xdpStats.EventsSubmitted,
		processorStats.Events,
		processorStats.ParseErrors,
		processorStats.WriteErrors,
		writerStats.Queued,
		writerStats.QueueDropped,
		writerStats.Written,
		writerStats.WriteDropped,
		writerStats.WriteErrors,
	)
}
