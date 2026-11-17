package influx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	influxdb3 "github.com/InfluxCommunity/influxdb3-go/v2/influxdb3"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/config"
)

var (
	ErrQueueFull    = errors.New("influx write queue is full")
	ErrWriterClosed = errors.New("influx writer is closed")
)

// PacketEvent contains metadata only; packet payloads are never persisted.
type PacketEvent struct {
	Timestamp            time.Time
	SourceIP, DestIP     string
	SourcePort, DestPort uint16
	Protocol             string
	PktLen               uint16
}

type WriterStats struct {
	Queued, QueueDropped, Written, WriteDropped, WriteErrors uint64
}

type Writer struct {
	client                                                   *influxdb3.Client
	queue                                                    chan *influxdb3.Point
	option                                                   influxdb3.WriteOption
	batchSize                                                int
	interval                                                 time.Duration
	mu                                                       sync.Mutex
	closed                                                   bool
	done                                                     chan struct{}
	queued, queueDropped, written, writeDropped, writeErrors atomic.Uint64
}

func NewWriter(cfg config.InfluxConfig) (*Writer, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 5000
	}

	if cfg.QueueSize < cfg.BatchSize {
		cfg.QueueSize = 100000
	}

	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}

	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host:     cfg.URL,
		Token:    cfg.Token,
		Database: cfg.Bucket,
	})

	if err != nil {
		return nil, fmt.Errorf("create InfluxDB client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	iterator, err := client.Query(ctx, "SELECT 1")
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("test InfluxDB connection: %w", err)
	}

	for iterator.Next() {
	}

	if err := iterator.Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("read InfluxDB health check: %w", err)
	}

	w := &Writer{
		client:    client,
		queue:     make(chan *influxdb3.Point, cfg.QueueSize),
		option:    influxdb3.WithPrecision(influxdb3.Nanosecond),
		batchSize: cfg.BatchSize,
		interval:  cfg.FlushInterval,
		done:      make(chan struct{}),
	}

	go w.run()

	return w, nil
}

func (w *Writer) Write(event PacketEvent) error {
	point := influxdb3.NewPoint("packet_event", map[string]string{
		"source_ip": event.SourceIP,
		"dest_ip":   event.DestIP,
		"protocol":  event.Protocol,
	},
		map[string]interface{}{
			"source_port": event.SourcePort,
			"dest_port":   event.DestPort,
			"pkt_len":     event.PktLen,
		},
		event.Timestamp,
	)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriterClosed
	}

	select {
	case w.queue <- point:
		w.queued.Add(1)
		return nil
	default:
		w.queueDropped.Add(1)
		return ErrQueueFull
	}
}

func (w *Writer) run() {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	batch := make([]*influxdb3.Point, 0, w.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}

		pointCount := uint64(len(batch))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := w.client.WritePoints(ctx, batch, w.option)
		cancel()

		if err != nil {
			w.writeErrors.Add(1)
			w.writeDropped.Add(pointCount)

			log.Printf(
				"InfluxDB batch write failed: points=%d total_failed=%d error=%v",
				pointCount,
				w.writeDropped.Load(),
				err,
			)
		} else {
			w.written.Add(pointCount)
		}

		batch = batch[:0]
	}

	for {
		select {
		case point, ok := <-w.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, point)
			if len(batch) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *Writer) Stats() WriterStats {
	return WriterStats{
		Queued:       w.queued.Load(),
		QueueDropped: w.queueDropped.Load(),
		Written:      w.written.Load(),
		WriteDropped: w.writeDropped.Load(),
		WriteErrors:  w.writeErrors.Load(),
	}
}

func (w *Writer) Close(ctx context.Context) error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-ctx.Done():
		return fmt.Errorf("wait for InfluxDB writer shutdown: %w", ctx.Err())
	}

	return w.client.Close()
}
