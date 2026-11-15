package influx

import (
	"context"
	"fmt"
	"sync"
	"time"

	influxdb3 "github.com/InfluxCommunity/influxdb3-go/v2/influxdb3"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/config"
)

type PacketEvent struct {
	Timestamp  time.Time
	SourceIP   string
	DestIP     string
	SourcePort uint16
	DestPort   uint16
	Protocol   string
	PktLen     uint16
}

type Writer struct {
	client    *influxdb3.Client
	mu        sync.Mutex
	batch     []*influxdb3.Point
	option    influxdb3.WriteOption
	batchSize int
	closed    bool
}

func NewWriter(cfg config.InfluxConfig) (*Writer, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host: cfg.URL, Token: cfg.Token, Database: cfg.Bucket,
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
		return nil, fmt.Errorf("read InfluxDB health-check result: %w", err)
	}

	return &Writer{
		client: client,
		batch: make([]*influxdb3.Point, 0, cfg.BatchSize),
		option: influxdb3.WithPrecision(influxdb3.Nanosecond),
		batchSize: cfg.BatchSize,
	}, nil
}

func (w *Writer) Write(event PacketEvent) error {
	point := influxdb3.NewPoint("packet_event", map[string]string{
		"source_ip": event.SourceIP,
		"dest_ip": event.DestIP,
		"protocol": event.Protocol,
	}, map[string]interface{}{
		"source_port": event.SourcePort,
		"dest_port": event.DestPort,
		"pkt_len": event.PktLen,
	}, event.Timestamp)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("InfluxDB writer is closed")
	}
	w.batch = append(w.batch, point)
	if len(w.batch) >= w.batchSize {
		return w.flushLocked(context.Background())
	}
	return nil
}

func (w *Writer) Flush() error {
	return w.FlushContext(context.Background())
}

func (w *Writer) FlushContext(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	return w.flushLocked(ctx)
}

func (w *Writer) flushLocked(ctx context.Context) error {
	if len(w.batch) == 0 {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := w.client.WritePoints(writeCtx, w.batch, w.option); err != nil {
		return fmt.Errorf("write %d packet points to InfluxDB: %w", len(w.batch), err)
	}
	w.batch = w.batch[:0]
	return nil
}

func (w *Writer) Close(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	if err := w.flushLocked(ctx); err != nil {
		return err
	}
	if err := w.client.Close(); err != nil {
		return fmt.Errorf("close InfluxDB client: %w", err)
	}
	w.closed = true
	return nil
}
