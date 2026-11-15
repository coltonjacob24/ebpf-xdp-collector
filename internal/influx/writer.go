package influx

import (
	"context"
	"fmt"
	"time"

	influxdb3 "github.com/InfluxCommunity/influxdb3-go/v2/influxdb3"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/config"
)

// PacketEvent represents the data to write to InfluxDB
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
	batch     []*influxdb3.Point
	option    influxdb3.WriteOption
	batchSize int
}

func NewWriter(cfg config.InfluxConfig) (*Writer, error) {
	client, err := influxdb3.New(influxdb3.ClientConfig{
		Host:     cfg.URL,
		Token:    cfg.Token,
		Database: cfg.Bucket,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create InfluxDB client: %w", err)
	}

	// Test the connection to InfluxDB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	iterator, err := client.Query(ctx, "SELECT 1")
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to test InfluxDB connection: %w", err)
	}

	for iterator.Next() {
		// Process each row of the query result
		// This is just a test query, so we don't need to do anything with the result
	}

	return &Writer{
		client:    client,
		batch:     make([]*influxdb3.Point, 0, cfg.BatchSize),
		option:    influxdb3.WithPrecision(influxdb3.Nanosecond),
		batchSize: cfg.BatchSize,
	}, nil
}

func (w *Writer) Write(event PacketEvent) error {
	point := influxdb3.NewPoint(
		"packet_event",
		map[string]string{
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

	w.batch = append(w.batch, point)
	if len(w.batch) >= w.batchSize {
		return w.Flush()
	}
	return nil
}

func (w *Writer) Flush() error {
	if len(w.batch) == 0 {
		return nil
	}

	err := w.client.WritePoints(context.Background(), w.batch, w.option)
	if err != nil {
		return fmt.Errorf("failed to write batch to InfluxDB: %w", err)
	}

	w.batch = w.batch[:0]

	return nil
}

func (w *Writer) Close(ctx context.Context) error {
	// Flush any remaining points in the batch
	if err := w.Flush(); err != nil {
		return err
	}

	// Close the InfluxDB client
	if err := w.client.Close(); err != nil {
		return fmt.Errorf("failed to close InfluxDB client: %w", err)
	}

	return nil
}
