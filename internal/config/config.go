package config

import (
	"fmt"
	"os"
	"time"
	"go.yaml.in/yaml/v3"
)

type InfluxConfig struct {
	URL string `yaml:"url"`
	Token string `yaml:"token"`
	Org string `yaml:"org"`
	Bucket string `yaml:"bucket"`
	BatchSize int `yaml:"batch_size"`
	QueueSize int `yaml:"queue_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}
type Config struct {
	Interface string `yaml:"interface"`
	Influx InfluxConfig `yaml:"influx"`
	LogLevel string `yaml:"log_level"`
}

func Load(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil { return nil, fmt.Errorf("read config file: %w", err) }
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil { return nil, fmt.Errorf("unmarshal config file: %w", err) }
	if cfg.Interface == "" { return nil, fmt.Errorf("interface must be configured") }
	if cfg.Influx.URL == "" { return nil, fmt.Errorf("influx.url must be configured") }
	if cfg.Influx.Bucket == "" { return nil, fmt.Errorf("influx.bucket (database) must be configured") }
	if cfg.Influx.BatchSize == 0 { cfg.Influx.BatchSize = 5000 }
	if cfg.Influx.QueueSize == 0 { cfg.Influx.QueueSize = 100000 }
	if cfg.Influx.FlushInterval == 0 { cfg.Influx.FlushInterval = time.Second }
	if cfg.Influx.BatchSize < 1 { return nil, fmt.Errorf("influx.batch_size must be greater than zero") }
	if cfg.Influx.QueueSize < cfg.Influx.BatchSize { return nil, fmt.Errorf("influx.queue_size must be >= influx.batch_size") }
	if cfg.Influx.FlushInterval < time.Millisecond { return nil, fmt.Errorf("influx.flush_interval must be at least 1ms") }
	if token := os.Getenv("INFLUX_TOKEN"); token != "" { cfg.Influx.Token = token }
	if url := os.Getenv("INFLUX_URL"); url != "" { cfg.Influx.URL = url }
	return &cfg, nil
}
