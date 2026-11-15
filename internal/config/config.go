package config

import (
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

type InfluxConfig struct {
	URL           string        `yaml:"url"`
	Token         string        `yaml:"token"`
	Org           string        `yaml:"org"`
	Bucket        string        `yaml:"bucket"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

type Config struct {
	Interface string       `yaml:"interface"`
	Influx    InfluxConfig `yaml:"influx"`
	LogLevel  string       `yaml:"log_level"`
}

func Load(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config file %q: %w", filePath, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config file %q: %w", filePath, err)
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("config field interface is required")
	}
	if cfg.Influx.BatchSize <= 0 {
		cfg.Influx.BatchSize = 5000
	}
	if cfg.Influx.FlushInterval <= 0 {
		cfg.Influx.FlushInterval = 2 * time.Second
	}
	if token := os.Getenv("INFLUX_TOKEN"); token != "" {
		cfg.Influx.Token = token
	}
	if url := os.Getenv("INFLUX_URL"); url != "" {
		cfg.Influx.URL = url
	}
	if cfg.Influx.URL == "" || cfg.Influx.Bucket == "" {
		return nil, fmt.Errorf("influx.url and influx.bucket are required")
	}
	return &cfg, nil
}
