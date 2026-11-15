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
	var cfg Config

	file, err := os.ReadFile(filePath)

	if err != nil {
		return nil, fmt.Errorf("Error reading config file: %w", err)
	}

	if err := yaml.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("Error unmarshalling config file: %w", err)

	}

	// Set sensible defaults if not provided
	if cfg.Interface == "" {

	}

	if cfg.Influx.BatchSize == 0 {
		cfg.Influx.BatchSize = 500 // Default batch size
	}

	if cfg.Influx.FlushInterval == 0 {
		cfg.Influx.FlushInterval = 2 * time.Second // Default flush interval
	}

	// Optional overrides with environment variables

	if token := os.Getenv("INFLUX_TOKEN"); token != "" {
		cfg.Influx.Token = token
	}

	if url := os.Getenv("INFLUX_URL"); url != "" {
		cfg.Influx.URL = url
	}

	return &cfg, nil
}
