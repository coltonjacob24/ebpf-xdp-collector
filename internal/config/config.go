package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
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
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	config := &Config{}
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}
	return config, nil
}s