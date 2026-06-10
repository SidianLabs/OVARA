package converter

import (
	"encoding/json"
	"fmt"
	"os"
)

type LegacyConfig struct {
	AppName    string                 `json:"app_name"`
	Debug      bool                   `json:"debug"`
	Database   string                 `json:"database"`
	RedisURL   string                 `json:"redis_url"`
	CORS       []string               `json:"cors"`
	SecretKey  string                 `json:"secret_key"`
	Custom     map[string]interface{} `json:"custom"`
}

type V1Config struct {
	Version   string                 `json:"version"`
	Name      string                 `json:"name"`
	Settings  Settings               `json:"settings"`
	Providers Providers              `json:"providers"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type Settings struct {
	Debug       bool     `json:"debug"`
	CORSOrigins []string `json:"cors_origins"`
}

type Providers struct {
	Database DatabaseConfig `json:"database"`
	Cache    CacheConfig    `json:"cache"`
}

type DatabaseConfig struct {
	DSN string `json:"dsn"`
}

type CacheConfig struct {
	RedisURL string `json:"redis_url"`
}

type Converter struct {
	dryRun bool
}

func New(dryRun bool) *Converter {
	return &Converter{dryRun: dryRun}
}

func (c *Converter) ConvertLegacyToV1(inputPath, outputPath string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading legacy config: %w", err)
	}

	var legacy LegacyConfig
	if err := json.Unmarshal(inputData, &legacy); err != nil {
		return fmt.Errorf("parsing legacy config: %w", err)
	}

	v1 := V1Config{
		Version: "1.0",
		Name:    legacy.AppName,
		Settings: Settings{
			Debug:       legacy.Debug,
			CORSOrigins: legacy.CORS,
		},
		Providers: Providers{
			Database: DatabaseConfig{DSN: legacy.Database},
			Cache:    CacheConfig{RedisURL: legacy.RedisURL},
		},
	}

	if len(legacy.Custom) > 0 {
		v1.Metadata = legacy.Custom
	}

	outputData, err := json.MarshalIndent(v1, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling v1 config: %w", err)
	}

	if c.dryRun {
		fmt.Printf("[dry-run] Would write v1 config to %s\n", outputPath)
		return nil
	}

	if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
		return fmt.Errorf("writing v1 config: %w", err)
	}

	return nil
}
