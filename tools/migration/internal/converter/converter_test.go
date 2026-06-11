package converter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConvertLegacyToV1_ValidInput(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := LegacyConfig{
		AppName:  "TestApp",
		Debug:    true,
		Database: "postgres://localhost/testdb",
		RedisURL: "redis://localhost:6379",
		CORS:     []string{"https://example.com"},
		SecretKey: "secret123",
	}
	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	c := New(false)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	outputData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected output file, got %v", err)
	}

	var v1 V1Config
	if err := json.Unmarshal(outputData, &v1); err != nil {
		t.Fatalf("expected valid v1 json, got %v", err)
	}

	if v1.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", v1.Version)
	}
	if v1.Name != "TestApp" {
		t.Errorf("expected name TestApp, got %s", v1.Name)
	}
	if !v1.Settings.Debug {
		t.Errorf("expected debug true")
	}
	if v1.Providers.Database.DSN != "postgres://localhost/testdb" {
		t.Errorf("expected database DSN, got %s", v1.Providers.Database.DSN)
	}
	if v1.Providers.Cache.RedisURL != "redis://localhost:6379" {
		t.Errorf("expected redis URL, got %s", v1.Providers.Cache.RedisURL)
	}
	if len(v1.Settings.CORSOrigins) != 1 || v1.Settings.CORSOrigins[0] != "https://example.com" {
		t.Errorf("expected cors origins, got %v", v1.Settings.CORSOrigins)
	}
}

func TestConvertLegacyToV1_WithCustomMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := LegacyConfig{
		AppName: "CustomApp",
		Custom:  map[string]interface{}{"key": "value", "num": 42},
	}
	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	c := New(false)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	outputData, _ := os.ReadFile(outputPath)
	var v1 V1Config
	json.Unmarshal(outputData, &v1)

	if v1.Metadata == nil {
		t.Errorf("expected metadata, got nil")
	}
	if v1.Metadata["key"] != "value" {
		t.Errorf("expected key=value, got %v", v1.Metadata["key"])
	}
}

func TestConvertLegacyToV1_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := LegacyConfig{AppName: "DryRunTest"}
	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	c := New(true)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if _, err := os.Stat(outputPath); err == nil {
		t.Errorf("expected no output file in dry-run mode")
	}
}

func TestConvertLegacyToV1_InvalidInputFile(t *testing.T) {
	tmpDir := t.TempDir()
	c := New(false)
	err := c.ConvertLegacyToV1(filepath.Join(tmpDir, "nonexistent.json"), filepath.Join(tmpDir, "out.json"))
	if err == nil {
		t.Errorf("expected error for nonexistent input")
	}
}

func TestConvertLegacyToV1_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	os.WriteFile(inputPath, []byte("not valid json"), 0644)

	c := New(false)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err == nil {
		t.Errorf("expected error for invalid JSON")
	}
}

func TestConvertLegacyToV1_EmptyCustom(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := LegacyConfig{AppName: "TestApp", Custom: map[string]interface{}{}}
	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	c := New(false)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	outputData, _ := os.ReadFile(outputPath)
	var v1 V1Config
	json.Unmarshal(outputData, &v1)

	if v1.Metadata != nil {
		t.Errorf("expected nil metadata for empty custom, got %v", v1.Metadata)
	}
}

func TestConvertLegacyToV1_MultipleCORSOrigins(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := LegacyConfig{
		AppName: "MultiCORS",
		CORS:    []string{"https://a.com", "https://b.com", "https://c.com"},
	}
	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	c := New(false)
	err := c.ConvertLegacyToV1(inputPath, outputPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	outputData, _ := os.ReadFile(outputPath)
	var v1 V1Config
	json.Unmarshal(outputData, &v1)

	if len(v1.Settings.CORSOrigins) != 3 {
		t.Errorf("expected 3 cors origins, got %d", len(v1.Settings.CORSOrigins))
	}
}