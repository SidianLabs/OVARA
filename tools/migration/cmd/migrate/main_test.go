package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ovara.tools.migration/internal/converter"
	"ovara.tools.migration/internal/validator"
)

func TestConverterLegacyToV1(t *testing.T) {
	tmpDir := t.TempDir()

	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := map[string]interface{}{
		"app_name":   "test-app",
		"debug":      true,
		"database":   "postgres://localhost/test",
		"redis_url":  "redis://localhost:6379",
		"cors":       []string{"http://localhost:3000"},
		"secret_key": "secret123",
		"custom": map[string]interface{}{
			"feature_flag": true,
		},
	}

	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(inputPath, data, 0644); err != nil {
		t.Fatalf("failed to write input: %v", err)
	}

	conv := converter.New(false)
	if err := conv.ConvertLegacyToV1(inputPath, outputPath); err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	outputData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var v1 map[string]interface{}
	if err := json.Unmarshal(outputData, &v1); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	if v1["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %v", v1["version"])
	}

	if v1["name"] != "test-app" {
		t.Errorf("expected name test-app, got %v", v1["name"])
	}

	settings, ok := v1["settings"].(map[string]interface{})
	if !ok {
		t.Fatal("expected settings object")
	}

	if settings["debug"] != true {
		t.Errorf("expected debug true, got %v", settings["debug"])
	}
}

func TestConverterDryRun(t *testing.T) {
	tmpDir := t.TempDir()

	inputPath := filepath.Join(tmpDir, "legacy.json")
	outputPath := filepath.Join(tmpDir, "v1.json")

	legacy := map[string]interface{}{
		"app_name": "test-app",
		"debug":    false,
	}

	data, _ := json.Marshal(legacy)
	os.WriteFile(inputPath, data, 0644)

	conv := converter.New(true)
	if err := conv.ConvertLegacyToV1(inputPath, outputPath); err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("dry-run should not create output file")
	}
}

func TestValidatorJSONLFile(t *testing.T) {
	tmpDir := t.TempDir()

	content := `{"id":"1","name":"test1"}
{"id":"2","name":"test2"}
`
	path := filepath.Join(tmpDir, "test.jsonl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	v := validator.New(false)
	result, err := v.ValidateJSONLFile(path)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
}

func TestValidatorJSONLFileInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	content := `{"id":"1","name":"test1"}
invalid json
`
	path := filepath.Join(tmpDir, "test.jsonl")
	os.WriteFile(path, []byte(content), 0644)

	v := validator.New(false)
	result, err := v.ValidateJSONLFile(path)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid for malformed JSON")
	}

	if len(result.Errors) == 0 {
		t.Error("expected error messages")
	}
}

func TestValidatorConfig(t *testing.T) {
	tmpDir := t.TempDir()

	config := map[string]interface{}{
		"version":  "1.0",
		"settings": map[string]interface{}{"debug": true},
	}

	path := filepath.Join(tmpDir, "config.json")
	data, _ := json.Marshal(config)
	os.WriteFile(path, data, 0644)

	v := validator.New(false)
	result, err := v.ValidateConfig(path)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid config, got errors: %v", result.Errors)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("expected no warnings, got: %v", result.Warnings)
	}
}

func TestValidatorDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	content1 := `{"id":"1"}
{"id":"2"}
`
	content2 := `{"id":"3"}
`

	os.WriteFile(filepath.Join(tmpDir, "file1.jsonl"), []byte(content1), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.jsonl"), []byte(content2), 0644)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not jsonl"), 0644)

	v := validator.New(false)
	result, err := v.ValidateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}

	found := false
	for _, w := range result.Warnings {
		if w == "non-JSONL file: readme.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning about non-JSONL file")
	}
}
