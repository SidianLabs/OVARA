package validator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateJSONLFile_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.jsonl")

	os.WriteFile(filePath, []byte(`{"key": "value"}
{"foo": "bar"}
{"num": 123}`), 0644)

	v := New(false)
	result, err := v.ValidateJSONLFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateJSONLFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.jsonl")

	os.WriteFile(filePath, []byte(`{"key": "value"}
not json
{"foo": "bar"}`), 0644)

	v := New(false)
	result, err := v.ValidateJSONLFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid")
	}
	if len(result.Errors) == 0 {
		t.Errorf("expected errors")
	}
}

func TestValidateJSONLFile_EmptyObject(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.jsonl")

	os.WriteFile(filePath, []byte(`{"key": "value"}
{}`), 0644)

	v := New(false)
	result, err := v.ValidateJSONLFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid (empty object is not invalid)")
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for empty object")
	}
}

func TestValidateJSONLFile_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.jsonl")

	os.WriteFile(filePath, []byte(`{"": "value"}`), 0644)

	v := New(false)
	result, err := v.ValidateJSONLFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for empty key")
	}
}

func TestValidateJSONLFile_EmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.jsonl")

	os.WriteFile(filePath, []byte(`{"key": "value"}

{"foo": "bar"}

`), 0644)

	v := New(false)
	result, err := v.ValidateJSONLFile(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid (empty lines skipped)")
	}
}

func TestValidateJSONLFile_NonexistentFile(t *testing.T) {
	v := New(false)
	_, err := v.ValidateJSONLFile("/nonexistent/path.jsonl")
	if err == nil {
		t.Errorf("expected error for nonexistent file")
	}
}

func TestValidateDirectory_Valid(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "a.jsonl"), []byte(`{"key": "value"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "b.jsonl"), []byte(`{"foo": "bar"}`), 0644)

	v := New(false)
	result, err := v.ValidateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateDirectory_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "valid.jsonl"), []byte(`{"key": "value"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "invalid.jsonl"), []byte(`not json`), 0644)

	v := New(false)
	result, err := v.ValidateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid")
	}
}

func TestValidateDirectory_NonJSONLWarning(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "data.jsonl"), []byte(`{"key": "value"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte(`some text`), 0644)

	v := New(false)
	result, err := v.ValidateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for non-jsonl file")
	}
}

func TestValidateDirectory_NonexistentDir(t *testing.T) {
	v := New(false)
	_, err := v.ValidateDirectory("/nonexistent/dir")
	if err == nil {
		t.Errorf("expected error for nonexistent directory")
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config.json")

	os.WriteFile(filePath, []byte(`{"version": "1.0", "settings": {}}`), 0644)

	v := New(false)
	result, err := v.ValidateConfig(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("expected no warnings for complete config, got %v", result.Warnings)
	}
}

func TestValidateConfig_MissingVersion(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config.json")

	os.WriteFile(filePath, []byte(`{"settings": {}}`), 0644)

	v := New(false)
	result, err := v.ValidateConfig(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid (missing fields are warnings, not errors)")
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for missing version")
	}
}

func TestValidateConfig_MissingSettings(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config.json")

	os.WriteFile(filePath, []byte(`{"version": "1.0"}`), 0644)

	v := New(false)
	result, err := v.ValidateConfig(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for missing settings")
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config.json")

	os.WriteFile(filePath, []byte(`not json`), 0644)

	v := New(false)
	result, err := v.ValidateConfig(filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid")
	}
	if len(result.Errors) == 0 {
		t.Errorf("expected errors for invalid JSON")
	}
}

func TestValidateConfig_NonexistentFile(t *testing.T) {
	v := New(false)
	_, err := v.ValidateConfig("/nonexistent/config.json")
	if err == nil {
		t.Errorf("expected error for nonexistent file")
	}
}