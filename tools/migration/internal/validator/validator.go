package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type Validator struct {
	dryRun bool
}

func New(dryRun bool) *Validator {
	return &Validator{dryRun: dryRun}
}

func (v *Validator) ValidateJSONLFile(path string) (*ValidationResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	result := &ValidationResult{Valid: true}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: invalid JSON: %v", i+1, err))
			continue
		}

		if len(obj) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("line %d: empty object", i+1))
		}

		for key := range obj {
			if strings.TrimSpace(key) == "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("line %d: empty key", i+1))
			}
		}
	}

	return result, nil
}

func (v *Validator) ValidateDirectory(dirPath string) (*ValidationResult, error) {
	result := &ValidationResult{Valid: true}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dirPath, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("non-JSONL file: %s", entry.Name()))
			continue
		}

		path := filepath.Join(dirPath, entry.Name())
		fileResult, err := v.ValidateJSONLFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("file %s: %v", entry.Name(), err))
			result.Valid = false
			continue
		}

		if !fileResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, fileResult.Errors...)
		}
		result.Warnings = append(result.Warnings, fileResult.Warnings...)
	}

	return result, nil
}

func (v *Validator) ValidateConfig(path string) (*ValidationResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	result := &ValidationResult{Valid: true}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid JSON: %v", err))
		return result, nil
	}

	if _, ok := config["version"]; !ok {
		result.Warnings = append(result.Warnings, "missing 'version' field")
	}

	if _, ok := config["settings"]; !ok {
		result.Warnings = append(result.Warnings, "missing 'settings' field")
	}

	return result, nil
}
