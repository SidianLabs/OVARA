package importer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ImportResult struct {
	FilesProcessed int `json:"files_processed"`
	RecordsImported int `json:"records_imported"`
	Errors         int `json:"errors"`
}

type Importer struct {
	sourceDir string
	targetURL string
	apiKey    string
	dryRun    bool
	client    *http.Client
}

func New(sourceDir, targetURL, apiKey string, dryRun bool) *Importer {
	return &Importer{
		sourceDir: sourceDir,
		targetURL: strings.TrimRight(targetURL, "/"),
		apiKey:    apiKey,
		dryRun:    dryRun,
		client:    &http.Client{},
	}
}

func (imp *Importer) Run() (*ImportResult, error) {
	entries, err := os.ReadDir(imp.sourceDir)
	if err != nil {
		return nil, fmt.Errorf("reading source directory: %w", err)
	}

	result := &ImportResult{}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}

		path := filepath.Join(imp.sourceDir, entry.Name())
		count, err := imp.importFile(path, entry.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error importing %s: %v\n", entry.Name(), err)
			result.Errors++
			continue
		}

		result.FilesProcessed++
		result.RecordsImported += count
		fmt.Printf("imported %d records from %s\n", count, entry.Name())
	}

	return result, nil
}

func (imp *Importer) importFile(filePath, collection string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	endpoint := fmt.Sprintf("%s/api/v1/collections/%s/documents", imp.targetURL, collection)

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !json.Valid([]byte(line)) {
			fmt.Fprintf(os.Stderr, "skipping invalid JSON in %s: %s\n", collection, line)
			continue
		}

		if imp.dryRun {
			count++
			continue
		}

		req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(line))
		if err != nil {
			return count, fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+imp.apiKey)

		resp, err := imp.client.Do(req)
		if err != nil {
			return count, fmt.Errorf("sending request: %w", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			fmt.Fprintf(os.Stderr, "API error for %s: status %d\n", collection, resp.StatusCode)
			continue
		}

		count++
	}

	return count, scanner.Err()
}
