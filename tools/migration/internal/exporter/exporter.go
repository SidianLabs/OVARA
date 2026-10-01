package exporter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ExportResult struct {
	FilesWritten    int `json:"files_written"`
	RecordsExported int `json:"records_exported"`
	Errors          int `json:"errors"`
}

type APIResponse struct {
	Data []map[string]interface{} `json:"data"`
}

type Exporter struct {
	sourceURL string
	targetDir string
	apiKey    string
	dryRun    bool
	client    *http.Client
}

func New(sourceURL, targetDir, apiKey string, dryRun bool) *Exporter {
	return &Exporter{
		sourceURL: strings.TrimRight(sourceURL, "/"),
		targetDir: targetDir,
		apiKey:    apiKey,
		dryRun:    dryRun,
		client:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (exp *Exporter) Run() (*ExportResult, error) {
	if !exp.dryRun {
		if err := os.MkdirAll(exp.targetDir, 0755); err != nil {
			return nil, fmt.Errorf("creating target directory: %w", err)
		}
	}

	endpoint := fmt.Sprintf("%s/api/v1/collections", exp.sourceURL)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+exp.apiKey)

	resp, err := exp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching collections: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("API error: status %d: failed to read response body: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("API error: status %d: %s", resp.StatusCode, string(body))
	}

	var collectionsResp struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&collectionsResp); err != nil {
		return nil, fmt.Errorf("decoding collections response: %w", err)
	}

	result := &ExportResult{}

	for _, col := range collectionsResp.Data {
		count, err := exp.exportCollection(col.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error exporting collection %s: %v\n", col.Name, err)
			result.Errors++
			continue
		}

		if !exp.dryRun {
			result.FilesWritten++
		}
		result.RecordsExported += count
		fmt.Printf("exported %d records to %s.jsonl\n", count, col.Name)
	}

	return result, nil
}

// validCollectionName restricts collection names (which come from the remote
// server) to a safe charset so they can be used in URL paths and output
// filenames without path traversal.
var validCollectionName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (exp *Exporter) exportCollection(collection string) (int, error) {
	if !validCollectionName.MatchString(collection) {
		return 0, fmt.Errorf("unsafe collection name %q: skipping (must match [a-zA-Z0-9_-]+)", collection)
	}
	endpoint := fmt.Sprintf("%s/api/v1/collections/%s/documents", exp.sourceURL, url.PathEscape(collection))
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+exp.apiKey)

	resp, err := exp.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching documents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("API error: status %d: %s", resp.StatusCode, string(body))
	}

	var docsResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&docsResp); err != nil {
		return 0, fmt.Errorf("decoding documents: %w", err)
	}

	if exp.dryRun {
		return len(docsResp.Data), nil
	}

	outputPath := filepath.Join(exp.targetDir, collection+".jsonl")
	file, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("creating output file: %w", err)
	}
	defer file.Close()

	count := 0
	for _, doc := range docsResp.Data {
		line, err := json.Marshal(doc)
		if err != nil {
			continue
		}

		if _, err := file.Write(append(line, '\n')); err != nil {
			return count, fmt.Errorf("writing record: %w", err)
		}
		count++
	}

	return count, nil
}
