package importer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImporter_Run_Success(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "users.jsonl"), []byte(`{"id":1,"name":"Alice"}
{"id":2,"name":"Bob"}`), 0644)

	serverMux := http.NewServeMux()
	var postCount int
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer testkey" {
			t.Errorf("expected Authorization header")
		}
		body, _ := io.ReadAll(r.Body)
		if !json.Valid(body) {
			t.Errorf("expected valid JSON body")
		}
		postCount++
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "testkey", false)
	result, err := imp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("expected 1 file processed, got %d", result.FilesProcessed)
	}
	if result.RecordsImported != 2 {
		t.Errorf("expected 2 records imported, got %d", result.RecordsImported)
	}
	if postCount != 2 {
		t.Errorf("expected 2 POST requests, got %d", postCount)
	}
}

func TestImporter_Run_DryRun(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "users.jsonl"), []byte(`{"id":1}
{"id":2}
{"id":3}`), 0644)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("should not make requests in dry-run mode")
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "testkey", true)
	result, err := imp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("expected 1 file processed, got %d", result.FilesProcessed)
	}
	if result.RecordsImported != 3 {
		t.Errorf("expected 3 records in dry-run, got %d", result.RecordsImported)
	}
}

func TestImporter_Run_NonexistentDir(t *testing.T) {
	imp := New("/nonexistent/dir", "http://localhost", "key", false)
	_, err := imp.Run()
	if err == nil {
		t.Errorf("expected error for nonexistent directory")
	}
}

func TestImporter_Run_SkipsNonJSONL(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "users.jsonl"), []byte(`{"id":1}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte(`some text`), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	result, err := imp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("expected 1 file processed, got %d", result.FilesProcessed)
	}
}

func TestImporter_importFile_InvalidJSONLinesSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "users.jsonl")

	os.WriteFile(filePath, []byte(`{"id":1}
not json
{"id":2}`), 0644)

	serverMux := http.NewServeMux()
	var validCount int
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if json.Valid(body) {
			validCount++
		}
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	count, err := imp.importFile(filePath, "users")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 valid records imported, got %d", count)
	}
}

func TestImporter_importFile_SkipsEmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "users.jsonl")

	os.WriteFile(filePath, []byte(`{"id":1}

{"id":2}

`), 0644)

	serverMux := http.NewServeMux()
	var count int
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	_, err := imp.importFile(filePath, "users")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 records (empty lines skipped), got %d", count)
	}
}

func TestImporter_importFile_APIError(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "users.jsonl")

	os.WriteFile(filePath, []byte(`{"id":1}`), 0644)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	count, err := imp.importFile(filePath, "users")
	if err == nil {
		t.Fatalf("expected error for API failure, got nil")
	}
	if count != 0 {
		t.Errorf("expected 0 successful imports, got %d", count)
	}
}

func TestImporter_importFile_NonexistentFile(t *testing.T) {
	imp := New(t.TempDir(), "http://localhost", "key", false)
	_, err := imp.importFile("/nonexistent/file.jsonl", "users")
	if err == nil {
		t.Errorf("expected error for nonexistent file")
	}
}

func TestImporter_TargetURLTrim(t *testing.T) {
	imp := New("/tmp", "http://example.com///", "key", false)
	if imp.targetURL != "http://example.com" {
		t.Errorf("expected trimmed URL, got %s", imp.targetURL)
	}
}

func TestImportResult_Fields(t *testing.T) {
	result := &ImportResult{
		FilesProcessed:  3,
		RecordsImported: 50,
		Errors:          1,
	}
	if result.FilesProcessed != 3 {
		t.Errorf("expected 3, got %d", result.FilesProcessed)
	}
}

func TestImporter_Run_WithMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "users.jsonl"), []byte(`{"id":1}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "orders.jsonl"), []byte(`{"id":100}`), 0644)

	serverMux := http.NewServeMux()
	var usersCount, ordersCount int
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		usersCount++
		w.WriteHeader(http.StatusCreated)
	})
	serverMux.HandleFunc("/api/v1/collections/orders/documents", func(w http.ResponseWriter, r *http.Request) {
		ordersCount++
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	result, err := imp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesProcessed != 2 {
		t.Errorf("expected 2 files processed, got %d", result.FilesProcessed)
	}
	if result.RecordsImported != 2 {
		t.Errorf("expected 2 records imported, got %d", result.RecordsImported)
	}
	if usersCount != 1 || ordersCount != 1 {
		t.Errorf("expected 1 POST each, got users=%d orders=%d", usersCount, ordersCount)
	}
}

func TestImporter_importFile_WhitespaceOnlyLines(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "users.jsonl")

	os.WriteFile(filePath, []byte("   \n\t\n"), 0644)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	count, err := imp.importFile(filePath, "users")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 records (whitespace only lines), got %d", count)
	}
}

func TestImporter_Run_ErrorsCounted(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "users.jsonl"), []byte(`{"id":1}`), 0644)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	result, err := imp.Run()
	if err != nil {
		t.Fatalf("expected no fatal error, got %v", err)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error counted, got %d", result.Errors)
	}
}

func TestImporter_importFile_CollectionFromFilename(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "mycollection.jsonl")

	os.WriteFile(filePath, []byte(`{"key":"value"}`), 0644)

	serverMux := http.NewServeMux()
	var capturedPath string
	serverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	imp := New(tmpDir, testServer.URL, "key", false)
	_, err := imp.importFile(filePath, "mycollection")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(capturedPath, "mycollection") {
		t.Errorf("expected collection in path, got %s", capturedPath)
	}
}