package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestExporter_Run_Success(t *testing.T) {
	tmpDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collections" {
			t.Errorf("expected /api/v1/collections, got %s", r.URL.Path)
			return
		}
		if r.Header.Get("Authorization") != "Bearer testkey" {
			t.Errorf("expected Authorization header")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"name": "users"},
				{"name": "orders"},
			},
		})
	}))
	defer server.Close()

	usersData := []map[string]interface{}{
		{"id": 1, "name": "Alice"},
		{"id": 2, "name": "Bob"},
	}
	ordersData := []map[string]interface{}{
		{"id": 100, "total": 50.0},
	}

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"name": "users"},
				{"name": "orders"},
			},
		})
	})
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": usersData,
		})
	})
	serverMux.HandleFunc("/api/v1/collections/orders/documents", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": ordersData,
		})
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", false)
	result, err := exp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesWritten != 2 {
		t.Errorf("expected 2 files written, got %d", result.FilesWritten)
	}
	if result.RecordsExported != 3 {
		t.Errorf("expected 3 records exported, got %d", result.RecordsExported)
	}
}

func TestExporter_Run_DryRun(t *testing.T) {
	tmpDir := t.TempDir()

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{"name": "users"}},
		})
	})
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{"id": 1}},
		})
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", true)
	result, err := exp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesWritten != 0 {
		t.Errorf("expected 0 files written in dry-run, got %d", result.FilesWritten)
	}

	// In dry-run mode, no files should be created
	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Errorf("expected no files in dry-run mode")
	}
}

func TestExporter_Run_APIError(t *testing.T) {
	tmpDir := t.TempDir()

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", false)
	_, err := exp.Run()
	if err == nil {
		t.Errorf("expected error for API failure")
	}
}

func TestExporter_Run_CollectionAPIError(t *testing.T) {
	tmpDir := t.TempDir()

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{"name": "users"}},
		})
	})
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", false)
	result, err := exp.Run()
	if err != nil {
		t.Fatalf("expected no fatal error (errors counted), got %v", err)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error, got %d", result.Errors)
	}
}

func TestExporter_Run_EmptyCollections(t *testing.T) {
	tmpDir := t.TempDir()

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{},
		})
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", false)
	result, err := exp.Run()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FilesWritten != 0 {
		t.Errorf("expected 0 files written, got %d", result.FilesWritten)
	}
}

func TestExporter_exportCollection_DryRunReturnsCount(t *testing.T) {
	tmpDir := t.TempDir()

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/api/v1/collections/users/documents", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"id": 1}, {"id": 2}, {"id": 3},
			},
		})
	})

	testServer := httptest.NewServer(serverMux)
	defer testServer.Close()

	exp := New(testServer.URL, tmpDir, "testkey", true)
	count, err := exp.exportCollection("users")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 in dry-run, got %d", count)
	}
}

func TestExporter_SourceURLTrim(t *testing.T) {
	exp := New("http://example.com///", "/tmp", "key", false)
	if exp.sourceURL != "http://example.com" {
		t.Errorf("expected trimmed URL, got %s", exp.sourceURL)
	}
}

func TestExportResult_Fields(t *testing.T) {
	result := &ExportResult{
		FilesWritten:    5,
		RecordsExported: 100,
		Errors:          2,
	}
	if result.FilesWritten != 5 {
		t.Errorf("expected 5, got %d", result.FilesWritten)
	}
}