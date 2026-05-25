package enrollment

import (
	"path/filepath"
	"testing"
)

func TestLocalService_Initialize(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "enrollment.json")

	svc := NewLocalService(filePath)

	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	identity := svc.GetIdentity()
	if identity == nil {
		t.Fatal("GetIdentity returned nil after Initialize")
	}
	if identity.ID == "" {
		t.Error("identity.ID is empty")
	}
	if identity.EnrollmentState != EnrollmentStateLocal {
		t.Errorf("EnrollmentState = %v, want local", identity.EnrollmentState)
	}
	if identity.Environment != "local" {
		t.Errorf("Environment = %v, want local", identity.Environment)
	}
}

func TestLocalService_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "enrollment.json")

	svc1 := NewLocalService(filePath)
	err := svc1.Initialize("dev")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	id1 := svc1.GetIdentity()
	originalID := id1.ID

	svc2 := NewLocalService(filePath)
	err = svc2.Initialize("dev")
	if err != nil {
		t.Fatalf("Initialize (reload) failed: %v", err)
	}
	id2 := svc2.GetIdentity()

	if id2.ID != originalID {
		t.Errorf("reloaded ID = %v, want %v", id2.ID, originalID)
	}
	if id2.EnrollmentState != EnrollmentStateLocal {
		t.Errorf("reloaded EnrollmentState = %v, want local", id2.EnrollmentState)
	}
}

func TestLocalService_Heartbeat(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "enrollment.json")

	svc := NewLocalService(filePath)
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	before := svc.GetIdentity().LastSeenAt

	svc.Heartbeat()

	after := svc.GetIdentity().LastSeenAt
	if !after.After(before) {
		t.Error("Heartbeat did not update LastSeenAt")
	}
}

func TestLocalService_IsEnrolled(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "enrollment.json")

	svc := NewLocalService(filePath)
	if svc.IsEnrolled() {
		t.Error("new service should not be enrolled")
	}

	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if svc.IsEnrolled() {
		t.Error("local enrollment should not be enrolled")
	}
}

func TestLocalService_NoFilePath(t *testing.T) {
	svc := NewLocalService("")
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	identity := svc.GetIdentity()
	if identity == nil {
		t.Fatal("GetIdentity returned nil")
	}
	if identity.EnrollmentState != EnrollmentStateLocal {
		t.Errorf("EnrollmentState = %v, want local", identity.EnrollmentState)
	}
}

func TestEnrollmentState_Constants(t *testing.T) {
	if EnrollmentStateLocal != "local" {
		t.Errorf("EnrollmentStateLocal = %v, want local", EnrollmentStateLocal)
	}
	if EnrollmentStateEnrolled != "enrolled" {
		t.Errorf("EnrollmentStateEnrolled = %v, want enrolled", EnrollmentStateEnrolled)
	}
	if EnrollmentStatePending != "pending" {
		t.Errorf("EnrollmentStatePending = %v, want pending", EnrollmentStatePending)
	}
}

func TestGatewayIdentity_GetStatus(t *testing.T) {
	svc := NewLocalService("")
	err := svc.Initialize("staging")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	status := svc.GetStatus()
	if status == nil {
		t.Fatal("GetStatus returned nil")
	}
	if status.EnrollmentState != EnrollmentStateLocal {
		t.Errorf("status.EnrollmentState = %v, want local", status.EnrollmentState)
	}
	if status.Environment != "staging" {
		t.Errorf("status.Environment = %v, want staging", status.Environment)
	}
	if !status.IsHealthy {
		t.Error("status.IsHealthy should be true")
	}
}