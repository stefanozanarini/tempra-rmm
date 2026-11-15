package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

func TestProfiles(t *testing.T)         { testProfiles(t, NewMemory()) }
func TestPostgresProfiles(t *testing.T) { testProfiles(t, openTestDB(t)) }

func testProfiles(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	s.CreateTenant(ctx, tenant)
	id := ids.NewUUID()
	doc := []byte(`{"steps": [{"type": "reboot"}]}`)
	if v, err := s.SaveProfile(ctx, Profile{TenantID: tenant.ID, ID: id, Name: "PC", Document: doc, Author: "anna"}); err != nil || v != 1 {
		t.Fatalf("save = %d, %v", v, err)
	}
	if v, err := s.SaveProfile(ctx, Profile{TenantID: tenant.ID, ID: id, Name: "PC ufficio", Document: doc, Comment: "renamed", Author: "bob"}); err != nil || v != 2 {
		t.Fatalf("save again = %d, %v", v, err)
	}
	if _, err := s.SaveProfile(ctx, Profile{TenantID: tenant.ID, ID: ids.NewUUID(), Name: "PC ufficio", Document: doc, Author: "anna"}); !errors.Is(err, ErrProfileExists) {
		t.Fatalf("duplicate name: %v", err)
	}

	// Approve version 1.
	now := time.Now().Truncate(time.Second)
	exp := now.Add(30 * 24 * time.Hour)
	if err := s.ApproveProfile(ctx, Profile{TenantID: tenant.ID, ID: id, Version: 1, Envelope: []byte("env"), MaxTTLSeconds: 3600,
		ApprovedBy: "anna", ApprovedAt: &now, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveProfile(ctx, Profile{TenantID: tenant.ID, ID: id, Version: 9, Envelope: []byte("env")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve a missing version: %v", err)
	}
	p, err := s.GetProfile(ctx, tenant.ID, id, 1)
	if err != nil || p.Name != "PC ufficio" || string(p.Envelope) != "env" || p.MaxTTLSeconds != 3600 || !p.Approved(now) || p.Approved(exp) {
		t.Fatalf("version 1 = %+v, %v", p, err)
	}
	if latest, _ := s.GetProfile(ctx, tenant.ID, id, 0); latest.Version != 2 || latest.Comment != "renamed" || latest.Approved(now) {
		t.Fatalf("latest = %+v", latest)
	}
	versions, err := s.ProfileVersions(ctx, tenant.ID, id)
	if err != nil || len(versions) != 2 || versions[0].Version != 2 || versions[1].ApprovedAt == nil || versions[1].Envelope != nil {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	if list, _ := s.ListProfiles(ctx, tenant.ID); len(list) != 1 || list[0].Version != 2 {
		t.Fatalf("list = %+v", list)
	}
	if other, _ := s.ListProfiles(ctx, ids.NewUUID()); len(other) != 0 {
		t.Fatal("profile visible from another tenant")
	}

	// Runs: one in progress per computer.
	agent := ids.NewUUID()
	run := ProvisioningRun{TenantID: tenant.ID, ID: ids.NewUUID(), ProfileID: id, Version: 1, AgentID: agent, State: RunRunning,
		Jobs: []string{""}, CreatedBy: "anna"}
	if err := s.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	second := run
	second.ID = ids.NewUUID()
	if err := s.CreateRun(ctx, second); !errors.Is(err, ErrRunActive) {
		t.Fatalf("second run in progress: %v", err)
	}
	run.Jobs[0], run.Step, run.State, run.Error, run.FinishedAt = ids.NewUUID(), 1, RunFailed, "step_failed", &now
	if err := s.UpdateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRun(ctx, tenant.ID, run.ID)
	if err != nil || got.State != RunFailed || got.Step != 1 || got.Jobs[0] != run.Jobs[0] || got.Error != "step_failed" || got.FinishedAt == nil {
		t.Fatalf("run = %+v, %v", got, err)
	}
	// Now the computer is free for another run, and the failed one can no
	// longer be resumed while that runs.
	if err := s.CreateRun(ctx, second); err != nil {
		t.Fatal(err)
	}
	run.State, run.FinishedAt = RunRunning, nil
	if err := s.UpdateRun(ctx, run); !errors.Is(err, ErrRunActive) {
		t.Fatalf("resumed beside another run: %v", err)
	}
	if runs, _ := s.ListRuns(ctx, tenant.ID); len(runs) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
	if err := s.DeleteProfile(ctx, tenant.ID, id); err != nil {
		t.Fatal(err)
	}
	if runs, _ := s.ListRuns(ctx, tenant.ID); len(runs) != 0 {
		t.Fatalf("runs left after deleting the profile: %+v", runs)
	}
}
