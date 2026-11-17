package gateway

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/pki"
)

// A check a module stops reporting (fixed, or no longer applicable) must
// stop counting as a problem, not keep showing its last stale status.
func TestIngestChecksClearsWhatsNoLongerReported(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "t"})
	root, _ := pki.NewRootCA("r", time.Now())
	ca, _ := pki.NewIntermediateCA(root, "a", time.Now())
	now := time.Now().UTC().Truncate(time.Second)
	s, err := New(Config{Store: st, AgentsCA: ca, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Agent{TenantID: tenant, ID: ids.NewUUID(), Status: store.AgentActive, Host: store.HostInfo{Hostname: "DC-01"},
		CertFingerprint: "fp", CertNotAfter: now.Add(time.Hour)}
	st.CreateAgent(ctx, a)

	s.ingestChecks(ctx, a, "inventory", []byte(`{"checks":[
		{"id":"privileged-groups","status":"failing","summary":"non-standard member"},
		{"id":"battery","status":"ok","summary":"fine"}]}`))
	cs, _ := st.ListChecks(ctx, tenant, a.ID)
	if len(cs) != 2 {
		t.Fatalf("after first report: %+v", cs)
	}

	// Next run: the domain's groups are back to standard, and the machine
	// (a desktop, say) reports no battery check at all any more.
	s.ingestChecks(ctx, a, "inventory", []byte(`{"checks":[
		{"id":"privileged-groups","status":"ok","summary":"standard members"}]}`))
	cs, _ = st.ListChecks(ctx, tenant, a.ID)
	if len(cs) != 1 || cs[0].CheckID != "inventory/privileged-groups" || cs[0].Status != store.CheckOK {
		t.Fatalf("after second report: %+v", cs)
	}

	// A module that sends no "checks" key at all (does not use the
	// convention, or this result type never did) must not clear anything.
	s.ingestChecks(ctx, a, "inventory", []byte(`{"schema":1}`))
	cs, _ = st.ListChecks(ctx, tenant, a.ID)
	if len(cs) != 1 {
		t.Fatalf("checks key absent should not clear: %+v", cs)
	}

	// An explicit empty list ("checks":[]), as a module now always sends
	// when nothing applies, clears everything left for that module.
	s.ingestChecks(ctx, a, "inventory", []byte(`{"checks":[]}`))
	cs, _ = st.ListChecks(ctx, tenant, a.ID)
	if len(cs) != 0 {
		t.Fatalf("empty checks list should clear: %+v", cs)
	}

	// A check from another module is never touched by this one's reports.
	s.ingestChecks(ctx, a, "protection-status", []byte(`{"checks":[{"id":"antivirus","status":"ok","summary":"ok"}]}`))
	s.ingestChecks(ctx, a, "inventory", []byte(`{"checks":[{"id":"privileged-groups","status":"ok","summary":"ok"}]}`))
	s.ingestChecks(ctx, a, "inventory", []byte(`{"checks":[]}`))
	cs, _ = st.ListChecks(ctx, tenant, a.ID)
	if len(cs) != 1 || cs[0].CheckID != "protection-status/antivirus" {
		t.Fatalf("other module's check was touched: %+v", cs)
	}
}
