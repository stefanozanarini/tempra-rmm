package store

import (
	"context"
	"slices"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

func TestMemoryScopes(t *testing.T)   { testScopes(t, NewMemory()) }
func TestPostgresScopes(t *testing.T) { testScopes(t, openTestDB(t)) }

func testScopes(t *testing.T, s Store) {
	ctx := context.Background()
	tenant, other := Tenant{ID: ids.NewUUID(), Name: "t"}, Tenant{ID: ids.NewUUID(), Name: "o"}
	s.CreateTenant(ctx, tenant)
	s.CreateTenant(ctx, other)
	oid, site := ids.NewUUID(), ids.NewUUID()
	sc := Scope{TenantID: tenant.ID, SubjectOID: oid, SubjectName: "IT Bologna", SiteIDs: []string{site}, UpdatedBy: "boss"}
	if err := s.PutScope(ctx, sc); err != nil {
		t.Fatal(err)
	}
	sc.GroupIDs = []string{ids.NewUUID()}
	if err := s.PutScope(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListScopes(ctx, tenant.ID)
	if err != nil || len(got) != 1 || !slices.Equal(got[0].SiteIDs, []string{site}) || len(got[0].GroupIDs) != 1 || got[0].UpdatedAt.IsZero() {
		t.Fatalf("scopes = %+v %v", got, err)
	}
	if got, _ := s.ListScopes(ctx, other.ID); len(got) != 0 {
		t.Fatalf("other tenant: %+v", got)
	}
	if err := s.DeleteScope(ctx, tenant.ID, oid); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteScope(ctx, tenant.ID, oid); err != ErrNotFound {
		t.Fatalf("second delete: %v", err)
	}
}
