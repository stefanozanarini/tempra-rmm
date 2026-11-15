package store

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Scope limits an operator, or the members of an Entra group, to the
// computers of some sites or computer groups.
type Scope struct {
	TenantID    string
	SubjectOID  string // user or Entra group object id
	SubjectName string
	SiteIDs     []string
	GroupIDs    []string
	UpdatedBy   string
	UpdatedAt   time.Time
}

// ScopeStore keeps the operators' scopes.
type ScopeStore interface {
	PutScope(ctx context.Context, sc Scope) error // insert or replace by subject
	DeleteScope(ctx context.Context, tenantID, subjectOID string) error
	ListScopes(ctx context.Context, tenantID string) ([]Scope, error)
}

// ---- memory ----

func (m *Memory) PutScope(_ context.Context, sc Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[sc.TenantID]; !ok {
		return ErrNotFound
	}
	if m.scopes == nil {
		m.scopes = map[string]Scope{}
	}
	sc.UpdatedAt = time.Now()
	m.scopes[sc.TenantID+"/"+sc.SubjectOID] = sc
	return nil
}

func (m *Memory) DeleteScope(_ context.Context, tenantID, subjectOID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.scopes[tenantID+"/"+subjectOID]; !ok {
		return ErrNotFound
	}
	delete(m.scopes, tenantID+"/"+subjectOID)
	return nil
}

func (m *Memory) ListScopes(_ context.Context, tenantID string) ([]Scope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Scope
	for _, sc := range m.scopes {
		if sc.TenantID == tenantID {
			out = append(out, sc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubjectName < out[j].SubjectName })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutScope(ctx context.Context, sc Scope) error {
	err := p.inTenant(ctx, sc.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO operator_scopes (tenant_id, subject_oid, subject_name, site_ids, group_ids, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id, subject_oid) DO UPDATE SET subject_name = EXCLUDED.subject_name,
				site_ids = EXCLUDED.site_ids, group_ids = EXCLUDED.group_ids, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			sc.TenantID, sc.SubjectOID, sc.SubjectName, nonNil(sc.SiteIDs), nonNil(sc.GroupIDs), sc.UpdatedBy)
		return err
	})
	return fkNotFound(err)
}

func (p *Postgres) DeleteScope(ctx context.Context, tenantID, subjectOID string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM operator_scopes WHERE subject_oid = $1`, subjectOID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func (p *Postgres) ListScopes(ctx context.Context, tenantID string) ([]Scope, error) {
	var out []Scope
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT subject_oid::text, subject_name, site_ids::text[], group_ids::text[], updated_by, updated_at
			FROM operator_scopes ORDER BY subject_name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sc := Scope{TenantID: tenantID}
			if err := rows.Scan(&sc.SubjectOID, &sc.SubjectName, &sc.SiteIDs, &sc.GroupIDs, &sc.UpdatedBy, &sc.UpdatedAt); err != nil {
				return err
			}
			out = append(out, sc)
		}
		return rows.Err()
	})
	return out, err
}
