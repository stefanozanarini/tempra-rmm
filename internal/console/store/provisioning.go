package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrProfileExists is returned for a duplicate profile name.
	ErrProfileExists = errors.New("a provisioning profile with this name exists")
	// ErrRunActive is returned when the computer already has a run in
	// progress.
	ErrRunActive = errors.New("a provisioning run is already in progress on this computer")
)

// Profile is a provisioning profile with one of its versions (the latest,
// in listings) and that version's approval, if any.
type Profile struct {
	TenantID    string
	ID          string
	Name        string
	Description string
	CreatedBy   string
	CreatedAt   time.Time

	Version   int
	Document  []byte // provisioning.Document as JSON
	Comment   string
	Author    string
	UpdatedAt time.Time

	// Approval of this version: the signed ProfileRequest, nil until an
	// administrator approves it.
	Envelope      []byte
	MaxTTLSeconds int
	ApprovedBy    string
	ApprovedAt    *time.Time
	ExpiresAt     *time.Time
}

// Approved tells whether the version carries an approval valid at now.
func (p Profile) Approved(now time.Time) bool {
	return len(p.Envelope) > 0 && p.ExpiresAt != nil && now.Before(*p.ExpiresAt)
}

// Run states.
const (
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunCanceled  = "canceled"
)

// ProvisioningRun is a profile version running on one computer.
type ProvisioningRun struct {
	TenantID  string
	ID        string
	ProfileID string
	Version   int
	AgentID   string
	State     string
	// Step is the index of the current step (len(Jobs) once all ran).
	Step int
	// Jobs holds the job of each step, "" while not dispatched; one entry
	// per step of the profile version.
	Jobs       []string
	Error      string
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
}

// ProfileStore keeps provisioning profiles, their versions and runs.
type ProfileStore interface {
	// SaveProfile creates the profile, or renames it, and adds a version
	// with p's Document, Comment and Author; it returns the version.
	SaveProfile(ctx context.Context, p Profile) (int, error)
	DeleteProfile(ctx context.Context, tenantID, id string) error
	// ListProfiles returns the profiles with their latest version.
	ListProfiles(ctx context.Context, tenantID string) ([]Profile, error)
	// GetProfile returns a version of a profile; 0 is the latest.
	GetProfile(ctx context.Context, tenantID, id string, version int) (Profile, error)
	// ProfileVersions lists the versions, newest first, without documents
	// or envelopes.
	ProfileVersions(ctx context.Context, tenantID, id string) ([]Profile, error)
	// ApproveProfile stores the approval of a version (p's Envelope,
	// MaxTTLSeconds, ApprovedBy, ApprovedAt and ExpiresAt).
	ApproveProfile(ctx context.Context, p Profile) error

	// CreateRun starts a run; ErrRunActive if the computer has one in
	// progress.
	CreateRun(ctx context.Context, r ProvisioningRun) error
	// UpdateRun saves State, Step, Jobs, Error and FinishedAt.
	UpdateRun(ctx context.Context, r ProvisioningRun) error
	GetRun(ctx context.Context, tenantID, id string) (ProvisioningRun, error)
	// ListRuns returns the runs of the tenant, newest first.
	ListRuns(ctx context.Context, tenantID string) ([]ProvisioningRun, error)
}

// ---- memory ----

type memProfile struct {
	head     Profile
	versions []Profile // version i+1
}

func (m *Memory) SaveProfile(_ context.Context, p Profile) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profiles == nil {
		m.profiles = map[string]*memProfile{}
	}
	for k, cur := range m.profiles {
		if cur.head.TenantID == p.TenantID && cur.head.Name == p.Name && k != p.TenantID+"/"+p.ID {
			return 0, ErrProfileExists
		}
	}
	now := time.Now()
	cur, ok := m.profiles[p.TenantID+"/"+p.ID]
	if !ok {
		cur = &memProfile{head: Profile{TenantID: p.TenantID, ID: p.ID, CreatedBy: p.Author, CreatedAt: now}}
		m.profiles[p.TenantID+"/"+p.ID] = cur
	}
	cur.head.Name, cur.head.Description = p.Name, p.Description
	v := cur.head
	v.Version, v.Document, v.Comment, v.Author, v.UpdatedAt = len(cur.versions)+1, append([]byte(nil), p.Document...), p.Comment, p.Author, now
	cur.versions = append(cur.versions, v)
	return v.Version, nil
}

func (m *Memory) DeleteProfile(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[tenantID+"/"+id]; !ok {
		return ErrNotFound
	}
	delete(m.profiles, tenantID+"/"+id)
	for k, r := range m.runs {
		if r.TenantID == tenantID && r.ProfileID == id {
			delete(m.runs, k)
		}
	}
	return nil
}

// version returns version n (0: the latest) with the current name.
func (p *memProfile) version(n int) (Profile, bool) {
	if n == 0 {
		n = len(p.versions)
	}
	if n < 1 || n > len(p.versions) {
		return Profile{}, false
	}
	v := p.versions[n-1]
	v.Name, v.Description = p.head.Name, p.head.Description
	return v, true
}

func (m *Memory) ListProfiles(_ context.Context, tenantID string) ([]Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Profile
	for _, p := range m.profiles {
		if p.head.TenantID == tenantID {
			v, _ := p.version(0)
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetProfile(_ context.Context, tenantID, id string, version int) (Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[tenantID+"/"+id]
	if !ok {
		return Profile{}, ErrNotFound
	}
	v, ok := p.version(version)
	if !ok {
		return Profile{}, ErrNotFound
	}
	return v, nil
}

func (m *Memory) ProfileVersions(_ context.Context, tenantID, id string) ([]Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[tenantID+"/"+id]
	if !ok {
		return nil, ErrNotFound
	}
	var out []Profile
	for i := len(p.versions); i > 0; i-- {
		v, _ := p.version(i)
		v.Document, v.Envelope = nil, nil
		out = append(out, v)
	}
	return out, nil
}

func (m *Memory) ApproveProfile(_ context.Context, a Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[a.TenantID+"/"+a.ID]
	if !ok || a.Version < 1 || a.Version > len(p.versions) {
		return ErrNotFound
	}
	v := &p.versions[a.Version-1]
	v.Envelope, v.MaxTTLSeconds, v.ApprovedBy = append([]byte(nil), a.Envelope...), a.MaxTTLSeconds, a.ApprovedBy
	v.ApprovedAt, v.ExpiresAt = a.ApprovedAt, a.ExpiresAt
	return nil
}

func (m *Memory) CreateRun(_ context.Context, r ProvisioningRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs == nil {
		m.runs = map[string]ProvisioningRun{}
	}
	for _, cur := range m.runs {
		if cur.TenantID == r.TenantID && cur.AgentID == r.AgentID && cur.State == RunRunning {
			return ErrRunActive
		}
	}
	now := time.Now()
	r.CreatedAt, r.UpdatedAt, r.Jobs = now, now, append([]string(nil), r.Jobs...)
	m.runs[r.TenantID+"/"+r.ID] = r
	return nil
}

func (m *Memory) UpdateRun(_ context.Context, r ProvisioningRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := r.TenantID + "/" + r.ID
	cur, ok := m.runs[k]
	if !ok {
		return ErrNotFound
	}
	if r.State == RunRunning && cur.State != RunRunning {
		for _, o := range m.runs {
			if o.TenantID == r.TenantID && o.AgentID == cur.AgentID && o.State == RunRunning {
				return ErrRunActive
			}
		}
	}
	cur.State, cur.Step, cur.Jobs, cur.Error, cur.FinishedAt = r.State, r.Step, append([]string(nil), r.Jobs...), r.Error, r.FinishedAt
	cur.UpdatedAt = time.Now()
	m.runs[k] = cur
	return nil
}

func (m *Memory) GetRun(_ context.Context, tenantID, id string) (ProvisioningRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[tenantID+"/"+id]
	if !ok {
		return ProvisioningRun{}, ErrNotFound
	}
	r.Jobs = append([]string(nil), r.Jobs...)
	return r, nil
}

func (m *Memory) ListRuns(_ context.Context, tenantID string) ([]ProvisioningRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ProvisioningRun
	for _, r := range m.runs {
		if r.TenantID == tenantID {
			r.Jobs = append([]string(nil), r.Jobs...)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) SaveProfile(ctx context.Context, pr Profile) (int, error) {
	var v int
	err := p.inTenant(ctx, pr.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO provisioning_profiles (tenant_id, id, name, description, created_by) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description`,
			pr.TenantID, pr.ID, pr.Name, pr.Description, pr.Author); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO provisioning_profile_versions (tenant_id, profile_id, version, document, comment, author)
			SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3::jsonb, $4, $5 FROM provisioning_profile_versions WHERE profile_id = $2
			RETURNING version`, pr.TenantID, pr.ID, jsonbText(pr.Document), pr.Comment, pr.Author).Scan(&v)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "provisioning_profiles_tenant_id_name_key" {
		return 0, ErrProfileExists
	}
	return v, err
}

func (p *Postgres) DeleteProfile(ctx context.Context, tenantID, id string) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM provisioning_profiles WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

const profileColumns = `p.id::text, p.name, p.description, p.created_by, p.created_at, v.version, v.comment, v.author, v.created_at,
	v.max_ttl_seconds, v.approved_by, v.approved_at, v.expires_at`

func scanProfile(row pgx.Row, pr *Profile, extra ...any) error {
	return row.Scan(append([]any{&pr.ID, &pr.Name, &pr.Description, &pr.CreatedBy, &pr.CreatedAt, &pr.Version, &pr.Comment,
		&pr.Author, &pr.UpdatedAt, &pr.MaxTTLSeconds, &pr.ApprovedBy, &pr.ApprovedAt, &pr.ExpiresAt}, extra...)...)
}

func (p *Postgres) ListProfiles(ctx context.Context, tenantID string) ([]Profile, error) {
	var out []Profile
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+profileColumns+`, v.document::text, v.envelope FROM provisioning_profiles p
			JOIN LATERAL (SELECT * FROM provisioning_profile_versions x WHERE x.tenant_id = p.tenant_id AND x.profile_id = p.id
				ORDER BY version DESC LIMIT 1) v ON true ORDER BY p.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			pr := Profile{TenantID: tenantID}
			var doc string
			if err := scanProfile(rows, &pr, &doc, &pr.Envelope); err != nil {
				return err
			}
			pr.Document = []byte(doc)
			out = append(out, pr)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetProfile(ctx context.Context, tenantID, id string, version int) (Profile, error) {
	pr := Profile{TenantID: tenantID}
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var doc string
		err := scanProfile(tx.QueryRow(ctx, `SELECT `+profileColumns+`, v.document::text, v.envelope FROM provisioning_profiles p
			JOIN provisioning_profile_versions v ON v.tenant_id = p.tenant_id AND v.profile_id = p.id
			WHERE p.id = $1 AND ($2 = 0 OR v.version = $2) ORDER BY v.version DESC LIMIT 1`, id, version), &pr, &doc, &pr.Envelope)
		pr.Document = []byte(doc)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	return pr, err
}

func (p *Postgres) ProfileVersions(ctx context.Context, tenantID, id string) ([]Profile, error) {
	var out []Profile
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+profileColumns+` FROM provisioning_profiles p
			JOIN provisioning_profile_versions v ON v.tenant_id = p.tenant_id AND v.profile_id = p.id
			WHERE p.id = $1 ORDER BY v.version DESC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			pr := Profile{TenantID: tenantID}
			if err := scanProfile(rows, &pr); err != nil {
				return err
			}
			out = append(out, pr)
		}
		return rows.Err()
	})
	if err == nil && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, err
}

func (p *Postgres) ApproveProfile(ctx context.Context, pr Profile) error {
	return p.inTenant(ctx, pr.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE provisioning_profile_versions SET envelope = $3, max_ttl_seconds = $4,
			approved_by = $5, approved_at = $6, expires_at = $7 WHERE profile_id = $1 AND version = $2`,
			pr.ID, pr.Version, pr.Envelope, pr.MaxTTLSeconds, pr.ApprovedBy, pr.ApprovedAt, pr.ExpiresAt)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

func isActiveRunConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "provisioning_runs_active"
}

func (p *Postgres) CreateRun(ctx context.Context, r ProvisioningRun) error {
	err := p.inTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO provisioning_runs (tenant_id, id, profile_id, version, agent_id, state, step, jobs, error, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			r.TenantID, r.ID, r.ProfileID, r.Version, r.AgentID, r.State, r.Step, r.Jobs, r.Error, r.CreatedBy)
		return err
	})
	if isActiveRunConflict(err) {
		return ErrRunActive
	}
	return err
}

func (p *Postgres) UpdateRun(ctx context.Context, r ProvisioningRun) error {
	err := p.inTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE provisioning_runs SET state = $2, step = $3, jobs = $4, error = $5, finished_at = $6,
			updated_at = now() WHERE id = $1`, r.ID, r.State, r.Step, r.Jobs, r.Error, r.FinishedAt)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
	if isActiveRunConflict(err) {
		return ErrRunActive
	}
	return err
}

const runColumns = `id::text, profile_id::text, version, agent_id::text, state, step, jobs, error, created_by, created_at, updated_at, finished_at`

func scanRun(row pgx.Row, tenantID string) (ProvisioningRun, error) {
	r := ProvisioningRun{TenantID: tenantID}
	err := row.Scan(&r.ID, &r.ProfileID, &r.Version, &r.AgentID, &r.State, &r.Step, &r.Jobs, &r.Error, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedAt, &r.FinishedAt)
	return r, err
}

func (p *Postgres) GetRun(ctx context.Context, tenantID, id string) (ProvisioningRun, error) {
	var r ProvisioningRun
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+` FROM provisioning_runs WHERE id = $1`, id), tenantID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ProvisioningRun{}, ErrNotFound
	}
	return r, err
}

func (p *Postgres) ListRuns(ctx context.Context, tenantID string) ([]ProvisioningRun, error) {
	var out []ProvisioningRun
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+runColumns+` FROM provisioning_runs ORDER BY created_at DESC LIMIT 2000`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRun(rows, tenantID)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
