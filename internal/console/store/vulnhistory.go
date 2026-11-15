package store

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// SevCounts counts by severity: critical (CVSS 9 or more), high (7),
// medium (4), low (below 4 or not scored).
type SevCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Total is the sum of the severities.
func (c SevCounts) Total() int { return c.Critical + c.High + c.Medium + c.Low }

// VulnCounts are the vulnerabilities of a tenant on a day.
type VulnCounts struct {
	CVEs      SevCounts `json:"cves"` // distinct CVEs
	Hits      SevCounts `json:"hits"` // CVE × computer
	KEV       int       `json:"kev"`  // exploited in the wild (CISA)
	Endpoints int       `json:"endpoints"`
}

// VulnSnapshot is the row of a day (Day at midnight UTC).
type VulnSnapshot struct {
	TenantID string
	Day      time.Time
	Counts   VulnCounts
}

// VulnHistoryStore keeps the daily vulnerability counts.
type VulnHistoryStore interface {
	// PutVulnSnapshot replaces the row of the day.
	PutVulnSnapshot(ctx context.Context, s VulnSnapshot) error
	// ListVulnSnapshots returns the days from since on, oldest first.
	ListVulnSnapshots(ctx context.Context, tenantID string, since time.Time) ([]VulnSnapshot, error)
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// ---- memory ----

func (m *Memory) PutVulnSnapshot(_ context.Context, s VulnSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vulnHistory == nil {
		m.vulnHistory = map[string]map[time.Time]VulnCounts{}
	}
	if m.vulnHistory[s.TenantID] == nil {
		m.vulnHistory[s.TenantID] = map[time.Time]VulnCounts{}
	}
	m.vulnHistory[s.TenantID][dayOf(s.Day)] = s.Counts
	return nil
}

func (m *Memory) ListVulnSnapshots(_ context.Context, tenantID string, since time.Time) ([]VulnSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []VulnSnapshot
	for d, c := range m.vulnHistory[tenantID] {
		if !d.Before(dayOf(since)) {
			out = append(out, VulnSnapshot{TenantID: tenantID, Day: d, Counts: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day.Before(out[j].Day) })
	return out, nil
}

// ---- postgres ----

func (p *Postgres) PutVulnSnapshot(ctx context.Context, s VulnSnapshot) error {
	raw, err := json.Marshal(s.Counts)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO vuln_history (tenant_id, day, counts, updated_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (tenant_id, day) DO UPDATE SET counts = EXCLUDED.counts, updated_at = now()`, s.TenantID, dayOf(s.Day), raw)
	return err
}

func (p *Postgres) ListVulnSnapshots(ctx context.Context, tenantID string, since time.Time) ([]VulnSnapshot, error) {
	rows, err := p.pool.Query(ctx, `SELECT day, counts FROM vuln_history WHERE tenant_id = $1 AND day >= $2 ORDER BY day`,
		tenantID, dayOf(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnSnapshot
	for rows.Next() {
		s := VulnSnapshot{TenantID: tenantID}
		var raw []byte
		if err := rows.Scan(&s.Day, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &s.Counts); err != nil {
			return nil, err
		}
		s.Day = dayOf(s.Day)
		out = append(out, s)
	}
	return out, rows.Err()
}
