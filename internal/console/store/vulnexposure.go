package store

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// VulnExposure is a CVE affecting a computer.
type VulnExposure struct {
	AgentID, CVE string
	Severity     string // critical | high | medium | low
}

// SevDays are mean durations in days by severity (0: none).
type SevDays struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
}

// ExposureWeek counts the exposures found and fixed in a week (Start is a
// Monday, midnight UTC).
type ExposureWeek struct {
	Start      time.Time
	New, Fixed SevCounts
}

// ExposureStats summarizes the exposures of a period.
type ExposureStats struct {
	Weeks []ExposureWeek // oldest first, only weeks with something
	// Fixed and MeanDays: exposures fixed in the period, and the mean time
	// from when they were found (baseline ones excluded, their age is unknown).
	Fixed    SevCounts
	MeanDays SevDays
	// Tracking: when the recording started (zero: never).
	Tracking time.Time
}

// VulnExposureStore keeps each CVE found on each computer.
type VulnExposureStore interface {
	// SyncVulnExposures records the exposures found now: new ones are
	// opened, open ones no longer found are closed (removed when their
	// computer is not in active).
	SyncVulnExposures(ctx context.Context, tenantID string, current []VulnExposure, active map[string]bool, at time.Time) error
	VulnExposureStats(ctx context.Context, tenantID string, since time.Time) (ExposureStats, error)
}

type exposureRow struct {
	VulnExposure
	FirstSeen         time.Time
	ResolvedAt        *time.Time
	Baseline, Removed bool
}

func weekOf(t time.Time) time.Time {
	d := dayOf(t)
	return d.AddDate(0, 0, -((int(d.Weekday()) + 6) % 7))
}

func addSeverity(c *SevCounts, sev string) {
	switch sev {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	default:
		c.Low++
	}
}

// exposureStats computes the stats from the rows (both stores).
func exposureStats(rows []exposureRow, since time.Time) ExposureStats {
	var st ExposureStats
	weeks := map[time.Time]*ExposureWeek{}
	week := func(t time.Time) *ExposureWeek {
		k := weekOf(t)
		if weeks[k] == nil {
			weeks[k] = &ExposureWeek{Start: k}
		}
		return weeks[k]
	}
	var sum SevDays
	for _, r := range rows {
		if st.Tracking.IsZero() || r.FirstSeen.Before(st.Tracking) {
			st.Tracking = r.FirstSeen
		}
		if !r.Baseline && !r.FirstSeen.Before(since) {
			addSeverity(&week(r.FirstSeen).New, r.Severity)
		}
		if r.ResolvedAt == nil || r.Removed || r.ResolvedAt.Before(since) {
			continue
		}
		addSeverity(&week(*r.ResolvedAt).Fixed, r.Severity)
		if r.Baseline {
			continue
		}
		days := r.ResolvedAt.Sub(r.FirstSeen).Hours() / 24
		switch r.Severity {
		case "critical":
			st.Fixed.Critical++
			sum.Critical += days
		case "high":
			st.Fixed.High++
			sum.High += days
		case "medium":
			st.Fixed.Medium++
			sum.Medium += days
		default:
			st.Fixed.Low++
			sum.Low += days
		}
	}
	mean := func(total float64, n int) float64 {
		if n == 0 {
			return 0
		}
		return total / float64(n)
	}
	st.MeanDays = SevDays{mean(sum.Critical, st.Fixed.Critical), mean(sum.High, st.Fixed.High),
		mean(sum.Medium, st.Fixed.Medium), mean(sum.Low, st.Fixed.Low)}
	for _, w := range weeks {
		st.Weeks = append(st.Weeks, *w)
	}
	sort.Slice(st.Weeks, func(i, j int) bool { return st.Weeks[i].Start.Before(st.Weeks[j].Start) })
	return st
}

// ---- memory ----

func (m *Memory) SyncVulnExposures(_ context.Context, tenantID string, current []VulnExposure, active map[string]bool, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exposures == nil {
		m.exposures = map[string][]exposureRow{}
	}
	rows := m.exposures[tenantID]
	baseline := len(rows) == 0
	now := map[[2]string]bool{}
	for _, e := range current {
		now[[2]string{e.AgentID, e.CVE}] = true
	}
	open := map[[2]string]bool{}
	for i := range rows {
		r := &rows[i]
		if r.ResolvedAt != nil {
			continue
		}
		k := [2]string{r.AgentID, r.CVE}
		if now[k] {
			open[k] = true
			continue
		}
		t := at
		r.ResolvedAt, r.Removed = &t, !active[r.AgentID]
	}
	for _, e := range current {
		if k := [2]string{e.AgentID, e.CVE}; !open[k] {
			open[k] = true
			rows = append(rows, exposureRow{VulnExposure: e, FirstSeen: at, Baseline: baseline})
		}
	}
	m.exposures[tenantID] = rows
	return nil
}

func (m *Memory) VulnExposureStats(_ context.Context, tenantID string, since time.Time) (ExposureStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := exposureStats(m.exposures[tenantID], since)
	return st, nil
}

// ---- postgres ----

func (p *Postgres) SyncVulnExposures(ctx context.Context, tenantID string, current []VulnExposure, active map[string]bool, at time.Time) error {
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var seen bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vuln_exposures)`).Scan(&seen); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT agent_id::text, cve FROM vuln_exposures WHERE resolved_at IS NULL`)
		if err != nil {
			return err
		}
		open := map[[2]string]bool{}
		for rows.Next() {
			var k [2]string
			if err := rows.Scan(&k[0], &k[1]); err != nil {
				rows.Close()
				return err
			}
			open[k] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		now := map[[2]string]bool{}
		var addAgents, addCVEs, addSev []string
		for _, e := range current {
			k := [2]string{e.AgentID, e.CVE}
			if now[k] {
				continue
			}
			now[k] = true
			if !open[k] {
				addAgents, addCVEs, addSev = append(addAgents, e.AgentID), append(addCVEs, e.CVE), append(addSev, e.Severity)
			}
		}
		var fixAgents, fixCVEs, goneAgents, goneCVEs []string
		for k := range open {
			if now[k] {
				continue
			}
			if active[k[0]] {
				fixAgents, fixCVEs = append(fixAgents, k[0]), append(fixCVEs, k[1])
			} else {
				goneAgents, goneCVEs = append(goneAgents, k[0]), append(goneCVEs, k[1])
			}
		}
		closeRows := func(agents, cves []string, removed bool) error {
			if len(agents) == 0 {
				return nil
			}
			_, err := tx.Exec(ctx, `UPDATE vuln_exposures e SET resolved_at = $3, removed = $4
				FROM unnest($1::uuid[], $2::text[]) AS x(agent_id, cve)
				WHERE e.resolved_at IS NULL AND e.agent_id = x.agent_id AND e.cve = x.cve`, agents, cves, at, removed)
			return err
		}
		if err := closeRows(fixAgents, fixCVEs, false); err != nil {
			return err
		}
		if err := closeRows(goneAgents, goneCVEs, true); err != nil {
			return err
		}
		if len(addAgents) == 0 {
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO vuln_exposures (tenant_id, agent_id, cve, severity, first_seen, baseline)
			SELECT $1, x.agent_id, x.cve, x.severity, $5, $6 FROM unnest($2::uuid[], $3::text[], $4::text[]) AS x(agent_id, cve, severity)`,
			tenantID, addAgents, addCVEs, addSev, at, !seen)
		return err
	})
}

func (p *Postgres) VulnExposureStats(ctx context.Context, tenantID string, since time.Time) (ExposureStats, error) {
	var out []exposureRow
	var tracking *time.Time
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT min(first_seen) FROM vuln_exposures`).Scan(&tracking); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT severity, first_seen, resolved_at, baseline, removed FROM vuln_exposures
			WHERE first_seen >= $1 OR resolved_at >= $1`, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r exposureRow
			if err := rows.Scan(&r.Severity, &r.FirstSeen, &r.ResolvedAt, &r.Baseline, &r.Removed); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return ExposureStats{}, err
	}
	st := exposureStats(out, since)
	st.Tracking = time.Time{}
	if tracking != nil {
		st.Tracking = *tracking
	}
	return st, nil
}
