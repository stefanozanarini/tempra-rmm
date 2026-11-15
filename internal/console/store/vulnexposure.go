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
	// VulnExposureStats summarizes the period; agents, when not nil, limits
	// it to some computers.
	VulnExposureStats(ctx context.Context, tenantID string, since time.Time, agents []string) (ExposureStats, error)
	// VulnExposureHistory rebuilds the daily counts of some computers from
	// their exposures (VulnSnapshot only keeps the whole tenant), from the
	// day of since or of the first recording, to the day of now. KEV is
	// not known.
	VulnExposureHistory(ctx context.Context, tenantID string, since, now time.Time, agents []string) ([]VulnSnapshot, error)
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

// exposureHistory counts, for each day from since (or the first exposure)
// to now, the exposures open at the end of the day: found before it ends
// and not yet resolved.
func exposureHistory(rows []exposureRow, since, now time.Time) []VulnSnapshot {
	first := dayOf(since)
	var tracking time.Time
	for _, r := range rows {
		if tracking.IsZero() || r.FirstSeen.Before(tracking) {
			tracking = r.FirstSeen
		}
	}
	if tracking.IsZero() {
		return nil
	}
	if t := dayOf(tracking); t.After(first) {
		first = t
	}
	n := int(dayOf(now).Sub(first).Hours()/24) + 1
	if n <= 0 {
		return nil
	}
	// index of the first day an exposure counts on, or stops counting on.
	index := func(t time.Time) int {
		i := int(dayOf(t).Sub(first).Hours() / 24)
		return min(max(i, 0), n)
	}
	type span struct{ from, to int }
	spans := func(r exposureRow) span {
		s := span{index(r.FirstSeen), n}
		if r.ResolvedAt != nil {
			s.to = index(*r.ResolvedAt)
		}
		return s
	}
	hits := make([]SevCounts, n+1) // differences: +1 from, -1 to
	byCVE := map[string][]span{}
	sev := map[string]string{}
	byAgent := map[string][]span{}
	for _, r := range rows {
		sp := spans(r)
		if sp.from >= sp.to {
			continue
		}
		addSevN(&hits[sp.from], r.Severity, 1)
		addSevN(&hits[sp.to], r.Severity, -1)
		byCVE[r.CVE] = append(byCVE[r.CVE], sp)
		sev[r.CVE] = r.Severity
		byAgent[r.AgentID] = append(byAgent[r.AgentID], sp)
	}
	// covered marks with +1/-1 the days covered by any of the spans.
	covered := func(list []span, mark func(day, d int)) {
		sort.Slice(list, func(i, j int) bool { return list[i].from < list[j].from })
		from, to := list[0].from, list[0].to
		for _, sp := range list[1:] {
			if sp.from > to {
				mark(from, 1)
				mark(to, -1)
				from, to = sp.from, sp.to
			} else if sp.to > to {
				to = sp.to
			}
		}
		mark(from, 1)
		mark(to, -1)
	}
	cves := make([]SevCounts, n+1)
	for id, list := range byCVE {
		covered(list, func(day, d int) { addSevN(&cves[day], sev[id], d) })
	}
	endpoints := make([]int, n+1)
	for _, list := range byAgent {
		covered(list, func(day, d int) { endpoints[day] += d })
	}
	out := make([]VulnSnapshot, n)
	var h, c SevCounts
	e := 0
	for i := range out {
		h, c, e = sumSev(h, hits[i]), sumSev(c, cves[i]), e+endpoints[i]
		out[i] = VulnSnapshot{Day: first.AddDate(0, 0, i), Counts: VulnCounts{CVEs: c, Hits: h, Endpoints: e}}
	}
	return out
}

func addSevN(c *SevCounts, sev string, n int) {
	switch sev {
	case "critical":
		c.Critical += n
	case "high":
		c.High += n
	case "medium":
		c.Medium += n
	default:
		c.Low += n
	}
}

func sumSev(a, b SevCounts) SevCounts {
	return SevCounts{Critical: a.Critical + b.Critical, High: a.High + b.High, Medium: a.Medium + b.Medium, Low: a.Low + b.Low}
}

// ofAgents keeps the rows of agents (all when nil).
func ofAgents(rows []exposureRow, agents []string) []exposureRow {
	if agents == nil {
		return rows
	}
	keep := map[string]bool{}
	for _, a := range agents {
		keep[a] = true
	}
	var out []exposureRow
	for _, r := range rows {
		if keep[r.AgentID] {
			out = append(out, r)
		}
	}
	return out
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

func (m *Memory) VulnExposureStats(_ context.Context, tenantID string, since time.Time, agents []string) (ExposureStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := exposureStats(ofAgents(m.exposures[tenantID], agents), since)
	return st, nil
}

func (m *Memory) VulnExposureHistory(_ context.Context, tenantID string, since, now time.Time, agents []string) ([]VulnSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := exposureHistory(ofAgents(m.exposures[tenantID], agents), since, now)
	for i := range out {
		out[i].TenantID = tenantID
	}
	return out, nil
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

func (p *Postgres) VulnExposureStats(ctx context.Context, tenantID string, since time.Time, agents []string) (ExposureStats, error) {
	var out []exposureRow
	var tracking *time.Time
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT min(first_seen) FROM vuln_exposures
			WHERE $1::uuid[] IS NULL OR agent_id = ANY($1)`, agents).Scan(&tracking); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT severity, first_seen, resolved_at, baseline, removed FROM vuln_exposures
			WHERE (first_seen >= $1 OR resolved_at >= $1) AND ($2::uuid[] IS NULL OR agent_id = ANY($2))`, since, agents)
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

func (p *Postgres) VulnExposureHistory(ctx context.Context, tenantID string, since, now time.Time, agents []string) ([]VulnSnapshot, error) {
	var out []exposureRow
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, cve, severity, first_seen, resolved_at FROM vuln_exposures
			WHERE (resolved_at IS NULL OR resolved_at >= $1) AND ($2::uuid[] IS NULL OR agent_id = ANY($2))`, dayOf(since), agents)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r exposureRow
			if err := rows.Scan(&r.AgentID, &r.CVE, &r.Severity, &r.FirstSeen, &r.ResolvedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	days := exposureHistory(out, since, now)
	for i := range days {
		days[i].TenantID = tenantID
	}
	return days, nil
}
