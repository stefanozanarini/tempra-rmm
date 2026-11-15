package store

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Tenant-wide figures for the Reporting dashboard.

// JobCount counts the jobs of an agent and a module in a state created on
// a day (midnight UTC).
type JobCount struct {
	Day     time.Time
	AgentID string
	Module  string
	State   JobState
	Count   int
}

// AgentChange is an inventory change of an agent.
type AgentChange struct {
	AgentID string
	InventoryChange
}

// DashStatsStore reads the dashboard figures.
type DashStatsStore interface {
	// JobCounts counts the jobs created from since on, by day, agent,
	// module and state.
	JobCounts(ctx context.Context, tenantID string, since time.Time) ([]JobCount, error)
	// RecentInventoryChanges returns the changes from since on whose kind
	// starts with prefix, the most recent first, at most limit.
	RecentInventoryChanges(ctx context.Context, tenantID string, since time.Time, prefix string, limit int) ([]AgentChange, error)
}

// ---- memory ----

func (m *Memory) JobCounts(_ context.Context, tenantID string, since time.Time) ([]JobCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[JobCount]int{}
	for _, j := range m.jobs {
		if j.TenantID != tenantID || j.CreatedAt.Before(since) {
			continue
		}
		counts[JobCount{Day: dayOf(j.CreatedAt), AgentID: j.AgentID, Module: j.Module, State: j.State}]++
	}
	var out []JobCount
	for k, n := range counts {
		k.Count = n
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day.Before(out[j].Day) })
	return out, nil
}

func (m *Memory) RecentInventoryChanges(_ context.Context, tenantID string, since time.Time, prefix string, limit int) ([]AgentChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AgentChange
	for _, cur := range m.inventories {
		if cur.inv.TenantID != tenantID {
			continue
		}
		for _, c := range cur.changes {
			if c.At.Before(since) || !strings.HasPrefix(c.Kind, prefix) {
				continue
			}
			out = append(out, AgentChange{AgentID: cur.inv.AgentID, InventoryChange: c})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---- postgres ----

func (p *Postgres) JobCounts(ctx context.Context, tenantID string, since time.Time) ([]JobCount, error) {
	var out []JobCount
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT date_trunc('day', created_at AT TIME ZONE 'UTC'), agent_id::text, module, state, count(*)
			FROM jobs WHERE created_at >= $1 GROUP BY 1, 2, 3, 4 ORDER BY 1`, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c JobCount
			var day time.Time
			if err := rows.Scan(&day, &c.AgentID, &c.Module, &c.State, &c.Count); err != nil {
				return err
			}
			c.Day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) RecentInventoryChanges(ctx context.Context, tenantID string, since time.Time, prefix string, limit int) ([]AgentChange, error) {
	var out []AgentChange
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		like := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
		rows, err := tx.Query(ctx, `SELECT agent_id::text, at, kind, detail FROM inventory_changes WHERE at >= $1 AND kind LIKE $2
			ORDER BY at DESC, seq DESC LIMIT $3`, since, like, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c AgentChange
			if err := rows.Scan(&c.AgentID, &c.At, &c.Kind, &c.Detail); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
