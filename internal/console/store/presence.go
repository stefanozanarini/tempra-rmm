package store

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentPresence counts the availability samples of an agent on a day
// (midnight UTC) and how many found it online.
type AgentPresence struct {
	AgentID         string
	Day             time.Time
	Samples, Online int
}

// PresenceStore keeps the availability samples.
type PresenceStore interface {
	// RecordPresence adds a sample for each agent: online or not.
	RecordPresence(ctx context.Context, tenantID string, online map[string]bool, at time.Time) error
	// ListPresence returns the rows from since on, oldest first.
	ListPresence(ctx context.Context, tenantID string, since time.Time) ([]AgentPresence, error)
}

// ---- memory ----

func (m *Memory) RecordPresence(_ context.Context, tenantID string, online map[string]bool, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.presence == nil {
		m.presence = map[string]map[[2]string]*AgentPresence{}
	}
	if m.presence[tenantID] == nil {
		m.presence[tenantID] = map[[2]string]*AgentPresence{}
	}
	day := dayOf(at)
	for id, on := range online {
		k := [2]string{id, day.Format("2006-01-02")}
		p := m.presence[tenantID][k]
		if p == nil {
			p = &AgentPresence{AgentID: id, Day: day}
			m.presence[tenantID][k] = p
		}
		p.Samples++
		if on {
			p.Online++
		}
	}
	return nil
}

func (m *Memory) ListPresence(_ context.Context, tenantID string, since time.Time) ([]AgentPresence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AgentPresence
	for _, p := range m.presence[tenantID] {
		if !p.Day.Before(dayOf(since)) {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Day.Equal(out[j].Day) {
			return out[i].Day.Before(out[j].Day)
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out, nil
}

// ---- postgres ----

func (p *Postgres) RecordPresence(ctx context.Context, tenantID string, online map[string]bool, at time.Time) error {
	if len(online) == 0 {
		return nil
	}
	agents := make([]string, 0, len(online))
	on := make([]int32, 0, len(online))
	for id, o := range online {
		agents = append(agents, id)
		if o {
			on = append(on, 1)
		} else {
			on = append(on, 0)
		}
	}
	return p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_presence (tenant_id, agent_id, day, samples, online)
			SELECT $1, x.agent_id, $2, 1, x.online FROM unnest($3::uuid[], $4::int[]) AS x(agent_id, online)
			ON CONFLICT (tenant_id, agent_id, day) DO UPDATE
			SET samples = agent_presence.samples + 1, online = agent_presence.online + EXCLUDED.online`,
			tenantID, dayOf(at), agents, on)
		return err
	})
}

func (p *Postgres) ListPresence(ctx context.Context, tenantID string, since time.Time) ([]AgentPresence, error) {
	var out []AgentPresence
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT agent_id::text, day, samples, online FROM agent_presence WHERE day >= $1
			ORDER BY day, agent_id`, dayOf(since))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AgentPresence
			if err := rows.Scan(&a.AgentID, &a.Day, &a.Samples, &a.Online); err != nil {
				return err
			}
			a.Day = dayOf(a.Day)
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
