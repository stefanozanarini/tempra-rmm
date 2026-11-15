package web

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// Availability: RunPresence samples every 15 minutes whether each approved
// agent is online; the dashboard charts the days and the servers offline
// the longest.

// presenceInterval is how often RunPresence is called (openrmm-server).
const presenceInterval = 15 * time.Minute

// RunPresence records whether each approved agent of every tenant is online.
func (s *Server) RunPresence(ctx context.Context) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Warn("availability", "err", err)
		return
	}
	now := s.now()
	for _, t := range tenants {
		agents, err := s.store.ListAgents(ctx, t.ID)
		if err != nil {
			s.log.Warn("availability", "tenant", t.ID, "err", err)
			continue
		}
		online := map[string]bool{}
		for _, a := range agents {
			if a.Status == store.AgentActive {
				online[a.ID] = s.online(a)
			}
		}
		if err := s.store.RecordPresence(ctx, t.ID, online, now); err != nil {
			s.log.Warn("availability", "tenant", t.ID, "err", err)
		}
	}
}

// availabilityCharts adds the availability of the agents in keep (nil:
// every agent) over the last days.
func (s *Server) availabilityCharts(ctx context.Context, lang, t string, d *dashData, agents []store.Agent, keep map[string]bool) error {
	now := s.now()
	first := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -jobDays+1)
	rows, err := s.store.ListPresence(ctx, t, first)
	if err != nil {
		return err
	}
	server := map[string]string{} // agent -> hostname, servers only
	for _, a := range agents {
		if a.Host.OSFamily == "server" && a.Status == store.AgentActive {
			server[a.ID] = a.Host.Hostname
		}
	}
	type day struct {
		agents, seen, maxSamples, online int
	}
	days := map[time.Time]*day{}
	offline := map[string]int{} // server -> samples offline
	for _, p := range rows {
		if keep != nil && !keep[p.AgentID] {
			continue
		}
		x := days[p.Day]
		if x == nil {
			x = &day{}
			days[p.Day] = x
		}
		x.agents++
		if p.Online > 0 {
			x.seen++
		}
		if p.Samples > x.maxSamples {
			x.maxSamples = p.Samples
		}
		x.online += p.Online
		if _, ok := server[p.AgentID]; ok {
			offline[p.AgentID] += p.Samples - p.Online
		}
	}
	var at []time.Time
	for k := range days {
		at = append(at, k)
	}
	sort.Slice(at, func(i, j int) bool { return at[i].Before(at[j]) })
	defs := []seriesDef{
		{Label: tr(lang, "Approvati"), Short: tr(lang, "approvati"), Class: "st-none"},
		{Label: tr(lang, "Online almeno una volta"), Short: tr(lang, "visti"), Class: "cat-1"},
		{Label: tr(lang, "Online in media"), Short: tr(lang, "in media"), Class: "st-good"},
	}
	for _, k := range at {
		x := days[k]
		avg := 0
		if x.maxSamples > 0 {
			avg = (x.online + x.maxSamples/2) / x.maxSamples
		}
		defs[0].Values = append(defs[0].Values, x.agents)
		defs[1].Values = append(defs[1].Values, x.seen)
		defs[2].Values = append(defs[2].Values, avg)
	}
	if len(at) > 0 {
		ch := newLineChart(tr(lang, "Disponibilità"), trf(lang, "computer online ogni giorno negli ultimi %d giorni, da un controllo ogni 15 minuti", jobDays), at, defs)
		d.Presence = &ch
	}
	var bars []bar
	for id, n := range offline {
		if n == 0 {
			continue
		}
		hours := int(math.Ceil((time.Duration(n) * presenceInterval).Hours()))
		bars = append(bars, bar{Label: server[id], Count: hours, Link: "/agents/" + id})
	}
	sort.Slice(bars, func(i, j int) bool {
		if bars[i].Count != bars[j].Count {
			return bars[i].Count > bars[j].Count
		}
		return bars[i].Label < bars[j].Label
	})
	if len(bars) > maxBars {
		bars = bars[:maxBars]
	}
	d.ServerDown = newBars(tr(lang, "Server offline più a lungo"), trf(lang, "ore offline negli ultimi %d giorni, stimate dai controlli ogni 15 minuti", jobDays), bars)
	d.ServerDown.Empty = tr(lang, "Nessun server offline nel periodo.")
	return nil
}
