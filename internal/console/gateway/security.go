package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/accesslog"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// Detection thresholds.
const (
	// LearningPeriod: until an agent has this much logon history, a new
	// source address is not reported (everything is new at first).
	LearningPeriod   = 7 * 24 * time.Hour
	failureThreshold = 10 // failed logons from one source in one batch
	sprayThreshold   = 5  // distinct users failing from one source in one batch
	maxChecks        = 50
)

var checkIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

// reportedCheck is the "checks" convention: any module may report checks
// in its result as {"checks":[{"id":"…","status":"ok|warning|failing","summary":"…"}]}.
type reportedCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// ingestChecks stores the checks of a result. A check that starts failing
// raises an alert, closed on its own when the check is no longer failing.
//
// A module's "checks" list is the complete, declarative set of checks it
// currently finds applicable to this agent: any check it reported before
// but omits this time (fixed, or no longer applicable, e.g. a demoted
// domain controller or a removed battery) is cleared rather than left
// showing its last, now-stale, status forever.
func (s *Server) ingestChecks(ctx context.Context, a store.Agent, module string, raw []byte) {
	var top struct {
		Checks *[]reportedCheck `json:"checks"`
	}
	if json.Unmarshal(raw, &top) != nil || top.Checks == nil {
		return
	}
	now := s.now()
	seen := make(map[string]bool, len(*top.Checks))
	for i, c := range *top.Checks {
		if i >= maxChecks {
			break
		}
		if !checkIDRe.MatchString(c.ID) {
			continue
		}
		switch c.Status {
		case store.CheckOK, store.CheckWarning, store.CheckFailing:
		default:
			continue
		}
		seen[c.ID] = true
		chk := store.Check{TenantID: a.TenantID, AgentID: a.ID, CheckID: module + "/" + c.ID, Status: c.Status,
			Summary: clip(c.Summary, 500), UpdatedAt: now}
		prev, err := s.store.PutCheck(ctx, chk)
		if err != nil {
			s.log.Error("store check", "agent", a.ID, "check", chk.CheckID, "err", err)
			continue
		}
		if c.Status == store.CheckFailing && prev != store.CheckFailing {
			s.raise(ctx, a, store.SeverityWarning, "check.failing", "check/"+chk.CheckID,
				fmt.Sprintf("Controllo %s non superato: %s", chk.CheckID, chk.Summary), now)
		}
		if c.Status != store.CheckFailing {
			closed, err := s.store.ResolveAlert(ctx, a.TenantID, a.ID+"/check/"+chk.CheckID, "check:"+c.Status, now)
			if err != nil {
				s.log.Error("resolve alert", "agent", a.ID, "check", chk.CheckID, "err", err)
			} else if closed {
				s.audit(ctx, a.TenantID, "agent:"+a.ID, "alert.resolved", a.ID, map[string]any{"check": chk.CheckID, "status": c.Status})
			}
		}
	}
	s.clearStaleChecks(ctx, a, module, seen, now)
}

// clearStaleChecks removes this module's checks for the agent that were not
// part of its latest report, and resolves any alert still open for them.
func (s *Server) clearStaleChecks(ctx context.Context, a store.Agent, module string, seen map[string]bool, now time.Time) {
	existing, err := s.store.ListChecks(ctx, a.TenantID, a.ID)
	if err != nil {
		s.log.Error("list checks", "agent", a.ID, "err", err)
		return
	}
	prefix := module + "/"
	for _, c := range existing {
		id, ok := strings.CutPrefix(c.CheckID, prefix)
		if !ok || seen[id] {
			continue
		}
		if err := s.store.DeleteCheck(ctx, a.TenantID, a.ID, c.CheckID); err != nil {
			s.log.Error("delete check", "agent", a.ID, "check", c.CheckID, "err", err)
			continue
		}
		closed, err := s.store.ResolveAlert(ctx, a.TenantID, a.ID+"/check/"+c.CheckID, "check:cleared", now)
		if err != nil {
			s.log.Error("resolve alert", "agent", a.ID, "check", c.CheckID, "err", err)
		} else if closed {
			s.audit(ctx, a.TenantID, "agent:"+a.ID, "alert.resolved", a.ID, map[string]any{"check": c.CheckID, "status": "cleared"})
		}
	}
}

func (s *Server) raise(ctx context.Context, a store.Agent, severity, kind, key, summary string, at time.Time) {
	alert := store.Alert{TenantID: a.TenantID, AgentID: a.ID, Severity: severity, Kind: kind,
		DedupeKey: a.ID + "/" + key, Summary: clip(summary, 500), FirstSeen: at, LastSeen: at}
	created, err := s.store.RaiseAlert(ctx, alert)
	if err != nil {
		s.log.Error("raise alert", "agent", a.ID, "kind", kind, "err", err)
		return
	}
	if created {
		s.log.Warn("alert", "agent", a.ID, "hostname", a.Host.Hostname, "severity", severity, "kind", kind, "summary", summary)
		s.audit(ctx, a.TenantID, "agent:"+a.ID, "alert.raised", a.ID, map[string]any{
			"severity": severity, "kind": kind, "summary": alert.Summary})
	}
}

// ingestLogons stores logon events and evaluates the unusual-logon rules
// on the events not seen before.
func (s *Server) ingestLogons(ctx context.Context, a store.Agent, raw []byte) {
	res, err := accesslog.Parse(raw)
	if err != nil {
		s.log.Warn("invalid logon events", "agent", a.ID, "err", err)
		return
	}
	events := make([]store.LogonEvent, 0, len(res.Events))
	for _, e := range res.Events {
		events = append(events, store.LogonEvent{Channel: e.Channel, RecordID: e.RecordID, At: e.Time, EventID: e.EventID,
			Kind: e.Kind, User: e.User, Domain: e.Domain, LogonType: e.LogonType, SourceIP: e.SourceIP,
			SourceHost: e.SourceHost, Status: e.Status})
	}
	now := s.now()
	added, err := s.store.AddLogonEvents(ctx, a.TenantID, a.ID, events, now)
	if err != nil {
		s.log.Error("store logon events", "agent", a.ID, "err", err)
		return
	}
	if res.Truncated {
		s.raise(ctx, a, store.SeverityInfo, "logon.truncated", "logon.truncated",
			"Troppi eventi di accesso in una sola raccolta: alcuni non sono stati letti", now)
	}
	if len(added) == 0 {
		return
	}
	s.noteLogonUser(ctx, a, added)
	settings, err := s.store.GetSettings(ctx, a.TenantID)
	if err != nil {
		s.log.Error("load settings", "err", err)
		return
	}
	allowed, err := accesslog.ParseSubnets(settings.RDPAllowedSubnets)
	if err != nil || len(allowed) == 0 {
		allowed = accesslog.DefaultAllowed
	}
	s.detectLogons(ctx, a, added, allowed)
}

func userOf(e store.LogonEvent) string {
	if e.Domain != "" && !strings.Contains(e.User, `\`) {
		return e.Domain + `\` + e.User
	}
	return e.User
}

func (s *Server) detectLogons(ctx context.Context, a store.Agent, events []store.LogonEvent, allowed []netip.Prefix) {
	type source struct {
		count int
		users map[string]bool
		last  time.Time
	}
	failures := map[string]*source{}
	newSources := map[string]bool{}
	for _, e := range events {
		user := userOf(e)
		switch {
		case e.SuccessfulLogon() && accesslog.IsRDP(e.Kind, e.LogonType) && e.SourceIP != "":
			if !accesslog.Allowed(e.SourceIP, allowed) {
				s.raise(ctx, a, store.SeverityCritical, "rdp.outside_lan", "rdp.outside/"+e.SourceIP+"/"+strings.ToLower(user),
					fmt.Sprintf("Accesso RDP di %s da %s, fuori dalle reti consentite", user, e.SourceIP), e.At)
				continue
			}
			key := strings.ToLower(user) + "|" + e.SourceIP
			if newSources[key] {
				continue
			}
			first, seen, err := s.store.LogonHistory(ctx, a.TenantID, a.ID, e.User, e.SourceIP, e.At)
			if err != nil {
				s.log.Error("logon history", "err", err)
				continue
			}
			if !seen && !first.IsZero() && e.At.Sub(first) >= LearningPeriod {
				newSources[key] = true
				s.raise(ctx, a, store.SeverityWarning, "rdp.new_source", "rdp.new/"+e.SourceIP+"/"+strings.ToLower(user),
					fmt.Sprintf("Accesso RDP di %s da un indirizzo mai visto prima: %s", user, e.SourceIP), e.At)
			}
		case e.Kind == accesslog.KindLogonFailed:
			src := e.SourceIP
			if src == "" {
				src = e.SourceHost
			}
			if src == "" {
				src = "locale"
			}
			f := failures[src]
			if f == nil {
				f = &source{users: map[string]bool{}}
				failures[src] = f
			}
			f.count++
			f.users[strings.ToLower(user)] = true
			if e.At.After(f.last) {
				f.last = e.At
			}
		case e.Kind == accesslog.KindLockout:
			s.raise(ctx, a, store.SeverityWarning, "account.lockout", "lockout/"+strings.ToLower(e.User),
				fmt.Sprintf("Account %s bloccato per troppi tentativi", e.User), e.At)
		}
	}
	for src, f := range failures {
		switch {
		case len(f.users) >= sprayThreshold:
			s.raise(ctx, a, store.SeverityCritical, "logon.spray", "spray/"+src,
				fmt.Sprintf("%d accessi falliti su %d utenti diversi da %s (possibile password spraying)", f.count, len(f.users), src), f.last)
		case f.count >= failureThreshold:
			s.raise(ctx, a, store.SeverityWarning, "logon.failures", "failures/"+src,
				fmt.Sprintf("%d accessi falliti da %s", f.count, src), f.last)
		}
	}
}
