package web

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// More dashboard charts: hardware age and minimum requirements, disk
// health, the outcome of the jobs and the recent software changes.

const (
	jobDays        = 30
	changeDays     = 7
	maxChangesRead = 5000
	maxChangesShow = 12
)

// hardwareAge is the estimated age of a computer: from the oldest of the
// installed BIOS release date and the Windows installation date. Both are
// later than the purchase (a BIOS update or a reinstall moves them), so it
// is a lower bound.
func hardwareAge(inv *inventory.Inventory, now time.Time) (time.Duration, bool) {
	var oldest time.Time
	if d, err := time.Parse("2006-01-02", inv.Firmware.Date); err == nil {
		oldest = d
	}
	if t := inv.OS.InstallDate; t != nil && !t.IsZero() && (oldest.IsZero() || t.Before(oldest)) {
		oldest = *t
	}
	if oldest.IsZero() || oldest.After(now) {
		return 0, false
	}
	return now.Sub(oldest), true
}

// hasHDD reports a spinning disk among the computer's disks.
func hasHDD(inv *inventory.Inventory) bool {
	for _, d := range inv.Disks {
		if strings.EqualFold(d.MediaType, "HDD") {
			return true
		}
	}
	return false
}

// diskHealthState is the worst SMART state of the disks: 0 healthy,
// 1 warning, 2 unhealthy, 3 no data.
func diskHealthState(inv *inventory.Inventory) int {
	state := 3
	for _, d := range inv.Disks {
		var s int
		switch strings.ToLower(d.Health) {
		case "healthy":
			s = 0
		case "warning":
			s = 1
		case "unhealthy":
			s = 2
		default:
			continue
		}
		if state == 3 || s > state {
			state = s
		}
	}
	return state
}

// Buckets of the hardware charts.
var (
	hwAgeLabels   = []string{"meno di 1 anno", "da 1 a 3 anni", "da 3 a 5 anni", "oltre 5 anni", "sconosciuta"}
	hwBelowLabels = []string{"RAM sotto 8 GB", "disco meccanico (HDD)", "meno di 4 core", "disco di sistema sotto 128 GB"}
)

// hardwareCharts adds the hardware charts for the approved agents.
func hardwareCharts(lang string, d *dashData, agents []store.Agent, byInv map[string]*inventory.Inventory, now time.Time) {
	var age [5][]string // < 1, 1-3, 3-5, 5+ years, unknown
	var below [4][]string
	var health checkBucket
	year := 365.25 * 24 * time.Hour
	for _, a := range agents {
		if a.Status != store.AgentActive {
			continue
		}
		inv := byInv[a.ID]
		if inv == nil {
			age[4] = append(age[4], a.ID)
			health.add(3, a.ID)
			continue
		}
		health.add(diskHealthState(inv), a.ID)
		if a.Host.OS == "windows" {
			if dur, ok := hardwareAge(inv, now); !ok {
				age[4] = append(age[4], a.ID)
			} else {
				switch {
				case dur < year:
					age[0] = append(age[0], a.ID)
				case dur < 3*year:
					age[1] = append(age[1], a.ID)
				case dur < 5*year:
					age[2] = append(age[2], a.ID)
				default:
					age[3] = append(age[3], a.ID)
				}
			}
		}
		if inv.Memory.TotalBytes > 0 && inv.Memory.TotalBytes < 15<<30/2 { // under 8 GB, as Windows reports it
			below[0] = append(below[0], a.ID)
		}
		if hasHDD(inv) {
			below[1] = append(below[1], a.ID)
		}
		cores := 0
		for _, c := range inv.CPUs {
			cores += c.Cores
		}
		if cores > 0 && cores < 4 {
			below[2] = append(below[2], a.ID)
		}
		if v := systemVolume(inv); v != nil && v.SizeBytes > 0 && v.SizeBytes < 120<<30 {
			below[3] = append(below[3], a.ID)
		}
	}
	d.Donuts = append(d.Donuts, newDonut(tr(lang, "Salute dei dischi"), tr(lang, "stato SMART, il disco peggiore di ogni agente"), []seg{
		{Label: tr(lang, "Guasto imminente"), Class: "st-critical", Count: health.n[2], Link: health.link(2)},
		{Label: tr(lang, "Da tenere d'occhio"), Class: "st-warning", Count: health.n[1], Link: health.link(1)},
		{Label: tr(lang, "Nessun dato"), Class: "st-none", Count: health.n[3], Link: health.link(3)},
		{Label: tr(lang, "In buona salute"), Class: "st-good", Count: health.n[0], Link: health.link(0)},
	}))
	var ageBars []bar
	for i, l := range hwAgeLabels {
		ageBars = append(ageBars, bar{Label: tr(lang, l), Count: len(age[i]), Link: idsLink(age[i])})
	}
	d.Bars = append(d.Bars, newBars(tr(lang, "Età dell'hardware"),
		tr(lang, "stimata dalla data del BIOS o dell'installazione di Windows, la più vecchia: un'età minima"), ageBars))
	var belowBars []bar
	for i, l := range hwBelowLabels {
		belowBars = append(belowBars, bar{Label: tr(lang, l), Count: len(below[i]), Link: idsLink(below[i])})
	}
	hw := newBars(tr(lang, "Hardware sotto i requisiti"), tr(lang, "computer da potenziare o sostituire, dall'inventario"), belowBars)
	hw.Empty = tr(lang, "Nessun computer sotto i requisiti.")
	if len(below[0])+len(below[1])+len(below[2])+len(below[3]) == 0 {
		hw.Bars = nil
	}
	d.Bars = append(d.Bars, hw)
}

// jobStates are the lines of the job chart: the final states, the rest
// counted as in progress.
var jobStates = []struct {
	State        store.JobState
	Label, Class string
}{
	{store.JobSucceeded, "Completati", "st-good"},
	{store.JobFailed, "Falliti", "st-critical"},
	{store.JobExpired, "Scaduti", "st-warning"},
	{store.JobRejected, "Rifiutati dall'agente", "st-serious"},
}

// softwareChange is a row of the recent software changes.
type softwareChange struct {
	At                        time.Time
	AgentID, Hostname, Detail string
	Kind                      string // added | removed | updated
}

type changesView struct {
	Added, Removed, Updated int
	Rows                    []softwareChange
	Days                    int
}

// activityCharts adds the outcome of the jobs and the software changes of
// the agents in keep (nil: every agent).
func (s *Server) activityCharts(ctx context.Context, lang, t string, d *dashData, keep map[string]bool, names map[string]string) error {
	now := s.now()
	counts, err := s.store.JobCounts(ctx, t, now.AddDate(0, 0, -jobDays+1).Truncate(24*time.Hour))
	if err != nil {
		return err
	}
	first := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -jobDays+1)
	var at []time.Time
	for i := 0; i < jobDays; i++ {
		at = append(at, first.AddDate(0, 0, i))
	}
	defs := make([]seriesDef, len(jobStates))
	for i, js := range jobStates {
		defs[i] = seriesDef{Label: tr(lang, js.Label), Short: tr(lang, js.Label), Class: js.Class, Values: make([]int, jobDays)}
	}
	failed := map[string]int{}
	total := 0
	for _, c := range counts {
		if keep != nil && !keep[c.AgentID] {
			continue
		}
		i := int(c.Day.Sub(first).Hours() / 24)
		if i < 0 || i >= jobDays {
			continue
		}
		for k, js := range jobStates {
			if c.State == js.State {
				defs[k].Values[i] += c.Count
			}
		}
		if c.State == store.JobFailed || c.State == store.JobRejected {
			failed[c.Module] += c.Count
		}
		total += c.Count
	}
	if total > 0 {
		ch := newLineChart(tr(lang, "Esito dei job"), trf(lang, "job creati ogni giorno negli ultimi %d giorni, per esito", jobDays), at, defs)
		d.Jobs = &ch
	}
	var fb []bar
	for m, n := range failed {
		fb = append(fb, bar{Label: m, Count: n, Link: "/jobs?" + url.Values{"q": {m}}.Encode()})
	}
	sort.Slice(fb, func(i, j int) bool {
		if fb[i].Count != fb[j].Count {
			return fb[i].Count > fb[j].Count
		}
		return fb[i].Label < fb[j].Label
	})
	if len(fb) > maxBars {
		fb = fb[:maxBars]
	}
	d.JobFails = newBars(tr(lang, "Moduli con più job falliti"), trf(lang, "falliti o rifiutati negli ultimi %d giorni", jobDays), fb)
	d.JobFails.Empty = tr(lang, "Nessun job fallito.")

	changes, err := s.store.RecentInventoryChanges(ctx, t, now.AddDate(0, 0, -changeDays), "software.", maxChangesRead)
	if err != nil {
		return err
	}
	cv := &changesView{Days: changeDays}
	for _, c := range changes {
		if keep != nil && !keep[c.AgentID] {
			continue
		}
		row := softwareChange{At: c.At, AgentID: c.AgentID, Hostname: names[c.AgentID], Detail: c.Detail}
		switch c.Kind {
		case "software.added":
			cv.Added++
			row.Kind = "added"
		case "software.removed":
			cv.Removed++
			row.Kind = "removed"
		default:
			cv.Updated++
			row.Kind = "updated"
		}
		if len(cv.Rows) < maxChangesShow {
			cv.Rows = append(cv.Rows, row)
		}
	}
	d.Changes = cv
	return nil
}
