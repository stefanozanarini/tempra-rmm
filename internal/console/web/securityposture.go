package web

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
	"github.com/stefanozanarini/tempra-rmm/internal/updates"
)

// The security posture of the approved computers, from the latest
// inventory, checks, update scans and matched CVEs: a compliance baseline,
// how old the missing security updates are, operating systems out of
// support, and the computers and applications most exposed.

// criterion is a rule of the compliance baseline.
type criterion struct {
	Key, Label, Help string
	// test: pass, fail, or applies false (no data or not relevant).
	test func(p *postureCtx) (pass, applies bool)
}

type postureCtx struct {
	a       store.Agent
	inv     *inventory.Inventory
	av      *store.Check
	win     *store.UpdateStatus
	osEnd   time.Time
	osKnown bool
	now     time.Time
}

func (p *postureCtx) windows() bool { return p.a.Host.OS == "windows" }
func (p *postureCtx) client() bool  { return p.a.Host.OSFamily != "server" }

var criteria = []criterion{
	{"bitlocker", "Disco di sistema cifrato (BitLocker)", "solo client Windows", func(p *postureCtx) (bool, bool) {
		if !p.windows() || !p.client() || p.inv == nil {
			return false, false
		}
		v := systemVolume(p.inv)
		if v == nil || v.BitLocker == "" {
			return false, false
		}
		return v.BitLocker == "on", true
	}},
	{"secure_boot", "Secure Boot attivo", "computer Windows", func(p *postureCtx) (bool, bool) {
		if !p.windows() || p.inv == nil || p.inv.Firmware.SecureBoot == nil {
			return false, false
		}
		return *p.inv.Firmware.SecureBoot, true
	}},
	{"tpm", "TPM 2.0", "solo client Windows", func(p *postureCtx) (bool, bool) {
		if !p.windows() || !p.client() || p.inv == nil {
			return false, false
		}
		return p.inv.TPM.Present && strings.HasPrefix(strings.TrimSpace(p.inv.TPM.Version), "2"), true
	}},
	{"antivirus", "Antivirus attivo e aggiornato", "dal controllo protection-status/antivirus", func(p *postureCtx) (bool, bool) {
		if p.av == nil {
			return false, false
		}
		return p.av.Status == store.CheckOK, true
	}},
	{"updates", "Aggiornamenti di sicurezza installati", "dall'ultima scansione degli aggiornamenti", func(p *postureCtx) (bool, bool) {
		if p.win == nil {
			return false, false
		}
		return p.win.Important == 0, true
	}},
	{"os_support", "Sistema operativo supportato", "dalle date di fine supporto di Microsoft", func(p *postureCtx) (bool, bool) {
		if !p.osKnown {
			return false, false
		}
		return p.osEnd.After(p.now), true
	}},
}

// patchAgeLabels name the age buckets of the missing security updates.
var patchAgeLabels = []string{"fino a 7 giorni", "da 8 a 30 giorni", "da 31 a 90 giorni", "oltre 90 giorni", "data di uscita sconosciuta"}

// criterionView is a row of the compliance table.
type criterionView struct {
	Label, Help        string
	Pass, Fail, NoData int
	Pct                int
	FailLink           string // the computers failing it
}

// softwareRisk is an application with known vulnerabilities.
type softwareRisk struct {
	Product             string
	Computers           int
	CVEs                int
	Critical, High, KEV int
	Link, UpgradeLink   string
}

// exposureView is the time to fix of a severity.
type exposureView struct {
	Label, Class string
	Fixed        int
	Days         string // mean, e.g. "4.2"
}

type posture struct {
	Compliance   donut
	CompliantPct int
	Criteria     []criterionView
	PatchAge     barChart
	OSSupport    donut
	OSReleases   barChart
	TopHosts     barChart
	Software     []softwareRisk
	// Exposures: weekly new and fixed, and the time to fix.
	Weekly   lineChart
	HasWeeks bool
	MTTR     []exposureView
	Tracking string // when the recording started
}

func idsLink(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return "/agents?" + url.Values{"ids": {strings.Join(ids, ",")}}.Encode()
}

// securityPosture computes the posture of the tenant's approved computers
// (those of allow, when not nil).
func (s *Server) securityPosture(ctx context.Context, lang, t string, fs []vuln.Finding, days int, allow map[string]bool) (*posture, error) {
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		return nil, err
	}
	invs, err := s.store.ListInventories(ctx, t)
	if err != nil {
		return nil, err
	}
	byInv := map[string]*inventory.Inventory{}
	for _, i := range invs {
		if p, err := inventory.Parse(i.Data); err == nil {
			byInv[i.AgentID] = p
		}
	}
	av, err := s.store.ChecksByID(ctx, t, "protection-status/antivirus")
	if err != nil {
		return nil, err
	}
	statuses, err := s.store.ListUpdateStatus(ctx, t, "")
	if err != nil {
		return nil, err
	}
	win := map[string]store.UpdateStatus{}
	for _, st := range statuses {
		if st.Source == updates.SourceWindows {
			win[st.AgentID] = st
		}
	}
	now := s.now()
	p := &posture{}
	views := make([]criterionView, len(criteria))
	fails := make([][]string, len(criteria))
	var compliant, nonCompliant []string
	var ages [5][]string          // 0-7, 8-30, 31-90, >90 days, release date unknown
	osState := [4][]string{}      // supported, ending within 6 months, out of support, unknown
	releases := map[string]*bar{} // out of support or ending, by release
	for _, a := range agents {
		if a.Status != store.AgentActive || (allow != nil && !allow[a.ID]) {
			continue
		}
		pc := &postureCtx{a: a, inv: byInv[a.ID], now: now}
		if c, ok := av[a.ID]; ok {
			pc.av = &c
		}
		if st, ok := win[a.ID]; ok {
			pc.win = &st
		}
		// Operating system support.
		if pc.windows() {
			name, build := a.Host.OSVersion, ""
			if pc.inv != nil && pc.inv.OS.Build != "" {
				name, build = pc.inv.OS.Name, pc.inv.OS.Build
			} else if b, _, ok := vuln.WindowsBuild(a.Host.OSVersion); ok {
				build = strconv.Itoa(b)
			}
			label, end, ok := supportEnd(name, build, a.Host.OSFamily == "server")
			pc.osEnd, pc.osKnown = end, ok
			switch {
			case !ok:
				osState[3] = append(osState[3], a.ID)
			case !end.After(now):
				osState[2] = append(osState[2], a.ID)
			case end.Before(now.AddDate(0, 6, 0)):
				osState[1] = append(osState[1], a.ID)
			default:
				osState[0] = append(osState[0], a.ID)
			}
			if ok && end.Before(now.AddDate(0, 6, 0)) {
				key := label + "|" + end.Format("2006-01-02")
				b := releases[key]
				if b == nil {
					note := trf(lang, "fine supporto %s", end.Format("02/01/2006"))
					if !end.After(now) {
						note = trf(lang, "fuori supporto dal %s", end.Format("02/01/2006"))
					}
					b = &bar{Label: label, Note: note}
					releases[key] = b
				}
				b.Count++
				b.Link += a.ID + ","
			}
		}
		// Compliance.
		known, ok := 0, true
		for i, c := range criteria {
			pass, applies := c.test(pc)
			switch {
			case !applies:
				views[i].NoData++
			case pass:
				views[i].Pass++
				known++
			default:
				views[i].Fail++
				fails[i] = append(fails[i], a.ID)
				known++
				ok = false
			}
		}
		if known > 0 {
			if ok {
				compliant = append(compliant, a.ID)
			} else {
				nonCompliant = append(nonCompliant, a.ID)
			}
		}
		// Age of the oldest missing security update.
		if pc.win != nil && pc.win.Important > 0 {
			oldest := time.Time{}
			if rep := osUpdateReport(*pc.win); rep != nil {
				for _, u := range rep.Updates {
					if u.Important() && u.Released != nil && (oldest.IsZero() || u.Released.Before(oldest)) {
						oldest = *u.Released
					}
				}
			}
			bucket := 4
			if !oldest.IsZero() {
				switch d := now.Sub(oldest).Hours() / 24; {
				case d <= 7:
					bucket = 0
				case d <= 30:
					bucket = 1
				case d <= 90:
					bucket = 2
				default:
					bucket = 3
				}
			}
			ages[bucket] = append(ages[bucket], a.ID)
		}
	}
	for i, c := range criteria {
		v := views[i]
		v.Label, v.Help, v.FailLink = tr(lang, c.Label), tr(lang, c.Help), idsLink(fails[i])
		if v.Pass+v.Fail > 0 {
			v.Pct = 100 * v.Pass / (v.Pass + v.Fail)
		}
		p.Criteria = append(p.Criteria, v)
	}
	p.Compliance = newDonut(tr(lang, "Conformità"), tr(lang, "Computer che rispettano tutti i criteri che li riguardano"), []seg{
		{Label: tr(lang, "conformi"), Class: "st-good", Count: len(compliant), Link: idsLink(compliant)},
		{Label: tr(lang, "non conformi"), Class: "st-critical", Count: len(nonCompliant), Link: idsLink(nonCompliant)},
	})
	if n := len(compliant) + len(nonCompliant); n > 0 {
		p.CompliantPct = 100 * len(compliant) / n
	}

	var ageBars []bar
	for i, l := range patchAgeLabels {
		if i == 4 && len(ages[i]) == 0 {
			continue
		}
		ageBars = append(ageBars, bar{Label: tr(lang, l), Count: len(ages[i]), Link: idsLink(ages[i])})
	}
	p.PatchAge = newBars(tr(lang, "Patch di sicurezza mancanti per anzianità"),
		tr(lang, "Computer per età del più vecchio aggiornamento di sicurezza non installato"), ageBars)
	p.PatchAge.Empty = tr(lang, "Nessun computer con aggiornamenti di sicurezza mancanti.")
	total := 0
	for _, b := range ageBars {
		total += b.Count
	}
	if total == 0 {
		p.PatchAge.Bars = nil
	}

	p.OSSupport = newDonut(tr(lang, "Supporto del sistema operativo"), tr(lang, "Computer Windows secondo le date di fine supporto di Microsoft"), []seg{
		{Label: tr(lang, "supportato"), Class: "st-good", Count: len(osState[0]), Link: idsLink(osState[0])},
		{Label: tr(lang, "fine supporto entro 6 mesi"), Class: "st-warning", Count: len(osState[1]), Link: idsLink(osState[1])},
		{Label: tr(lang, "fuori supporto"), Class: "st-critical", Count: len(osState[2]), Link: idsLink(osState[2])},
		{Label: tr(lang, "versione non riconosciuta"), Class: "st-none", Count: len(osState[3]), Link: idsLink(osState[3])},
	})
	var rel []bar
	for _, b := range releases {
		b.Link = idsLink(strings.Split(strings.TrimSuffix(b.Link, ","), ","))
		rel = append(rel, *b)
	}
	sort.Slice(rel, func(i, j int) bool {
		if rel[i].Count != rel[j].Count {
			return rel[i].Count > rel[j].Count
		}
		return rel[i].Label < rel[j].Label
	})
	p.OSReleases = newBars(tr(lang, "Versioni fuori supporto o in scadenza"), tr(lang, "Computer per versione di Windows"), rel)
	p.OSReleases.Empty = tr(lang, "Tutti i computer hanno una versione supportata per almeno 6 mesi.")

	p.TopHosts, p.Software = topExposed(lang, fs)

	if err := s.exposureTrend(ctx, lang, t, days, allowList(allow), p); err != nil {
		return nil, err
	}
	return p, nil
}

// topExposed ranks the computers and the applications by the vulnerabilities
// affecting them.
func topExposed(lang string, fs []vuln.Finding) (barChart, []softwareRisk) {
	type host struct {
		name, id string
		sev      store.SevCounts
		kev      int
	}
	hosts := map[string]*host{}
	type app struct {
		risk  softwareRisk
		pcs   map[string]bool
		linux bool // a package of the Linux package manager, not winget
	}
	apps := map[string]*app{}
	for _, f := range fs {
		sev := severityOf(f)
		for _, h := range f.Hits {
			x := hosts[h.AgentID]
			if x == nil {
				x = &host{name: h.Hostname, id: h.AgentID}
				hosts[h.AgentID] = x
			}
			addSev(&x.sev, sev, 1)
			if f.KEV {
				x.kev++
			}
		}
		if f.Product == "" || f.Product == "Windows" {
			continue
		}
		ap := apps[f.Product]
		if ap == nil {
			ap = &app{risk: softwareRisk{Product: f.Product}, pcs: map[string]bool{}}
			apps[f.Product] = ap
		}
		ap.risk.CVEs++
		switch sev {
		case "critical":
			ap.risk.Critical++
		case "high":
			ap.risk.High++
		}
		if f.KEV {
			ap.risk.KEV++
		}
		for _, h := range f.Hits {
			ap.pcs[h.AgentID] = true
			ap.linux = ap.linux || h.Package != ""
		}
	}
	var hs []*host
	for _, h := range hosts {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if a.kev != b.kev {
			return a.kev > b.kev
		}
		if a.sev.Critical != b.sev.Critical {
			return a.sev.Critical > b.sev.Critical
		}
		if a.sev.High != b.sev.High {
			return a.sev.High > b.sev.High
		}
		if a.sev.Total() != b.sev.Total() {
			return a.sev.Total() > b.sev.Total()
		}
		return a.name < b.name
	})
	var bars []bar
	for i, h := range hs {
		if i == 10 {
			break
		}
		b := bar{Label: h.name, Count: h.sev.Total(), Link: "/security/vulnerabilities?" + url.Values{"agent": {h.id}}.Encode()}
		if h.kev > 0 {
			b.Note = trf(lang, "%d sfruttate", h.kev)
		}
		for _, sv := range severities {
			b.Parts = append(b.Parts, part{Label: tr(lang, sv.Label), Class: sv.Class, Count: sevValue(h.sev, sv.Key)})
		}
		bars = append(bars, b)
	}
	top := newBars(tr(lang, "Computer più esposti"), tr(lang, "Vulnerabilità per computer, prima quelle sfruttate attivamente e critiche"), bars)
	top.Wide = true
	top.Empty = tr(lang, "Nessuna vulnerabilità trovata.")
	for _, sv := range severities {
		top.Legend = append(top.Legend, seg{Label: tr(lang, sv.Label), Class: sv.Class})
	}

	var sw []softwareRisk
	for _, ap := range apps {
		r := ap.risk
		r.Computers = len(ap.pcs)
		r.Link = "/security/vulnerabilities?" + url.Values{"q": {r.Product}}.Encode()
		if !ap.linux {
			r.UpgradeLink = "/reports?" + url.Values{"tab": {"computers"}, "software": {r.Product}}.Encode()
		}
		sw = append(sw, r)
	}
	sort.Slice(sw, func(i, j int) bool {
		a, b := sw[i], sw[j]
		if a.KEV != b.KEV {
			return a.KEV > b.KEV
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.Computers != b.Computers {
			return a.Computers > b.Computers
		}
		return a.Product < b.Product
	})
	if len(sw) > 10 {
		sw = sw[:10]
	}
	return top, sw
}

// exposureTrend adds the weekly new and fixed exposures and the time to fix.
func (s *Server) exposureTrend(ctx context.Context, lang, t string, days int, agents []string, p *posture) error {
	st, err := s.store.VulnExposureStats(ctx, t, s.now().AddDate(0, 0, -days), agents)
	if err != nil {
		return err
	}
	if !st.Tracking.IsZero() {
		p.Tracking = st.Tracking.Format("02/01/2006")
	}
	var at []time.Time
	newDef := seriesDef{Label: tr(lang, "Nuove"), Short: tr(lang, "nuove"), Class: "st-serious"}
	fixDef := seriesDef{Label: tr(lang, "Corrette"), Short: tr(lang, "corrette"), Class: "st-good"}
	for _, w := range st.Weeks {
		at = append(at, w.Start)
		newDef.Values = append(newDef.Values, w.New.Total())
		fixDef.Values = append(fixDef.Values, w.Fixed.Total())
	}
	p.HasWeeks = len(at) > 0
	p.Weekly = newLineChart(tr(lang, "Esposizioni nuove e corrette"),
		tr(lang, "Coppie CVE × computer comparse e sparite ogni settimana (dal lunedì)"), at, []seriesDef{newDef, fixDef})
	for _, sv := range severities {
		mean := map[string]float64{"critical": st.MeanDays.Critical, "high": st.MeanDays.High, "medium": st.MeanDays.Medium, "low": st.MeanDays.Low}[sv.Key]
		v := exposureView{Label: tr(lang, sv.Label), Class: sv.Class, Fixed: sevValue(st.Fixed, sv.Key)}
		if v.Fixed > 0 {
			v.Days = strconv.FormatFloat(mean, 'f', 1, 64)
			if lang != "en" {
				v.Days = strings.Replace(v.Days, ".", ",", 1)
			}
		}
		p.MTTR = append(p.MTTR, v)
	}
	return nil
}
