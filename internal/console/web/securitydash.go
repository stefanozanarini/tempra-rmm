package web

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
)

// Security: the dashboard with the trend of the vulnerabilities by
// severity, recorded once a day (store.VulnSnapshot) each time the CVEs are
// matched, and the vulnerabilities list.

// severities in the order of the charts, with their color token.
var severities = []struct{ Key, Label, Short, Class string }{
	{"critical", "Critica", "Critica", "st-critical"},
	{"high", "Alta", "Alta", "st-serious"},
	{"medium", "Media", "Media", "st-warning"},
	{"low", "Bassa o non valutata", "Bassa", "st-none"},
}

// severityOf buckets a CVE by its CVSS score, or by the vendor severity
// when it has no score.
func severityOf(f vuln.Finding) string {
	switch {
	case f.CVSS >= 9:
		return "critical"
	case f.CVSS >= 7:
		return "high"
	case f.CVSS >= 4:
		return "medium"
	case f.CVSS > 0:
		return "low"
	}
	switch strings.ToLower(f.Severity) {
	case "critical":
		return "critical"
	case "important", "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	}
	return "low"
}

func addSev(c *store.SevCounts, sev string, n int) {
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

func sevValue(c store.SevCounts, sev string) int {
	switch sev {
	case "critical":
		return c.Critical
	case "high":
		return c.High
	case "medium":
		return c.Medium
	}
	return c.Low
}

// vulnCounts counts the findings of a tenant.
func vulnCounts(fs []vuln.Finding) store.VulnCounts {
	var c store.VulnCounts
	affected := map[string]bool{}
	for _, f := range fs {
		sev := severityOf(f)
		addSev(&c.CVEs, sev, 1)
		addSev(&c.Hits, sev, len(f.Hits))
		if f.KEV {
			c.KEV++
		}
		for _, h := range f.Hits {
			affected[h.AgentID] = true
		}
	}
	c.Endpoints = len(affected)
	return c
}

// lineChart is a multi-series line chart in viewBox units.
type lineChart struct {
	Title, Sub string
	Ticks      []chartTick // horizontal grid lines
	XTicks     []chartTick // dates
	Series     []lineSeries
	Rows       []chartRow // the same data as a table
	Single     bool       // one day only: points, no lines
}

type chartTick struct {
	X, Y   float64
	Label  string
	Anchor string // text-anchor of a date
}

type lineSeries struct {
	Label, Class string
	Short        string // at the end of the line
	Path         string
	Points       []linePoint
	Last         int     // latest value, labelled at the end of the line
	LabelY       float64 // where the end label goes (kept apart)
}

type linePoint struct {
	X, Y  float64
	Title string
}

type chartRow struct {
	Day    string
	Values []int
}

// Chart geometry (viewBox 0 0 chartW chartH).
const (
	chartW      = 640
	chartH      = 250
	chartLeft   = 44.0
	chartRight  = 530.0
	chartTop    = 12.0
	chartBottom = 214.0
)

// niceMax rounds up to 1, 2 or 5 × 10^n, so 4 grid steps read well.
func niceMax(v int) int {
	if v <= 4 {
		return 4
	}
	step := float64(v) / 4
	mag := math.Pow(10, math.Floor(math.Log10(step)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if step <= m*mag {
			return int(m*mag) * 4
		}
	}
	return v
}

// seriesDef is a line: one value per point in time.
type seriesDef struct {
	Label, Short, Class string
	Values              []int
}

// sevSeries are the lines of the severities of pick over the days.
func sevSeries(lang string, days []store.VulnSnapshot, pick func(store.VulnCounts) store.SevCounts) ([]time.Time, []seriesDef) {
	at := make([]time.Time, len(days))
	for i, d := range days {
		at[i] = d.Day
	}
	var defs []seriesDef
	for _, sv := range severities {
		def := seriesDef{Label: tr(lang, sv.Label), Short: tr(lang, sv.Short), Class: sv.Class}
		for _, d := range days {
			def.Values = append(def.Values, sevValue(pick(d.Counts), sv.Key))
		}
		defs = append(defs, def)
	}
	return at, defs
}

// newLineChart draws the series over the points in time (oldest first).
func newLineChart(title, sub string, at []time.Time, defs []seriesDef) lineChart {
	ch := lineChart{Title: title, Sub: sub, Single: len(at) == 1}
	max := 0
	for _, d := range defs {
		for _, v := range d.Values {
			max = int(math.Max(float64(max), float64(v)))
		}
	}
	top := niceMax(max)
	y := func(v int) float64 { return chartBottom - (chartBottom-chartTop)*float64(v)/float64(top) }
	for i := 0; i <= 4; i++ {
		v := top * i / 4
		ch.Ticks = append(ch.Ticks, chartTick{Y: y(v), Label: strconv.Itoa(v)})
	}
	if len(at) == 0 {
		return ch
	}
	first, last := at[0], at[len(at)-1]
	span := last.Sub(first).Hours() / 24
	x := func(t time.Time) float64 {
		if span == 0 {
			return (chartLeft + chartRight) / 2
		}
		return chartLeft + (chartRight-chartLeft)*(t.Sub(first).Hours()/24)/span
	}
	n := 5
	if int(span) < n {
		n = int(span)
	}
	for i := 0; i <= n; i++ {
		t := first
		if n > 0 {
			t = first.Add(time.Duration(float64(i) / float64(n) * span * 24 * float64(time.Hour)))
		}
		anchor := "middle"
		switch {
		case n > 0 && i == 0:
			anchor = "start"
		case n > 0 && i == n:
			anchor = "end"
		}
		ch.XTicks = append(ch.XTicks, chartTick{X: x(t), Label: t.Format("02/01"), Anchor: anchor})
	}
	for _, d := range defs {
		s := lineSeries{Label: d.Label, Short: d.Short, Class: d.Class}
		var path strings.Builder
		for i, v := range d.Values {
			px, py := x(at[i]), y(v)
			if i == 0 {
				fmt.Fprintf(&path, "M%.1f %.1f", px, py)
			} else {
				fmt.Fprintf(&path, " L%.1f %.1f", px, py)
			}
			s.Points = append(s.Points, linePoint{X: px, Y: py, Title: fmt.Sprintf("%s · %s: %d", at[i].Format("02/01/2006"), s.Label, v)})
			s.Last = v
		}
		s.Path = path.String()
		s.LabelY = y(s.Last)
		ch.Series = append(ch.Series, s)
	}
	// End labels at least 13 units apart, in the order of the values.
	order := make([]int, len(ch.Series))
	for i := range order {
		order[i] = i
	}
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && ch.Series[order[j]].LabelY < ch.Series[order[j-1]].LabelY; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	for k := 1; k < len(order); k++ {
		prev, cur := &ch.Series[order[k-1]], &ch.Series[order[k]]
		if cur.LabelY-prev.LabelY < 13 {
			cur.LabelY = prev.LabelY + 13
		}
	}
	for i := len(at) - 1; i >= 0; i-- {
		row := chartRow{Day: at[i].Format("02/01/2006")}
		for _, d := range defs {
			row.Values = append(row.Values, d.Values[i])
		}
		ch.Rows = append(ch.Rows, row)
	}
	return ch
}

// secCard is a figure of the dashboard with its change over the period.
type secCard struct {
	Label, Class, Link string
	Value              int
	Delta              int
	HasDelta           bool
}

type securityData struct {
	Tab   string // dashboard | vulns
	Vulns *vulnData
	// Dashboard.
	Ready      bool
	Days       int
	DayChoices []int
	Cards      []secCard
	Charts     []lineChart
	Since      string // first day recorded in the period
	History    int    // days recorded in the period
	Posture    *posture
	// Site and Group narrow the dashboard to some computers (ids, as on the
	// Reporting dashboard); Sites and Groups are the choices.
	Site, Group string
	Sites       []store.Site
	Groups      []store.Group
}

// filterQS is the site and group of the filter, to keep in links.
func filterQS(site, group string) string {
	v := url.Values{}
	if site != "" {
		v.Set("site", site)
	}
	if group != "" {
		v.Set("group", group)
	}
	return v.Encode()
}

// withFilter adds the site and group of the filter to a link.
func (d securityData) withFilter(link string) string {
	qs := filterQS(d.Site, d.Group)
	switch {
	case qs == "":
		return link
	case strings.Contains(link, "?"):
		return link + "&" + qs
	}
	return link + "?" + qs
}

// securityFilter returns the computers of a site or group (nil: all), and
// the sites and groups to choose from.
func (s *Server) securityFilter(r *http.Request, t, site, group string) (map[string]bool, []store.Site, []store.Group, error) {
	ctx := r.Context()
	sites, err := s.store.ListSites(ctx, t)
	if err != nil {
		return nil, nil, nil, err
	}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		return nil, nil, nil, err
	}
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		return nil, nil, nil, err
	}
	allow, err := s.dashboardFilter(r, t, agents, site, group)
	return allow, sites, groups, err
}

// filterFindings keeps the hits on the computers of allow (all when nil),
// and the findings with some left.
func filterFindings(fs []vuln.Finding, allow map[string]bool) []vuln.Finding {
	if allow == nil {
		return fs
	}
	var out []vuln.Finding
	for _, f := range fs {
		var hits []vuln.Hit
		for _, h := range f.Hits {
			if allow[h.AgentID] {
				hits = append(hits, h)
			}
		}
		if len(hits) > 0 {
			f.Hits = hits
			out = append(out, f)
		}
	}
	return out
}

// allowList lists the computers of allow (nil when all).
func allowList(allow map[string]bool) []string {
	if allow == nil {
		return nil
	}
	out := make([]string, 0, len(allow))
	for id := range allow {
		out = append(out, id)
	}
	return out
}

var securityDayChoices = []int{30, 90, 180, 365}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	lang := s.lang(r)
	d := securityData{Tab: "dashboard", Days: 90, DayChoices: securityDayChoices,
		Site: r.URL.Query().Get("site"), Group: r.URL.Query().Get("group")}
	allow, sites, groups, err := s.securityFilter(r, t, d.Site, d.Group)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Sites, d.Groups = sites, groups
	if n, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil {
		for _, c := range securityDayChoices {
			if n == c {
				d.Days = n
			}
		}
	}
	ix, err := s.vulnIndex(ctx)
	if err != nil && !errors.Is(err, vuln.ErrNoData) {
		s.fail(w, r, err)
		return
	}
	var now store.VulnCounts
	var fs []vuln.Finding
	if err == nil {
		d.Ready = true
		if fs, _, err = s.vulnFindings(ctx, t, ix); err != nil {
			s.fail(w, r, err)
			return
		}
		fs = filterFindings(fs, allow)
		now = vulnCounts(fs)
	}
	since := s.now().AddDate(0, 0, -d.Days)
	var days []store.VulnSnapshot
	if allow == nil {
		days, err = s.store.ListVulnSnapshots(ctx, t, since)
	} else {
		// The daily rows keep the whole tenant: the history of some
		// computers comes from their exposures.
		days, err = s.store.VulnExposureHistory(ctx, t, since, s.now(), allowList(allow))
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Today as computed now, also before the row of the day is written.
	today := s.now().UTC().Truncate(24 * time.Hour)
	if d.Ready {
		if n := len(days); n > 0 && days[n-1].Day.Equal(today) {
			days[n-1].Counts = now
		} else {
			days = append(days, store.VulnSnapshot{TenantID: t, Day: today, Counts: now})
		}
	}
	d.History = len(days)
	if len(days) > 0 {
		d.Since = days[0].Day.Format("02/01/2006")
	}
	var base *store.VulnCounts
	if len(days) > 1 {
		base = &days[0].Counts
	}
	card := func(label, class, link string, v int, old func(store.VulnCounts) int) secCard {
		c := secCard{Label: label, Class: class, Link: d.withFilter(link), Value: v}
		if base != nil && old != nil {
			c.Delta, c.HasDelta = v-old(*base), true
		}
		return c
	}
	// The history rebuilt for some computers does not know KEV.
	kevOld := func(c store.VulnCounts) int { return c.KEV }
	if allow != nil {
		kevOld = nil
	}
	d.Cards = []secCard{
		card(tr(lang, "vulnerabilità trovate"), "", "/security/vulnerabilities", now.CVEs.Total(), func(c store.VulnCounts) int { return c.CVEs.Total() }),
		card(tr(lang, "critiche (CVSS 9 o più)"), "bad", "/security/vulnerabilities?sort=cvss", now.CVEs.Critical, func(c store.VulnCounts) int { return c.CVEs.Critical }),
		card(tr(lang, "alte (CVSS 7-8.9)"), "warn", "/security/vulnerabilities?sort=cvss", now.CVEs.High, func(c store.VulnCounts) int { return c.CVEs.High }),
		card(tr(lang, "sfruttate attivamente (CISA)"), "bad", "/security/vulnerabilities?exploited=1", now.KEV, kevOld),
		card(tr(lang, "computer colpiti"), "", "/security/vulnerabilities?sort=hosts", now.Endpoints, func(c store.VulnCounts) int { return c.Endpoints }),
	}
	at, cves := sevSeries(lang, days, func(c store.VulnCounts) store.SevCounts { return c.CVEs })
	_, hits := sevSeries(lang, days, func(c store.VulnCounts) store.SevCounts { return c.Hits })
	d.Charts = []lineChart{
		newLineChart(tr(lang, "Vulnerabilità per gravità"), tr(lang, "CVE distinte che colpiscono almeno un computer, giorno per giorno"), at, cves),
		newLineChart(tr(lang, "Esposizioni per gravità"), tr(lang, "Coppie CVE × computer: scendono quando gli aggiornamenti arrivano sui computer"), at, hits),
	}
	if d.Ready {
		if d.Posture, err = s.securityPosture(ctx, lang, t, fs, d.Days, allow); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	s.render(w, r, "security", s.T(r, "Security"), d)
}

func (s *Server) handleSecurityVulns(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	v, err := s.vulnReport(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "security", s.T(r, "Vulnerabilità"), securityData{Tab: "vulns", Vulns: v})
}

// recordVulns writes the counts of the day and each CVE found on each
// computer after the CVEs were matched.
func (s *Server) recordVulns(tenant string, agents []store.Agent, fs []vuln.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := s.now()
	if err := s.store.PutVulnSnapshot(ctx, store.VulnSnapshot{TenantID: tenant, Day: now, Counts: vulnCounts(fs)}); err != nil {
		s.log.Warn("vulnerability history", "tenant", tenant, "err", err)
	}
	active := map[string]bool{}
	for _, a := range agents {
		if a.Status == store.AgentActive {
			active[a.ID] = true
		}
	}
	var cur []store.VulnExposure
	for _, f := range fs {
		sev := severityOf(f)
		for _, h := range f.Hits {
			cur = append(cur, store.VulnExposure{AgentID: h.AgentID, CVE: f.ID, Severity: sev})
		}
	}
	if err := s.store.SyncVulnExposures(ctx, tenant, cur, active, now); err != nil {
		s.log.Warn("vulnerability exposures", "tenant", tenant, "err", err)
	}
}
