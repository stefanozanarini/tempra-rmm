package web

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
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

// newLineChart draws one line per severity of pick over the days.
func newLineChart(lang, title, sub string, days []store.VulnSnapshot, pick func(store.VulnCounts) store.SevCounts) lineChart {
	ch := lineChart{Title: title, Sub: sub, Single: len(days) == 1}
	max := 0
	for _, d := range days {
		c := pick(d.Counts)
		for _, sv := range severities {
			max = int(math.Max(float64(max), float64(sevValue(c, sv.Key))))
		}
	}
	top := niceMax(max)
	y := func(v int) float64 { return chartBottom - (chartBottom-chartTop)*float64(v)/float64(top) }
	for i := 0; i <= 4; i++ {
		v := top * i / 4
		ch.Ticks = append(ch.Ticks, chartTick{Y: y(v), Label: strconv.Itoa(v)})
	}
	if len(days) == 0 {
		return ch
	}
	first, last := days[0].Day, days[len(days)-1].Day
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
	for _, sv := range severities {
		s := lineSeries{Label: tr(lang, sv.Label), Short: tr(lang, sv.Short), Class: sv.Class}
		var path strings.Builder
		for i, d := range days {
			v := sevValue(pick(d.Counts), sv.Key)
			px, py := x(d.Day), y(v)
			if i == 0 {
				fmt.Fprintf(&path, "M%.1f %.1f", px, py)
			} else {
				fmt.Fprintf(&path, " L%.1f %.1f", px, py)
			}
			s.Points = append(s.Points, linePoint{X: px, Y: py, Title: fmt.Sprintf("%s · %s: %d", d.Day.Format("02/01/2006"), s.Label, v)})
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
	for i := len(days) - 1; i >= 0; i-- {
		row := chartRow{Day: days[i].Day.Format("02/01/2006")}
		for _, sv := range severities {
			row.Values = append(row.Values, sevValue(pick(days[i].Counts), sv.Key))
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
	d := securityData{Tab: "dashboard", Days: 90, DayChoices: securityDayChoices}
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
	if err == nil {
		d.Ready = true
		fs, _, err := s.vulnFindings(ctx, t, ix)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		now = vulnCounts(fs)
	}
	days, err := s.store.ListVulnSnapshots(ctx, t, s.now().AddDate(0, 0, -d.Days))
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
		c := secCard{Label: label, Class: class, Link: link, Value: v}
		if base != nil {
			c.Delta, c.HasDelta = v-old(*base), true
		}
		return c
	}
	d.Cards = []secCard{
		card(tr(lang, "vulnerabilità trovate"), "", "/security/vulnerabilities", now.CVEs.Total(), func(c store.VulnCounts) int { return c.CVEs.Total() }),
		card(tr(lang, "critiche (CVSS 9 o più)"), "bad", "/security/vulnerabilities?sort=cvss", now.CVEs.Critical, func(c store.VulnCounts) int { return c.CVEs.Critical }),
		card(tr(lang, "alte (CVSS 7-8.9)"), "warn", "/security/vulnerabilities?sort=cvss", now.CVEs.High, func(c store.VulnCounts) int { return c.CVEs.High }),
		card(tr(lang, "sfruttate attivamente (CISA)"), "bad", "/security/vulnerabilities?exploited=1", now.KEV, func(c store.VulnCounts) int { return c.KEV }),
		card(tr(lang, "computer colpiti"), "", "/security/vulnerabilities?sort=hosts", now.Endpoints, func(c store.VulnCounts) int { return c.Endpoints }),
	}
	d.Charts = []lineChart{
		newLineChart(lang, tr(lang, "Vulnerabilità per gravità"), tr(lang, "CVE distinte che colpiscono almeno un computer, giorno per giorno"),
			days, func(c store.VulnCounts) store.SevCounts { return c.CVEs }),
		newLineChart(lang, tr(lang, "Esposizioni per gravità"), tr(lang, "Coppie CVE × computer: scendono quando gli aggiornamenti arrivano sui computer"),
			days, func(c store.VulnCounts) store.SevCounts { return c.Hits }),
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

// recordVulns writes the counts of the day after the CVEs were matched.
func (s *Server) recordVulns(tenant string, fs []vuln.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.PutVulnSnapshot(ctx, store.VulnSnapshot{TenantID: tenant, Day: s.now(), Counts: vulnCounts(fs)}); err != nil {
		s.log.Warn("vulnerability history", "tenant", tenant, "err", err)
	}
}
