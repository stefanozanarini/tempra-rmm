package e2e

import (
	"context"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// Reports listing computers (computer and software inventory, CVE page,
// patches): the bulk actions open on the approved computers listed.
func TestConsoleReportBulk(t *testing.T) {
	e := startConsole(t)
	c, _ := e.login(t, admin)
	chrome := inventory.Software{Name: "Google Chrome", Publisher: "Google LLC", Version: "157.0.8103.79", Scope: "machine"}
	a := e.addWindowsAgent(t, "SRV-A", chrome)
	b := e.addWindowsAgent(t, "SRV-B", chrome)
	other := e.addWindowsAgent(t, "PC-OTHER", inventory.Software{Name: "7-Zip 24.09 (x64)", Version: "24.09", Scope: "machine"})

	bulkLink := regexp.MustCompile(`href="(/agents/bulk\?[^"#]*)">Azioni su questi computer…`)
	check := func(name, page string) {
		t.Helper()
		_, body := get(t, c, e.console.URL+page)
		m := bulkLink.FindStringSubmatch(html.UnescapeString(body))
		if m == nil {
			t.Fatalf("%s: no bulk actions: %s", name, body)
		}
		q, _ := url.ParseQuery(strings.TrimPrefix(m[1], "/agents/bulk?"))
		if got := strings.Join(q["agent"], ","); !strings.Contains(got, a) || !strings.Contains(got, b) || strings.Contains(got, other) {
			t.Fatalf("%s: agents %s", name, got)
		}
		if code, body := get(t, c, e.console.URL+m[1]); code != 200 || !strings.Contains(body, "SRV-A") || !strings.Contains(body, "SRV-B") {
			t.Fatalf("%s: bulk form %d: %s", name, code, body)
		}
	}
	check("computers", "/reports?tab=computers&software=Chrome")
	check("software", "/reports?tab=software&view=installs&q=Chrome")

	ctx := context.Background()
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "msrc/2026-Oct", Data: []byte(`[]`)})
	raw, _ := json.Marshal([]vuln.AppCVE{{ID: "CVE-2026-90009", Title: "test", CVSS: 9, Ranges: []vuln.VerRange{{EndExcl: "158.0.8127.36"}}}})
	e.store.PutVulnFeed(ctx, store.VulnFeed{Key: "nvd/google:chrome", Data: raw})
	check("CVE", "/security/vulnerabilities?id=CVE-2026-90009")

	for _, id := range []string{a, b} {
		e.store.PutUpdateStatus(ctx, store.UpdateStatus{TenantID: e.tenant, AgentID: id, Source: "winget", ScannedAt: time.Now(),
			Data: []byte(`{"upgrades":[{"name":"Google Chrome","id":"Google.Chrome","version":"157.0.8103.79","available":"158.0.8127.36"}]}`), ThirdParty: 1})
	}
	check("patches", "/patches?show=apps")

	// Without a filter the software inventory is every computer: no button.
	if _, body := get(t, c, e.console.URL+"/reports?tab=software&view=titles"); strings.Contains(body, "Azioni su questi computer") {
		t.Fatalf("bulk actions without a filter: %s", body)
	}
}
