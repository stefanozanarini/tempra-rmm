package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// The agents list narrows by state; the filter is kept by the other links.
func TestAgentsStateFilter(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	bad := e.addWindowsAgent(t, "PC-GUASTO")
	e.addWindowsAgent(t, "PC-SANO")
	e.store.PutCheck(ctx, store.Check{TenantID: e.tenant, AgentID: bad, CheckID: "protection-status/antivirus", Status: store.CheckFailing, UpdatedAt: time.Now()})
	c, _ := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/agents?show=critical")
	if !strings.Contains(body, "PC-GUASTO") || strings.Contains(body, "PC-SANO") {
		t.Fatalf("serious issues filter: %s", body)
	}
	if !strings.Contains(body, `href="/agents?family=client&amp;show=critical"`) || !strings.Contains(body, `<input type="hidden" name="show" value="critical">`) {
		t.Fatalf("filter not kept by the links: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents?show=offline"); !strings.Contains(body, "PC-GUASTO") || !strings.Contains(body, "PC-SANO") {
		t.Fatalf("offline filter: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents?show=online"); strings.Contains(body, "PC-GUASTO") || strings.Contains(body, "PC-SANO") {
		t.Fatalf("online filter: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/agents?show=bogus"); !strings.Contains(body, "PC-SANO") {
		t.Fatal("an unknown filter shows everything")
	}
}
