package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// MSP mode unlocks the "Clienti" (customers) page, where a console
// administrator creates tenants without the offline CLI; it stays 404 off.
func TestConsoleCustomersMSPMode(t *testing.T) {
	e := startConsole(t)
	c, csrf := e.login(t, admin)

	if code, _ := get(t, c, e.console.URL+"/customers"); code != http.StatusNotFound {
		t.Fatalf("customers page before MSP mode: %d", code)
	}

	_, body, _ := post(t, c, e.console.URL+"/setup/msp-mode", url.Values{"csrf": {csrf}, "on": {"1"}})
	if !strings.Contains(body, "Impostazione salvata") {
		t.Fatalf("msp-mode on: %s", body)
	}
	if cs, err := e.store.GetConsoleSettings(context.Background()); err != nil || !cs.MSPMode {
		t.Fatalf("console settings = %+v, %v", cs, err)
	}

	code, body := get(t, c, e.console.URL+"/customers")
	if code != http.StatusOK || !strings.Contains(body, "Clienti") {
		t.Fatalf("customers page: %d %s", code, body)
	}

	_, body, _ = post(t, c, e.console.URL+"/customers", url.Values{"csrf": {csrf}, "name": {"Cliente Nuovo"}})
	if !strings.Contains(body, "Cliente Nuovo") || !strings.Contains(body, "OPENRMM_TENANT_MAP") {
		t.Fatalf("create customer: %s", body)
	}
	tenants, err := e.store.ListTenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tn := range tenants {
		found = found || tn.Name == "Cliente Nuovo"
	}
	if !found {
		t.Fatalf("tenant not created: %+v", tenants)
	}

	// An invalid name is refused, and MSP mode turned back off hides the page again.
	if _, body, _ = post(t, c, e.console.URL+"/customers", url.Values{"csrf": {csrf}, "name": {""}}); !strings.Contains(body, "Nome non valido") {
		t.Fatalf("invalid name accepted: %s", body)
	}
	post(t, c, e.console.URL+"/setup/msp-mode", url.Values{"csrf": {csrf}}) // "on" omitted: off
	if code, _ := get(t, c, e.console.URL+"/customers"); code != http.StatusNotFound {
		t.Fatalf("customers page after MSP mode off: %d", code)
	}
}

// With the directory mapped to every tenant, a customer created in the
// console is at once in the selector of an operator already signed in, and
// the signer approves commands for it.
func TestCustomerOnAllTenantsMap(t *testing.T) {
	e := startConsoleMapped(t, true)
	ctx := context.Background()
	c, csrf := e.login(t, admin)
	post(t, c, e.console.URL+"/setup/msp-mode", url.Values{"csrf": {csrf}, "on": {"1"}})
	_, body, _ := post(t, c, e.console.URL+"/customers", url.Values{"csrf": {csrf}, "name": {"Cliente Nuovo"}})
	if !strings.Contains(body, "è già nel selettore dei tenant") {
		t.Fatalf("create customer: %s", body)
	}
	var id string
	tenants, _ := e.store.ListTenants(ctx)
	for _, tn := range tenants {
		if tn.Name == "Cliente Nuovo" {
			id = tn.ID
		}
	}
	if _, body = get(t, c, e.console.URL+"/agents"); !strings.Contains(body, `<option value="`+id+`"`) {
		t.Fatalf("new customer not in the selector: %s", body)
	}
	if code, body, _ := post(t, c, e.console.URL+"/tenant", url.Values{"csrf": {csrf}, "tenant": {id}}); code != 200 {
		t.Fatalf("switch to the new customer: %d %s", code, body)
	}

	// A command on an agent of the new customer is signed.
	pc := ids.NewUUID()
	e.store.CreateAgent(ctx, store.Agent{TenantID: id, ID: pc, Status: store.AgentActive,
		Host:            store.HostInfo{Hostname: "nuovo01", OS: "linux", Arch: "amd64"},
		CertFingerprint: "fp2", CertNotAfter: time.Now().Add(time.Hour)})
	_, body, _ = post(t, c, e.console.URL+"/agents/bulk", url.Values{"csrf": {csrf}, "agent": {pc},
		"target": {"sysinfo|" + e.module.Manifest.Version + "|info"}, "ttl_minutes": {"60"}})
	if !strings.Contains(body, "riquadro in basso a destra") {
		t.Fatalf("job on the new customer: %s", body)
	}
	if j := lastJob(t, e.store, id, pc); j.Module != "sysinfo" {
		t.Fatalf("job = %+v", j)
	}
}
