package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
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
