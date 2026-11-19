package web

import (
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

func TestInventoryQuery(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	boot := now.AddDate(0, 0, -40)
	seen := now.AddDate(0, 0, -2)
	yes, no := true, false
	inv := &inventory.Inventory{
		System:   inventory.System{Manufacturer: "Dell Inc.", Model: "Latitude 5440", Serial: "ABC123", Chassis: "Notebook"},
		OS:       inventory.OS{Name: "Microsoft Windows 11 Pro", DisplayVersion: "24H2", Build: "26100.2605", Family: "client", LastBoot: &boot},
		Firmware: inventory.Firmware{Version: "1.18.0", SecureBoot: &yes, UEFI: &no},
		Memory:   inventory.Memory{TotalBytes: 8 << 30},
		TPM:      inventory.TPM{Present: true, Version: "2.0"},
		Volumes:  []inventory.Volume{{Mount: "C:", SizeBytes: 100 << 30, FreeBytes: 5 << 30, BitLocker: "off"}},
		Network:  []inventory.NIC{{MAC: "AA:BB", IPv4: []string{"10.1.2.3"}}},
		Software: []inventory.Software{
			{Name: "7-Zip 23.01 (x64)", Version: "23.01"},
			{Name: "Google Chrome", Version: "141.0.7390.55", Publisher: "Google LLC"},
		},
		Batteries: []inventory.Battery{{HealthPercent: 65}},
		Identity:  inventory.Identity{JoinType: "hybrid", TenantName: "Contoso", MDMServer: "enrollment.manage.microsoft.com"},
		Office:    inventory.Office{Version: "16.0.18129.20158", Channel: "Monthly Enterprise", Products: []string{"O365BusinessRetail"}, License: "subscription"},
		CloudAccounts: []inventory.CloudAccount{
			{User: `CONTOSO\jdoe`, Office: []inventory.OfficeAccount{{Account: "jdoe@contoso.com", Kind: "work"}},
				OneDrive: []inventory.OneDriveAccount{{Account: "jdoe@contoso.com", Kind: "work", KnownFolders: []string{"Desktop", "Documents"}}}},
			{User: `CONTOSO\guest`, Office: []inventory.OfficeAccount{{Account: "me@outlook.com", Kind: "personal"}}},
		},
	}
	a := store.Agent{ID: "a1", Status: store.AgentActive, LastSeenAt: &seen}
	a.Host.Hostname, a.Host.AgentVersion = "VWUKE135L", "1.1.2"
	row := &reportRow{Site: "London", User: "jdoe", OS: "Microsoft Windows 11 Pro 24H2 (26100.2605)"}
	c := &queryCtx{lang: "en", now: now, a: a, inv: inv, row: row}

	for q, want := range map[string]bool{
		`hostname:vwuke`:                true,
		`hostname:VWUK*`:                true,
		`hostname:VWUS*`:                false,
		`hostname=VWUKE135L`:            true,
		`hostname=VWUKE`:                false,
		`vwuke135l`:                     true,
		`10.1.2.3`:                      true,
		`model:Latitude ram_gb<16`:      true,
		`model:Latitude AND ram_gb>=16`: false,
		`(model:OptiPlex OR model:Latitude) AND tpm:yes`: true,
		`model:OptiPlex OR model:Latitude AND tpm:no`:    false,
		`NOT model:Latitude`:                             false,
		`-model:Latitude`:                                false,
		`! model:OptiPlex`:                               true,
		`software:7-Zip`:                                 true,
		`software:"7-Zip@24*"`:                           false,
		`software:"7-Zip" AND NOT software:"7-Zip@24*"`:  true,
		`software<"Google Chrome@142"`:                   true,
		`software>="Google Chrome@142"`:                  false,
		`software!="Trend Micro*"`:                       true,
		`NOT software:"Trend Micro*"`:                    true,
		`publisher:google`:                               true,
		`agent_version<1.1.3`:                            true,
		`agent_version>=1.1.3`:                           false,
		`last_seen<30d`:                                  false,
		`last_seen>30d`:                                  true,
		`last_seen:2026-11`:                              true,
		`last_boot<2026-10-10`:                           true,
		`uptime_days>30`:                                 true,
		`secure_boot:sì uefi:no`:                         true,
		`virtual:yes`:                                    false,
		`bitlocker!=on`:                                  true,
		`bitlocker=on`:                                   false,
		`free_gb<10 OR free_pct<10`:                      true,
		`battery<70`:                                     true,
		`teamviewer:*`:                                   false,
		`NOT teamviewer:*`:                               true,
		`serial:*`:                                       true,
		`site:"london" user:jdoe os_release=24h2`:        true,
		`status:active`:                                  true,
		`mac:aa:bb`:                                      true,
		`"latitude 5440"`:                                true,
		`"model:latitude"`:                               false,
		`entra_join:hybrid intune:yes mde:no`:            true,
		`entra_tenant:contoso`:                           true,
		`office_channel:"monthly*" office_license:subscription office_updates:yes`: true,
		`office_version<16.0.17000`:      false,
		`office_product:O365Business*`:   true,
		`cloud_account:jdoe@contoso.com`: true,
		`personal_account:yes`:           true,
		`onedrive_backup:yes`:            false,
	} {
		n, err := parseQuery(q, now)
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		if got := n.eval(c); got != want {
			t.Errorf("%s = %v, want %v", q, got, want)
		}
	}

	// Without inventory only the agent fields match.
	empty := &queryCtx{lang: "en", now: now, a: a, inv: &inventory.Inventory{}, row: &reportRow{}}
	if n, _ := parseQuery(`hostname:VWUKE AND NOT software:*`, now); !n.eval(empty) {
		t.Error("computer without inventory")
	}

	// The applications a software term matched are shown.
	n, _ := parseQuery(`software:chrome OR software:7-zip`, now)
	if terms := softwareTerms(n); len(terms) != 2 || len(terms[0].apps(c)) != 1 {
		t.Errorf("software terms: %d", len(terms))
	}

	for _, q := range []string{
		`unknown:1`, `ram_gb<lots`, `last_seen<yesterday`, `virtual:maybe`, `(model:x`, `model:x)`,
		`model:x AND`, `OR model:x`, `"unclosed`, `model:`, `software:@24`, `software>7-Zip`, `ram_gb>*`,
	} {
		if _, err := parseQuery(q, now); err == nil {
			t.Errorf("%s: accepted", q)
		} else if queryErrorText("en", err) == "" {
			t.Errorf("%s: no message", q)
		}
	}
	if n, err := parseQuery("  ", now); n != nil || err != nil {
		t.Errorf("empty query: %v %v", n, err)
	}
}

// The simple filters of Computer inventory become an advanced search that
// finds the same computers.
func TestFilterQuery(t *testing.T) {
	sites := []store.Site{{ID: "s1", Name: "London Office"}}
	for _, c := range []struct {
		software, version, os, user, model, site string
		want                                     string
	}{
		{software: "7-Zip", want: `software:7-Zip`},
		{software: "Google Chrome", version: "142.", want: `software:"Google Chrome@142."`},
		{version: "24.", want: `software:*@24.`},
		{software: "a@b", want: `software:a@b@`},
		{os: "Windows 11 23H2", user: "jdoe", model: "Dell Latitude", want: `os:"Windows 11 23H2" user:jdoe device:"Dell Latitude"`},
		{site: "s1", want: `site="London Office"`},
		{site: "none", want: `NOT site:*`},
		{site: "gone", want: ``},
		{model: `-x"y`, want: `device:"-xy"`},
	} {
		got := filterQuery(c.software, c.version, c.os, c.user, c.model, c.site, sites)
		if got != c.want {
			t.Errorf("filterQuery = %s, want %s", got, c.want)
			continue
		}
		if _, err := parseQuery(got, time.Now()); err != nil {
			t.Errorf("%s: %v", got, err)
		}
	}
	if got := andQuery("os:x", "a OR b"); got != "os:x AND (a OR b)" {
		t.Errorf("andQuery = %s", got)
	}
	for q, want := range map[string]string{
		`software:"7-Zip" ram_gb<16`:  "7-zip",
		`software:chrome OR os:linux`: "",
		`NOT software:chrome`:         "",
		`software:"chrome@142"`:       "",
		`software:chr*`:               "",
	} {
		n, _ := parseQuery(q, time.Now())
		if got := upgradeName(n); got != want {
			t.Errorf("upgradeName(%s) = %q, want %q", q, got, want)
		}
	}
}
