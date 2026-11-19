package inventory

import (
	"os"
	"strings"
	"testing"
	"time"
)

const sample = `{"schema":1,"collected_at":"2026-10-19T10:00:00Z",
 "system":{"manufacturer":"Dell Inc.","model":"Latitude 5440","serial":"ABC123\u0007","unknown_field":1},
 "os":{"name":"Windows 11 Pro","build":"26100","family":"client"},
 "firmware":{"version":"1.10.0","secure_boot":true},
 "memory":{"total_bytes":17179869184},
 "disks":[{"model":"PM9A1","serial":"S1","health":"Healthy","size_bytes":512110190592}],
 "volumes":[{"mount":"C:","bitlocker":"on"}],
 "software":[{"name":"Zeta"},{"name":"7-Zip","version":"23.01","scope":"machine","arch":"x64"},{"name":""},
   {"name":"Visual C++ Runtime","system_component":true}],
 "remote_access":{"supremo_id":"123 456 789","anydesk_id":"12","teamviewer_id":"987654321"}}`

func TestParseNormalizes(t *testing.T) {
	inv, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if inv.System.Serial != "ABC123" {
		t.Fatalf("control characters kept: %q", inv.System.Serial)
	}
	if inv.RemoteAccess.SupremoID != "123456789" || inv.RemoteAccess.AnyDeskID != "" || inv.RemoteAccess.TeamViewerID != "987654321" {
		t.Fatalf("remote ids = %+v", inv.RemoteAccess)
	}
	if len(inv.Software) != 3 || inv.Software[0].Name != "7-Zip" || inv.Software[2].Name != "Zeta" {
		t.Fatalf("software = %+v", inv.Software)
	}
	if len(inv.VisibleSoftware()) != 2 {
		t.Fatal("system components not hidden")
	}
}

func TestParseRejects(t *testing.T) {
	for _, raw := range []string{`{"schema":2,"collected_at":"2026-10-19T10:00:00Z"}`, `{"schema":1}`, `[]`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestClipLongStrings(t *testing.T) {
	s := clip(strings.Repeat("è", 400))
	if len(s) > maxString || !strings.HasPrefix(s, "è") {
		t.Fatalf("len %d", len(s))
	}
}

func TestDiff(t *testing.T) {
	a, _ := Parse([]byte(sample))
	b, _ := Parse([]byte(sample))
	if d := Diff(a, b); len(d) != 0 {
		t.Fatalf("identical inventories differ: %+v", d)
	}
	if Diff(nil, b) != nil {
		t.Fatal("first inventory produced changes")
	}
	b.Software = append(b.Software[:0:0], b.Software...)
	b.Software[0].Version = "24.08"                        // 7-Zip updated
	b.Software = append(b.Software[:1], b.Software[2:]...) // Visual C++ removed
	b.Software = append(b.Software, Software{Name: "Firefox", Version: "131"})
	b.Memory.TotalBytes *= 2
	b.Disks = []Disk{{Model: "PM9A1", Serial: "S1", Health: "Warning"}}
	b.Volumes = []Volume{{Mount: "C:", BitLocker: "off"}}
	b.RemoteAccess.SupremoID = ""
	a.Identity.JoinType, b.Identity.JoinType = "hybrid", "entra"
	kinds := map[string]int{}
	for _, c := range Diff(a, b) {
		kinds[c.Kind]++
	}
	for _, k := range []string{ChangeSoftwareAdded, ChangeSoftwareRemoved, ChangeSoftwareUpdated, ChangeHardware,
		ChangeDiskHealth, ChangeEncryption, ChangeRemoteAccess, ChangeIdentity} {
		if kinds[k] != 1 {
			t.Errorf("%s: %d changes", k, kinds[k])
		}
	}
}

func TestBytes(t *testing.T) {
	if got := Bytes(17179869184); got != "16.0 GiB" {
		t.Fatal(got)
	}
}

// testdata/windows.json is the output of Main.ps1 run with simulated WMI
// classes (registry sections filled in by hand).
func TestParseWindowsModuleOutput(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows.json")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if inv.System.Model != "ThinkPad T14 Gen 3" || inv.OS.Family != "client" || inv.Memory.TotalBytes != 16<<30 ||
		len(inv.Volumes) != 1 || inv.Volumes[0].BitLocker != "on" || inv.Firmware.SecureBoot == nil || !*inv.Firmware.SecureBoot ||
		inv.RemoteAccess.SupremoID != "123456789" || len(inv.Software) != 3 || inv.Batteries[0].HealthPercent != 85 ||
		inv.OS.LastBoot == nil || !inv.Identity.Entra() || !inv.Identity.Intune() || !inv.Identity.MDEOnboarded ||
		inv.Office.Channel != "Monthly Enterprise" || inv.Office.License != "subscription" ||
		len(inv.CloudAccounts) != 1 || len(inv.CloudAccounts[0].Office) != 2 || inv.CloudAccounts[0].OneDrive[0].KnownFolders[1] != "Documents" {
		t.Fatalf("parsed = %+v", inv)
	}
}

func TestCarryOver(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	old := &Inventory{CollectedAt: t0,
		NetworkShares: []NetworkShare{{User: `CORP\anna`, Drive: "S:"}, {User: `CORP\bob`, Drive: "T:"}},
		CloudAccounts: []CloudAccount{{User: `CORP\anna`}, {User: `CORP\carl`, SeenAt: ptr(t0.Add(-100 * 24 * time.Hour))}}}
	cur := &Inventory{CollectedAt: t0.Add(24 * time.Hour), LoadedUsers: []string{`corp\BOB`},
		CloudAccounts: []CloudAccount{{User: `CORP\bob`, SeenAt: ptr(t0)}}}
	CarryOver(old, cur)
	// anna is carried with the old collection time; bob is logged on and
	// has no share now; carl was last seen too long ago.
	if len(cur.NetworkShares) != 1 || cur.NetworkShares[0].Drive != "S:" || !cur.NetworkShares[0].SeenAt.Equal(t0) {
		t.Fatalf("shares = %+v", cur.NetworkShares)
	}
	if len(cur.CloudAccounts) != 2 || cur.CloudAccounts[0].SeenAt != nil || cur.CloudAccounts[1].User != `CORP\anna` {
		t.Fatalf("accounts = %+v", cur.CloudAccounts)
	}
	// Carried again, the first time it was seen is kept.
	next := &Inventory{CollectedAt: t0.Add(48 * time.Hour), LoadedUsers: []string{}}
	CarryOver(cur, next)
	if len(next.NetworkShares) != 1 || !next.NetworkShares[0].SeenAt.Equal(t0) || len(next.CloudAccounts) != 2 {
		t.Fatalf("second carry = %+v %+v", next.NetworkShares, next.CloudAccounts)
	}
	// Without the list of loaded users nothing is carried.
	none := &Inventory{CollectedAt: t0.Add(48 * time.Hour)}
	if CarryOver(cur, none); len(none.NetworkShares) != 0 {
		t.Fatal("carried without loaded users")
	}
}

func ptr[T any](v T) *T { return &v }
