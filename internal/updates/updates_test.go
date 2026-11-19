package updates

import (
	"testing"
	"time"
)

func TestPatchTuesday(t *testing.T) {
	cases := map[time.Month]int{time.October: 14, time.November: 11, time.December: 9}
	for m, day := range cases {
		if got := PatchTuesday(2025, m); got.Day() != day || got.Weekday() != time.Tuesday {
			t.Errorf("%s 2025: %s", m, got)
		}
	}
	from := time.Date(2025, 9, 20, 0, 0, 0, 0, time.UTC)
	if n := PatchTuesdaysBetween(from, time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)); n != 2 {
		t.Fatalf("between = %d", n)
	}
}

func TestParseWindows(t *testing.T) {
	now := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	r, err := ParseWindows([]byte(`{"managed_by":"weird","scanned_at":"2030-01-01T00:00:00Z","updates":[
	 {"title":"Defender definitions","classification":"definition","kbs":["KB2267602"]},
	 {"title":"2025-10 Cumulative Update","classification":"security","kbs":["KB5066835","kb1; rm -rf"],"released":"2025-10-14T17:00:00Z"},
	 {"title":"","classification":"security"}],
	 "pending_reboot":{"required":true,"reasons":["windows_update"],"since":"2025-11-25T00:00:00Z"}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.ManagedBy != "none" || !r.ScannedAt.Equal(now) || len(r.Updates) != 2 || r.Updates[0].Classification != "security" ||
		len(r.Updates[0].KBs) != 1 {
		t.Fatalf("report = %+v", r)
	}
	s := r.Summarize(now)
	if s.Important != 1 || s.Other != 1 || s.OldestDays != 47 || s.Behind != 1 || !s.Reboot {
		t.Fatalf("summary = %+v", s)
	}
	if Score(s, 3, now) <= Score(Summary{}, 0, now) {
		t.Fatal("score")
	}
}

func TestParseWindowsRelease(t *testing.T) {
	r, err := ParseWindows([]byte(`{"managed_by":"none","updates":[],
	 "release":{"product":"Windows 11","display_version":"25H2","build":"26200.7171","installation_type":"Client"},
	 "feature_updates":[
	  {"title":"Feature update to Windows 11, version 26H2","version":"26h2","kbs":["KB5099999","bad"],"optional":true},
	  {"title":"Windows 11, version 25H2 enablement package","version":"25H2; evil"},
	  {"title":"","version":"27H1"}]}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Release == nil || r.Release.DisplayVersion != "25H2" || r.Release.Build != "26200.7171" {
		t.Fatalf("release = %+v", r.Release)
	}
	if len(r.FeatureUpdates) != 2 || r.FeatureUpdates[0].Version != "26H2" || !r.FeatureUpdates[0].Optional ||
		len(r.FeatureUpdates[0].KBs) != 1 || r.FeatureUpdates[1].Version != "" {
		t.Fatalf("feature updates = %+v", r.FeatureUpdates)
	}
	if got := r.NewerRelease(); got != "26H2" {
		t.Fatalf("newer = %q", got)
	}
	if SourceOf(WindowsModule, FeatureUpdateAction) != SourceWindows || SourceOf(OSUpdateModule, FeatureUpdateAction) != "" {
		t.Fatal("feature_update source")
	}
}

func TestParseWinget(t *testing.T) {
	r, err := ParseWinget([]byte(`{"upgrades":[{"name":"Zoom","id":"Zoom.Zoom","version":"5","available":"6"},{"name":"bad","id":"--force"}]}`), time.Now())
	if err != nil || len(r.Upgrades) != 1 || r.Upgrades[0].ID != "Zoom.Zoom" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestParseFirmware(t *testing.T) {
	now := time.Now()
	r, err := ParseFirmware([]byte(`{"vendor":"dell","supported":true,"tool":"Dell Command Update","updates":[
	 {"title":"Intel Wi-Fi Driver","category":"driver","severity":"recommended"},
	 {"title":"Dell BIOS Update","version":"1.21.0","category":"bios","severity":"critical"},
	 {"title":"Weird","category":"x","severity":"y"},
	 {"title":"","category":"driver"}]}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Updates) != 3 || r.Updates[0].Category != "bios" || r.Updates[2].Category != "other" || r.Updates[2].Severity != "optional" {
		t.Fatalf("updates = %+v", r.Updates)
	}
	critical, other, bios := r.Counts()
	if critical != 1 || other != 2 || !bios || r.ScannedAt.IsZero() {
		t.Fatalf("counts = %d %d %v", critical, other, bios)
	}
	if SourceOf("firmware", "install") != SourceFirmware || SourceOf("firmware", "install-tool") != SourceFirmware || SourceOf("firmware", "other") != "" {
		t.Fatal("SourceOf")
	}
}

func TestFirmwareVirtual(t *testing.T) {
	vm := `{"vendor":"dell","supported":false,"tool_missing":"Dell Command Update","updates":[],
		"components":[{"category":"bios","name":"BIOS","version":"VMW71.00V.11599183.B64.1901030933","provider":"VMware, Inc."}]}`
	dell := `{"vendor":"dell","supported":false,"tool_missing":"Dell Command Update","updates":[],
		"components":[{"category":"bios","name":"BIOS","version":"2.12.2","provider":"Dell Inc."}]}`
	for raw, want := range map[string]bool{vm: true, dell: false, `{"vendor":"virtual","updates":[]}`: true} {
		r, err := ParseFirmware([]byte(raw), time.Now())
		if err != nil || r.Virtual() != want {
			t.Errorf("%s: Virtual() = %v, %v", raw, r.Virtual(), err)
		}
	}
}
