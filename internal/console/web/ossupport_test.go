package web

import "testing"

func TestSupportEnd(t *testing.T) {
	for _, c := range []struct {
		name, build string
		server      bool
		label, end  string
	}{
		{"Microsoft Windows 11 Pro", "26100.2605", false, "Windows 11 24H2", "2026-10-13"},
		{"Microsoft Windows 11 Enterprise", "26100.2605", false, "Windows 11 24H2", "2027-10-12"},
		{"Microsoft Windows 11 Education", "22631.4460", false, "Windows 11 23H2", "2026-11-10"},
		{"Microsoft Windows 11 Enterprise LTSC", "26100.1", false, "Windows 11 LTSC 2024", "2029-10-09"},
		{"Microsoft Windows 10 Pro", "19045.5011", false, "Windows 10 22H2", "2025-10-14"},
		{"Microsoft Windows 10 Enterprise LTSC 2019", "17763.1", false, "Windows 10 LTSC 2019", "2029-01-09"},
		{"Microsoft Windows 10 Pro", "17763.1", false, "Windows 10/8.1/7 (build 17763)", "2022-06-13"},
		{"Microsoft Windows Server 2019 Standard", "17763.6414", true, "Windows Server 2019", "2029-01-09"},
		{"Microsoft Windows Server 2012 R2 Standard", "9600", true, "Windows Server 2012 R2", "2023-10-10"},
	} {
		label, end, ok := supportEnd(c.name, c.build, c.server)
		if !ok || label != c.label || end.Format("2006-01-02") != c.end {
			t.Errorf("%s %s: %q %s %v", c.name, c.build, label, end.Format("2006-01-02"), ok)
		}
	}
	// A release not listed yet (preview builds) is unknown.
	if _, _, ok := supportEnd("Microsoft Windows 11 Pro", "26300.9974", false); ok {
		t.Error("26300 known")
	}
	if _, _, ok := supportEnd("", "", false); ok {
		t.Error("no build known")
	}
}
