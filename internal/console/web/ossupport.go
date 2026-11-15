package web

import (
	"strconv"
	"strings"
	"time"
)

// End of support of the Windows releases, from Microsoft's lifecycle pages
// (without paid Extended Security Updates). Home and Pro editions end
// before Enterprise and Education; LTSC/LTSB and Server have their own
// dates. A build missing here is reported as unknown.

type osLifecycle struct {
	Build   int
	Server  bool
	Edition string // pro (also Home), ent (Enterprise, Education), ltsc; "" any
	Label   string
	End     string // YYYY-MM-DD
}

var osLifecycles = []osLifecycle{
	// Windows 11.
	{26200, false, "pro", "Windows 11 25H2", "2027-10-12"},
	{26200, false, "ent", "Windows 11 25H2", "2028-10-10"},
	{26100, false, "pro", "Windows 11 24H2", "2026-10-13"},
	{26100, false, "ent", "Windows 11 24H2", "2027-10-12"},
	{26100, false, "ltsc", "Windows 11 LTSC 2024", "2029-10-09"},
	{22631, false, "pro", "Windows 11 23H2", "2025-11-11"},
	{22631, false, "ent", "Windows 11 23H2", "2026-11-10"},
	{22621, false, "pro", "Windows 11 22H2", "2024-10-08"},
	{22621, false, "ent", "Windows 11 22H2", "2025-10-14"},
	{22000, false, "pro", "Windows 11 21H2", "2023-10-10"},
	{22000, false, "ent", "Windows 11 21H2", "2024-10-08"},
	// Windows 10.
	{19045, false, "", "Windows 10 22H2", "2025-10-14"},
	{19044, false, "ltsc", "Windows 10 LTSC 2021", "2027-01-12"},
	{19044, false, "pro", "Windows 10 21H2", "2022-06-13"},
	{19044, false, "ent", "Windows 10 21H2", "2023-06-13"},
	{17763, false, "ltsc", "Windows 10 LTSC 2019", "2029-01-09"},
	{14393, false, "ltsc", "Windows 10 LTSB 2016", "2026-10-13"},
	{10240, false, "ltsc", "Windows 10 LTSB 2015", "2025-10-14"},
	// Windows Server.
	{26100, true, "", "Windows Server 2025", "2034-10-10"},
	{20348, true, "", "Windows Server 2022", "2031-10-14"},
	{17763, true, "", "Windows Server 2019", "2029-01-09"},
	{14393, true, "", "Windows Server 2016", "2027-01-12"},
	{9600, true, "", "Windows Server 2012 R2", "2023-10-10"},
	{9200, true, "", "Windows Server 2012", "2023-10-10"},
	{7601, true, "", "Windows Server 2008 R2", "2020-01-14"},
}

func windowsEdition(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "ltsc"), strings.Contains(n, "ltsb"):
		return "ltsc"
	case strings.Contains(n, "enterprise"), strings.Contains(n, "education"):
		return "ent"
	}
	return "pro"
}

// supportEnd returns the release and the end of support of a Windows
// build ("26100.2605" or "26100"), or ok false when unknown.
func supportEnd(name, build string, server bool) (label string, end time.Time, ok bool) {
	b, err := strconv.Atoi(strings.SplitN(strings.TrimSpace(build), ".", 2)[0])
	if err != nil || b == 0 {
		return "", time.Time{}, false
	}
	ed := windowsEdition(name)
	for _, l := range osLifecycles {
		if l.Build == b && l.Server == server && (l.Edition == ed || l.Edition == "") {
			end, _ = time.Parse("2006-01-02", l.End)
			return l.Label, end, true
		}
	}
	// Other Windows 10 releases (e.g. 1809 Pro on an LTSC build) and older
	// Windows are long out of support.
	if !server && b >= 7600 && b < 22000 {
		return "Windows 10/8.1/7 (build " + strconv.Itoa(b) + ")", time.Date(2022, 6, 13, 0, 0, 0, 0, time.UTC), true
	}
	return "", time.Time{}, false
}
