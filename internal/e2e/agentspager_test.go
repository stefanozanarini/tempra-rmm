package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// The agents list comes a page at a time, keeps the selection across the
// pages and remembers the page size.
func TestAgentsListPages(t *testing.T) {
	e := startConsole(t) // its own agent is pending: listed apart
	var ids []string
	for i := range 55 {
		ids = append(ids, e.addWindowsAgent(t, fmt.Sprintf("PC-%02d", i)))
	}
	c, _ := e.login(t, admin)
	// The active agents' boxes, after the pending ones.
	boxes := func(body string) int {
		_, list, _ := strings.Cut(body, `class="agents-list"`)
		return strings.Count(list, `<input type="checkbox" name="agent"`)
	}
	hidden := func(body string) int { return strings.Count(body, `<input type="hidden" name="agent"`) }

	_, body := get(t, c, e.console.URL+"/agents")
	if boxes(body) != 50 || !strings.Contains(body, "1–50 di 55") || !strings.Contains(body, "seleziona tutti (55)") || !strings.Contains(body, `rel="next"`) {
		t.Fatalf("first page: %d boxes", boxes(body))
	}
	if _, body = get(t, c, e.console.URL+"/agents?page=2"); boxes(body) != 5 || !strings.Contains(body, "51–55 di 55") || !strings.Contains(body, `rel="prev"`) {
		t.Fatalf("second page: %d boxes", boxes(body))
	}
	_, onPage2, _ := strings.Cut(body, `class="agents-list"`)
	_, onPage2, _ = strings.Cut(onPage2, `<input type="checkbox" name="agent" value="`)
	onPage2, _, _ = strings.Cut(onPage2, `"`)
	// Select all: this page's boxes ticked, the other page's agents sent as hidden fields.
	if _, body = get(t, c, e.console.URL+"/agents?select=all"); hidden(body) != 5 || !strings.Contains(body, "page=2&amp;select=all") {
		t.Fatalf("select all: %d hidden", hidden(body))
	}
	// Boxes ticked by hand come along (sel=) to the other page.
	_, body = get(t, c, e.console.URL+"/agents?page=2&sel="+ids[0]+"&sel="+ids[54])
	if ticked := strings.Count(body, " checked aria-label"); hidden(body)+ticked != 2 || hidden(body) == 0 {
		t.Fatalf("selection carried: %d hidden, %d ticked", hidden(body), ticked)
	}
	// The agent open in the panel opens its page.
	if _, body = get(t, c, e.console.URL+"/agents?agent="+onPage2); !strings.Contains(body, "51–55 di 55") {
		i := strings.Index(body, " di 55")
		t.Fatalf("panel agent %s not on its page: %q", onPage2, body[max(i-20, 0):i+10])
	}
	// Page size: all, remembered.
	get(t, c, e.console.URL+"/agents?per=0")
	if _, body = get(t, c, e.console.URL+"/agents"); boxes(body) != 55 || strings.Contains(body, `rel="next"`) {
		t.Fatalf("all on one page: %d boxes", boxes(body))
	}
}
