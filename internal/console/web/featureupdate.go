package web

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/updates"
)

// featureUpdateSince is the first winupdate version with feature_update.
const featureUpdateSince = "1.5.0"

// clientOnly tells whether a module action is for Windows clients only.
func clientOnly(module, action string) bool {
	return module == updates.WindowsModule && action == updates.FeatureUpdateAction
}

// releaseOffer is a Windows release offered by Windows Update to some of
// the agents, according to their latest scan.
type releaseOffer struct {
	Version string
	Agents  int
}

// offeredReleases returns the releases offered to the agents by a feature
// update, newest first, and how many agents have a Windows Update report.
func (s *Server) offeredReleases(r *http.Request, t string, agents []store.Agent) ([]releaseOffer, int, error) {
	want := map[string]bool{}
	for _, a := range agents {
		want[a.ID] = true
	}
	agentID := ""
	if len(agents) == 1 {
		agentID = agents[0].ID
	}
	list, err := s.store.ListUpdateStatus(r.Context(), t, agentID)
	if err != nil {
		return nil, 0, err
	}
	count := map[string]int{}
	scanned := 0
	for _, st := range list {
		if st.Source != updates.SourceWindows || !want[st.AgentID] {
			continue
		}
		var rep updates.WindowsReport
		if json.Unmarshal(st.Data, &rep) != nil {
			continue
		}
		scanned++
		seen := map[string]bool{}
		for _, f := range rep.FeatureUpdates {
			if f.Version != "" && !seen[f.Version] {
				seen[f.Version] = true
				count[f.Version]++
			}
		}
	}
	var out []releaseOffer
	for v, n := range count {
		out = append(out, releaseOffer{Version: v, Agents: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, scanned, nil
}

// suggestReleases fills the target field of the feature_update form with
// the releases offered to the agents, the newest preselected.
func (s *Server) suggestReleases(r *http.Request, t string, x *runnable, agents []store.Agent) error {
	offers, scanned, err := s.offeredReleases(r, t, agents)
	if err != nil {
		return err
	}
	lang := s.lang(r)
	for i := range x.Fields {
		f := &x.Fields[i]
		if f.Name != "target" {
			continue
		}
		f.Suggest = nil
		for _, o := range offers {
			f.Suggest = append(f.Suggest, paramOption{Value: o.Version, Label: trf(lang, "offerta a %d PC su %d", o.Agents, len(agents))})
		}
		switch {
		case len(offers) > 0:
			if f.Value == "" {
				f.Value = offers[0].Version
			}
			f.Note = tr(lang, "Versioni offerte da Windows Update all'ultima scansione:")
		case scanned == 0:
			f.Note = tr(lang, "Nessuna scansione di Windows Update ancora: le versioni offerte non sono note.")
		default:
			f.Note = tr(lang, "All'ultima scansione Windows Update non offriva versioni più recenti a questi PC.")
		}
	}
	return nil
}
