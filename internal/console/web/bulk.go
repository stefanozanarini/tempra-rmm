package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

type bulkData struct {
	Agents   []store.Agent
	Sites    []store.Site
	Commands []runnable
	Scripts  []runnable
	// Presets: the built-in script library, offered whenever Scripts is not
	// empty (the ad-hoc script module is available for every selected
	// agent's platform). They are PowerShell, so offered on Windows only.
	Presets  []scriptPreset
	Packages []store.Package
	// Preset: the action opened with its parameters filled in (?action=
	// module.action&p.<name>=…), and why (?for=, e.g. a CVE).
	Preset, For string
	// Files: a file session can be opened on the selected agents.
	Files bool
	// Group: the agents are those of a group (?group=); Groups: the
	// computer groups the agents can be added to.
	Group  *store.Group
	Groups []store.Group
	// Workflows: the distribution workflows; Workflow: the one preselected
	// (?workflow=).
	Workflows []store.Workflow
	Workflow  string
	// Profiles: the provisioning profiles with an approved version;
	// ProvisionServers: the selected servers (names joined by commas),
	// which provisioning refuses.
	Profiles         []store.Profile
	ProvisionServers string
	// Uninstall: an application can be removed from every selected agent
	// (software module published for their platforms); UninstallName and
	// UninstallVersion fill it in (?uninstall=&uninstall_version=).
	Uninstall                       bool
	UninstallName, UninstallVersion string
	// FeatureUpdate: the winupdate action that moves Windows clients to a
	// newer release, offered apart from the other commands (to
	// administrators); FeatureUpdateServers: the selected servers (names
	// joined by commas), which it refuses.
	FeatureUpdate        *runnable
	FeatureUpdateServers string
}

// selectedAgents returns the active agents listed in the "agent" values.
func (s *Server) selectedAgents(r *http.Request, t string, values []string) ([]store.Agent, string) {
	var out []store.Agent
	seen := map[string]bool{}
	for _, id := range values {
		if !ids.IsUUID(id) || seen[id] {
			continue
		}
		seen[id] = true
		a, err := s.store.GetAgent(r.Context(), t, id)
		if err != nil || a.Status != store.AgentActive {
			return nil, s.T(r, "Solo gli agenti approvati possono ricevere comandi.")
		}
		out = append(out, a)
	}
	if len(out) == 0 || len(out) > jobreq.MaxAgents {
		return nil, s.Tf(r, "Seleziona da 1 a %d agenti approvati.", jobreq.MaxAgents)
	}
	return out, ""
}

func (s *Server) handleBulkForm(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	values := r.URL.Query()["agent"]
	var group *store.Group
	if id := r.URL.Query().Get("group"); id != "" {
		g, err := s.findGroup(r, t, id)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		all, err := s.tenantAgents(r.Context(), t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		values, group = activeIDs(groupAgents(g, all)), &g
		if len(values) == 0 {
			s.flash(w, r, s.T(r, "Il gruppo non ha computer approvati."), "/groups/"+g.ID)
			return
		}
	}
	agents, msg := s.selectedAgents(r, t, values)
	if msg != "" {
		s.flash(w, r, msg, "/agents")
		return
	}
	sites, err := s.store.ListSites(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := bulkData{Agents: agents, Sites: sites, Group: group}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, g := range groups {
		if g.Kind == store.GroupComputer {
			d.Groups = append(d.Groups, g)
		}
	}
	if _, man, ok := s.fileModule(r); ok && s.shell != nil {
		d.Files = true
		for _, a := range agents {
			if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok || !filesAgent(a.Host.AgentVersion) {
				d.Files = false
			}
		}
	}
	if man, _, err := s.softwareModule(r.Context()); err == nil && onPlatforms(man, agents) {
		d.Uninstall = true
		d.UninstallName, d.UninstallVersion = r.URL.Query().Get("uninstall"), r.URL.Query().Get("uninstall_version")
	}
	// Actions available on every selected agent's platform.
	count := map[string]int{}
	byKey := map[string]runnable{}
	platforms := map[string]bool{}
	for _, a := range agents {
		p := a.Host.OS + "/" + a.Host.Arch
		if platforms[p] {
			continue
		}
		platforms[p] = true
		acts, err := s.runnableOn(r, a)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, x := range acts {
			k := x.Module + "|" + x.Version + "|" + x.Action
			count[k]++
			byKey[k] = x
		}
	}
	for k, n := range count {
		if n != len(platforms) {
			continue
		}
		if x := byKey[k]; x.AdHoc {
			d.Scripts = append(d.Scripts, x)
		} else {
			d.Commands = append(d.Commands, x)
		}
	}
	sortRunnables(d.Commands)
	sortRunnables(d.Scripts)
	if i := slices.IndexFunc(d.Commands, func(x runnable) bool { return clientOnly(x.Module, x.Action) }); i >= 0 {
		x := d.Commands[i]
		d.FeatureUpdate, d.FeatureUpdateServers = &x, strings.Join(serverNames(agents), ", ")
		d.Commands = slices.Delete(d.Commands, i, i+1)
		if err := s.suggestReleases(r, t, d.FeatureUpdate, agents); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(d.Scripts) > 0 {
		d.Presets = scriptPresets
	}
	q := r.URL.Query()
	if preset := q.Get("action"); preset != "" {
		for i := range d.Commands {
			c := &d.Commands[i]
			if c.Module+"."+c.Action != preset {
				continue
			}
			c.Open, d.Preset, d.For = true, preset, q.Get("for")
			for j := range c.Fields {
				if vals, ok := q["p."+c.Fields[j].Name]; ok {
					presetField(&c.Fields[j], vals)
				}
			}
		}
	}
	if d.Packages, err = s.store.ListPackages(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, _, err := s.publishedModule(r.Context(), workflow.ModuleID); err == nil {
		if d.Workflows, err = s.store.ListWorkflows(r.Context(), t); err != nil {
			s.fail(w, r, err)
			return
		}
		d.Workflow = q.Get("workflow")
	}
	if d.Profiles, err = s.approvedProfiles(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	d.ProvisionServers = strings.Join(serverNames(agents), ", ")
	title := s.Tf(r, "Azioni su %d agenti", len(agents))
	if group != nil {
		title = s.Tf(r, "Azioni sul gruppo %s (%d computer)", group.Name, len(agents))
	}
	s.render(w, r, "bulk", title, d)
}

func (s *Server) handleBulkJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	agents, msg := s.selectedAgents(r, t, r.PostForm["agent"])
	back := "/agents"
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	var targets []string
	for _, a := range agents {
		targets = append(targets, a.ID)
	}
	back = "/agents/bulk?" + url.Values{"agent": targets}.Encode()
	if id := r.PostFormValue("workflow"); id != "" {
		req, msg := s.workflowJob(r, t, id, targets)
		if msg != "" {
			s.flash(w, r, msg, back)
			return
		}
		s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
		return
	}
	if sha := r.PostFormValue("package"); sha != "" {
		if !shaHexRe.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/packages/"+sha+"/deploy?"+url.Values{"agent": targets}.Encode(), http.StatusSeeOther)
		return
	}
	if r.PostFormValue("uninstall") == "1" {
		man, mod, err := s.softwareModule(r.Context())
		if err != nil {
			s.flash(w, r, s.T(r, "Pubblica prima il modulo software."), back)
			return
		}
		if !onPlatforms(man, agents) {
			s.flash(w, r, s.T(r, "La disinstallazione è disponibile solo sui computer Windows: togli gli altri dalla selezione."), back)
			return
		}
		params, msg := s.uninstallParams(r)
		if msg != "" {
			s.flash(w, r, msg, back)
			return
		}
		s.startBulkJob(w, r, t, man, mod, "uninstall", params, targets, back)
		return
	}
	target := strings.Split(r.PostFormValue("target"), "|")
	if len(target) != 3 {
		s.flash(w, r, s.T(r, "Seleziona un'azione."), back)
		return
	}
	mod, err := s.store.GetModule(r.Context(), target[0], target[1])
	if err != nil {
		s.flash(w, r, s.T(r, "Modulo non trovato."), back)
		return
	}
	man, err := modules.ParseManifest(mod.Manifest)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Workflows run only from their own form, which validates them.
	if _, ok := man.Actions[target[2]]; !ok || man.Interactive() || man.ID == workflow.ModuleID {
		s.flash(w, r, s.T(r, "Azione non disponibile."), back)
		return
	}
	if names := serverNames(agents); clientOnly(man.ID, target[2]) && len(names) > 0 {
		s.flash(w, r, s.Tf(r, "L'aggiornamento della versione di Windows è solo per i client: togli i server dalla selezione (%s).", strings.Join(names, ", ")), back)
		return
	}
	params, msg := s.jobParams(r, mod, man, target[2])
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	if man.HasCapability(modules.CapAdHocScript) {
		script := r.PostFormValue("script")
		if strings.TrimSpace(script) == "" {
			s.flash(w, r, s.T(r, "Scrivi lo script da eseguire."), back)
			return
		}
		params["script"] = script
	}
	s.startBulkJob(w, r, t, man, mod, target[2], params, targets, back)
}

// startBulkJob starts the approval of one job of a module action on the
// targets.
func (s *Server) startBulkJob(w http.ResponseWriter, r *http.Request, t string, man *modules.Manifest, mod store.Module,
	action string, params map[string]any, targets []string, back string) {
	raw, err := json.Marshal(params)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req := &openrmmv1.JobRequest{TenantId: t, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
		Action: action, ParamsJson: raw, TtlSeconds: ttlFrom(r), RequestNonce: jobreq.NewRequestNonce()}
	if len(targets) == 1 {
		req.AgentId = targets[0]
	} else {
		req.AgentIds = targets
	}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

// onPlatforms tells whether a module runs on the platform of every agent.
func onPlatforms(man *modules.Manifest, agents []store.Agent) bool {
	for _, a := range agents {
		if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok {
			return false
		}
	}
	return true
}

// presetField fills a parameter field with values from the URL.
func presetField(f *paramField, vals []string) {
	switch f.Type {
	case modules.ParamMulti:
		for i := range f.Options {
			f.Options[i].Checked = slices.Contains(vals, f.Options[i].Value)
		}
	case modules.ParamList, modules.ParamText:
		f.Value = strings.Join(vals, "\n")
	case modules.ParamBool:
		f.Value = ""
		if len(vals) > 0 && vals[0] == "true" {
			f.Value = "true"
		}
	default:
		if len(vals) > 0 {
			f.Value = vals[0]
		}
		for i := range f.Options {
			f.Options[i].Checked = f.Options[i].Value == f.Value
		}
	}
}
