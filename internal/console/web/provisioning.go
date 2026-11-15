package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/audit"
	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/profilereq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/provisioning"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

// Provisioning profiles (internal/provisioning): ordered steps run on a
// freshly installed computer. An administrator approves each version once
// with MFA; runs then go one step at a time, RunProvisioning dispatching the
// next step when the agent has reported the previous one, with jobs the
// signer issues on its own earlier approval (SignProfileRun).

const (
	// provisioningStepTTL bounds how long a step's job stays valid for a
	// computer that is off, capped by the approval's max ttl.
	provisioningStepTTL = 24 * time.Hour
	// provisioningRebootWait: how long after a reboot step the computer
	// may take to reconnect before the run fails.
	provisioningRebootWait = 2 * time.Hour
	// provisioningBlankRows: empty step rows offered by the editor.
	provisioningBlankRows = 3
)

// Run failure reasons stored in ProvisioningRun.Error that are not the
// error of a step's job (those are on the job itself).
const (
	runErrApproval  = "approval_expired"
	runErrProfile   = "invalid_profile"
	runErrAgent     = "agent_revoked"
	runErrReconnect = "no_reconnect"
	runErrSigner    = "signer_refused"
	runErrStep      = "step_failed"
)

var (
	runErrorLabels = map[string]string{
		runErrApproval:  "L'approvazione del profilo è scaduta: approvalo di nuovo e riprova.",
		runErrProfile:   "Il profilo non è valido.",
		runErrAgent:     "L'agente non è più attivo.",
		runErrReconnect: "Il computer non si è riconnesso dopo il riavvio.",
		runErrSigner:    "Il servizio di firma ha rifiutato il passo.",
		runErrStep:      "Un passo non è riuscito.",
	}
	runStateLabels = map[string]string{store.RunRunning: "in corso", store.RunSucceeded: "completato",
		store.RunFailed: "non riuscito", store.RunCanceled: "annullato"}
	provStepLabels = map[string]string{provisioning.StepWorkflow: "Workflow", provisioning.StepReboot: "Riavvio"}
)

// Outcome of a step of a run.
const (
	stepPending = "pending" // not dispatched yet
	stepRunning = "running"
	stepReboot  = "reboot" // rebooting: waiting for the agent to reconnect
	stepOK      = "ok"
	stepFailed  = "failed"
)

// stepOutcome tells where a dispatched step stands from its job and, for a
// reboot, from the agent's sessions.
func stepOutcome(st provisioning.Step, j store.Job, a store.Agent, now time.Time) string {
	switch {
	case j.State == store.JobSucceeded:
	case j.State.Final():
		return stepFailed
	case (j.State == store.JobQueued || j.State == store.JobSent) && now.After(j.ExpiresAt):
		// The agent never picked it up in time: it will not run.
		return stepFailed
	default:
		return stepRunning
	}
	if st.Type != provisioning.StepReboot {
		return stepOK
	}
	var res struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal(j.Result, &res)
	if res.Action == "skipped" {
		return stepOK
	}
	// A session that began after the result means the computer went down
	// and came back. If the result itself only arrived after the reboot
	// (through the agent's outbox), accept a session begun after the job
	// was queued once the computer has had time to reboot.
	if a.ConnectedAt != nil && j.FinishedAt != nil && a.ConnectedAt.After(*j.FinishedAt) {
		return stepOK
	}
	if j.FinishedAt != nil && now.Sub(*j.FinishedAt) > provisioningRebootWait {
		if a.ConnectedAt != nil && a.DisconnectedAt == nil && a.ConnectedAt.After(j.CreatedAt) {
			return stepOK
		}
		return stepFailed
	}
	return stepReboot
}

// RunProvisioning advances every run in progress. Called periodically
// from main, and right after a run starts or is retried.
func (s *Server) RunProvisioning(ctx context.Context) {
	if s.signer == nil {
		return
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Error("provisioning", "err", err)
		return
	}
	for _, t := range tenants {
		runs, err := s.store.ListRuns(ctx, t.ID)
		if err != nil {
			s.log.Error("provisioning", "tenant", t.ID, "err", err)
			continue
		}
		for _, run := range runs {
			if run.State == store.RunRunning {
				s.advanceRun(ctx, run)
			}
		}
	}
}

// advanceRun moves a run past its finished steps and dispatches the next
// one, or ends the run.
func (s *Server) advanceRun(ctx context.Context, run store.ProvisioningRun) {
	// One at a time, on a fresh copy: the scheduler and a start or retry
	// must not both dispatch the same step.
	s.provMu.Lock()
	defer s.provMu.Unlock()
	t := run.TenantID
	run, err := s.store.GetRun(ctx, t, run.ID)
	if err != nil || run.State != store.RunRunning {
		return
	}
	prof, err := s.store.GetProfile(ctx, t, run.ProfileID, run.Version)
	if err != nil {
		s.log.Error("provisioning run", "run", run.ID, "err", err)
		return
	}
	doc, err := provisioning.Parse(prof.Document)
	if err != nil || len(run.Jobs) != len(doc.Steps) {
		s.endRun(ctx, run, store.RunFailed, runErrProfile)
		return
	}
	ag, err := s.store.GetAgent(ctx, t, run.AgentID)
	if err != nil || ag.Status == store.AgentRevoked {
		s.endRun(ctx, run, store.RunFailed, runErrAgent)
		return
	}
	now := s.now()
	for run.Step < len(doc.Steps) {
		st := doc.Steps[run.Step]
		if run.Jobs[run.Step] == "" {
			if !prof.Approved(now) {
				s.endRun(ctx, run, store.RunFailed, runErrApproval)
				return
			}
			jobID, err := s.dispatchStep(ctx, prof, run)
			if err != nil {
				s.log.Warn("provisioning step not dispatched", "run", run.ID, "step", run.Step+1, "err", err)
				// Refusals are final; anything else is retried next time.
				if c := status.Code(err); c == codes.PermissionDenied || c == codes.InvalidArgument {
					s.endRun(ctx, run, store.RunFailed, runErrSigner)
				}
				return
			}
			run.Jobs[run.Step] = jobID
			if err := s.store.UpdateRun(ctx, run); err != nil {
				s.log.Error("provisioning run", "run", run.ID, "err", err)
			}
			return
		}
		j, err := s.store.GetJob(ctx, t, run.Jobs[run.Step])
		if err != nil {
			s.log.Error("provisioning run job", "run", run.ID, "job", run.Jobs[run.Step], "err", err)
			return
		}
		switch stepOutcome(st, j, ag, now) {
		case stepOK:
		case stepFailed:
			if !st.ContinueOnError {
				reason := runErrStep
				if st.Type == provisioning.StepReboot && j.State == store.JobSucceeded {
					reason = runErrReconnect
				}
				s.endRun(ctx, run, store.RunFailed, reason)
				return
			}
		default:
			return
		}
		run.Step++
	}
	s.endRun(ctx, run, store.RunSucceeded, "")
}

// endRun records the end of a run and audits it.
func (s *Server) endRun(ctx context.Context, run store.ProvisioningRun, state, reason string) {
	now := s.now()
	run.State, run.Error, run.FinishedAt = state, reason, &now
	if err := s.store.UpdateRun(ctx, run); err != nil {
		s.log.Error("provisioning run", "run", run.ID, "err", err)
		return
	}
	if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: run.TenantID, Actor: "console", Action: "provisioning.run." + state,
		Target: run.ID, OccurredAt: now, Details: map[string]any{"agent": run.AgentID, "profile": run.ProfileID,
			"version": run.Version, "step": run.Step + 1, "reason": reason}}); err != nil {
		s.log.Error("audit append failed", "err", err)
	}
}

// dispatchStep has the signer issue the job of the run's current step and
// queues it.
func (s *Server) dispatchStep(ctx context.Context, prof store.Profile, run store.ProvisioningRun) (string, error) {
	ttl := provisioningStepTTL
	if max := time.Duration(prof.MaxTTLSeconds) * time.Second; max < ttl {
		ttl = max
	}
	env, req := &openrmmv1.SignedEnvelope{}, &openrmmv1.ProfileRequest{}
	if err := proto.Unmarshal(prof.Envelope, env); err != nil {
		return "", err
	}
	// The console's own copy of what was approved, for the job record;
	// the signer re-verifies the envelope before issuing anything.
	if err := proto.Unmarshal(env.GetPayload(), req); err != nil {
		return "", err
	}
	if run.Step >= len(req.GetSteps()) {
		return "", status.Error(codes.InvalidArgument, "the approved profile has fewer steps")
	}
	st := req.GetSteps()[run.Step]
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignProfileRun(sctx, &openrmmv1.SignProfileRunRequest{ProfileEnvelope: prof.Envelope,
		Step: int32(run.Step), AgentIds: []string{run.AgentID}, TtlSeconds: int64(ttl / time.Second)}) // #nosec G115 -- bounded by MaxSteps
	if err != nil {
		return "", err
	}
	j := store.Job{TenantID: run.TenantID, ID: resp.GetJobId(), AgentID: run.AgentID, Module: st.GetModule(),
		ModuleVersion: st.GetModuleVersion(), Action: st.GetAction(), Params: st.GetParamsJson(), Envelope: resp.GetEnvelope(),
		CreatedBy: "automatic (provisioning)", ExpiresAt: time.Unix(resp.GetExpiresUnix(), 0)}
	if err := s.store.CreateJob(ctx, j); err != nil {
		return "", err
	}
	if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: run.TenantID, Actor: "console", Action: "job.created",
		Target: j.ID, OccurredAt: s.now(), Details: map[string]any{"agent": j.AgentID, "module": j.Module, "action": j.Action,
			"approved_by": resp.GetOperator(), "provisioning_run": run.ID, "step": run.Step + 1}}); err != nil {
		s.log.Error("audit append failed", "err", err)
	}
	return j.ID, nil
}

// approvedVersion returns the newest version of a profile with an approval
// valid now.
func (s *Server) approvedVersion(ctx context.Context, t, id string) (store.Profile, error) {
	versions, err := s.store.ProfileVersions(ctx, t, id)
	if err != nil {
		return store.Profile{}, err
	}
	now := s.now()
	for _, v := range versions {
		if v.ApprovedAt != nil && v.ExpiresAt != nil && now.Before(*v.ExpiresAt) {
			return s.store.GetProfile(ctx, t, id, v.Version)
		}
	}
	return store.Profile{}, store.ErrNotFound
}

// approvedProfiles returns the profiles that can be started now, with the
// version a run would use.
func (s *Server) approvedProfiles(ctx context.Context, t string) ([]store.Profile, error) {
	list, err := s.store.ListProfiles(ctx, t)
	if err != nil {
		return nil, err
	}
	var out []store.Profile
	for _, p := range list {
		v, err := s.approvedVersion(ctx, t, p.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ---- pages ----

type profileRow struct {
	store.Profile
	Steps int
	// Approved: the version runs would use, 0 if none.
	Approved int
	Counts   map[string]int
}

type profilesData struct {
	Rows []profileRow
}

// profileStepView is a step in the editor, with its workflow's name.
type profileStepView struct {
	provisioning.Step
	WorkflowName string
	// Latest: the workflow's newest revision, when newer than the pinned one.
	Latest int
}

type profileData struct {
	New      bool
	P        store.Profile
	Steps    []profileStepView
	Latest   int // newest version; P.Version may be an older one
	Versions []store.Profile
	// Approved: the version runs use (0: none), and when its approval ends.
	Approved        int
	ApprovedExpires *time.Time
	Workflows       []store.Workflow
	Runs            []runView
	Blank           []int
	StepTypes       []string
	Error           string
}

// runView is a run with its computer and profile names.
type runView struct {
	store.ProvisioningRun
	Hostname    string
	ProfileName string
	Steps       int
}

type runsData struct {
	Runs []runView
}

func (d runsData) refresh() int {
	for _, r := range d.Runs {
		if r.State == store.RunRunning {
			return 20
		}
	}
	return 0
}

type runStepView struct {
	provisioning.Step
	WorkflowName string
	Outcome      string
	Job          *store.Job
}

type runData struct {
	Run   runView
	Steps []runStepView
}

func (d runData) refresh() int {
	if d.Run.State == store.RunRunning {
		return 15
	}
	return 0
}

// runViews names the computers and profiles of runs.
func (s *Server) runViews(ctx context.Context, t string, runs []store.ProvisioningRun) ([]runView, error) {
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		return nil, err
	}
	hosts := map[string]string{}
	for _, a := range agents {
		hosts[a.ID] = a.Host.Hostname
	}
	profiles, err := s.store.ListProfiles(ctx, t)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, p := range profiles {
		names[p.ID] = p.Name
	}
	out := make([]runView, 0, len(runs))
	for _, r := range runs {
		out = append(out, runView{ProvisioningRun: r, Hostname: hosts[r.AgentID], ProfileName: names[r.ProfileID], Steps: len(r.Jobs)})
	}
	return out, nil
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	list, err := s.store.ListProfiles(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs, err := s.store.ListRuns(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	counts := map[string]map[string]int{}
	for _, run := range runs {
		if counts[run.ProfileID] == nil {
			counts[run.ProfileID] = map[string]int{}
		}
		counts[run.ProfileID][run.State]++
	}
	var d profilesData
	for _, p := range list {
		row := profileRow{Profile: p, Counts: counts[p.ID]}
		if doc, err := provisioning.Parse(p.Document); err == nil {
			row.Steps = len(doc.Steps)
		}
		if v, err := s.approvedVersion(r.Context(), t, p.ID); err == nil {
			row.Approved = v.Version
		}
		d.Rows = append(d.Rows, row)
	}
	s.render(w, r, "profiles", s.T(r, "Profili di provisioning"), d)
}

// profileForm fills the editor data common to a new and an existing
// profile.
func (s *Server) profileForm(r *http.Request, t string, d *profileData, doc provisioning.Document) error {
	var err error
	if d.Workflows, err = s.store.ListWorkflows(r.Context(), t); err != nil {
		return err
	}
	latest := map[string]store.Workflow{}
	for _, wf := range d.Workflows {
		latest[wf.ID] = wf
	}
	d.Steps = nil
	for _, st := range doc.Steps {
		v := profileStepView{Step: st}
		if wf, ok := latest[st.WorkflowID]; ok {
			v.WorkflowName = wf.Name
			if wf.Revision > st.Revision {
				v.Latest = wf.Revision
			}
		}
		d.Steps = append(d.Steps, v)
	}
	d.Blank = nil
	for i := 0; i < provisioningBlankRows; i++ {
		d.Blank = append(d.Blank, len(doc.Steps)+i)
	}
	d.StepTypes = provisioning.StepTypes
	return nil
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	d := profileData{}
	id := r.PathValue("id")
	if id == "" {
		d.New = true
		if err := s.profileForm(r, t, &d, provisioning.Document{}); err != nil {
			s.fail(w, r, err)
			return
		}
		s.render(w, r, "profile", s.T(r, "Nuovo profilo di provisioning"), d)
		return
	}
	if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	version, _ := strconv.Atoi(r.URL.Query().Get("v"))
	p, err := s.store.GetProfile(r.Context(), t, id, version)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.P = p
	var doc provisioning.Document
	if parsed, err := provisioning.Parse(p.Document); err == nil {
		doc = *parsed
	}
	if d.Versions, err = s.store.ProfileVersions(r.Context(), t, id); err != nil {
		s.fail(w, r, err)
		return
	}
	d.Latest = d.Versions[0].Version
	if v, err := s.approvedVersion(r.Context(), t, id); err == nil {
		d.Approved, d.ApprovedExpires = v.Version, v.ExpiresAt
	}
	runs, err := s.store.ListRuns(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var mine []store.ProvisioningRun
	for _, run := range runs {
		if run.ProfileID == id {
			mine = append(mine, run)
		}
	}
	if d.Runs, err = s.runViews(r.Context(), t, mine); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.profileForm(r, t, &d, doc); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "profile", p.Name, d)
}

var profileField = regexp.MustCompile(`^s\.(\d+)\.([a-z_]+)$`)

// parseProfileForm reads the editor: "s.N.<field>" for each step, ordered
// by "s.N.order" and then N. Rows without a type are blank and left out.
// Workflow steps are pinned to the revision in revisions (the newest).
func parseProfileForm(form map[string][]string, revisions map[string]int) provisioning.Document {
	steps := map[int]map[string]string{}
	for k, vs := range form {
		m := profileField.FindStringSubmatch(k)
		if m == nil || len(vs) == 0 {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if steps[n] == nil {
			steps[n] = map[string]string{}
		}
		steps[n][m[2]] = vs[0]
	}
	var order []int
	for n := range steps {
		order = append(order, n)
	}
	pos := func(n int) int {
		if p, err := strconv.Atoi(strings.TrimSpace(steps[n]["order"])); err == nil {
			return p
		}
		return n + 1
	}
	sort.Slice(order, func(i, j int) bool {
		if pi, pj := pos(order[i]), pos(order[j]); pi != pj {
			return pi < pj
		}
		return order[i] < order[j]
	})
	var d provisioning.Document
	for _, n := range order {
		f := steps[n]
		if f["type"] == "" {
			continue
		}
		st := provisioning.Step{Name: strings.TrimSpace(f["name"]), Type: f["type"], ContinueOnError: f["continue"] != ""}
		if st.Type == provisioning.StepWorkflow {
			st.WorkflowID = f["workflow"]
			st.Revision = revisions[st.WorkflowID]
		}
		d.Steps = append(d.Steps, st)
	}
	return d
}

// handleSaveProfile saves the editor as a new version, or deletes the
// profile.
func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	d := profileData{}
	id := r.PathValue("id")
	if id == "" {
		d.New, id = true, ids.NewUUID()
	} else if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	} else {
		cur, err := s.store.GetProfile(r.Context(), t, id, 0)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.P = cur
		if r.PostFormValue("delete") != "" {
			if err := s.store.DeleteProfile(r.Context(), t, id); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.fail(w, r, err)
				return
			}
			s.audit(r.Context(), t, op, "provisioning.profile.deleted", id, map[string]any{"name": cur.Name})
			s.flash(w, r, s.Tf(r, "Profilo %s eliminato.", cur.Name), "/provisioning")
			return
		}
	}
	workflows, err := s.store.ListWorkflows(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	revisions := map[string]int{}
	for _, wf := range workflows {
		revisions[wf.ID] = wf.Revision
	}
	d.P.ID = id
	d.P.Name = strings.TrimSpace(r.PostFormValue("name"))
	d.P.Description = strings.TrimSpace(r.PostFormValue("description"))
	d.P.Comment = strings.TrimSpace(r.PostFormValue("comment"))
	doc := parseProfileForm(r.PostForm, revisions)
	again := func(msg string) {
		if err := s.profileForm(r, t, &d, doc); err != nil {
			s.fail(w, r, err)
			return
		}
		if !d.New {
			d.Versions, _ = s.store.ProfileVersions(r.Context(), t, id)
			if len(d.Versions) > 0 {
				d.Latest = d.Versions[0].Version
				d.P.Version = d.Latest
			}
		}
		d.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		title := d.P.Name
		if d.New {
			title = s.T(r, "Nuovo profilo di provisioning")
		}
		s.render(w, r, "profile", title, d)
	}
	if name, ok := groupName(d.P.Name); !ok || len(d.P.Description) > 1000 || len(d.P.Comment) > 1000 {
		again(s.T(r, "Dai al profilo un nome (al massimo 64 caratteri)."))
		return
	} else {
		d.P.Name = name
	}
	if err := doc.Validate(); err != nil {
		again(s.Tf(r, "Profilo non valido: %v", err))
		return
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.store.SaveProfile(r.Context(), store.Profile{TenantID: t, ID: id, Name: d.P.Name, Description: d.P.Description,
		Document: raw, Comment: d.P.Comment, Author: op.Username})
	if errors.Is(err, store.ErrProfileExists) {
		again(s.T(r, "Esiste già un profilo con questo nome."))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "provisioning.profile.saved", id, map[string]any{"name": d.P.Name, "version": v,
		"comment": d.P.Comment, "profile": json.RawMessage(raw)})
	s.flash(w, r, s.Tf(r, "Profilo %s salvato: versione %d. Un amministratore deve approvarla prima di usarla.", d.P.Name, v),
		"/provisioning/profiles/"+id)
}

// buildProfileRequest assembles what an administrator approves: every step
// of a profile version pinned to a module version, parameters and
// packages, with the chosen validity and per-step ttl ceiling.
func (s *Server) buildProfileRequest(r *http.Request, p store.Profile, validityDays, maxTTLMinutes int) (*openrmmv1.ProfileRequest, string) {
	doc, err := provisioning.Parse(p.Document)
	if err != nil {
		return nil, s.Tf(r, "Profilo non valido: %v", err)
	}
	now := s.now()
	req := &openrmmv1.ProfileRequest{TenantId: p.TenantID, ProfileId: p.ID, Version: int32(p.Version), // #nosec G115 -- bounded version counter
		MaxTtlSeconds: int64(maxTTLMinutes) * 60, ExpiresUnix: now.Add(time.Duration(validityDays) * 24 * time.Hour).Unix(),
		RequestNonce: profilereq.NewRequestNonce()}
	for i, st := range doc.Steps {
		var step *openrmmv1.ProfileStep
		switch st.Type {
		case provisioning.StepWorkflow:
			wf, err := s.store.GetWorkflow(r.Context(), p.TenantID, st.WorkflowID, st.Revision)
			if err != nil {
				return nil, s.Tf(r, "Passo %d: workflow non trovato.", i+1)
			}
			man, mod, err := s.publishedModule(r.Context(), workflow.ModuleID)
			if err != nil {
				return nil, s.T(r, "Pubblica prima il modulo workflow dalla pagina Moduli.")
			}
			raw, refs, err := s.workflowParams(r.Context(), p.TenantID, wf)
			if err != nil {
				return nil, s.workflowParamsMessage(r, err)
			}
			step = &openrmmv1.ProfileStep{Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
				Action: workflow.Action, ParamsJson: raw, Packages: refs}
		case provisioning.StepReboot:
			man, mod, err := s.publishedModule(r.Context(), provisioning.RebootModule)
			if err != nil {
				return nil, s.T(r, "Pubblica prima il modulo reboot dalla pagina Moduli.")
			}
			step = &openrmmv1.ProfileStep{Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256,
				Action: provisioning.RebootAction, ParamsJson: provisioning.RebootParams}
		}
		req.Steps = append(req.Steps, step)
	}
	if err := profilereq.Validate(req, now); err != nil {
		return nil, s.Tf(r, "Profilo non valido: %v", err)
	}
	return req, ""
}

// handleApproveProfile starts the MFA approval of the latest version of a
// profile.
func (s *Server) handleApproveProfile(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/provisioning/profiles/" + id
	days, _ := strconv.Atoi(r.PostFormValue("validity_days"))
	valid := false
	for _, v := range assignmentValidities {
		valid = valid || v.Days == days
	}
	if !valid {
		s.flash(w, r, s.T(r, "Scegli per quanto resta valida l'approvazione."), back)
		return
	}
	ttlMin, err := strconv.Atoi(r.PostFormValue("ttl_minutes"))
	if err != nil || ttlMin < 5 || ttlMin > 48*60 {
		ttlMin = int(provisioningStepTTL / time.Minute)
	}
	p, err := s.store.GetProfile(r.Context(), t, id, 0)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if v, _ := strconv.Atoi(r.PostFormValue("version")); v != p.Version {
		s.flash(w, r, s.T(r, "Il profilo è cambiato nel frattempo: controlla l'ultima versione e approvala."), back)
		return
	}
	req, msg := s.buildProfileRequest(r, p, days, ttlMin)
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	raw, err := proto.Marshal(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sess := sessionFrom(r.Context())
	pd := &Pending{Purpose: "profile", State: ids.NewSecret(24), Nonce: profilereq.AuthNonce(req),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), ProfileReq: raw, Return: back}
	sess.data.Pending = pd
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectStepUp(w, r, sess, pd)
}

// completeProfile finishes the MFA approval and stores the signed profile.
func (s *Server) completeProfile(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, rawToken string) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil {
		http.Error(w, tr(lang, "sessione scaduta"), http.StatusUnauthorized)
		return
	}
	if c.ObjectID != op.ObjectID || c.TenantID != op.TenantID {
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	req := &openrmmv1.ProfileRequest{}
	if err := proto.Unmarshal(p.ProfileReq, req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !profilereq.CheckAuthNonce(c.Nonce, req) {
		http.Error(w, tr(lang, "approvazione non valida per questo profilo"), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignProfile(ctx, &openrmmv1.SignProfileRequest{Request: req, IdToken: rawToken})
	if err != nil {
		s.audit(r.Context(), req.GetTenantId(), op, "provisioning.profile.refused", req.GetProfileId(), map[string]any{"reason": err.Error()})
		s.flashTo(w, r, sess, trf(lang, "Il servizio di firma ha rifiutato il profilo: %v", err), p.Return)
		return
	}
	now, expires := s.now(), time.Unix(req.GetExpiresUnix(), 0)
	a := store.Profile{TenantID: req.GetTenantId(), ID: req.GetProfileId(), Version: int(req.GetVersion()), Envelope: resp.GetEnvelope(),
		MaxTTLSeconds: int(req.GetMaxTtlSeconds()), ApprovedBy: "operator:" + op.Username, ApprovedAt: &now, ExpiresAt: &expires}
	if err := s.store.ApproveProfile(r.Context(), a); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), req.GetTenantId(), op, "provisioning.profile.approved", a.ID, map[string]any{
		"version": a.Version, "steps": len(req.GetSteps()), "expires_at": expires, "approved_by": resp.GetOperator()})
	s.flashTo(w, r, sess, trf(lang, "Versione %d approvata: utilizzabile fino al %s.", a.Version, expires.Format(dateFormat(lang))), p.Return)
}

// handleStartProvisioning starts the newest approved version of a profile
// on the selected computers.
func (s *Server) handleStartProvisioning(w http.ResponseWriter, r *http.Request) {
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
	if msg == "" && len(agents) > profilereq.MaxAgents {
		msg = s.Tf(r, "Seleziona da 1 a %d agenti approvati.", profilereq.MaxAgents)
	}
	if msg != "" {
		s.flash(w, r, msg, "/agents")
		return
	}
	id := r.PostFormValue("profile")
	if !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	p, err := s.approvedVersion(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) {
		s.flash(w, r, s.T(r, "Il profilo non ha una versione approvata."), "/provisioning/profiles/"+id)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doc, err := provisioning.Parse(p.Document)
	if err != nil {
		s.flash(w, r, s.Tf(r, "Profilo non valido: %v", err), "/provisioning/profiles/"+id)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	var started []store.ProvisioningRun
	var busy []string
	for _, a := range agents {
		run := store.ProvisioningRun{TenantID: t, ID: ids.NewUUID(), ProfileID: p.ID, Version: p.Version, AgentID: a.ID,
			State: store.RunRunning, Jobs: make([]string, len(doc.Steps)), CreatedBy: "operator:" + op.Username}
		err := s.store.CreateRun(r.Context(), run)
		if errors.Is(err, store.ErrRunActive) {
			busy = append(busy, a.Host.Hostname)
			continue
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "provisioning.run.started", run.ID, map[string]any{"agent": a.ID, "profile": p.ID, "version": p.Version})
		started = append(started, run)
	}
	for _, run := range started {
		s.advanceRun(r.Context(), run)
	}
	msg = s.Tf(r, "Provisioning avviato su %d computer.", len(started))
	if len(busy) > 0 {
		msg += " " + s.Tf(r, "Già in corso su: %s.", strings.Join(busy, ", "))
	}
	s.flash(w, r, msg, "/provisioning/runs")
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	runs, err := s.store.ListRuns(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	views, err := s.runViews(r.Context(), t, runs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "provruns", s.T(r, "Esecuzioni di provisioning"), runsData{Runs: views})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	run, err := s.findRun(r, t)
	if err != nil {
		s.notFoundOr(w, r, err)
		return
	}
	views, err := s.runViews(r.Context(), t, []store.ProvisioningRun{run})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := runData{Run: views[0]}
	p, err := s.store.GetProfile(r.Context(), t, run.ProfileID, run.Version)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doc, err := provisioning.Parse(p.Document)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ag, _ := s.store.GetAgent(r.Context(), t, run.AgentID)
	workflows, err := s.store.ListWorkflows(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	wfNames := map[string]string{}
	for _, wf := range workflows {
		wfNames[wf.ID] = wf.Name
	}
	now := s.now()
	for i, st := range doc.Steps {
		v := runStepView{Step: st, WorkflowName: wfNames[st.WorkflowID], Outcome: stepPending}
		if i < len(run.Jobs) && run.Jobs[i] != "" {
			if j, err := s.store.GetJob(r.Context(), t, run.Jobs[i]); err == nil {
				v.Job, v.Outcome = &j, stepOutcome(st, j, ag, now)
				// The step that stopped a failed run is not waiting any more.
				if v.Outcome != stepOK && run.State == store.RunFailed && i == run.Step {
					v.Outcome = stepFailed
				}
			}
		}
		d.Steps = append(d.Steps, v)
	}
	s.render(w, r, "provrun", s.Tf(r, "Provisioning di %s", d.Run.Hostname), d)
}

// handleRunAction retries a failed run from the step that stopped it, or
// cancels a run in progress. Neither needs a new approval: they only decide
// whether the console uses the profile's existing one.
func (s *Server) handleRunAction(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	run, err := s.findRun(r, t)
	if err != nil {
		s.notFoundOr(w, r, err)
		return
	}
	back := "/provisioning/runs/" + run.ID
	op := sessionFrom(r.Context()).data.Operator
	switch r.PostFormValue("do") {
	case "retry":
		if run.State != store.RunFailed || run.Step >= len(run.Jobs) {
			s.flash(w, r, s.T(r, "Si può riprovare solo un provisioning non riuscito."), back)
			return
		}
		run.State, run.Error, run.FinishedAt, run.Jobs[run.Step] = store.RunRunning, "", nil, ""
		if err := s.store.UpdateRun(r.Context(), run); errors.Is(err, store.ErrRunActive) {
			s.flash(w, r, s.T(r, "Sul computer è già in corso un altro provisioning."), back)
			return
		} else if err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "provisioning.run.retried", run.ID, map[string]any{"step": run.Step + 1})
		s.advanceRun(r.Context(), run)
		s.flash(w, r, s.Tf(r, "Provisioning ripreso dal passo %d.", run.Step+1), back)
	case "cancel":
		if run.State != store.RunRunning {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		now := s.now()
		run.State, run.FinishedAt = store.RunCanceled, &now
		if err := s.store.UpdateRun(r.Context(), run); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "provisioning.run.canceled", run.ID, map[string]any{"step": run.Step + 1})
		s.flash(w, r, s.T(r, "Provisioning annullato: il passo già inviato al computer, se in corso, termina comunque."), back)
	default:
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
	}
}

func (s *Server) findRun(r *http.Request, t string) (store.ProvisioningRun, error) {
	id := r.PathValue("id")
	if !ids.IsUUID(id) {
		return store.ProvisioningRun{}, store.ErrNotFound
	}
	return s.store.GetRun(r.Context(), t, id)
}

func (s *Server) notFoundOr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	s.fail(w, r, err)
}
