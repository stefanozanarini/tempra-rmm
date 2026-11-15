package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

// latestJob returns the newest job of an agent.
func (e *consoleEnv) latestJob(t *testing.T, agent string) store.Job {
	t.Helper()
	jobs, err := e.store.ListJobs(context.Background(), e.tenant, agent, 1)
	if err != nil || len(jobs) == 0 {
		t.Fatalf("jobs of %s: %v, %v", agent, jobs, err)
	}
	return jobs[0]
}

func TestProvisioningProfile(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "workflow"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "reboot"))
	c, csrf := e.login(t, admin)

	file := []byte("an antivirus installer")
	upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"csrf", csrf}, {"name", "AV"}, {"version", "1"}, {"kind", "msi"}}, file)
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])
	e.store.SetPackageUnsigned(ctx, e.tenant, sha, true)
	wfID := e.createTestWorkflow(t, c, csrf, sha)

	// Workflow, reboot, workflow again; a blank row is left out, and the
	// order field decides the sequence.
	code, body, at := post(t, c, e.console.URL+"/provisioning/profiles/new", url.Values{"csrf": {csrf}, "name": {"PC ufficio"},
		"s.0.order": {"3"}, "s.0.type": {"workflow"}, "s.0.workflow": {wfID}, "s.0.name": {"Again"},
		"s.1.order": {"1"}, "s.1.type": {"workflow"}, "s.1.workflow": {wfID},
		"s.2.order": {"2"}, "s.2.type": {"reboot"},
		"s.3.order": {"4"}, "s.3.type": {""}})
	profileID := strings.TrimPrefix(at.Path, "/provisioning/profiles/")
	if code != 200 || profileID == at.Path || !ids.IsUUID(profileID) {
		t.Fatalf("create profile: %d at %s: %s", code, at, body)
	}
	p, err := e.store.GetProfile(ctx, e.tenant, profileID, 0)
	if err != nil || p.Version != 1 || len(p.Envelope) != 0 {
		t.Fatalf("profile = %+v, %v", p, err)
	}
	if !strings.Contains(string(p.Document), `"name":"Again"`) || !strings.HasPrefix(string(p.Document), `{"steps":[{"type":"workflow"`) {
		t.Fatalf("document = %s", p.Document)
	}

	agent := e.addWindowsAgent(t, "PC-01")
	// Not approved yet: it cannot start.
	post(t, c, e.console.URL+"/provisioning/start", url.Values{"csrf": {csrf}, "profile": {profileID}, "agent": {agent}, "confirm": {"1"}})
	if runs, _ := e.store.ListRuns(ctx, e.tenant); len(runs) != 0 {
		t.Fatalf("started an unapproved profile: %+v", runs)
	}

	// Only an administrator may approve it.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, _, _ := post(t, oc, e.console.URL+"/provisioning/profiles/"+profileID+"/approve",
		url.Values{"csrf": {ocsrf}, "version": {"1"}, "validity_days": {"90"}, "ttl_minutes": {"1440"}}); code != http.StatusForbidden {
		t.Fatalf("operator approved a profile: %d", code)
	}
	e.idp.signIn(admin)
	code, body, _ = post(t, c, e.console.URL+"/provisioning/profiles/"+profileID+"/approve",
		url.Values{"csrf": {csrf}, "version": {"1"}, "validity_days": {"90"}, "ttl_minutes": {"1440"}})
	if code != 200 || !strings.Contains(body, "Versione 1 approvata") {
		t.Fatalf("approve: %d %s", code, body)
	}
	e.idp.mu.Lock()
	nonce := e.idp.lastAuth.Get("nonce")
	e.idp.mu.Unlock()
	if !strings.HasPrefix(nonce, "profile.") {
		t.Fatalf("approval nonce = %q", nonce)
	}

	// Servers are refused, and so is a start without the confirmation
	// that the computer is freshly installed.
	e.idp.signIn(op)
	server := ids.NewUUID()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: server, Status: store.AgentActive, CertFingerprint: server,
		Host: store.HostInfo{Hostname: "SRV-01", OS: "windows", Arch: "amd64", OSFamily: "server"}, CertNotAfter: time.Now().Add(time.Hour)})
	_, body, _ = post(t, oc, e.console.URL+"/provisioning/start", url.Values{"csrf": {ocsrf}, "profile": {profileID},
		"agent": {agent, server}, "confirm": {"1"}})
	if !strings.Contains(body, "togli i server dalla selezione (SRV-01)") {
		t.Fatalf("server not refused: %s", body)
	}
	if _, body := get(t, oc, e.console.URL+"/agents/bulk?agent="+server); strings.Contains(body, `name="confirm"`) {
		t.Fatal("start form offered for a server")
	}
	_, body, _ = post(t, oc, e.console.URL+"/provisioning/start", url.Values{"csrf": {ocsrf}, "profile": {profileID}, "agent": {agent}})
	if !strings.Contains(body, "Conferma che i computer sono appena installati") {
		t.Fatalf("started without confirmation: %s", body)
	}
	if runs, _ := e.store.ListRuns(ctx, e.tenant); len(runs) != 0 {
		t.Fatalf("runs after refusals = %+v", runs)
	}

	// An operator starts it: the first step is dispatched at once.
	code, body, _ = post(t, oc, e.console.URL+"/provisioning/start", url.Values{"csrf": {ocsrf}, "profile": {profileID}, "agent": {agent}, "confirm": {"1"}})
	if code != 200 || !strings.Contains(body, "Provisioning avviato su 1 computer") {
		t.Fatalf("start: %d %s", code, body)
	}
	runs, _ := e.store.ListRuns(ctx, e.tenant)
	if len(runs) != 1 || runs[0].State != store.RunRunning || runs[0].Step != 0 {
		t.Fatalf("runs = %+v", runs)
	}
	runID := runs[0].ID
	j := e.latestJob(t, agent)
	var params workflow.Params
	if j.Module != "workflow" || json.Unmarshal(j.Params, &params) != nil || params.WorkflowID != wfID || params.Revision != 1 {
		t.Fatalf("first job = %+v", j)
	}
	// Starting again while it runs is refused.
	post(t, oc, e.console.URL+"/provisioning/start", url.Values{"csrf": {ocsrf}, "profile": {profileID}, "agent": {agent}, "confirm": {"1"}})
	if runs, _ = e.store.ListRuns(ctx, e.tenant); len(runs) != 1 {
		t.Fatalf("second run on a busy computer: %d", len(runs))
	}

	// Nothing more while the step runs.
	e.web.RunProvisioning(ctx)
	if jobs, _ := e.store.ListJobs(ctx, e.tenant, agent, 10); len(jobs) != 1 {
		t.Fatalf("dispatched ahead: %d jobs", len(jobs))
	}

	// Step 1 succeeds: the reboot goes out.
	e.store.UpdateJob(ctx, e.tenant, agent, j.ID, store.JobUpdate{State: store.JobSucceeded, Result: []byte(`{"verified":true}`)}, time.Now())
	e.web.RunProvisioning(ctx)
	reboot := e.latestJob(t, agent)
	if reboot.Module != "reboot" || !strings.Contains(string(reboot.Params), `"only_if_pending":false`) {
		t.Fatalf("second job = %+v", reboot)
	}

	// The reboot is scheduled: the run waits for the agent to come back.
	e.store.UpdateJob(ctx, e.tenant, agent, reboot.ID, store.JobUpdate{State: store.JobSucceeded,
		Result: []byte(`{"action":"scheduled","delay_seconds":60}`)}, time.Now())
	e.web.RunProvisioning(ctx)
	if got := e.latestJob(t, agent); got.ID != reboot.ID {
		t.Fatalf("dispatched before the reboot: %+v", got)
	}
	_, body = get(t, oc, e.console.URL+"/provisioning/runs/"+runID)
	if !strings.Contains(body, "in attesa che l&#39;agente si riconnetta") {
		t.Fatalf("run page while rebooting: %s", body)
	}
	host := store.HostInfo{Hostname: "PC-01", OS: "windows", Arch: "amd64", OSFamily: "client"}
	e.store.UpdateAgentSeen(ctx, e.tenant, agent, &host, time.Now().Add(time.Second), nil)
	e.web.RunProvisioning(ctx)
	third := e.latestJob(t, agent)
	if third.Module != "workflow" || third.ID == j.ID {
		t.Fatalf("third job = %+v", third)
	}

	// The last step fails: the run stops, then a retry resumes it there.
	e.store.UpdateJob(ctx, e.tenant, agent, third.ID, store.JobUpdate{State: store.JobFailed, Error: "exit code 1603"}, time.Now())
	e.web.RunProvisioning(ctx)
	run, _ := e.store.GetRun(ctx, e.tenant, runID)
	if run.State != store.RunFailed || run.Step != 2 || run.FinishedAt == nil {
		t.Fatalf("run after failure = %+v", run)
	}
	_, body, _ = post(t, oc, e.console.URL+"/provisioning/runs/"+runID, url.Values{"csrf": {ocsrf}, "do": {"retry"}})
	if !strings.Contains(body, "Provisioning ripreso dal passo 3") {
		t.Fatalf("retry: %s", body)
	}
	retried := e.latestJob(t, agent)
	if retried.ID == third.ID || retried.Module != "workflow" {
		t.Fatalf("retry job = %+v", retried)
	}
	e.store.UpdateJob(ctx, e.tenant, agent, retried.ID, store.JobUpdate{State: store.JobSucceeded, Result: []byte(`{"compliant":true}`)}, time.Now())
	e.web.RunProvisioning(ctx)
	if run, _ = e.store.GetRun(ctx, e.tenant, runID); run.State != store.RunSucceeded || run.Step != 3 {
		t.Fatalf("run at the end = %+v", run)
	}

	// The pages render.
	for _, u := range []string{"/provisioning", "/provisioning/profiles/" + profileID, "/provisioning/runs", "/provisioning/runs/" + runID,
		"/agents/bulk?agent=" + agent} {
		if code, body := get(t, oc, e.console.URL+u); code != 200 || !strings.Contains(body, "PC ufficio") {
			t.Fatalf("%s: %d %s", u, code, body)
		}
	}
}

func TestProvisioningNewVersionNeedsApproval(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "reboot"))
	c, csrf := e.login(t, admin)
	_, _, at := post(t, c, e.console.URL+"/provisioning/profiles/new", url.Values{"csrf": {csrf}, "name": {"Solo riavvio"}, "s.0.type": {"reboot"}})
	id := strings.TrimPrefix(at.Path, "/provisioning/profiles/")
	post(t, c, e.console.URL+"/provisioning/profiles/"+id+"/approve", url.Values{"csrf": {csrf}, "version": {"1"}, "validity_days": {"30"}, "ttl_minutes": {"60"}})

	// Version 2 is saved but not approved: runs keep using version 1.
	post(t, c, e.console.URL+"/provisioning/profiles/"+id, url.Values{"csrf": {csrf}, "name": {"Solo riavvio"}, "s.0.type": {"reboot"}, "s.0.name": {"Riavvio"}})
	// Approving a version other than the latest is refused.
	_, body, _ := post(t, c, e.console.URL+"/provisioning/profiles/"+id+"/approve", url.Values{"csrf": {csrf}, "version": {"1"}, "validity_days": {"30"}, "ttl_minutes": {"60"}})
	if !strings.Contains(body, "Il profilo è cambiato nel frattempo") {
		t.Fatalf("approved a stale version: %s", body)
	}
	agent := e.addWindowsAgent(t, "PC-01")
	post(t, c, e.console.URL+"/provisioning/start", url.Values{"csrf": {csrf}, "profile": {id}, "agent": {agent}, "confirm": {"1"}})
	runs, _ := e.store.ListRuns(ctx, e.tenant)
	if len(runs) != 1 || runs[0].Version != 1 {
		t.Fatalf("runs = %+v", runs)
	}
	// The approval is checked again before each step is issued: once it
	// has expired, the next step is never dispatched (and the signer
	// would refuse it on its own, see TestSignProfileRunRefuses).
	p, _ := e.store.GetProfile(ctx, e.tenant, id, 1)
	past := time.Now().Add(-time.Hour)
	p.ExpiresAt = &past
	e.store.ApproveProfile(ctx, p)
	run := runs[0]
	run.Jobs[0] = ""
	e.store.UpdateRun(ctx, run)
	e.web.RunProvisioning(ctx)
	if run, _ = e.store.GetRun(ctx, e.tenant, run.ID); run.State != store.RunFailed || run.Error != "approval_expired" {
		t.Fatalf("run with an expired approval = %+v", run)
	}
}
