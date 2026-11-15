package e2e

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// An operator of servers only (OpenRMM.Operator.Servers): the console
// refuses clients, the job carries the limit, and the signer refuses a
// request without it.
func TestServerOperator(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	e.store.ApproveAgent(ctx, e.tenant, e.agentID, "t", time.Now())
	op := opIdentity{OID: ids.NewUUID(), Name: "Anna Verdi", Username: "anna@cliente.it",
		Roles: []string{authn.AppOperatorServers}, AMR: []string{"pwd", "mfa"}}
	c, csrf := e.login(t, op)
	run := url.Values{"csrf": {csrf}, "target": {"sysinfo|1.0.0|info"}, "ttl_minutes": {"60"}}

	// pc01 is a client.
	e.store.UpdateAgentSeen(ctx, e.tenant, e.agentID, &store.HostInfo{Hostname: "pc01", OS: "linux", Arch: "amd64",
		OSFamily: "client", AgentVersion: "1.1.8"}, time.Now(), nil)
	if _, body, _ := post(t, c, e.console.URL+"/agents/"+e.agentID+"/jobs", run); !strings.Contains(html.UnescapeString(body), "non comprende") {
		t.Fatalf("job on a client accepted: %s", body)
	}
	// A server, but an agent too old to enforce the limit.
	e.store.UpdateAgentSeen(ctx, e.tenant, e.agentID, &store.HostInfo{Hostname: "pc01", OS: "linux", Arch: "amd64",
		OSFamily: "server", AgentVersion: "1.1.7"}, time.Now(), nil)
	if _, body, _ := post(t, c, e.console.URL+"/agents/"+e.agentID+"/jobs", run); !strings.Contains(html.UnescapeString(body), "non comprende") {
		t.Fatalf("job on an old agent accepted: %s", body)
	}
	// A recent server: the job carries the limit.
	e.store.UpdateAgentSeen(ctx, e.tenant, e.agentID, &store.HostInfo{Hostname: "pc01", OS: "linux", Arch: "amd64",
		OSFamily: "server", AgentVersion: "1.1.8"}, time.Now(), nil)
	if code, body, _ := post(t, c, e.console.URL+"/agents/"+e.agentID+"/jobs", run); code != 200 {
		t.Fatalf("job on a server: %d %s", code, body)
	}
	env := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(lastJob(t, e.store, e.tenant, e.agentID).Envelope, env)
	job := &openrmmv1.Job{}
	if err := proto.Unmarshal(env.GetPayload(), job); err != nil || job.GetOsFamily() != "server" {
		t.Fatalf("signed job os family = %q %v", job.GetOsFamily(), err)
	}

	// The signer reads the role from the token: a request for any family,
	// or for clients, is refused.
	for _, fam := range []string{"", "client"} {
		req := &openrmmv1.JobRequest{TenantId: e.tenant, AgentId: e.agentID, Module: e.module.Manifest.ID,
			ModuleVersion: e.module.Manifest.Version, ModuleSha256: e.module.ManifestHash, Action: "info", ParamsJson: []byte("{}"),
			TtlSeconds: 600, RequestNonce: jobreq.NewRequestNonce(), OsFamily: fam}
		if _, err := e.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req, IdToken: e.tokenFor(t, op, jobreq.AuthNonce(req))}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("request for %q: %v", fam, err)
		}
	}
	// Settings are for OpenRMM.Admin.
	if code, _ := get(t, c, e.console.URL+"/settings"); code != http.StatusForbidden {
		t.Fatalf("settings: %d", code)
	}
}

// A scope set on the console for an Entra group limits its members to the
// computers of a group, and only OpenRMM.Admin changes that group.
func TestScopeByEntraGroup(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	e.store.ApproveAgent(ctx, e.tenant, e.agentID, "t", time.Now())
	grp := store.Group{TenantID: e.tenant, ID: ids.NewUUID(), Name: "Contabilità", Kind: store.GroupComputer, CreatedBy: "t"}
	if err := e.store.PutGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	entraGroup := ids.NewUUID()

	// The admin sets the scope on the Scopes page.
	ac, acsrf := e.login(t, admin)
	if code, body, _ := post(t, ac, e.console.URL+"/scopes", url.Values{"csrf": {acsrf}, "subject": {entraGroup},
		"name": {"IT contabilità"}, "group": {grp.ID}}); code != 200 || !strings.Contains(html.UnescapeString(body), "salvato") {
		t.Fatalf("save scope: %d %s", code, body)
	}

	adm := opIdentity{OID: ids.NewUUID(), Name: "Luigi", Username: "luigi@cliente.it", Roles: []string{authn.AppAdminClients, authn.AppAdminServers},
		Groups: []string{entraGroup}, AMR: []string{"pwd", "mfa"}}
	c, csrf := e.login(t, adm)
	if code, _ := get(t, c, e.console.URL+"/scopes"); code != http.StatusForbidden {
		t.Fatalf("scopes page for a scoped admin: %d", code)
	}
	revoke := e.console.URL + "/agents/" + e.agentID + "/revoke"
	if _, body, _ := post(t, c, revoke, url.Values{"csrf": {csrf}}); !strings.Contains(html.UnescapeString(body), "non comprende") {
		t.Fatalf("revoked a computer outside the group: %s", body)
	}
	if _, body, _ := post(t, c, e.console.URL+"/groups/agents", url.Values{"csrf": {csrf}, "group": {grp.ID},
		"agent": {e.agentID}}); !strings.Contains(html.UnescapeString(body), "OpenRMM.Admin") {
		t.Fatalf("group changed by its administrator: %s", body)
	}
	e.store.AddGroupMembers(ctx, e.tenant, grp.ID, []string{e.agentID})
	if code, _, _ := post(t, c, revoke, url.Values{"csrf": {csrf}}); code != 200 {
		t.Fatalf("revoke in the group: %d", code)
	}
	if a, _ := e.store.GetAgent(ctx, e.tenant, e.agentID); a.Status != store.AgentRevoked {
		t.Fatalf("agent status = %s", a.Status)
	}
}
