package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// Access is an operator's role on one tenant: the levels of the Entra app
// roles on client and server computers (which the signer and the agents
// enforce too), narrowed by the scopes set on the console (sites and
// computer groups, which only the console enforces).
type Access struct {
	authn.Access
	// SiteIDs and GroupIDs limit the operator to the computers of some
	// sites or groups (empty: no limit). Not for superadministrators.
	SiteIDs, GroupIDs []string
}

// atLeast reports whether the operator has role on some computers.
func (a Access) atLeast(role string) bool { return authn.RoleAtLeast(a.Role(), role) }

// Scoped reports whether the access is limited to some computers.
func (a Access) Scoped() bool {
	return a.Clients != a.Servers || len(a.SiteIDs) > 0 || len(a.GroupIDs) > 0
}

// verifierOf returns the directory an operator comes from.
func (s *Server) verifierOf(op *Operator) *authn.Verifier {
	if op.Federated && s.fedVerifier != nil {
		return s.fedVerifier
	}
	return s.verifier
}

// operatorTenants returns the tenants an operator may manage: those mapped
// to the operator's directory, or every tenant of the console when it is
// mapped to all of them (customers created later included).
func (s *Server) operatorTenants(ctx context.Context, op *Operator) ([]string, error) {
	v := s.verifierOf(op)
	if v == nil {
		return nil, nil
	}
	ts := v.Config().TenantMap[op.TenantID]
	if !slices.Contains(ts, authn.AllTenants) {
		return ts, nil
	}
	all, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(all))
	for _, t := range all {
		out = append(out, t.ID)
	}
	return out, nil
}

// accessOf returns an operator's role on tenant: from the app roles of the
// sign-in, with the scopes of the operator and of the operator's groups.
func (s *Server) accessOf(ctx context.Context, op *Operator, tenant string) (Access, error) {
	if op == nil || tenant == "" {
		return Access{}, nil
	}
	v := s.verifierOf(op)
	if v == nil || !v.Allows(op.TenantID, tenant) {
		return Access{}, nil
	}
	a := Access{Access: v.AccessOf(op.Roles)}
	if a.Super() || a.Role() == "" {
		return a, nil
	}
	scopes, err := s.store.ListScopes(ctx, tenant)
	if err != nil {
		return Access{}, err
	}
	for _, sc := range scopes {
		if sc.SubjectOID != op.ObjectID && !slices.Contains(op.Groups, sc.SubjectOID) {
			continue
		}
		for _, id := range sc.SiteIDs {
			if !slices.Contains(a.SiteIDs, id) {
				a.SiteIDs = append(a.SiteIDs, id)
			}
		}
		for _, id := range sc.GroupIDs {
			if !slices.Contains(a.GroupIDs, id) {
				a.GroupIDs = append(a.GroupIDs, id)
			}
		}
	}
	return a, nil
}

// access returns the session operator's role on the session's tenant,
// looked up once per request (a scope changed meanwhile takes effect at
// once).
func (s *Server) access(ctx context.Context, sess *session) Access {
	if sess.access == nil {
		a, err := s.accessOf(ctx, sess.data.Operator, sess.data.Tenant)
		if err != nil {
			s.log.Error("scope lookup failed", "err", err)
		}
		sess.access = &a
	}
	return *sess.access
}

// minScopedAgent is the first agent version that refuses a job limited to
// another OS family: older agents may receive jobs only from operators
// whose role covers both clients and servers.
const minScopedAgent = "1.1.8"

// errOutOfScope reports agents an operator may not act on.
type errOutOfScope struct{ hosts []string }

func (e errOutOfScope) Error() string { return fmt.Sprintf("out of scope: %v", e.hosts) }

// checkScope requires min on every agent: from the app roles on the
// agent's OS family (and an agent recent enough to enforce a role limited
// to one family), within the sites or groups of the operator's scope.
func (s *Server) checkScope(r *http.Request, t string, a Access, min string, agentIDs []string) error {
	in, err := s.scope(r, t, a, min)
	if err != nil {
		return err
	}
	var out []string
	for _, id := range agentIDs {
		if !ids.IsUUID(id) {
			continue // the caller ignores it
		}
		ag, err := s.store.GetAgent(r.Context(), t, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if !in(ag) {
			name := ag.Host.Hostname
			if name == "" {
				name = ag.ID
			}
			out = append(out, name)
		}
	}
	if len(out) > 0 {
		return errOutOfScope{out}
	}
	return nil
}

// scope returns a test of whether the operator has min on an agent.
func (s *Server) scope(r *http.Request, t string, a Access, min string) (func(store.Agent) bool, error) {
	if a.Super() {
		return func(store.Agent) bool { return true }, nil
	}
	ctx := r.Context()
	var sites siteMatcher
	var sums map[string]store.InventorySummary
	if len(a.SiteIDs) > 0 {
		list, err := s.store.ListSites(ctx, t)
		if err != nil {
			return nil, err
		}
		manual, err := s.store.AgentSites(ctx, t)
		if err != nil {
			return nil, err
		}
		sites = newSiteMatcher(list, manual)
		if sums, err = s.store.InventorySummaries(ctx, t); err != nil {
			return nil, err
		}
	}
	members := map[string]bool{}
	if len(a.GroupIDs) > 0 {
		groups, err := s.store.ListGroups(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			if g.Kind == store.GroupComputer && slices.Contains(a.GroupIDs, g.ID) {
				for _, m := range g.Members {
					members[m] = true
				}
			}
		}
	}
	return func(ag store.Agent) bool { return inScope(a, min, ag, sites, sums, members) }, nil
}

func inScope(a Access, min string, ag store.Agent, sites siteMatcher, sums map[string]store.InventorySummary, members map[string]bool) bool {
	if !authn.RoleAtLeast(a.On(ag.Host.OSFamily), min) {
		return false
	}
	// A job limited to one family is only enforced by recent agents.
	if fam, _ := a.Family(min); fam != "" && (ag.Host.AgentVersion == "" ||
		vuln.CompareVersions(ag.Host.AgentVersion, minScopedAgent) < 0) {
		return false
	}
	if len(a.SiteIDs) == 0 && len(a.GroupIDs) == 0 {
		return true
	}
	if members[ag.ID] {
		return true
	}
	if len(a.SiteIDs) > 0 {
		id, _, _ := sites.match(ag, sums[ag.ID])
		return id != "" && slices.Contains(a.SiteIDs, id)
	}
	return false
}

// scopeMessage explains a refusal of checkScope to the operator.
func (s *Server) scopeMessage(r *http.Request, err error) string {
	var oos errOutOfScope
	if errors.As(err, &oos) {
		list := oos.hosts
		if len(list) > 5 {
			list = append(list[:5:5], "…")
		}
		return s.Tf(r, "Il tuo ruolo non comprende questi computer: %v.", list)
	}
	return s.T(r, "errore interno")
}

// guardScopeChange refuses, unless the operator is a superadministrator,
// a change to which computers a site or group holds when some scope is
// limited to it (for a site, to any site: moving a computer between two
// sites changes both): that would change what another operator may do.
// It reports whether it answered the request.
func (s *Server) guardScopeChange(w http.ResponseWriter, r *http.Request, t, groupID, back string) bool {
	if s.can(r, authn.RoleSuperadmin) {
		return false
	}
	scopes, err := s.store.ListScopes(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	for _, sc := range scopes {
		if (groupID == "" && len(sc.SiteIDs) > 0) || (groupID != "" && slices.Contains(sc.GroupIDs, groupID)) {
			msg := s.T(r, "Questo gruppo delimita il ruolo di un operatore: solo chi ha OpenRMM.Admin può cambiarlo.")
			if groupID == "" {
				msg = s.T(r, "Le sedi delimitano il ruolo di qualche operatore: solo chi ha OpenRMM.Admin può spostare i computer.")
			}
			s.flash(w, r, msg, back)
			return true
		}
	}
	return false
}
