package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// scopeView is one scope of the page, with names in place of ids.
type scopeView struct {
	store.Scope
	Sites, Groups []string
}

type scopesData struct {
	Scopes []scopeView
	Sites  []store.Site
	Groups []store.Group
	// Edit is the scope being edited (?subject=), or a blank one.
	Edit store.Scope
}

// handleScopes lists the scopes and shows the form for a new one, or for
// the one named by ?subject=.
func (s *Server) handleScopes(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	var d scopesData
	var err error
	if d.Sites, err = s.store.ListSites(ctx, t); err != nil {
		s.fail(w, r, err)
		return
	}
	if d.Groups, err = s.scopeGroups(ctx, t); err != nil {
		s.fail(w, r, err)
		return
	}
	names := map[string]string{}
	for _, st := range d.Sites {
		names[st.ID] = st.Name
	}
	for _, g := range d.Groups {
		names[g.ID] = g.Name
	}
	scopes, err := s.store.ListScopes(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	edit := strings.ToLower(r.URL.Query().Get("subject"))
	for _, sc := range scopes {
		v := scopeView{Scope: sc}
		for _, id := range sc.SiteIDs {
			v.Sites = append(v.Sites, nameOr(names, id))
		}
		for _, id := range sc.GroupIDs {
			v.Groups = append(v.Groups, nameOr(names, id))
		}
		d.Scopes = append(d.Scopes, v)
		if sc.SubjectOID == edit {
			d.Edit = sc
		}
	}
	s.render(w, r, "scopes", s.T(r, "Ambiti"), d)
}

func nameOr(names map[string]string, id string) string {
	if n, ok := names[id]; ok {
		return n
	}
	return id
}

// scopeGroups are the groups a scope may name: public computer groups (a
// personal group is its owner's to change).
func (s *Server) scopeGroups(ctx context.Context, t string) ([]store.Group, error) {
	gs, err := s.store.ListGroups(ctx, t)
	if err != nil {
		return nil, err
	}
	var out []store.Group
	for _, g := range gs {
		if g.Kind == store.GroupComputer && g.Owner == "" {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// handleSaveScope saves or deletes a scope.
func (s *Server) handleSaveScope(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	op := sessionFrom(ctx).data.Operator
	f := r.PostForm
	oid := strings.ToLower(strings.TrimSpace(f.Get("subject")))
	if !ids.IsUUID(oid) {
		s.flash(w, r, s.T(r, "Indica l'Object ID di un utente o di un gruppo di sicurezza di Entra ID (un GUID)."), "/scopes")
		return
	}
	if f.Get("do") == "delete" {
		if err := s.store.DeleteScope(ctx, t, oid); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err)
			return
		}
		s.audit(ctx, t, op, "scope.deleted", oid, nil)
		s.flash(w, r, s.T(r, "Ambito eliminato: valgono di nuovo tutti i computer."), "/scopes")
		return
	}
	sites, err := s.store.ListSites(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	groups, err := s.scopeGroups(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	known := map[string]bool{}
	for _, st := range sites {
		known[st.ID] = true
	}
	for _, g := range groups {
		known[g.ID] = true
	}
	sc := store.Scope{TenantID: t, SubjectOID: oid, SubjectName: strings.TrimSpace(f.Get("name")),
		SiteIDs: pickIDs(f["site"], known), GroupIDs: pickIDs(f["group"], known), UpdatedBy: "operator:" + op.Username}
	if sc.SubjectName == "" || len(sc.SubjectName) > 256 {
		sc.SubjectName = oid
	}
	if len(sc.SiteIDs) == 0 && len(sc.GroupIDs) == 0 {
		s.flash(w, r, s.T(r, "Scegli almeno una sede o un gruppo: senza, l'operatore agisce su tutti i computer e l'ambito non serve."), "/scopes?subject="+oid)
		return
	}
	if err := s.store.PutScope(ctx, sc); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(ctx, t, op, "scope.saved", oid, map[string]any{"name": sc.SubjectName, "sites": sc.SiteIDs, "groups": sc.GroupIDs})
	s.flash(w, r, s.Tf(r, "Ambito di %s salvato.", sc.SubjectName), "/scopes")
}

// pickIDs keeps the known ids among values, sorted and distinct.
func pickIDs(values []string, known map[string]bool) []string {
	var out []string
	for _, v := range values {
		if known[v] && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
