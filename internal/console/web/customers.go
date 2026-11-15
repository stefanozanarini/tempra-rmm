package web

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// MSP mode: create the tenants of an MSP's customers from the console, in
// place of the offline "openrmm-admin tenant create" CLI. An operator still
// needs the new tenant in OPENRMM_TENANT_MAP (or OPENRMM_FEDERATION_TENANT_MAP)
// to manage or switch to it: creating it here does not grant anyone access.

var customerNameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} .,&'()-]{0,79}$`)

type customersData struct {
	Tenants []store.Tenant
	NewName string
}

// mspMode tells whether the console-wide MSP mode is on.
func (s *Server) mspMode(ctx context.Context) bool {
	cs, err := s.store.GetConsoleSettings(ctx)
	return err == nil && cs.MSPMode
}

func (s *Server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	if !s.mspMode(r.Context()) {
		http.NotFound(w, r)
		return
	}
	tenants, err := s.store.ListTenants(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].Name < tenants[j].Name })
	s.render(w, r, "customers", s.T(r, "Clienti"), customersData{Tenants: tenants})
}

func (s *Server) handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	if !s.mspMode(r.Context()) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !customerNameRe.MatchString(name) {
		s.flash(w, r, s.T(r, "Nome non valido."), "/customers")
		return
	}
	t := store.Tenant{ID: ids.NewUUID(), Name: name}
	if err := s.store.CreateTenant(r.Context(), t); err != nil {
		s.fail(w, r, err)
		return
	}
	if tid, ok := tenantOf(r); ok {
		s.audit(r.Context(), tid, sessionFrom(r.Context()).data.Operator, "tenant.created", t.ID, map[string]any{"name": name})
	}
	s.flash(w, r, s.Tf(r, "Cliente %s creato. Aggiungilo a OPENRMM_TENANT_MAP per darne accesso a un operatore.", name), "/customers")
}
