package authn

// App roles are the Entra app roles assigned to operators (or to groups of
// them). OpenRMM.Admin is everything, as it always was; the others can be
// limited to client or server computers. An operator may hold several,
// e.g. Admin.Clients with Operator.Servers.
const (
	AppAdmin           = "OpenRMM.Admin"
	AppAdminClients    = "OpenRMM.Admin.Clients"
	AppAdminServers    = "OpenRMM.Admin.Servers"
	AppOperator        = "OpenRMM.Operator"
	AppOperatorClients = "OpenRMM.Operator.Clients"
	AppOperatorServers = "OpenRMM.Operator.Servers"
	AppReader          = "OpenRMM.Reader"
)

// Levels of access; each includes the ones below it.
const (
	// RoleSuperadmin manages everything on a tenant: settings, tokens,
	// policies, agent versions, sites, scopes.
	RoleSuperadmin = "superadmin"
	// RoleAdmin administers computers: approvals, revocations, permanent
	// assignments, provisioning, the package library.
	RoleAdmin = "admin"
	// RoleOperator runs commands and remote sessions.
	RoleOperator = "operator"
	// RoleReader only reads.
	RoleReader = "reader"
)

var roleRank = map[string]int{RoleReader: 1, RoleOperator: 2, RoleAdmin: 3, RoleSuperadmin: 4}

// maxRoleNames also accepts the app role names in a maximum role.
var maxRoleNames = map[string]string{AppAdmin: RoleSuperadmin, AppOperator: RoleOperator, AppReader: RoleReader}

// ValidRole reports whether r is a level.
func ValidRole(r string) bool { _, ok := roleRank[r]; return ok }

// RoleAtLeast reports whether role includes min.
func RoleAtLeast(role, min string) bool { return role != "" && roleRank[role] >= roleRank[min] }

func maxRole(a, b string) string {
	if roleRank[b] > roleRank[a] {
		return b
	}
	return a
}

func minRole(a, b string) string {
	if roleRank[b] < roleRank[a] {
		return b
	}
	return a
}

// Access is what an operator's app roles allow: a level on client
// computers and one on servers ("" for none).
type Access struct {
	Clients, Servers string
}

// AccessOf combines app roles, capped by max (a level; "" for no cap).
func AccessOf(appRoles []string, max string) Access {
	var a Access
	give := func(clients, servers string) {
		a.Clients, a.Servers = maxRole(a.Clients, clients), maxRole(a.Servers, servers)
	}
	for _, r := range appRoles {
		switch r {
		case AppAdmin:
			give(RoleSuperadmin, RoleSuperadmin)
		case AppAdminClients:
			give(RoleAdmin, "")
		case AppAdminServers:
			give("", RoleAdmin)
		case AppOperator:
			give(RoleOperator, RoleOperator)
		case AppOperatorClients:
			give(RoleOperator, "")
		case AppOperatorServers:
			give("", RoleOperator)
		case AppReader:
			give(RoleReader, RoleReader)
		}
	}
	// Whoever may act on one family may read everything.
	if a.Clients != "" || a.Servers != "" {
		give(RoleReader, RoleReader)
	}
	if max != "" {
		if a.Clients != "" {
			a.Clients = minRole(a.Clients, max)
		}
		if a.Servers != "" {
			a.Servers = minRole(a.Servers, max)
		}
	}
	return a
}

// Super reports a superadministrator.
func (a Access) Super() bool { return a.Clients == RoleSuperadmin && a.Servers == RoleSuperadmin }

// Role is the highest level, on either family: what the console's menus
// and pages go by.
func (a Access) Role() string { return maxRole(a.Clients, a.Servers) }

// On returns the level on a computer of family; for an unknown family,
// the lower of the two.
func (a Access) On(family string) string {
	switch family {
	case "client":
		return a.Clients
	case "server":
		return a.Servers
	}
	return minRole(a.Clients, a.Servers)
}

// Family returns the OS family an action needing min must be limited to:
// "" when min is held on both, "client" or "server" when only on one; ok is
// false when on neither.
func (a Access) Family(min string) (family string, ok bool) {
	c, s := RoleAtLeast(a.Clients, min), RoleAtLeast(a.Servers, min)
	switch {
	case c && s:
		return "", true
	case c:
		return "client", true
	case s:
		return "server", true
	}
	return "", false
}
