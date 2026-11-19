package authn

import (
	"encoding/base64"
	"testing"
)

func TestAccessOf(t *testing.T) {
	cases := []struct {
		roles            []string
		max              string
		clients, servers string
	}{
		{[]string{AppAdmin}, "", RoleSuperadmin, RoleSuperadmin},
		{[]string{AppAdminClients}, "", RoleAdmin, RoleReader},
		{[]string{AppAdminClients, AppOperatorServers}, "", RoleAdmin, RoleOperator},
		{[]string{AppAdminClients, AppAdminServers}, "", RoleAdmin, RoleAdmin},
		{[]string{AppOperatorServers}, "", RoleReader, RoleOperator},
		{[]string{AppReader}, "", RoleReader, RoleReader},
		{[]string{AppAdmin}, RoleOperator, RoleOperator, RoleOperator},
		{[]string{"User", "msiam_access"}, "", "", ""},
	}
	for _, c := range cases {
		if a := AccessOf(c.roles, c.max); a.Clients != c.clients || a.Servers != c.servers {
			t.Errorf("%v cap %q = %+v", c.roles, c.max, a)
		}
	}
	a := AccessOf([]string{AppAdminClients, AppOperatorServers}, "")
	if f, ok := a.Family(RoleOperator); !ok || f != "" {
		t.Fatalf("operator family = %q %v", f, ok)
	}
	if f, ok := a.Family(RoleAdmin); !ok || f != "client" {
		t.Fatalf("admin family = %q %v", f, ok)
	}
	if _, ok := a.Family(RoleSuperadmin); ok || a.Super() || a.Role() != RoleAdmin || a.On("") != RoleOperator {
		t.Fatal("superadmin, Role or On")
	}
}

func TestIssuerOf(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://login.example/t/v2.0"}`))
	if got := IssuerOf("h." + payload + ".s"); got != "https://login.example/t/v2.0" {
		t.Fatalf("IssuerOf = %q", got)
	}
	if IssuerOf("garbage") != "" || IssuerOf("a.!!.c") != "" {
		t.Fatal("malformed token")
	}
	a, b := &Verifier{cfg: Config{Issuer: "https://a"}}, &Verifier{cfg: Config{Issuer: "https://login.example/t/v2.0"}}
	if (Set{a, b}).For("h."+payload+".s") != b || (Set{a}).For("h."+payload+".s") != nil {
		t.Fatal("Set.For")
	}
}

func TestFederationFromEnv(t *testing.T) {
	t.Setenv("OPENRMM_FEDERATION_ISSUER", "")
	if _, ok, err := FederationFromEnv(); ok || err != nil {
		t.Fatalf("unset: %v %v", ok, err)
	}
	t.Setenv("OPENRMM_FEDERATION_ISSUER", "https://login.microsoftonline.com/x/v2.0")
	t.Setenv("OPENRMM_FEDERATION_CLIENT_ID", "app")
	t.Setenv("OPENRMM_FEDERATION_TENANT_MAP", "6f1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e=7a1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e")
	c, ok, err := FederationFromEnv()
	if !ok || err != nil || c.MaxRole != RoleSuperadmin || c.MFAClaim != "amr" {
		t.Fatalf("config = %+v %v %v", c, ok, err)
	}
	t.Setenv("OPENRMM_FEDERATION_MAX_ROLE", AppOperator)
	if c, _, err := FederationFromEnv(); err != nil || c.MaxRole != RoleOperator {
		t.Fatalf("app role as maximum: %q %v", c.MaxRole, err)
	}
	t.Setenv("OPENRMM_FEDERATION_MAX_ROLE", "root")
	if _, _, err := FederationFromEnv(); err == nil {
		t.Fatal("invalid role accepted")
	}
}

func TestCheckMFA(t *testing.T) {
	cases := []struct {
		mode string
		c    Claims
		ok   bool
	}{
		{"amr", Claims{AMR: []string{"pwd", "mfa"}}, true},
		{"amr", Claims{}, false},
		{"acrs:c1", Claims{ACRS: []string{"c1"}}, true},
		{"acrs:c1", Claims{AMR: []string{"mfa"}}, false},
		{"none", Claims{}, true},
	}
	for _, tc := range cases {
		v := &Verifier{cfg: Config{MFAClaim: tc.mode}}
		if err := v.checkMFA(&tc.c); (err == nil) != tc.ok {
			t.Errorf("%s %+v: err = %v", tc.mode, tc.c, err)
		}
	}
	base := Config{Issuer: "https://login.example.com/v2.0", ClientID: "app",
		TenantMap: map[string][]string{"a": {"b"}}}
	for mode, ok := range map[string]bool{"amr": true, "none": true, "acrs:c1": true, "off": false} {
		c := base
		c.MFAClaim = mode
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v", mode, err)
		}
	}
}

func TestTenantMapAll(t *testing.T) {
	const tid, t1 = "6f1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e", "7a1c2b1e-3d4a-4b5c-8d9e-0f1a2b3c4d5e"
	m, err := ParseTenantMap(tid + "=*")
	if err != nil || len(m[tid]) != 1 || m[tid][0] != AllTenants {
		t.Fatalf("map = %v %v", m, err)
	}
	c := Config{TenantMap: m}
	if !c.Allows(tid, t1) || c.Allows(t1, t1) || c.Allows(tid, "") {
		t.Fatal("Allows")
	}
	for _, bad := range []string{tid + "=*|" + t1, tid + "=" + t1 + "|*", tid + "=" + t1 + "," + tid + "=*", tid + "=*," + tid + "=" + t1} {
		if _, err := ParseTenantMap(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	t.Setenv("OPENRMM_FEDERATION_ISSUER", "https://login.microsoftonline.com/x/v2.0")
	t.Setenv("OPENRMM_FEDERATION_CLIENT_ID", "app")
	t.Setenv("OPENRMM_FEDERATION_TENANT_MAP", tid+"=*")
	if _, _, err := FederationFromEnv(); err == nil {
		t.Fatal("* accepted in the federation map")
	}
}
