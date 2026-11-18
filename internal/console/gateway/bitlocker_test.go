package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/pki"
)

func TestGetBitlockerPublicKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "t"})
	root, _ := pki.NewRootCA("r", time.Now())
	ca, _ := pki.NewIntermediateCA(root, "a", time.Now())
	now := time.Now().UTC().Truncate(time.Second)
	s, err := New(Config{Store: st, AgentsCA: ca, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Agent{TenantID: tenant, ID: ids.NewUUID(), Status: store.AgentActive, Host: store.HostInfo{Hostname: "PC-01"},
		CertFingerprint: "fp", CertNotAfter: now.Add(time.Hour)}
	st.CreateAgent(ctx, a)
	authed := context.WithValue(ctx, identityKey{}, caller{agent: a})

	if _, err := s.GetBitlockerPublicKey(ctx, &openrmmv1.GetBitlockerPublicKeyRequest{}); err == nil {
		t.Fatal("unauthenticated call accepted")
	}
	// No key created yet: empty, not an error.
	resp, err := s.GetBitlockerPublicKey(authed, &openrmmv1.GetBitlockerPublicKeyRequest{})
	if err != nil || len(resp.GetModulus()) != 0 {
		t.Fatalf("before creation: %+v, %v", resp, err)
	}
	// A PEM SPKI RSA key (not the full builder flow, just what the
	// console caches): the handler must split it into modulus/exponent,
	// never hand out PEM (Windows PowerShell 5.1 cannot import it).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	testPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err := st.SetBitlockerPublicKey(ctx, testPub); err != nil {
		t.Fatal(err)
	}
	resp, err = s.GetBitlockerPublicKey(authed, &openrmmv1.GetBitlockerPublicKeyRequest{})
	if err != nil || len(resp.GetModulus()) == 0 || len(resp.GetExponent()) == 0 {
		t.Fatalf("after caching: %+v, %v", resp, err)
	}
}

func TestIngestBitlockerKeys(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "t"})
	root, _ := pki.NewRootCA("r", time.Now())
	ca, _ := pki.NewIntermediateCA(root, "a", time.Now())
	now := time.Now().UTC().Truncate(time.Second)
	s, err := New(Config{Store: st, AgentsCA: ca, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Agent{TenantID: tenant, ID: ids.NewUUID(), Status: store.AgentActive, Host: store.HostInfo{Hostname: "PC-01"},
		CertFingerprint: "fp", CertNotAfter: now.Add(time.Hour)}
	st.CreateAgent(ctx, a)

	s.afterSuccess(ctx, a, "bitlocker", "backup", []byte(`{"volumes":[
		{"drive":"C:","key_protector_id":"{kp-1}","ciphertext":"3q2+7w=="},
		{"drive":"","key_protector_id":"{kp-2}","ciphertext":"AQID"},
		{"drive":"D:","key_protector_id":"{kp-3}","ciphertext":""}
	]}`))
	keys, err := st.ListBitlockerKeys(ctx, tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Drive != "C:" || string(keys[0].Ciphertext) != "\xde\xad\xbe\xef" {
		t.Fatalf("keys = %+v", keys)
	}
}
