package signer

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/signing"
)

func sampleProfile(now time.Time) *openrmmv1.ProfileRequest {
	sum := sha256.Sum256([]byte("manifest"))
	return &openrmmv1.ProfileRequest{
		TenantId: ids.NewUUID(), ProfileId: ids.NewUUID(), Version: 3,
		Steps: []*openrmmv1.ProfileStep{
			{Module: "workflow", ModuleVersion: "1.0.0", ModuleSha256: sum[:], Action: "run", ParamsJson: []byte(`{"workflow_id":"a"}`)},
			{Module: "reboot", ModuleVersion: "1.1.0", ModuleSha256: sum[:], Action: "reboot", ParamsJson: []byte(`{"only_if_pending":false}`)},
		},
		MaxTtlSeconds: int64((24 * time.Hour).Seconds()), ExpiresUnix: now.Add(90 * 24 * time.Hour).Unix(),
		RequestNonce: []byte("0123456789abcdef"),
	}
}

func TestSignProfileRun(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	p := sampleProfile(now)
	payload, _ := proto.Marshal(p)
	env := signedEnvelope(srv.signer, signing.DomainProfile, payload)
	agent := ids.NewUUID()

	resp, err := srv.SignProfileRun(context.Background(), &openrmmv1.SignProfileRunRequest{
		ProfileEnvelope: env, Step: 1, AgentIds: []string{agent}, TtlSeconds: 3600})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	jenv := &openrmmv1.SignedEnvelope{}
	proto.Unmarshal(resp.GetEnvelope(), jenv)
	job := &openrmmv1.Job{}
	proto.Unmarshal(jenv.GetPayload(), job)
	if job.GetModule() != "reboot" || job.GetAgentId() != agent || string(job.GetParamsJson()) != `{"only_if_pending":false}` {
		t.Fatalf("issued job = %+v", job)
	}
	if srv.signer.Verify(signing.DomainJob, jenv.GetKeyId(), jenv.GetPayload(), jenv.GetSignature()) != nil {
		t.Fatal("issued job not signed for DomainJob")
	}
}

func TestSignProfileRunRefuses(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	p := sampleProfile(now)
	payload, _ := proto.Marshal(p)
	good := signedEnvelope(srv.signer, signing.DomainProfile, payload)
	agents := []string{ids.NewUUID()}

	cases := map[string]*openrmmv1.SignProfileRunRequest{
		// An assignment signature must not be replayed as a profile.
		"wrong domain":      {ProfileEnvelope: signedEnvelope(srv.signer, signing.DomainAssignment, payload), AgentIds: agents, TtlSeconds: 3600},
		"step out of range": {ProfileEnvelope: good, Step: 2, AgentIds: agents, TtlSeconds: 3600},
		"negative step":     {ProfileEnvelope: good, Step: -1, AgentIds: agents, TtlSeconds: 3600},
		"ttl over maximum":  {ProfileEnvelope: good, AgentIds: agents, TtlSeconds: 25 * 3600},
		"no targets":        {ProfileEnvelope: good, TtlSeconds: 3600},
	}
	for name, req := range cases {
		if _, err := srv.SignProfileRun(context.Background(), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	srv.now = func() time.Time { return now.Add(91 * 24 * time.Hour) }
	if _, err := srv.SignProfileRun(context.Background(), &openrmmv1.SignProfileRunRequest{
		ProfileEnvelope: good, AgentIds: agents, TtlSeconds: 3600}); err == nil {
		t.Error("expired profile accepted")
	}
}
