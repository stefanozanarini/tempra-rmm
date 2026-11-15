package profilereq

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

func sample(now time.Time) *openrmmv1.ProfileRequest {
	sum := sha256.Sum256([]byte("manifest"))
	return &openrmmv1.ProfileRequest{
		TenantId: ids.NewUUID(), ProfileId: ids.NewUUID(), Version: 1,
		Steps: []*openrmmv1.ProfileStep{
			{Module: "workflow", ModuleVersion: "1.0.0", ModuleSha256: sum[:], Action: "run", ParamsJson: []byte(`{}`)},
			{Module: "reboot", ModuleVersion: "1.1.0", ModuleSha256: sum[:], Action: "reboot", ParamsJson: []byte(`{}`)},
		},
		MaxTtlSeconds: 86400, ExpiresUnix: now.Add(30 * 24 * time.Hour).Unix(), RequestNonce: NewRequestNonce(),
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	if err := Validate(sample(now), now); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(r *openrmmv1.ProfileRequest){
		"no steps":       func(r *openrmmv1.ProfileRequest) { r.Steps = nil },
		"bad params":     func(r *openrmmv1.ProfileRequest) { r.Steps[1].ParamsJson = []byte(`[]`) },
		"bad module":     func(r *openrmmv1.ProfileRequest) { r.Steps[0].Module = "../x" },
		"short validity": func(r *openrmmv1.ProfileRequest) { r.ExpiresUnix = now.Add(time.Hour).Unix() },
		"ttl too long":   func(r *openrmmv1.ProfileRequest) { r.MaxTtlSeconds = 3 * 86400 },
		"version zero":   func(r *openrmmv1.ProfileRequest) { r.Version = 0 },
	}
	for name, f := range bad {
		r := sample(now)
		f(r)
		if Validate(r, now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHashCoversSteps(t *testing.T) {
	now := time.Now()
	a := sample(now)
	h := Hash(a)
	b := proto.Clone(a).(*openrmmv1.ProfileRequest)
	if !bytes.Equal(Hash(b), h) {
		t.Fatal("hash not deterministic")
	}
	b.Steps[1].ParamsJson = []byte(`{"x":1}`)
	if bytes.Equal(Hash(b), h) {
		t.Fatal("hash ignores step parameters")
	}
	c := proto.Clone(a).(*openrmmv1.ProfileRequest)
	c.Steps[0], c.Steps[1] = c.Steps[1], c.Steps[0]
	if bytes.Equal(Hash(c), h) {
		t.Fatal("hash ignores step order")
	}
	if !CheckAuthNonce(AuthNonce(a), a) || CheckAuthNonce(AuthNonce(b), a) {
		t.Fatal("auth nonce check")
	}
}
