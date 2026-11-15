// Package profilereq defines the canonical hash of a provisioning profile
// version, shared by the console (which puts it in the step-up
// authentication nonce when an administrator approves the profile) and the
// signer (which recomputes it and compares). It mirrors assignreq: a profile
// names an ordered list of pinned jobs, not yet the computers they will run
// on.
package profilereq

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/pkgref"
)

const (
	// MaxAgents bounds the agents one SignProfileRun call issues jobs for.
	MaxAgents = 200
	// MaxSteps bounds the steps of a profile.
	MaxSteps = 30
	// MaxParams bounds the parameters of all the steps together, so the
	// signed profile stays below signing.MaxPayload.
	MaxParams = 900 << 10
	// MinTTL and MaxTTL bound a profile's max_ttl_seconds.
	MinTTL = time.Minute
	MaxTTL = 48 * time.Hour
	// MinValidity and MaxValidity bound how long an approval can be used
	// to sign runs before an administrator must approve the profile again.
	MinValidity  = 24 * time.Hour
	MaxValidity  = 366 * 24 * time.Hour
	nonceRandLen = 16
)

// Validate checks a profile before hashing or signing it. now is used only
// to bound expires_unix to a sensible range.
func Validate(r *openrmmv1.ProfileRequest, now time.Time) error {
	if !ids.IsUUID(r.GetTenantId()) {
		return errors.New("tenant must be a UUID")
	}
	if !ids.IsUUID(r.GetProfileId()) {
		return errors.New("profile must be a UUID")
	}
	if r.GetVersion() < 1 {
		return errors.New("version must be positive")
	}
	if n := len(r.GetSteps()); n == 0 || n > MaxSteps {
		return fmt.Errorf("between 1 and %d steps", MaxSteps)
	}
	size := 0
	for i, st := range r.GetSteps() {
		if err := validateStep(st); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
		size += len(st.GetParamsJson())
	}
	if size > MaxParams {
		return errors.New("parameters too large")
	}
	if ttl := time.Duration(r.GetMaxTtlSeconds()) * time.Second; ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("max ttl must be between %s and %s", MinTTL, MaxTTL)
	}
	valid := time.Unix(r.GetExpiresUnix(), 0).Sub(now)
	if valid < MinValidity || valid > MaxValidity {
		return fmt.Errorf("validity must be between %s and %s", MinValidity, MaxValidity)
	}
	if len(r.GetRequestNonce()) != nonceRandLen {
		return errors.New("request nonce must be 16 bytes")
	}
	return nil
}

func validateStep(st *openrmmv1.ProfileStep) error {
	if err := pkgref.Validate(st.GetPackages()); err != nil {
		return err
	}
	if !modules.ValidID(st.GetModule()) || !modules.ValidVersion(st.GetModuleVersion()) {
		return errors.New("invalid module reference")
	}
	if len(st.GetModuleSha256()) != sha256.Size {
		return errors.New("module hash must be SHA-256")
	}
	if a := st.GetAction(); a == "" || len(a) > 41 {
		return errors.New("invalid action")
	}
	var obj map[string]any
	if err := json.Unmarshal(st.GetParamsJson(), &obj); err != nil {
		return errors.New("parameters must be a JSON object")
	}
	return nil
}

// Hash returns the canonical SHA-256 of a profile request: every field
// length-prefixed in a fixed order, so no two requests share an encoding.
func Hash(r *openrmmv1.ProfileRequest) []byte {
	var b bytes.Buffer
	b.WriteString("openrmm/profile-request/v1\x00")
	field := func(p []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	u64 := func(n uint64) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], n)
		field(c[:])
	}
	field([]byte(r.GetTenantId()))
	field([]byte(r.GetProfileId()))
	u64(uint64(r.GetVersion())) // #nosec G115 -- validated positive
	u64(uint64(len(r.GetSteps())))
	for _, st := range r.GetSteps() {
		field([]byte(st.GetModule()))
		field([]byte(st.GetModuleVersion()))
		field(st.GetModuleSha256())
		field([]byte(st.GetAction()))
		field(st.GetParamsJson())
		u64(uint64(len(st.GetPackages())))
		for _, p := range st.GetPackages() {
			field(p.GetSha256())
			field([]byte(p.GetFileName()))
			u64(uint64(p.GetSize())) // #nosec G115 -- validated positive
		}
	}
	u64(uint64(r.GetMaxTtlSeconds())) // #nosec G115 -- validated positive
	u64(uint64(r.GetExpiresUnix()))   // #nosec G115 -- validated positive
	field(r.GetRequestNonce())
	sum := sha256.Sum256(b.Bytes())
	return sum[:]
}

// NewRequestNonce returns the random part of a request.
func NewRequestNonce() []byte { return ids.Random(nonceRandLen) }

// AuthNonce is the OIDC nonce for the step-up authentication approving r.
func AuthNonce(r *openrmmv1.ProfileRequest) string {
	return "profile." + base64.RawURLEncoding.EncodeToString(Hash(r))
}

// CheckAuthNonce reports whether nonce approves exactly r.
func CheckAuthNonce(nonce string, r *openrmmv1.ProfileRequest) bool {
	want := AuthNonce(r)
	return strings.HasPrefix(nonce, "profile.") && subtle.ConstantTimeCompare([]byte(nonce), []byte(want)) == 1
}
