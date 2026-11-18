package gateway

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// GetBitlockerPublicKey hands the agent the public key its BitLocker
// module encrypts recovery keys with. Not a secret (the private half never
// leaves the builder's encrypted state), so no authorization beyond the
// agent's own client certificate, already required for AgentService.
//
// Sent as the raw modulus and exponent, not PEM/DER: the module also runs
// on Windows PowerShell 5.1, whose .NET Framework cannot import either,
// but has had RSAParameters since .NET 1.1.
func (s *Server) GetBitlockerPublicKey(ctx context.Context, _ *openrmmv1.GetBitlockerPublicKeyRequest) (*openrmmv1.GetBitlockerPublicKeyResponse, error) {
	if _, ok := callerFromContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	cs, err := s.store.GetConsoleSettings(ctx)
	if err != nil {
		s.log.Error("console settings", "err", err)
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	if cs.BitlockerPublicKeyPEM == "" {
		return &openrmmv1.GetBitlockerPublicKeyResponse{}, nil
	}
	b, _ := pem.Decode([]byte(cs.BitlockerPublicKeyPEM))
	if b == nil {
		s.log.Error("bitlocker public key", "err", "unreadable PEM in console settings")
		return &openrmmv1.GetBitlockerPublicKeyResponse{}, nil
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		s.log.Error("bitlocker public key", "err", err)
		return &openrmmv1.GetBitlockerPublicKeyResponse{}, nil
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		s.log.Error("bitlocker public key", "err", "not an RSA key")
		return &openrmmv1.GetBitlockerPublicKeyResponse{}, nil
	}
	return &openrmmv1.GetBitlockerPublicKeyResponse{Modulus: rsaPub.N.Bytes(), Exponent: big.NewInt(int64(rsaPub.E)).Bytes()}, nil
}

// bitlockerResult is the shape of the bitlocker module's "backup" result.
type bitlockerResult struct {
	Volumes []struct {
		Drive          string `json:"drive"`
		KeyProtectorID string `json:"key_protector_id"`
		Ciphertext     string `json:"ciphertext"` // base64
	} `json:"volumes"`
}

const maxBitlockerVolumes = 64

// ingestBitlockerKeys stores the encrypted recovery keys of a "bitlocker
// backup" result. The plaintext never appears here: the agent already
// encrypted each key with the builder's public key before sending it.
func (s *Server) ingestBitlockerKeys(ctx context.Context, a store.Agent, raw []byte) {
	var res bitlockerResult
	if json.Unmarshal(raw, &res) != nil {
		return
	}
	now := s.now()
	for i, v := range res.Volumes {
		if i >= maxBitlockerVolumes || v.Drive == "" || v.Ciphertext == "" {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(v.Ciphertext)
		if err != nil || len(ct) == 0 {
			continue
		}
		k := store.BitlockerKey{TenantID: a.TenantID, AgentID: a.ID, Drive: v.Drive,
			KeyProtectorID: v.KeyProtectorID, Ciphertext: ct, UpdatedAt: now}
		if err := s.store.PutBitlockerKey(ctx, k); err != nil {
			s.log.Error("store bitlocker key", "agent", a.ID, "drive", v.Drive, "err", err)
		}
	}
}
