package builder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/codesign"
)

// The BitLocker recovery-key encryption pair lives next to the other keys,
// encrypted with the same passphrase, but is never used to sign anything:
// mixing a signing key's purpose with encryption is the kind of key reuse
// that invites subtle weaknesses, so this one is entirely its own.
const (
	fileBitlockerKey = "bitlocker.key" // encrypted
	bitlockerKeyBits = 3072
)

// CreateBitlockerKey creates the key pair once; replacing it would make
// every recovery key already encrypted with the old one unreadable, so
// existing material must be migrated (re-encrypted on the endpoint with
// the new public key) before a key is ever retired, not simply overwritten.
func (s *Service) CreateBitlockerKey(_ context.Context, req *openrmmv1.CreateBitlockerKeyRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exists(fileBitlockerKey) {
		return nil, status.Error(codes.AlreadyExists, "the BitLocker key already exists")
	}
	if err := s.checkPassphrase(req.GetPassphrase()); err != nil {
		return nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, bitlockerKeyBits)
	if err != nil {
		return nil, err
	}
	enc, err := codesign.EncryptKeyPEM(priv, req.GetPassphrase())
	if err != nil {
		return nil, invalid(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := s.write(fileBitlockerKey+".pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})); err != nil {
		return nil, err
	}
	if err := s.write(fileBitlockerKey, enc); err != nil {
		return nil, err
	}
	s.Log.Info("bitlocker key created")
	return s.status()
}

// GetBitlockerPublicKey returns the public key, relayed to agents so they
// can encrypt a recovery key before it ever leaves the endpoint. Not a
// secret: no passphrase needed.
func (s *Service) GetBitlockerPublicKey(context.Context, *openrmmv1.BuilderStatusRequest) (*openrmmv1.BitlockerPublicKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path(fileBitlockerKey + ".pub"))
	if err != nil {
		return &openrmmv1.BitlockerPublicKeyResponse{}, nil
	}
	return &openrmmv1.BitlockerPublicKeyResponse{PublicKeyPem: string(raw)}, nil
}

// DecryptBitlockerKey decrypts one recovery key. This is the only place its
// plaintext is ever produced outside the endpoint it was read from; the
// caller (the console) must show it once and never persist or log it.
func (s *Service) DecryptBitlockerKey(_ context.Context, req *openrmmv1.DecryptBitlockerKeyRequest) (*openrmmv1.DecryptBitlockerKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc, err := os.ReadFile(s.path(fileBitlockerKey))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "the BitLocker key has not been created")
	}
	key, err := codesign.DecryptKeyPEM(enc, req.GetPassphrase())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("bitlocker key is not RSA")
	}
	plain, err := priv.Decrypt(rand.Reader, req.GetCiphertext(), &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, invalid(errors.New("ciphertext does not match this key"))
	}
	return &openrmmv1.DecryptBitlockerKeyResponse{RecoveryKey: string(plain)}, nil
}
