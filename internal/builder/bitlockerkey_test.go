package builder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"google.golang.org/grpc/codes"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
)

func TestBitlockerKey(t *testing.T) {
	s := newService(t)
	ctx := context.Background()

	if resp, err := s.GetBitlockerPublicKey(ctx, &openrmmv1.BuilderStatusRequest{}); err != nil || resp.GetPublicKeyPem() != "" {
		t.Fatalf("public key before creation: %v, %q", err, resp.GetPublicKeyPem())
	}
	if _, err := s.DecryptBitlockerKey(ctx, &openrmmv1.DecryptBitlockerKeyRequest{Ciphertext: []byte("x"), Passphrase: pass}); code(err) != codes.FailedPrecondition {
		t.Fatalf("decrypt before creation: %v", err)
	}

	st, err := s.CreateBitlockerKey(ctx, &openrmmv1.CreateBitlockerKeyRequest{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetBitlockerKey() {
		t.Fatalf("status does not report the key: %+v", st)
	}
	if _, err := s.CreateBitlockerKey(ctx, &openrmmv1.CreateBitlockerKeyRequest{Passphrase: pass}); err == nil {
		t.Fatal("recreating the key was accepted")
	}

	pub, err := s.GetBitlockerPublicKey(ctx, &openrmmv1.BuilderStatusRequest{})
	if err != nil || pub.GetPublicKeyPem() == "" {
		t.Fatalf("public key after creation: %v, %q", err, pub.GetPublicKeyPem())
	}

	// Round trip: encrypt with the public key (as the endpoint would),
	// decrypt through the builder (as the console would, with the
	// passphrase) and get the same plaintext back.
	b, _ := pem.Decode([]byte(pub.GetPublicKeyPem()))
	if b == nil {
		t.Fatal("public key PEM unreadable")
	}
	parsed, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatal("public key is not RSA")
	}
	const recoveryKey = "123456-654321-111222-333444-555666-777888-999000-121314"
	ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, []byte(recoveryKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := s.DecryptBitlockerKey(ctx, &openrmmv1.DecryptBitlockerKeyRequest{Ciphertext: ciphertext, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetRecoveryKey() != recoveryKey {
		t.Fatalf("recovery key = %q", dec.GetRecoveryKey())
	}

	// A wrong passphrase decrypts nothing.
	if _, err := s.DecryptBitlockerKey(ctx, &openrmmv1.DecryptBitlockerKeyRequest{Ciphertext: ciphertext, Passphrase: "another long passphrase"}); code(err) != codes.PermissionDenied {
		t.Fatalf("wrong passphrase: %v", err)
	}
}
