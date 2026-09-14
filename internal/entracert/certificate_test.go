//go:build cgo

package entracert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
)

type noClose struct{ io.ReadWriter }

func (noClose) Close() error { return nil }

func TestTPMCertificateGeneratedReusedAndBoundToTPM(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { sim.Close() }()
	open := func() (io.ReadWriteCloser, error) { return noClose{sim}, nil }
	dir := t.TempDir()
	m, err := Prepare(context.Background(), dir, "deployment-a", open)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Certificate.CheckSignature(m.Certificate.SignatureAlgorithm, m.Certificate.RawTBSCertificate, m.Certificate.Signature); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("authentication assertion"))
	signature, err := m.Signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err = rsa.VerifyPSS(m.Certificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, BlobName))
	if err != nil {
		t.Fatal(err)
	}
	var saved wrappedKey
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	public, err := tpm2.DecodePublic(saved.Public)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []tpm2.KeyProp{tpm2.FlagFixedTPM, tpm2.FlagFixedParent, tpm2.FlagSensitiveDataOrigin} {
		if public.Attributes&flag == 0 {
			t.Fatal("key is not TPM-generated and non-exportable")
		}
	}
	if info, err := os.Stat(filepath.Join(dir, BlobName)); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wrapped key permissions")
	}
	if err = os.Remove(m.PublicPath); err != nil {
		t.Fatal(err)
	}
	again, err := Prepare(context.Background(), dir, "deployment-a", open)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Certificate.Raw) != string(m.Certificate.Raw) {
		t.Fatal("resume regenerated the key/certificate")
	}
	if _, err = Prepare(context.Background(), dir, "deployment-b", open); err == nil {
		t.Fatal("different deployment adopted the key")
	}
	// A reboot preserves the TPM seed and must keep the key usable.
	if err = sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err = again.Signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	// A new TPM creates a different root seed. A disk copy must not sign.
	if err = sim.Close(); err != nil {
		t.Fatal(err)
	}
	sim, err = simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = again.Signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("key worked after TPM replacement")
	}
}

func TestTPMCertificateRefusesForeignFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("missing-target", filepath.Join(dir, BlobName)); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := Prepare(context.Background(), dir, "deployment", func() (io.ReadWriteCloser, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatal("followed or replaced an existing nonregular key path")
	}
}
