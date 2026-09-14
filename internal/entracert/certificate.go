// Package entracert keeps an installer signing key inside the host TPM. The
// on-disk private blob is TPM-wrapped; no plaintext private key is exported.
package entracert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const BlobName = "entra-installer.tpm"
const PublicName = "entra-installer.cer"

// Open is injectable for simulator tests. Production uses the Linux resource
// manager, so closing the device also releases transient handles after a crash.
type Open func() (io.ReadWriteCloser, error)

type Material struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	PublicPath  string
}

type wrappedKey struct {
	Version                      int
	DeploymentID                 string
	Private, Public, Certificate []byte
}

func defaultOpen() (io.ReadWriteCloser, error) { return tpm2.OpenTPM("/dev/tpmrm0") }

var parentTemplate = tpm2.Public{
	Type: tpm2.AlgRSA, NameAlg: tpm2.AlgSHA256, Attributes: tpm2.FlagStorageDefault,
	RSAParameters: &tpm2.RSAParams{KeyBits: 2048, Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB}},
}

// FixedTPM + FixedParent prohibit duplication to another TPM/parent. Removing
// Restricted permits signing the externally hashed certificate and assertion.
var signerTemplate = tpm2.Public{
	Type: tpm2.AlgRSA, NameAlg: tpm2.AlgSHA256,
	Attributes:    tpm2.FlagSignerDefault &^ tpm2.FlagRestricted,
	RSAParameters: &tpm2.RSAParams{KeyBits: 2048},
}

func parent(rw io.ReadWriter) (tpmutil.Handle, error) {
	h, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", parentTemplate)
	return h, err
}

func Prepare(ctx context.Context, dir, deploymentID string, open Open) (Material, error) {
	var result Material
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if open == nil {
		open = defaultOpen
	}
	path := filepath.Join(dir, BlobName)
	var key wrappedKey
	b, err := readRegular(path)
	if err == nil {
		if json.Unmarshal(b, &key) != nil || key.Version != 1 || key.DeploymentID != deploymentID {
			return result, errors.New("the saved installer certificate does not belong to this deployment; it was left unchanged")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// Only the TPM creates key material. No software-key fallback exists.
		rw, err := open()
		if err != nil {
			return result, errors.New("certificate authentication needs an accessible TPM 2.0 at /dev/tpmrm0; enable a vTPM or choose client secret")
		}
		defer rw.Close()
		h, err := parent(rw)
		if err != nil {
			return result, errors.New("cannot create the TPM storage parent; check TPM availability and owner authorization")
		}
		defer tpm2.FlushContext(rw, h)
		priv, pub, _, _, _, err := tpm2.CreateKey(rw, h, tpm2.PCRSelection{}, "", "", signerTemplate)
		if err != nil {
			return result, errors.New("the TPM could not create an RSA installer signing key")
		}
		key = wrappedKey{Version: 1, DeploymentID: deploymentID, Private: priv, Public: pub}
		signer, err := newSigner(key, open)
		if err != nil {
			return result, err
		}
		// Reuse the current connection while creating the public certificate.
		kh, _, err := tpm2.Load(rw, h, "", pub, priv)
		if err != nil {
			return result, errors.New("the TPM could not load the new installer signing key")
		}
		defer tpm2.FlushContext(rw, kh)
		signer.loaded = func(d []byte, o crypto.SignerOpts) ([]byte, error) { return sign(rw, kh, d, o) }
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return result, err
		}
		now := time.Now()
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Guacamole installer " + deploymentID}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, SignatureAlgorithm: x509.SHA256WithRSA, BasicConstraintsValid: true}
		key.Certificate, err = x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			return result, errors.New("the TPM could not sign the installer certificate")
		}
		if err = os.MkdirAll(dir, 0700); err != nil {
			return result, err
		}
		b, _ = json.Marshal(key)
		if err = writeNew(path, b, 0600); err != nil {
			return result, err
		}
	} else {
		return result, err
	}
	cert, err := x509.ParseCertificate(key.Certificate)
	if err != nil {
		return result, errors.New("the saved installer certificate is invalid; it was left unchanged")
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Add(time.Minute).Before(cert.NotAfter) {
		return result, errors.New("the installer certificate is expired or not yet valid; check the clock, or use a client secret and arrange certificate replacement")
	}
	signer, err := newSigner(key, open)
	if err != nil {
		return result, err
	}
	pub1, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	pub2, _ := x509.MarshalPKIXPublicKey(signer.Public())
	if string(pub1) != string(pub2) {
		return result, errors.New("the saved installer certificate and TPM key do not match")
	}
	publicPath := filepath.Join(dir, PublicName)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key.Certificate})
	existing, err := readRegular(publicPath)
	if errors.Is(err, os.ErrNotExist) {
		err = writeNew(publicPath, publicPEM, 0644)
	} else if err == nil && string(existing) != string(publicPEM) {
		err = errors.New("a different public certificate exists at the export path; it was left unchanged")
	}
	if err != nil {
		return result, err
	}
	return Material{Certificate: cert, Signer: signer, PublicPath: publicPath}, nil
}

type tpmSigner struct {
	key    wrappedKey
	public crypto.PublicKey
	open   Open
	loaded func([]byte, crypto.SignerOpts) ([]byte, error)
}

func newSigner(key wrappedKey, open Open) (*tpmSigner, error) {
	p, err := tpm2.DecodePublic(key.Public)
	if err != nil || !p.MatchesTemplate(signerTemplate) {
		return nil, errors.New("the saved TPM key does not have the required non-exportable signing policy")
	}
	public, err := p.Key()
	if err != nil {
		return nil, errors.New("the saved TPM public key is invalid")
	}
	return &tpmSigner{key: key, public: public, open: open}, nil
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.public }
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.loaded != nil {
		return s.loaded(digest, opts)
	}
	rw, err := s.open()
	if err != nil {
		return nil, errors.New("cannot open the installer TPM")
	}
	defer rw.Close()
	h, err := parent(rw)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, h)
	k, _, err := tpm2.Load(rw, h, "", s.key.Public, s.key.Private)
	if err != nil {
		return nil, errors.New("cannot load the installer key on this TPM; it may belong to a different VM")
	}
	defer tpm2.FlushContext(rw, k)
	return sign(rw, k, digest, opts)
}

func sign(rw io.ReadWriter, h tpmutil.Handle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("installer signing requires SHA-256")
	}
	alg := tpm2.AlgRSASSA
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash {
			return nil, errors.New("installer signing requires a SHA-256 length PSS salt")
		}
		alg = tpm2.AlgRSAPSS
	}
	sig, err := tpm2.Sign(rw, h, "", digest, nil, &tpm2.SigScheme{Alg: alg, Hash: tpm2.AlgSHA256})
	if err != nil {
		return nil, err
	}
	if sig.RSA == nil {
		return nil, errors.New("TPM returned an unexpected signature type")
	}
	return sig.RSA.Signature, nil
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("installer certificate path is not a regular file")
	}
	return os.ReadFile(path)
}

// Publish only a fully written bundle. An interruption leaves a temporary
// TPM-wrapped file, never a truncated usable key or a plaintext private key.
func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".entra-certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
