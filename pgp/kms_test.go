package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	. "gopkg.in/check.v1"
)

type KmsSignerSuite struct{}

var _ = Suite(&KmsSignerSuite{})

// localRSASigner implements crypto.Signer with a local RSA key for testing
type localRSASigner struct {
	privKey *rsa.PrivateKey
}

func (s *localRSASigner) Public() crypto.PublicKey {
	return &s.privKey.PublicKey
}

func (s *localRSASigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.privKey, opts.HashFunc(), digest)
}

// localECDSASigner implements crypto.Signer with a local ECDSA key for testing
type localECDSASigner struct {
	privKey *ecdsa.PrivateKey
}

func (s *localECDSASigner) Public() crypto.PublicKey {
	return &s.privKey.PublicKey
}

func (s *localECDSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.privKey, digest)
}

func (s *KmsSignerSuite) TestSigningAlgorithmMapping(c *C) {
	algo, err := signingAlgorithm(types.KeySpecRsa2048, crypto.SHA256)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256)

	algo, err = signingAlgorithm(types.KeySpecRsa4096, crypto.SHA384)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384)

	algo, err = signingAlgorithm(types.KeySpecRsa3072, crypto.SHA512)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512)

	algo, err = signingAlgorithm(types.KeySpecEccNistP256, crypto.SHA256)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecEcdsaSha256)

	algo, err = signingAlgorithm(types.KeySpecEccNistP384, crypto.SHA384)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecEcdsaSha384)

	algo, err = signingAlgorithm(types.KeySpecEccNistP521, crypto.SHA512)
	c.Assert(err, IsNil)
	c.Assert(algo, Equals, types.SigningAlgorithmSpecEcdsaSha512)

	_, err = signingAlgorithm(types.KeySpecEccNistP256, crypto.SHA512)
	c.Assert(err, NotNil)
}

func (s *KmsSignerSuite) TestValidateKeyType(c *C) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	c.Assert(validateKeyType(&rsaKey.PublicKey, types.KeySpecRsa2048), IsNil)
	c.Assert(validateKeyType(&rsaKey.PublicKey, types.KeySpecRsa3072), IsNil)
	c.Assert(validateKeyType(&rsaKey.PublicKey, types.KeySpecRsa4096), IsNil)
	c.Assert(validateKeyType(&ecP256.PublicKey, types.KeySpecEccNistP256), IsNil)
	c.Assert(validateKeyType(&ecP384.PublicKey, types.KeySpecEccNistP384), IsNil)

	c.Assert(validateKeyType(&ecP256.PublicKey, types.KeySpecRsa2048), NotNil)
	c.Assert(validateKeyType(&rsaKey.PublicKey, types.KeySpecEccNistP256), NotNil)
	c.Assert(validateKeyType(&ecP384.PublicKey, types.KeySpecEccNistP256), NotNil)
}

func (s *KmsSignerSuite) TestLocalSignerRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	signer := &localRSASigner{privKey: privKey}

	message := []byte("hello world")
	hash := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	c.Assert(err, IsNil)
	c.Assert(len(sig) > 0, Equals, true)

	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hash[:], sig)
	c.Assert(err, IsNil)
}

func (s *KmsSignerSuite) TestLocalSignerECDSA(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	signer := &localECDSASigner{privKey: privKey}

	message := []byte("hello world")
	hash := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	c.Assert(err, IsNil)
	c.Assert(len(sig) > 0, Equals, true)

	valid := ecdsa.VerifyASN1(&privKey.PublicKey, hash[:], sig)
	c.Assert(valid, Equals, true)
}

func (s *KmsSignerSuite) TestDetachedSignAndVerifyRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	tempDir := c.MkDir()
	sourceFile := path.Join(tempDir, "release")
	err = os.WriteFile(sourceFile, []byte("test content for signing\n"), 0644)
	c.Assert(err, IsNil)

	destFile := path.Join(tempDir, "release.gpg")

	kmsSigner := buildTestKmsSignerRSA(c, privKey)
	err = kmsSigner.DetachedSign(sourceFile, destFile)
	c.Assert(err, IsNil)

	verifyDetached(c, kmsSigner.entity, sourceFile, destFile)
}

func (s *KmsSignerSuite) TestClearSignAndVerifyRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	tempDir := c.MkDir()
	sourceFile := path.Join(tempDir, "release")
	err = os.WriteFile(sourceFile, []byte("test content for clearsigning\n"), 0644)
	c.Assert(err, IsNil)

	destFile := path.Join(tempDir, "InRelease")

	kmsSigner := buildTestKmsSignerRSA(c, privKey)
	err = kmsSigner.ClearSign(sourceFile, destFile)
	c.Assert(err, IsNil)

	verifyClearsigned(c, kmsSigner.entity, destFile)
}

func (s *KmsSignerSuite) TestDetachedSignAndVerifyECDSA(c *C) {
	c.Skip("ECDSA signing not supported with ProtonMail/go-crypto due to internal type constraints")
}

func (s *KmsSignerSuite) TestClearSignAndVerifyECDSA(c *C) {
	c.Skip("ECDSA signing not supported with ProtonMail/go-crypto due to internal type constraints")
}

func (s *KmsSignerSuite) TestExportPublicKeyArmoredRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	kmsSigner := buildTestKmsSignerRSA(c, privKey)
	var buf bytes.Buffer
	err = exportEntityPublicKeyArmored(kmsSigner.entity, &buf)
	c.Assert(err, IsNil)

	armored := buf.String()
	c.Assert(strings.HasPrefix(armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"), Equals, true)
	c.Assert(strings.Contains(armored, "SECRET"), Equals, false)
	c.Assert(strings.Contains(armored, "PRIVATE KEY"), Equals, false)
}

// --- helpers ---

func buildTestKmsSignerRSA(c *C, privKey *rsa.PrivateKey) *KmsSigner {
	signer := &localRSASigner{privKey: privKey}
	return buildTestKmsSignerFromCryptoSigner(c, signer, types.KeySpecRsa2048)
}

func buildTestKmsSignerFromCryptoSigner(c *C, signer crypto.Signer, keySpec types.KeySpec) *KmsSigner {
	derPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	c.Assert(err, IsNil)

	entity, err := buildEntityFromSigner(signer, derPub, keySpec, time.Now())
	c.Assert(err, IsNil)

	return &KmsSigner{
		keyRef: "test-key",
		entity: entity,
		config: &packet.Config{DefaultHash: crypto.SHA256},
	}
}

func verifyDetached(c *C, entity *openpgp.Entity, sourceFile, sigFile string) {
	keyring := openpgp.EntityList{entity}

	sigF, err := os.Open(sigFile)
	c.Assert(err, IsNil)
	defer sigF.Close()

	srcF, err := os.Open(sourceFile)
	c.Assert(err, IsNil)
	defer srcF.Close()

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, srcF, sigF, nil)
	c.Assert(err, IsNil)
}

func verifyClearsigned(c *C, entity *openpgp.Entity, sigFile string) {
	keyring := openpgp.EntityList{entity}

	sigF, err := os.Open(sigFile)
	c.Assert(err, IsNil)
	defer sigF.Close()

	// Read the clearsigned data and verify
	block, _ := clearsign.Decode(readAll(c, sigF))
	c.Assert(block, NotNil)

	_, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil)
	c.Assert(err, IsNil)
}

func readAll(c *C, f *os.File) []byte {
	data, err := io.ReadAll(f)
	c.Assert(err, IsNil)
	return data
}
