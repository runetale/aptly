package pgp

import (
	"context"
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pkg/errors"
)

var _ Signer = &KmsSigner{}

// KmsSigner implements the Signer interface using AWS KMS for signing operations.
// The private key never leaves KMS; only the public key is retrieved for PGP entity construction.
type KmsSigner struct {
	keyRef string
	region string

	kmsClient *kms.Client
	entity    *openpgp.Entity
	config    *packet.Config
}

func (k *KmsSigner) SetKey(keyRef string) {
	k.keyRef = keyRef
}

func (k *KmsSigner) SetKeyRing(_, _ string) {}

func (k *KmsSigner) SetPassphrase(_, _ string) {}

func (k *KmsSigner) SetBatch(_ bool) {}

// SetRegion sets the AWS region for the KMS client.
func (k *KmsSigner) SetRegion(region string) {
	k.region = region
}

func (k *KmsSigner) Init() error {
	if k.keyRef == "" {
		return fmt.Errorf("KMS key ID is required (set via gpgKeys config or --gpg-key flag)")
	}

	k.config = &packet.Config{
		DefaultHash: crypto.SHA256,
	}

	ctx := context.Background()

	var opts []func(*config.LoadOptions) error
	if k.region != "" {
		opts = append(opts, config.WithRegion(k.region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return errors.Wrap(err, "failed to load AWS config")
	}

	k.kmsClient = kms.NewFromConfig(cfg)

	descOutput, err := k.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: &k.keyRef,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to describe KMS key %s", k.keyRef)
	}

	keyMeta := descOutput.KeyMetadata
	if keyMeta.KeyUsage != types.KeyUsageTypeSignVerify {
		return fmt.Errorf("KMS key %s is not a SIGN_VERIFY key (usage: %s)", k.keyRef, keyMeta.KeyUsage)
	}

	pubOutput, err := k.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &k.keyRef,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to get public key for KMS key %s", k.keyRef)
	}

	creationTime := time.Now()
	if keyMeta.CreationDate != nil {
		creationTime = *keyMeta.CreationDate
	}

	entity, err := buildEntityFromKMS(k.kmsClient, k.keyRef, pubOutput, creationTime)
	if err != nil {
		return errors.Wrap(err, "failed to build PGP entity from KMS key")
	}

	k.entity = entity
	return nil
}

func (k *KmsSigner) DetachedSign(source string, destination string) error {
	fmt.Printf("kms: signing file '%s'...\n", filepath.Base(source))

	message, err := os.Open(source)
	if err != nil {
		return errors.Wrap(err, "error opening source file")
	}
	defer message.Close()

	signature, err := os.Create(destination)
	if err != nil {
		return errors.Wrap(err, "error creating signature file")
	}
	defer signature.Close()

	err = openpgp.ArmoredDetachSign(signature, k.entity, message, k.config)
	if err != nil {
		return errors.Wrap(err, "error creating detached signature via KMS")
	}

	return nil
}

func (k *KmsSigner) ClearSign(source string, destination string) error {
	fmt.Printf("kms: clearsigning file '%s'...\n", filepath.Base(source))

	message, err := os.Open(source)
	if err != nil {
		return errors.Wrap(err, "error opening source file")
	}
	defer message.Close()

	out, err := os.Create(destination)
	if err != nil {
		return errors.Wrap(err, "error creating clearsigned file")
	}
	defer out.Close()

	stream, err := clearsign.Encode(out, k.entity.PrivateKey, k.config)
	if err != nil {
		return errors.Wrap(err, "error initializing clear signer via KMS")
	}

	_, err = io.Copy(stream, message)
	if err != nil {
		_ = stream.Close()
		return errors.Wrap(err, "error generating clearsigned signature")
	}

	err = stream.Close()
	if err != nil {
		return errors.Wrap(err, "error generating clearsigned signature")
	}

	return nil
}

// kmsCryptoSigner implements crypto.Signer by delegating Sign operations to AWS KMS.
type kmsCryptoSigner struct {
	kmsClient *kms.Client
	keyID     string
	keySpec   types.KeySpec
	pubKey    crypto.PublicKey
}

func (s *kmsCryptoSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *kmsCryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo, err := signingAlgorithm(s.keySpec, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	output, err := s.kmsClient.Sign(context.Background(), &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: algo,
	})
	if err != nil {
		return nil, errors.Wrap(err, "KMS Sign API call failed")
	}

	return output.Signature, nil
}

func signingAlgorithm(keySpec types.KeySpec, hashFunc crypto.Hash) (types.SigningAlgorithmSpec, error) {
	switch keySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		switch hashFunc {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
	case types.KeySpecEccNistP256:
		switch hashFunc {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		}
	case types.KeySpecEccNistP384:
		switch hashFunc {
		case crypto.SHA256, crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		}
	case types.KeySpecEccNistP521:
		switch hashFunc {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		}
	}

	return "", fmt.Errorf("unsupported KMS key spec %s with hash %v", keySpec, hashFunc)
}

// buildEntityFromKMS constructs an openpgp.Entity whose PrivateKey delegates signing to KMS.
func buildEntityFromKMS(kmsClient *kms.Client, keyID string, pubOutput *kms.GetPublicKeyOutput, creationTime time.Time) (*openpgp.Entity, error) {
	signer := &kmsCryptoSigner{
		kmsClient: kmsClient,
		keyID:     keyID,
		keySpec:   pubOutput.KeySpec,
		pubKey:    nil, // will be set below
	}

	pubKeyDER := pubOutput.PublicKey
	keySpec := pubOutput.KeySpec

	cryptoPub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse KMS public key DER")
	}

	if err := validateKeyType(cryptoPub, keySpec); err != nil {
		return nil, err
	}

	signer.pubKey = cryptoPub

	return buildEntityFromCryptoSigner(signer, creationTime, keyID)
}

// buildEntityFromSigner constructs an openpgp.Entity from a crypto.Signer and DER public key.
// Used for testing without a real KMS client.
func buildEntityFromSigner(signer crypto.Signer, pubKeyDER []byte, keySpec types.KeySpec, creationTime time.Time) (*openpgp.Entity, error) {
	cryptoPub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key DER")
	}

	if err := validateKeyType(cryptoPub, keySpec); err != nil {
		return nil, err
	}

	return buildEntityFromCryptoSigner(signer, creationTime, "test-key")
}

func buildEntityFromCryptoSigner(signer crypto.Signer, creationTime time.Time, keyID string) (*openpgp.Entity, error) {
	pk := new(packet.PrivateKey)

	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		pk.PublicKey = *packet.NewRSAPublicKey(creationTime, pub)
	default:
		return nil, fmt.Errorf("unsupported public key type %T for PGP entity (only RSA is supported for KMS signing)", pub)
	}
	pk.PrivateKey = signer

	uid := packet.NewUserId(fmt.Sprintf("KMS key %s", keyID), "", "")
	if uid == nil {
		return nil, fmt.Errorf("failed to create user ID for KMS key")
	}

	entity := &openpgp.Entity{
		PrimaryKey: &pk.PublicKey,
		PrivateKey: pk,
		Identities: make(map[string]*openpgp.Identity),
	}

	isPrimary := true
	selfSig := &packet.Signature{
		CreationTime: creationTime,
		SigType:      packet.SigTypePositiveCert,
		PubKeyAlgo:   pk.PubKeyAlgo,
		Hash:         crypto.SHA256,
		IsPrimaryId:  &isPrimary,
		FlagsValid:   true,
		FlagSign:     true,
		FlagCertify:  true,
		IssuerKeyId:  &pk.PublicKey.KeyId,
	}

	err := selfSig.SignUserId(uid.Id, &pk.PublicKey, pk, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to self-sign PGP identity")
	}

	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Id,
		UserId:        uid,
		SelfSignature: selfSig,
		Signatures:    []*packet.Signature{selfSig},
	}

	return entity, nil
}

// ExportKMSPublicKeyArmored writes the armored PGP public key for a KMS signing key to w.
func ExportKMSPublicKeyArmored(keyID, region string, w io.Writer) error {
	signer := &KmsSigner{keyRef: keyID, region: region}
	if err := signer.Init(); err != nil {
		return err
	}
	return exportEntityPublicKeyArmored(signer.entity, w)
}

func exportEntityPublicKeyArmored(entity *openpgp.Entity, w io.Writer) error {
	if entity == nil || entity.PrimaryKey == nil {
		return fmt.Errorf("no PGP entity to export")
	}

	armorWriter, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create armored public key writer")
	}
	defer armorWriter.Close()

	if err := entity.PrimaryKey.Serialize(armorWriter); err != nil {
		return errors.Wrap(err, "failed to serialize primary public key")
	}

	for _, ident := range entity.Identities {
		if err := ident.UserId.Serialize(armorWriter); err != nil {
			return errors.Wrap(err, "failed to serialize user id")
		}
		if ident.SelfSignature != nil {
			if err := ident.SelfSignature.Serialize(armorWriter); err != nil {
				return errors.Wrap(err, "failed to serialize self signature")
			}
		}
	}

	return nil
}

func validateKeyType(pub crypto.PublicKey, keySpec types.KeySpec) error {
	switch keySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("KMS key spec %s but got non-RSA public key", keySpec)
		}
	case types.KeySpecEccNistP256:
		k, ok := pub.(*stdecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("KMS key spec %s but got non-ECDSA public key", keySpec)
		}
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("KMS key spec %s but public key uses curve %s", keySpec, k.Curve.Params().Name)
		}
	case types.KeySpecEccNistP384:
		k, ok := pub.(*stdecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("KMS key spec %s but got non-ECDSA public key", keySpec)
		}
		if k.Curve != elliptic.P384() {
			return fmt.Errorf("KMS key spec %s but public key uses curve %s", keySpec, k.Curve.Params().Name)
		}
	case types.KeySpecEccNistP521:
		k, ok := pub.(*stdecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("KMS key spec %s but got non-ECDSA public key", keySpec)
		}
		if k.Curve != elliptic.P521() {
			return fmt.Errorf("KMS key spec %s but public key uses curve %s", keySpec, k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("unsupported KMS key spec: %s", keySpec)
	}
	return nil
}


