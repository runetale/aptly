// export-kms-pubkey exports an armored PGP public key from an AWS KMS SIGN_VERIFY key.
//
// Usage:
//
//	KMS_KEY_ID=alias/my-key AWS_REGION=ap-northeast-1 go run ./scripts/export-kms-pubkey/main.go > kms-test.pub
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aptly-dev/aptly/pgp"
)

func main() {
	keyID := flag.String("key", os.Getenv("KMS_KEY_ID"), "KMS key ID, ARN, or alias")
	region := flag.String("region", os.Getenv("AWS_REGION"), "AWS region for KMS")
	flag.Parse()

	if *keyID == "" {
		fmt.Fprintln(os.Stderr, "KMS key ID required: set KMS_KEY_ID or -key")
		os.Exit(1)
	}

	if err := pgp.ExportKMSPublicKeyArmored(*keyID, *region, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "export failed: %v\n", err)
		os.Exit(1)
	}
}
