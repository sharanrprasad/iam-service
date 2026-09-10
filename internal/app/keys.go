package app

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// loadRSAKeys reads the RS256 signing keypair from PEM files and verifies the
// two halves match. PKCS1 and PKCS8 private-key encodings are both accepted.
func loadRSAKeys(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("private key not found at %q: %w", privateKeyPath, err)
		}
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	privateBlock, _ := pem.Decode(privateKeyPEM)
	if privateBlock == nil {
		return nil, nil, fmt.Errorf("decode private key PEM: no PEM block found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		parsedKey, pkcs8Err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
		if pkcs8Err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}

		rsaPrivateKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("parse private key: unsupported key type %T", parsedKey)
		}
		privateKey = rsaPrivateKey
	}

	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("public key not found at %q: %w", publicKeyPath, err)
		}
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	publicBlock, _ := pem.Decode(publicKeyPEM)
	if publicBlock == nil {
		return nil, nil, fmt.Errorf("decode public key PEM: no PEM block found")
	}

	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("parse public key: unsupported key type %T", parsedPublicKey)
	}

	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		return nil, nil, fmt.Errorf("private/public RSA keys do not match")
	}

	return privateKey, publicKey, nil
}
