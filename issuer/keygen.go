package issuer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type keys struct {
	public  crypto.PublicKey
	private crypto.PrivateKey
}

func keygen() (*keys, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate keys: %s", err)
	}
	return &keys{
		publicKey, privateKey,
	}, nil
}

func fromPrivateKey(key crypto.PrivateKey) (*keys, error) {
	switch key := key.(type) {
	case *ed25519.PrivateKey:
		return &keys{
			private: key,
			public:  key.Public(),
		}, nil
	default:
		return nil, errors.New("Key type not supported or key malformed")
	}
}

func (k *keys) PublicKeyPEM() ([]byte, error) {
	x, err := x509.MarshalPKIXPublicKey(k.public)
	if err != nil {
		return nil, fmt.Errorf("Failed to mashal public key: %s", err)
	}
	pemBlock := pem.Block{Type: "PUBLIC KEY", Bytes: []byte(base64.StdEncoding.EncodeToString(x))}
	return pem.EncodeToMemory(&pemBlock), nil
}
