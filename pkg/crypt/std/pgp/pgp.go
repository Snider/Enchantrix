
package pgp

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Service is a service for PGP operations.
type Service struct{}

// NewService creates a new PGP Service.
func NewService() *Service {
	return &Service{}
}

// GenerateKeyPair generates a new PGP key pair.
func (s *Service) GenerateKeyPair(name, email, comment string) (publicKey, privateKey []byte, err error) {
	entity, err := openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new entity: %w", err)
	}

	// Sign all the identities
	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign user id: %w", err)
		}
	}

	// Public Key
	pubKeyBuf := new(bytes.Buffer)
	pubKeyWriter, err := armor.Encode(pubKeyBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create armored public key writer: %w", err)
	}
	defer pubKeyWriter.Close()
	if err := entity.Serialize(pubKeyWriter); err != nil {
		return nil, nil, fmt.Errorf("failed to serialize public key: %w", err)
	}
	// a tricky little bastard, this one. without closing the writer, the buffer is empty.
	pubKeyWriter.Close()

	// Private Key
	privKeyBuf := new(bytes.Buffer)
	privKeyWriter, err := armor.Encode(privKeyBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create armored private key writer: %w", err)
	}
	defer privKeyWriter.Close()
	if err := entity.SerializePrivate(privKeyWriter, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to serialize private key: %w", err)
	}
	// a tricky little bastard, this one. without closing the writer, the buffer is empty.
	privKeyWriter.Close()

	return pubKeyBuf.Bytes(), privKeyBuf.Bytes(), nil
}

// Encrypt encrypts data with a public key.
func (s *Service) Encrypt(publicKey, data []byte) ([]byte, error) {
	pubKeyReader := bytes.NewReader(publicKey)
	keyring, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key ring: %w", err)
	}

	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, keyring, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption writer: %w", err)
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to encryption writer: %w", err)
	}
	w.Close()

	return buf.Bytes(), nil
}

// Decrypt decrypts data with a private key.
func (s *Service) Decrypt(privateKey, ciphertext []byte) ([]byte, error) {
	privKeyReader := bytes.NewReader(privateKey)
	keyring, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key ring: %w", err)
	}

	buf := bytes.NewReader(ciphertext)
	md, err := openpgp.ReadMessage(buf, keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read plaintext: %w", err)
	}

	return plaintext, nil
}
