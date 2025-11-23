
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

var (
	openpgpNewEntity                    = openpgp.NewEntity
	openpgpReadArmoredKeyRing           = openpgp.ReadArmoredKeyRing
	openpgpEncrypt                      = openpgp.Encrypt
	openpgpReadMessage                  = openpgp.ReadMessage
	openpgpArmoredDetachSign            = openpgp.ArmoredDetachSign
	openpgpCheckArmoredDetachedSignature = openpgp.CheckArmoredDetachedSignature
	openpgpSymmetricallyEncrypt         = openpgp.SymmetricallyEncrypt
	armorEncode                         = armor.Encode
)

// NewService creates a new PGP Service.
func NewService() *Service {
	return &Service{}
}

// GenerateKeyPair generates a new PGP key pair.
func (s *Service) GenerateKeyPair(name, email, comment string) (publicKey, privateKey []byte, err error) {
	entity, err := openpgpNewEntity(name, comment, email, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new entity: %w", err)
	}

	// Sign all the identities
	for _, id := range entity.Identities {
		_ = id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
	}

	// Public Key
	pubKeyBuf := new(bytes.Buffer)
	pubKeyWriter, err := armorEncode(pubKeyBuf, openpgp.PublicKeyType, nil)
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
	privKeyWriter, err := armorEncode(privKeyBuf, openpgp.PrivateKeyType, nil)
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
	keyring, err := openpgpReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key ring: %w", err)
	}

	buf := new(bytes.Buffer)
	w, err := openpgpEncrypt(buf, keyring, nil, nil, nil)
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
	keyring, err := openpgpReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key ring: %w", err)
	}

	buf := bytes.NewReader(ciphertext)
	md, err := openpgpReadMessage(buf, keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read plaintext: %w", err)
	}

	return plaintext, nil
}

// Sign creates a detached signature for a message.
func (s *Service) Sign(privateKey, data []byte) ([]byte, error) {
	privKeyReader := bytes.NewReader(privateKey)
	keyring, err := openpgpReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key ring: %w", err)
	}

	signer := keyring[0]
	if signer.PrivateKey == nil {
		return nil, fmt.Errorf("private key not found in keyring")
	}

	buf := new(bytes.Buffer)
	err = openpgpArmoredDetachSign(buf, signer, bytes.NewReader(data), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return buf.Bytes(), nil
}

// Verify verifies a detached signature for a message.
func (s *Service) Verify(publicKey, data, signature []byte) error {
	pubKeyReader := bytes.NewReader(publicKey)
	keyring, err := openpgpReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return fmt.Errorf("failed to read public key ring: %w", err)
	}

	_, err = openpgpCheckArmoredDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(signature), nil)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	return nil
}

// SymmetricallyEncrypt encrypts data with a passphrase.
func (s *Service) SymmetricallyEncrypt(passphrase, data []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	buf := new(bytes.Buffer)
	w, err := openpgpSymmetricallyEncrypt(buf, passphrase, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric encryption writer: %w", err)
	}
	defer w.Close()

	_, err = w.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to symmetric encryption writer: %w", err)
	}
	w.Close()

	return buf.Bytes(), nil
}

// SymmetricallyDecrypt decrypts data with a passphrase.
func (s *Service) SymmetricallyDecrypt(passphrase, ciphertext []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	buf := bytes.NewReader(ciphertext)
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if failed {
			return nil, fmt.Errorf("decryption failed")
		}
		failed = true
		return passphrase, nil
	}

	md, err := openpgpReadMessage(buf, nil, prompt, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read plaintext: %w", err)
	}

	return plaintext, nil
}
