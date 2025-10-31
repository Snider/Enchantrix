package openpgp

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Service provides OpenPGP functionality.
type Service struct{}

// NewService creates a new OpenPGP service.
func NewService() *Service {
	return &Service{}
}

// GenerateKeyPair creates a new PGP key pair and returns the armored public and private keys.
func (s *Service) GenerateKeyPair(name, email, passphrase string) (publicKey, privateKey string, err error) {
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		RSABits:                4096,
	}
	entity, err := openpgp.NewEntity(name, "", email, config)
	if err != nil {
		return "", "", fmt.Errorf("failed to create new entity: %w", err)
	}

	// Add a subkey for encryption
	err = entity.AddEncryptionSubkey(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to add encryption subkey: %w", err)
	}

	// Encrypt the private key
	if passphrase != "" {
		err = entity.PrivateKey.Encrypt([]byte(passphrase))
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
		}
	}

	var pubKeyBuf, privKeyBuf bytes.Buffer
	pubKeyWriter, err := armor.Encode(&pubKeyBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", err
	}
	privKeyWriter, err := armor.Encode(&privKeyBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", err
	}

	err = entity.Serialize(pubKeyWriter)
	if err != nil {
		return "", "", err
	}
	pubKeyWriter.Close()

	err = entity.SerializePrivate(privKeyWriter, nil)
	if err != nil {
		return "", "", err
	}
	privKeyWriter.Close()

	return pubKeyBuf.String(), privKeyBuf.String(), nil
}

// AddSubkey adds a new subkey to an existing key pair.
func (s *Service) AddSubkey(privateKey, passphrase string) (updatedPrivateKey string, err error) {
	entity, err := readArmoredEntity(privateKey)
	if err != nil {
		return "", err
	}

	if entity.PrivateKey.Encrypted {
		err = entity.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return "", fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	config := &packet.Config{RSABits: 2048, DefaultHash: crypto.SHA256}
	err = entity.AddEncryptionSubkey(config)
	if err != nil {
		return "", fmt.Errorf("failed to add encryption subkey: %w", err)
	}

	// If the key was encrypted, re-encrypt it with the new subkey.
	if entity.PrivateKey.Encrypted {
		err = entity.PrivateKey.Encrypt([]byte(passphrase))
		if err != nil {
			return "", fmt.Errorf("failed to re-encrypt private key: %w", err)
		}
	}

	var privKeyBuf bytes.Buffer
	privKeyWriter, err := armor.Encode(&privKeyBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create private key armor writer: %w", err)
	}
	err = entity.SerializePrivate(privKeyWriter, nil)
	if err != nil {
		return "", fmt.Errorf("failed to serialize private key: %w", err)
	}
	privKeyWriter.Close()
	updatedPrivateKey = privKeyBuf.String()

	return updatedPrivateKey, nil
}

// EncryptPGP encrypts data for a recipient, optionally signing it.
func (s *Service) EncryptPGP(writer io.Writer, recipientPath, data string, signerPath, signerPassphrase *string) error {
	recipientFile, err := os.Open(recipientPath)
	if err != nil {
		return fmt.Errorf("failed to open recipient public key file: %w", err)
	}
	defer recipientFile.Close()

	recipient, err := openpgp.ReadArmoredKeyRing(recipientFile)
	if err != nil {
		return fmt.Errorf("failed to read recipient public key ring: %w", err)
	}

	var signer *openpgp.Entity
	if signerPath != nil {
		signerFile, err := os.Open(*signerPath)
		if err != nil {
			return fmt.Errorf("failed to open signer private key file: %w", err)
		}
		defer signerFile.Close()

		signerRing, err := openpgp.ReadArmoredKeyRing(signerFile)
		if err != nil {
			return fmt.Errorf("failed to read signer key ring: %w", err)
		}
		signer = signerRing[0]

		if signer.PrivateKey.Encrypted {
			if signerPassphrase == nil {
				return fmt.Errorf("signer key is encrypted but no passphrase was provided")
			}
			err = signer.PrivateKey.Decrypt([]byte(*signerPassphrase))
			if err != nil {
				return fmt.Errorf("failed to decrypt signer key: %w", err)
			}
		}
	}

	plaintext, err := openpgp.Encrypt(writer, recipient, signer, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %w", err)
	}

	_, err = io.Copy(plaintext, strings.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to write data to encryption writer: %w", err)
	}

	return plaintext.Close()
}

// DecryptPGP decrypts a PGP message, optionally verifying the signature.
func (s *Service) DecryptPGP(recipientPath, message, passphrase string, signerPath *string) (string, error) {
	recipientFile, err := os.Open(recipientPath)
	if err != nil {
		return "", fmt.Errorf("failed to open recipient private key file: %w", err)
	}
	defer recipientFile.Close()

	recipientRing, err := openpgp.ReadArmoredKeyRing(recipientFile)
	if err != nil {
		return "", fmt.Errorf("failed to read recipient key ring: %w", err)
	}
	recipient := recipientRing[0]

	if recipient.PrivateKey.Encrypted {
		err = recipient.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return "", fmt.Errorf("failed to decrypt recipient key: %w", err)
		}
	}

	var signer openpgp.EntityList
	if signerPath != nil {
		signerFile, err := os.Open(*signerPath)
		if err != nil {
			return "", fmt.Errorf("failed to open signer public key file: %w", err)
		}
		defer signerFile.Close()

		signer, err = openpgp.ReadArmoredKeyRing(signerFile)
		if err != nil {
			return "", fmt.Errorf("failed to read signer key ring: %w", err)
		}
	}

	var md *openpgp.MessageDetails
	if signer != nil {
		md, err = openpgp.ReadMessage(strings.NewReader(message), recipientRing, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(passphrase), nil
		}, nil)
	} else {
		md, err = openpgp.ReadMessage(strings.NewReader(message), recipientRing, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(passphrase), nil
		}, nil)
	}
	if err != nil {
		return "", fmt.Errorf("failed to read message: %w", err)
	}

	if signer != nil {
		if md.Signature == nil {
			return "", fmt.Errorf("message is not signed, but a signer was provided")
		}
		hash := md.Signature.Hash.New()
		io.Copy(hash, md.UnverifiedBody)
		err = signer[0].PrimaryKey.VerifySignature(hash, md.Signature)
		if err != nil {
			return "", fmt.Errorf("signature verification failed: %w", err)
		}
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("failed to read plaintext: %w", err)
	}

	return string(plaintext), nil
}

func readArmoredEntity(armoredKey string) (*openpgp.Entity, error) {
	in := strings.NewReader(armoredKey)
	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}
