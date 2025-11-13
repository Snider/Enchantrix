package examples_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExample_Checksums(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./checksums"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_Hash(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./hash"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_PGPEncryptDecrypt(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./pgp_encrypt_decrypt"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_PGPGenerateKeys(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./pgp_generate_keys"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_PGPSignVerify(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./pgp_sign_verify"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_PGPSymmetricEncrypt(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./pgp_symmetric_encrypt"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}

func TestExample_RSA(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = "./rsa"
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, string(out))
}
