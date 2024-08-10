package eciesbls12381

import (
	"bytes"
	"errors"
	"testing"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

// TestGenerateECPrivateKey tests the GenerateECPrivateKey function.
func TestGenerateECPrivateKey(t *testing.T) {
	privateKey := GenerateECPrivateKey()
	if privateKey == nil {
		t.Error("Failed to generate private key")
	}
}

// TestGenerateECKeypair tests the GenerateECKeypair function.
func TestGenerateECKeypair(t *testing.T) {
	publicKey, privateKey := GenerateECKeypair()
	if publicKey == nil || privateKey == nil {
		t.Error("Failed to generate key pair")
	}
}

// TestGetECPublicKeyFromPrivateKey tests the GetECPublicKeyFromPrivateKey function.
func TestGetECPublicKeyFromPrivateKey(t *testing.T) {
	_, privateKey := GenerateECKeypair()
	publicKey, err := GetECPublicKeyFromPrivateKey(privateKey)
	if err != nil || publicKey == nil {
		t.Error("Failed to derive public key from private key")
	}

	_, err = GetECPublicKeyFromPrivateKey(nil)
	if err == nil {
		t.Error("Expected an error when private key is nil")
	}
}

// TestEncryptWithECAndDecryptWithEC tests the EncryptWithEC and DecryptWithEC functions.
func TestEncryptWithECAndDecryptWithEC(t *testing.T) {
	publicKey, privateKey := GenerateECKeypair()
	message := []byte("Hello, BLS12381!")

	ciphertext, err := EncryptWithEC(publicKey, message)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	plaintext, err := DecryptWithEC(privateKey, ciphertext)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Errorf("Decrypted message does not match original. Got %s, want %s", string(plaintext), string(message))
	}
}

// TestInvalidDecryptWithEC tests DecryptWithEC with an invalid private key.
func TestInvalidDecryptWithEC(t *testing.T) {
	publicKey, _ := GenerateECKeypair()
	message := []byte("Hello, BLS12381!")

	ciphertext, err := EncryptWithEC(publicKey, message)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	_, invalidPrivateKey := GenerateECKeypair()
	plaintext, err := DecryptWithEC(invalidPrivateKey, ciphertext)
	if err == nil {
		t.Error("Decryption should have failed with an invalid private key")
	}

	if plaintext != nil {
		t.Errorf("Decryption should have returned nil, got %s", string(plaintext))
	}
}

// TestEncryptWithECError tests EncryptWithEC to cover error handling.
func TestEncryptWithECError(t *testing.T) {
	// Test with nil public key
	message := []byte("Hello, BLS12381!")
	_, err := EncryptWithEC(nil, message)
	if err == nil {
		t.Error("Expected an error when public key is nil")
	}

	// Test with nil message
	publicKey, _ := GenerateECKeypair()
	_, err = EncryptWithEC(publicKey, nil)
	if err == nil {
		t.Error("Expected an error when message is nil")
	}
}

// TestDecryptWithECError tests DecryptWithEC to cover error handling.
func TestDecryptWithECError(t *testing.T) {
	// Test with nil private key
	ciphertext := []byte("encrypted message")
	_, err := DecryptWithEC(nil, ciphertext)
	if err == nil {
		t.Error("Expected an error when private key is nil")
	}

	// Test with nil ciphertext
	_, privateKey := GenerateECKeypair()
	_, err = DecryptWithEC(privateKey, nil)
	if err == nil {
		t.Error("Expected an error when ciphertext is nil")
	}
}

// Mocking a faulty encrypt function to force an error
type faultyEncryptSuite struct {
	kyber.Group
}

func (f *faultyEncryptSuite) Point() kyber.Point {
	return &faultyPoint{}
}

type faultyPoint struct {
	kyber.Point
}

func (p *faultyPoint) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	return p
}

func (p *faultyPoint) MarshalBinary() ([]byte, error) {
	return nil, errors.New("forced error")
}

func TestEncryptWithECForcedError(t *testing.T) {
	oldSuite := suite
	defer func() { suite = oldSuite }()
	suite = &faultyEncryptSuite{Group: bls.NewBLS12381Suite().G2()}

	publicKey, _ := GenerateECKeypair()
	message := []byte("Hello, BLS12381!")

	_, err := EncryptWithEC(publicKey, message)
	if err == nil {
		t.Error("Encryption should have failed with a forced error")
	}
}
