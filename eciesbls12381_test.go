package eciesbls12381

import (
	"bytes"
	"testing"
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
	publicKey := GetECPublicKeyFromPrivateKey(privateKey)
	if publicKey == nil {
		t.Error("Failed to derive public key from private key")
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
