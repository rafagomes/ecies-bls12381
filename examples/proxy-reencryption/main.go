package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	eciesbls12381 "github.com/rafagomes/ecies-bls12381"
)

func main() {
	// Generate key pair
	publicKey, privateKey := eciesbls12381.GenerateECKeypair()
	fmt.Println("Public Key:", publicKey)
	fmt.Println("Private Key:", privateKey)

	// Sample message
	message := []byte("Hello, BLS12381!")

	// Generate AES key
	aesKey, err := generateAESKey()
	if err != nil {
		fmt.Println("Error generating AES Key:", err)
		return
	}

	// Encrypt message with AES key
	aesCiphertext, err := encryptWithAES(aesKey, message)
	if err != nil {
		fmt.Println("Error encrypting with AES key:", err)
		return
	}

	// Encrypt AES key with ECIES
	aesKeyciphertext, err := eciesbls12381.EncryptWithEC(publicKey, aesKey)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	// Ref: This is the proxy re-encryption part
	// You can use the encrypted AES when you need without compromising the security of the message
	// eg: {aesEncryptedKey: aesKeyciphertext, message: aesCiphertext}

	// Decrypt AES key with ECIES
	decryptedAESKey, err := eciesbls12381.DecryptWithEC(privateKey, aesKeyciphertext)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	// Decrypt message with decrypted AES key
	decryptedMessage, err := decryptWithAES(decryptedAESKey, aesCiphertext)
	if err != nil {
		fmt.Println("Erorr trying to decrypt with AES Key:", err)
		return
	}

	fmt.Println("Plaintext:", string(decryptedMessage))
}

// generateAESKey generates a new AES key
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}

// encryptWithAES encrypts a message with an AES key
func encryptWithAES(key, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

// decryptWithAES decrypts the given ciphertext using the given key
func decryptWithAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
