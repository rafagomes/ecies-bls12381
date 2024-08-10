package main

import (
	"fmt"

	eciesbls12381 "github.com/rafagomes/ecies-bls12381"
)

func main() {
	// Generate key pair
	publicKey, privateKey := eciesbls12381.GenerateECKeypair()
	fmt.Println("Public Key:", publicKey)
	fmt.Println("Private Key:", privateKey)

	// Encrypt a message
	message := []byte("Hello, BLS12381!")
	ciphertext, err := eciesbls12381.EncryptWithEC(publicKey, message)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Println("Ciphertext:", ciphertext)

	// Decrypt the message
	plaintext, err := eciesbls12381.DecryptWithEC(privateKey, ciphertext)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Println("Plaintext:", string(plaintext))
}
