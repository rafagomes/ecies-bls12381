package eciesbls12381

import (
	"math/big"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ecies"
	"github.com/drand/kyber/util/random"
	"golang.org/x/crypto/sha3"
)

type ECPoint struct {
	X, Y *big.Int
}

var suite kyber.Group = bls.NewBLS12381Suite().G2()

// GenerateECPrivateKey generates a new elliptic curve private key.
func GenerateECPrivateKey() kyber.Scalar {
	privateKey := suite.Scalar().Pick(random.New())
	return privateKey
}

// GenerateECKeypair generates a new elliptic curve key pair.
func GenerateECKeypair() (kyber.Point, kyber.Scalar) {
	privateKey := GenerateECPrivateKey()
	publicKey := suite.Point().Mul(privateKey, nil)
	return publicKey, privateKey
}

// GetECPublicKeyFromPrivateKey derives the public key from a given private key.
func GetECPublicKeyFromPrivateKey(privateKey kyber.Scalar) kyber.Point {
	return suite.Point().Mul(privateKey, nil)
}

// EncryptWithEC encrypts a message using the recipient's public key.
func EncryptWithEC(publicKey kyber.Point, message []byte) ([]byte, error) {
	ciphertext, err := ecies.Encrypt(suite, publicKey, message, sha3.New256)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithEC decrypts a ciphertext using the recipient's private key.
func DecryptWithEC(privateKey kyber.Scalar, ciphertext []byte) ([]byte, error) {
	plaintext, err := ecies.Decrypt(suite, privateKey, ciphertext, sha3.New256)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
