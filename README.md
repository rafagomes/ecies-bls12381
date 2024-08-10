# Package ecies-bls12381

[![GoDoc](https://pkg.go.dev/badge/github.com/rafagomes/ecies-bls12381)](https://pkg.go.dev/github.com/rafagomes/ecies-bls12381)
[![codecov](https://codecov.io/github/rafagomes/ecies-bls12381/graph/badge.svg?token=6BDB7436C1)](https://codecov.io/github/rafagomes/ecies-bls12381)
[![Go Report Card](https://goreportcard.com/badge/github.com/rafagomes/ecies-bls12381)](https://goreportcard.com/report/github.com/rafagomes/ecies-bls12381)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`ecies-bls12381` is a Go package that simplifies keypair generation, encryption, and decryption using Elliptic Curve Integrated Encryption Scheme (ECIES) with the BLS12381 elliptic curve. It leverages the Kyber cryptographic library for secure operations, making it easy for developers to integrate robust cryptographic functionalities into their applications. Suitable for proxy re-encryption.

This package is built on top of the [github.com/drand/kyber](https://github.com/drand/kyber) library, which provides a high-level API for cryptographic operations. The BLS12381 elliptic curve is a pairing-friendly curve that is widely used in cryptographic applications, including proxy re-encryption and secure data sharing.

## Key Features

- **Key Pair Generation:** Generate secure elliptic curve key pairs.
- **Public Key Derivation:** Derive public keys from private keys.
- **Message Encryption:** Encrypt messages securely using public keys.
- **Message Decryption:** Decrypt messages using corresponding private keys.
- **Proxy Re-Encryption Support:** Suitable for use cases involving proxy re-encryption for secure data sharing.

## Installation

To install the package, run:

```sh
go get github.com/rafagomes/ecies-bls12381
```

## Usage

### Import the package

```go
import (
    "github.com/rafagomes/ecies-bls12381"
)
```

### Example code

```go
package main

import (
    "fmt"
    "github.com/rafagomes/ecies-bls12381"
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
```
This can also be found in the [example](example) directory.
<!-- TODO: CREATE THE PROXY REENCRYPTION EXAMPLE -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
