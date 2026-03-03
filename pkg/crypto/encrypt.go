package crypto

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewCipher creates a new ChaCha20-Poly1305 AEAD cipher.
func NewCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}
	return chacha20poly1305.New(key)
}

// Encrypt encrypts the plaintext using the given AEAD, nonce, and additional data.
func Encrypt(aead cipher.AEAD, nonce, plaintext, additionalData []byte) []byte {
	return aead.Seal(nil, nonce, plaintext, additionalData)
}

// Decrypt decrypts the ciphertext using the given AEAD, nonce, and additional data.
func Decrypt(aead cipher.AEAD, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return aead.Open(nil, nonce, ciphertext, additionalData)
}
