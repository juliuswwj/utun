package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// GenerateKeyPair generates a new Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// LoadPrivateKey loads a private key from a hex-encoded string.
func LoadPrivateKey(hexStr string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// LoadPublicKey loads a public key from a hex-encoded string.
func LoadPublicKey(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// SaveKeyToFile saves a key to a file as a hex-encoded string.
func SaveKeyToFile(filePath string, key []byte) error {
	return os.WriteFile(filePath, []byte(hex.EncodeToString(key)), 0600)
}

// LoadKeyFromFile loads a key from a file.
func LoadKeyFromFile(filePath string) ([]byte, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(b))
}

// Sign signs a message using the private key.
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify verifies a signature against a message and public key.
func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}
