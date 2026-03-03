package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEd25519Keys(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)

	loadedPub, err := LoadPublicKey(pubHex)
	if err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}

	loadedPriv, err := LoadPrivateKey(privHex)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	if !ed25519.PublicKey(pub).Equal(loadedPub) {
		t.Errorf("Loaded public key doesn't match original")
	}

	if !ed25519.PrivateKey(priv).Equal(loadedPriv) {
		t.Errorf("Loaded private key doesn't match original")
	}
}

func TestEd25519Signature(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	message := []byte("hello, utun!")

	sig := Sign(priv, message)
	if !Verify(pub, message, sig) {
		t.Errorf("Signature verification failed")
	}

	// Test with tampered message
	if Verify(pub, []byte("wrong message"), sig) {
		t.Errorf("Signature verification should have failed for tampered message")
	}
}

func TestEncryption(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	aead, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	plaintext := []byte("Hello, utun!")
	additionalData := []byte("additional data")

	ciphertext := Encrypt(aead, nonce, plaintext, additionalData)
	decrypted, err := Decrypt(aead, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match original plaintext: got %s, want %s", string(decrypted), string(plaintext))
	}

	// Test with wrong additional data
	_, err = Decrypt(aead, nonce, ciphertext, []byte("wrong data"))
	if err == nil {
		t.Error("Decrypt should have failed with wrong additional data")
	}
}
