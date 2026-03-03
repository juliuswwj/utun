package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"
)

const (
	HeaderData      = 0x43
	HeaderHandshake = 0x81
	HeaderSize      = 1 + 8 // 1 byte header + 8 byte SessionID/Timestamp
	NonceSize       = 12
	MaxPadding      = 256
	MinPacketSize   = HeaderSize + NonceSize + 1
)

var (
	ErrPacketTooShort = errors.New("packet too short")
	ErrInvalidHeader  = errors.New("invalid packet header")
)

// CreateHandshake creates a signed handshake packet.
func CreateHandshake(priv ed25519.PrivateKey) []byte {
	packet := make([]byte, 1+8+64)
	packet[0] = HeaderHandshake
	
	ts := time.Now().Unix()
	for i := 0; i < 8; i++ {
		packet[1+i] = byte(ts >> (i * 8))
	}

	sig := ed25519.Sign(priv, packet[1:9])
	copy(packet[9:], sig)
	return packet
}

// VerifyHandshake verifies a handshake packet against a public key.
func VerifyHandshake(data []byte, pub ed25519.PublicKey) bool {
	if len(data) < 73 || data[0] != HeaderHandshake {
		return false
	}
	var ts int64
	for i := 0; i < 8; i++ {
		ts |= int64(data[1+i]) << (i * 8)
	}

	now := time.Now().Unix()
	if now-ts > 30 || ts-now > 30 {
		return false
	}

	return ed25519.Verify(pub, data[1:9], data[9:73])
}

// Seal encapsulates the payload into an obfuscated UDP packet.
func Seal(sessionID uint64, nonce, payload []byte) ([]byte, error) {
	padLenB := make([]byte, 1)
	rand.Read(padLenB)
	actualPadLen := int(padLenB[0])

	totalLen := HeaderSize + NonceSize + len(payload) + actualPadLen + 1
	packet := make([]byte, totalLen)
	packet[0] = HeaderData
	
	for i := 0; i < 8; i++ {
		packet[1+i] = byte(sessionID >> (i * 8))
	}
	copy(packet[HeaderSize:], nonce)
	copy(packet[HeaderSize+NonceSize:], payload)
	
	paddingStart := HeaderSize + NonceSize + len(payload)
	rand.Read(packet[paddingStart : paddingStart+actualPadLen])
	packet[totalLen-1] = byte(actualPadLen)

	return packet, nil
}

// Unseal extracts the sessionID, nonce and encrypted payload.
func Unseal(data []byte) (uint64, []byte, []byte, error) {
	if len(data) < MinPacketSize {
		return 0, nil, nil, ErrPacketTooShort
	}
	if data[0] != HeaderData {
		return 0, nil, nil, ErrInvalidHeader
	}
	var sessionID uint64
	for i := 0; i < 8; i++ {
		sessionID |= uint64(data[1+i]) << (i * 8)
	}
	nonce := data[HeaderSize : HeaderSize+NonceSize]
	padLen := int(data[len(data)-1])
	payloadEnd := len(data) - 1 - padLen
	if payloadEnd < HeaderSize+NonceSize {
		return 0, nil, nil, errors.New("invalid padding")
	}
	payload := data[HeaderSize+NonceSize : payloadEnd]
	return sessionID, nonce, payload, nil
}
