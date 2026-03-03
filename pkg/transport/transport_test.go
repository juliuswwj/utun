package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestSealUnseal(t *testing.T) {
	sessionID := uint64(0x1234567890ABCDEF)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	payload := []byte("secret payload")

	// Test multiple times to cover different random padding lengths
	for i := 0; i < 100; i++ {
		packet, err := Seal(sessionID, nonce, payload)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		gotSessionID, gotNonce, gotPayload, err := Unseal(packet)
		if err != nil {
			t.Fatalf("Unseal failed: %v", err)
		}

		if gotSessionID != sessionID {
			t.Errorf("SessionID mismatch: got %x, want %x", gotSessionID, sessionID)
		}

		for i, b := range gotNonce {
			if b != nonce[i] {
				t.Fatalf("Nonce mismatch at index %d", i)
			}
		}

		if string(gotPayload) != string(payload) {
			t.Errorf("Payload mismatch: got %s, want %s", string(gotPayload), string(payload))
		}
	}
}

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()
	s := &Session{
		ID:       1,
		StaticIP: "10.0.0.1",
		LastSeen: time.Now(),
	}

	sm.Add(s)

	if got, ok := sm.GetByID(1); !ok || got != s {
		t.Error("Failed to get session by ID")
	}

	if got, ok := sm.GetByIP("10.0.0.1"); !ok || got != s {
		t.Error("Failed to get session by IP")
	}

	sm.UpdateActivity(1, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	
	sm.RemoveExpired(time.Millisecond) // This should not remove it if we just updated it or if we wait
	time.Sleep(2 * time.Millisecond)
	sm.RemoveExpired(time.Millisecond)
	
	if _, ok := sm.GetByID(1); ok {
		t.Error("Session should have expired")
	}
}

func TestMultiPortListener(t *testing.T) {
	// Use dynamic ports for testing
	l := NewMultiPortListener([]int{0}) // 0 tells OS to choose a port
	if err := l.Start(); err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer l.Stop()

	addr := l.conns[0].LocalAddr().(*net.UDPAddr)
	
	sessionID := uint64(123)
	nonce := make([]byte, NonceSize)
	payload := []byte("test")
	
	packet, _ := Seal(sessionID, nonce, payload)
	
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()
	
	conn.Write(packet)
	
	select {
	case p := <-l.Packets():
		if p.SessionID != sessionID {
			t.Errorf("Got sessionID %d, want %d", p.SessionID, sessionID)
		}
		if string(p.Payload) != "test" {
			t.Errorf("Got payload %s, want test", string(p.Payload))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timed out waiting for packet")
	}
}

func TestHandshakeAckVerification(t *testing.T) {
	// 1. Generate keys for server and two clients (one correct, one "wrong" like the bug)
	serverPub, serverPriv, _ := ed25519.GenerateKey(nil)
	clientPub, _, _ := ed25519.GenerateKey(nil)
	
	clientIP := "10.8.8.2"
	subnets := []string{"192.168.1.0/24"}
	
	// 2. Server creates a signed ACK
	ack := CreateHandshakeAck(serverPriv, clientIP, subnets)
	
	// 3. Test verification with CORRECT server public key (Expected: SUCCESS)
	gotIP, gotSubnets, err := VerifyHandshakeAck(ack, serverPub)
	if err != nil {
		t.Fatalf("HandshakeAck verification failed with correct key: %v", err)
	}
	if gotIP != clientIP {
		t.Errorf("Got IP %s, want %s", gotIP, clientIP)
	}
	if len(gotSubnets) != 1 || gotSubnets[0] != subnets[0] {
		t.Errorf("Got subnets %v, want %v", gotSubnets, subnets)
	}
	
	// 4. Test verification with WRONG public key (Expected: FAILURE)
	// This simulates the bug where the client was using its OWN public key instead of the server's.
	_, _, err = VerifyHandshakeAck(ack, clientPub)
	if err == nil {
		t.Error("HandshakeAck verification SHOULD HAVE FAILED with client public key, but it succeeded")
	} else {
		t.Logf("Correctly failed with wrong key: %v", err)
	}
}
