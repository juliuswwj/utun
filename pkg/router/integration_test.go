package router

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
	"utun/pkg/config"
	"utun/pkg/crypto"
	"utun/pkg/transport"
	"utun/pkg/tun"
)

type clientBundle struct {
	mockTun  *tun.MockDevice
	listener *transport.MultiPortListener
	engine   *Engine
}

func TestFullSystemIntegration(t *testing.T) {
	// 1. Prepare Keys
	pub1, priv1, _ := crypto.GenerateKeyPair()
	pub2, priv2, _ := crypto.GenerateKeyPair()
	
	pub1Hex := hex.EncodeToString(pub1)
	pub2Hex := hex.EncodeToString(pub2)

	// 2. Setup Server Config with new format
	configContent := fmt.Sprintf(`
ports=10000,10001
ip=10.8.8.1/24
tun=utun_test
10.8.8.2=%s
10.8.8.3=%s
`, pub1Hex, pub2Hex)
	
	configFile := "test_integration.cfg"
	os.WriteFile(configFile, []byte(configContent), 0644)
	defer os.Remove(configFile)

	cfgMgr, err := config.NewManager(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// 3. Start Server with fixed ports for test stability
	serverSm := transport.NewSessionManager()
	serverRouter := NewRouter(serverSm)
	serverTun := tun.NewMockDevice()
	serverEngine := NewEngine(serverTun, serverRouter, serverSm, cfgMgr)
	
	// Use dynamic ports 0,0 but we need to know what they are
	serverListener := transport.NewMultiPortListener([]int{0, 0}) 
	serverListener.Start()
	defer serverListener.Stop()
	serverEngine.SetListener(serverListener)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverEngine.Start(ctx)
	
	// Get both server addresses
	serverAddrs := serverListener.AllLocalAddrs()
	serverAddr1 := serverAddrs[0]
	serverAddr2 := serverAddrs[1]

	// 4. Setup Clients (with CIDR and multi-server-addrs)
	client1 := setupClient(t, ctx, "10.8.8.2/24", priv1, serverAddrs)
	client2 := setupClient(t, ctx, "10.8.8.3/24", priv2, serverAddrs)

	// 5. Perform Handshakes
	sendHandshake(client1.listener, priv1, serverAddr1)
	sendHandshake(client2.listener, priv2, serverAddr2)

	// Wait for handshakes to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify Server has both sessions
	if _, ok := serverSm.GetByIP("10.8.8.2"); !ok {
		t.Fatal("Server failed to establish session for Client 1")
	}
	if _, ok := serverSm.GetByIP("10.8.8.3"); !ok {
		t.Fatal("Server failed to establish session for Client 2")
	}

	// 6. Data Plane Test: Client 1 -> Client 2 (Multi-Path)
	testData := []byte("SECURE PING via multi-server-ports")
	// Manual IP Packet (minimal)
	ipPacket := make([]byte, 20+len(testData))
	ipPacket[0] = 0x45
	ipPacket[9] = 17 // UDP (not strictly checked by router but good for realism)
	copy(ipPacket[12:16], net.ParseIP("10.8.8.2").To4())
	copy(ipPacket[16:20], net.ParseIP("10.8.8.3").To4())
	copy(ipPacket[20:], testData)

	fmt.Println("Client 1 sending encrypted packet jumping between server ports...")
	for i := 0; i < 5; i++ {
		client1.mockTun.ReadChan <- ipPacket
		
		select {
		case received := <-client2.mockTun.WriteChan:
			if string(received[20:]) != string(testData) {
				t.Errorf("Data corruption: got %s, want %s", string(received[20:]), string(testData))
			}
		case <-time.After(500 * time.Millisecond):
			t.Errorf("Timed out on iteration %d", i)
		}
	}
	fmt.Println("SUCCESS: Data flowed correctly across multiple server ports")

	// 8. Test Socket Rotation
	fmt.Println("Testing Client 1 socket rotation...")
	oldAddrs := client1.listener.AllLocalAddrs()
	client1.listener.RotateOne()
	newAddrs := client1.listener.AllLocalAddrs()
	
	if len(newAddrs) != len(oldAddrs) {
		t.Error("Socket count changed after rotation")
	}
	
	// Send new handshake from rotated socket
	sendHandshake(client1.listener, priv1, serverAddr1)
	time.Sleep(100 * time.Millisecond)
	
	// Send data from rotated socket
	client1.mockTun.ReadChan <- ipPacket
	select {
	case <-client2.mockTun.WriteChan:
		fmt.Println("SUCCESS: Data flowed after client socket rotation")
	case <-time.After(500 * time.Millisecond):
		t.Error("Data failed after rotation")
	}
}

func setupClient(t *testing.T, ctx context.Context, ipCIDR string, priv ed25519.PrivateKey, serverAddrs []*net.UDPAddr) *clientBundle {
	mockTun := tun.NewMockDevice()
	sm := transport.NewSessionManager()
	r := NewRouter(sm)
	
	_, ipnet, _ := net.ParseCIDR(ipCIDR)
	pub := priv.Public().(ed25519.PublicKey)
	sessionID := binary.BigEndian.Uint64(pub[:8])
	
	ciph, _ := crypto.NewCipher(pub)

	serverSession := &transport.Session{
		ID:          sessionID,
		RemoteAddrs: serverAddrs,
		Cipher:      ciph,
		LastSeen:    time.Now(),
		StaticIP:    "10.8.8.1",
	}
	sm.Add(serverSession)
	r.AddSubnet(ipnet.String(), serverSession)
	
	engine := NewEngine(mockTun, r, sm, nil)
	listener := transport.NewMultiPortListener([]int{0, 0})
	listener.Start()
	engine.SetListener(listener)
	engine.Start(ctx)
	
	return &clientBundle{mockTun, listener, engine}
}

func sendHandshake(l *transport.MultiPortListener, priv ed25519.PrivateKey, serverAddr *net.UDPAddr) {
	hs := transport.CreateHandshake(priv)
	l.WriteTo(hs, serverAddr)
}
