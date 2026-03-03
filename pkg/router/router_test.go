package router

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"utun/pkg/transport"
)

func TestRouter_Route(t *testing.T) {
	sm := transport.NewSessionManager()
	s1 := &transport.Session{ID: 1, StaticIP: "10.0.0.1"}
	sm.Add(s1)

	r := NewRouter(sm)

	// Mock IPv4 packet with Destination 10.0.0.1
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 1

	session, err := r.Route(packet)
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if session.ID != 1 {
		t.Errorf("Wrong session: got %d, want 1", session.ID)
	}
}

func TestRouter_HasRoute(t *testing.T) {
	sm := transport.NewSessionManager()
	s1 := &transport.Session{ID: 1, StaticIP: "10.0.0.1"}
	sm.Add(s1)

	r := NewRouter(sm)
	r.AddSubnet("192.168.1.0/24", s1)

	tests := []struct {
		ip    string
		want  bool
	}{
		{"10.0.0.1", true},    // Peer IP
		{"192.168.1.10", true}, // Subnet IP
		{"10.0.0.2", false},   // Unknown IP
		{"192.168.2.1", false}, // Unknown Subnet
	}

	for _, tt := range tests {
		if got := r.HasRoute(net.ParseIP(tt.ip)); got != tt.want {
			t.Errorf("HasRoute(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// MockEthernetDevice implements EthernetDevice for testing.
type MockEthernetDevice struct {
	In  chan []byte
	Out chan []byte
}

func (m *MockEthernetDevice) WritePacketData(data []byte) error {
	m.Out <- data
	return nil
}

func (m *MockEthernetDevice) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data := <-m.In
	return data, gopacket.CaptureInfo{}, nil
}

func (m *MockEthernetDevice) Close() {}

func TestProxyARP_Dynamic(t *testing.T) {
	hwAddr, _ := net.ParseMAC("00:11:22:33:44:55")
	localIP := net.ParseIP("192.168.0.10")
	sm := transport.NewSessionManager()
	r := NewRouter(sm)
	
	mockDev := &MockEthernetDevice{
		In:  make(chan []byte, 10),
		Out: make(chan []byte, 10),
	}
	pa := NewProxyARP("eth0", hwAddr, localIP, mockDev, r)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pa.Run(ctx)

	// Case 1: Target is unknown, should NOT respond
	targetIP := net.ParseIP("10.0.0.1")
	sendARPRequest(mockDev, targetIP)
	
	select {
	case <-mockDev.Out:
		t.Error("Should not have responded to unknown IP")
	case <-time.After(50 * time.Millisecond):
		// OK
	}

	// Case 2: Server/Peer is added to Router, should NOW respond
	s_server := &transport.Session{ID: 0, StaticIP: "10.0.0.1"}
	sm.Add(s_server)
	
	sendARPRequest(mockDev, targetIP)
	select {
	case replyData := <-mockDev.Out:
		if !isARPReply(replyData, hwAddr) {
			t.Error("Invalid ARP reply for server IP")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timed out waiting for ARP reply for server IP")
	}

	// Case 3: Subnet from another client is added, should NOW respond
	s_other := &transport.Session{ID: 2, StaticIP: "10.0.0.2"}
	sm.Add(s_other)
	r.AddSubnet("172.16.0.0/16", s_other)
	
	subnetIP := net.ParseIP("172.16.1.1")
	sendARPRequest(mockDev, subnetIP)
	select {
	case replyData := <-mockDev.Out:
		if !isARPReply(replyData, hwAddr) {
			t.Error("Invalid ARP reply for subnet IP")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timed out waiting for ARP reply for subnet IP")
	}
}

func sendARPRequest(dev *MockEthernetDevice, target net.IP) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		SourceProtAddress: []byte{192, 168, 0, 50},
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    target.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp)
	dev.In <- buf.Bytes()
}

func isARPReply(data []byte, expectedMAC net.HardwareAddr) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		reply := arpLayer.(*layers.ARP)
		return reply.Operation == layers.ARPReply && bytesEqual(reply.SourceHwAddress, expectedMAC)
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
