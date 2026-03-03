package router

import (
	"errors"
	"net"
	"strings"
	"sync"
	"utun/pkg/transport"
)

// RouteEntry represents a subnet route.
type RouteEntry struct {
	Network *net.IPNet
	Session *transport.Session
}

// Router handles L3 packet forwarding between peers and subnets.
type Router struct {
	sm      *transport.SessionManager
	mu      sync.RWMutex
	subnets []RouteEntry // Longest prefix match will be performed
}

func NewRouter(sm *transport.SessionManager) *Router {
	return &Router{sm: sm}
}

// AddSubnet adds a subnet route to the router.
func (r *Router) AddSubnet(cidr string, session *transport.Session) error {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if already exists, update if it does
	for i, entry := range r.subnets {
		if entry.Network.String() == ipnet.String() {
			r.subnets[i].Session = session
			return nil
		}
	}

	r.subnets = append(r.subnets, RouteEntry{Network: ipnet, Session: session})
	return nil
}

// Route determines the destination session for a given IP packet.
func (r *Router) Route(packet []byte) (*transport.Session, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short")
	}

	dstIPRaw := net.IPv4(packet[16], packet[17], packet[18], packet[19])
	dstIPStr := dstIPRaw.String()

	// 1. Direct Peer Lookup (Static IP)
	if session, ok := r.sm.GetByIP(dstIPStr); ok {
		return session, nil
	}

	// 2. Subnet Lookup (Longest Prefix Match)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestMatch *RouteEntry
	bestMaskLen := -1

	for _, entry := range r.subnets {
		if entry.Network.Contains(dstIPRaw) {
			maskLen, _ := entry.Network.Mask.Size()
			if maskLen > bestMaskLen {
				bestMaskLen = maskLen
				bestMatch = &entry
			}
		}
	}

	if bestMatch != nil {
		return bestMatch.Session, nil
	}

	return nil, errors.New("no route for destination IP: " + dstIPStr)
}

// HasRoute checks if the router knows how to reach the given IP.
// This includes direct peers and subnets.
func (r *Router) HasRoute(ip net.IP) bool {
	ipStr := ip.String()
	
	// Check direct peers
	if _, ok := r.sm.GetByIP(ipStr); ok {
		return true
	}

	// Check subnets
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.subnets {
		if entry.Network.Contains(ip) {
			return true
		}
	}

	return false
}

// GetSrcIP extracts the source IP from an IPv4 packet.
func GetSrcIP(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", errors.New("packet too short")
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15]).String(), nil
}

// GetDstIP extracts the destination IP from an IPv4 packet.
func GetDstIP(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", errors.New("packet too short")
	}
	return net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(), nil
}
