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
	Network   *net.IPNet
	SessionID uint64
}

// Router handles L3 packet forwarding between peers and subnets.
type Router struct {
	sm      *transport.SessionManager
	mu      sync.RWMutex
	subnets []RouteEntry 
}

func NewRouter(sm *transport.SessionManager) *Router {
	return &Router{sm: sm}
}

// AddSubnet adds a subnet route to the router.
func (r *Router) AddSubnet(cidr string, sessionID uint64) error {
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
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
			r.subnets[i].SessionID = sessionID
			return nil
		}
	}

	r.subnets = append(r.subnets, RouteEntry{Network: ipnet, SessionID: sessionID})
	return nil
}

// Route determines the destination session for a given IP packet.
func (r *Router) Route(packet []byte) (*transport.Session, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short")
	}

	version := packet[0] >> 4
	var dstIP net.IP

	if version == 4 {
		dstIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	} else if version == 6 {
		if len(packet) < 40 {
			return nil, errors.New("ipv6 packet too short")
		}
		dstIP = make(net.IP, 16)
		copy(dstIP, packet[24:40])
	} else {
		return nil, errors.New("unsupported IP version")
	}

	dstIPStr := dstIP.String()

	// 1. Direct Peer Lookup (Static IP)
	if session, ok := r.sm.GetByIP(dstIPStr); ok {
		return session, nil
	}

	// 2. Subnet Lookup (Longest Prefix Match)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestMatchID uint64
	found := false
	bestMaskLen := -1

	for i := range r.subnets {
		entry := &r.subnets[i]
		if entry.Network.Contains(dstIP) {
			maskLen, _ := entry.Network.Mask.Size()
			if maskLen > bestMaskLen {
				bestMaskLen = maskLen
				bestMatchID = entry.SessionID
				found = true
			}
		}
	}

	if found {
		if session, ok := r.sm.GetByID(bestMatchID); ok {
			return session, nil
		}
	}

	return nil, errors.New("no route for destination IP: " + dstIPStr)
}

// HasRoute checks if the router knows how to reach the given IP.
func (r *Router) HasRoute(ip net.IP) bool {
	ipStr := ip.String()
	if _, ok := r.sm.GetByIP(ipStr); ok {
		return true
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.subnets {
		if entry.Network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetSrcIP extracts the source IP from an IP packet.
func GetSrcIP(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", errors.New("packet too short")
	}
	version := packet[0] >> 4
	if version == 4 {
		return net.IPv4(packet[12], packet[13], packet[14], packet[15]).String(), nil
	} else if version == 6 {
		if len(packet) < 40 {
			return "", errors.New("ipv6 packet too short")
		}
		src := make(net.IP, 16)
		copy(src, packet[8:24])
		return src.String(), nil
	}
	return "", errors.New("unsupported IP version")
}

// GetDstIP extracts the destination IP from an IP packet.
func GetDstIP(packet []byte) (string, error) {
	if len(packet) < 20 {
		return "", errors.New("packet too short")
	}
	version := packet[0] >> 4
	if version == 4 {
		return net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(), nil
	} else if version == 6 {
		if len(packet) < 40 {
			return "", errors.New("ipv6 packet too short")
		}
		dst := make(net.IP, 16)
		copy(dst, packet[24:40])
		return dst.String(), nil
	}
	return "", errors.New("unsupported IP version")
}
