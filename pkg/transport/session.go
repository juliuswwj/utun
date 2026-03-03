package transport

import (
	"crypto/cipher"
	"net"
	"sync"
	"time"
)

// Session represents an active secure connection with a peer.
type Session struct {
	ID          uint64
	RemoteAddrs []*net.UDPAddr // Support multiple paths (multiple server ports)
	Cipher      cipher.AEAD
	LastSeen    time.Time
	StaticIP    string
	PublicKey   []byte
}

// SessionManager handles session lifecycle and lookup.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint64]*Session
	peers    map[string]*Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint64]*Session),
		peers:    make(map[string]*Session),
	}
}

func (sm *SessionManager) Add(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.ID] = session
	if session.StaticIP != "" {
		sm.peers[session.StaticIP] = session
	}
}

func (sm *SessionManager) GetByID(id uint64) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

func (sm *SessionManager) GetByIP(ip string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.peers[ip]
	return s, ok
}

func (sm *SessionManager) UpdateActivity(id uint64, addr *net.UDPAddr) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[id]; ok {
		s.LastSeen = time.Now()
		
		// For server: update the single active path
		// For client: keep the predefined paths, but maybe track the 'last working' one
		found := false
		for i, existing := range s.RemoteAddrs {
			if existing.String() == addr.String() {
				// Move to front (LRU-like)
				s.RemoteAddrs[0], s.RemoteAddrs[i] = s.RemoteAddrs[i], s.RemoteAddrs[0]
				found = true
				break
			}
		}
		if !found {
			if len(s.RemoteAddrs) == 0 {
				s.RemoteAddrs = append(s.RemoteAddrs, addr)
			} else {
				// Server mode: Update current remote addr
				s.RemoteAddrs[0] = addr
			}
		}
	}
}

func (sm *SessionManager) RemoveExpired(timeout time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	for id, s := range sm.sessions {
		if now.Sub(s.LastSeen) > timeout {
			delete(sm.sessions, id)
			if s.StaticIP != "" {
				delete(sm.peers, s.StaticIP)
			}
		}
	}
}
