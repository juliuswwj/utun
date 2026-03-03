package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
	"utun/pkg/config"
	"utun/pkg/crypto"
	"utun/pkg/transport"
	"utun/pkg/tun"
)

// Engine orchestrates data flow between TUN and UDP with encryption.
type Engine struct {
	tun    tun.TUNDevice
	router *Router
	sm     *transport.SessionManager
	cfg    *config.Manager
	udp    *transport.MultiPortListener
}

func NewEngine(t tun.TUNDevice, r *Router, sm *transport.SessionManager, cfg *config.Manager) *Engine {
	return &Engine{
		tun:    t,
		router: r,
		sm:     sm,
		cfg:    cfg,
	}
}

func (e *Engine) SetListener(l *transport.MultiPortListener) {
	e.udp = l
}

func (e *Engine) Start(ctx context.Context) error {
	go e.tunToUDP(ctx)
	if e.udp != nil {
		go e.udpToTUN(ctx)
	}
	return nil
}

func (e *Engine) tunToUDP(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := e.tun.Read(buf)
			if err != nil {
				continue
			}
			packet := make([]byte, n)
			copy(packet, buf[:n])
			e.handleOutbound(packet)
		}
	}
}

func (e *Engine) handleOutbound(packet []byte) {
	session, err := e.router.Route(packet)
	if err != nil || len(session.RemoteAddrs) == 0 || session.Cipher == nil {
		return
	}

	nonce := make([]byte, transport.NonceSize)
	rand.Read(nonce)

	// 1. Encrypt Payload
	encrypted := crypto.Encrypt(session.Cipher, nonce, packet, nil)

	// 2. Obfuscate (Seal)
	sealed, err := transport.Seal(session.ID, nonce, encrypted)
	if err != nil {
		return
	}

	// Pick a random destination from the available paths (e.g. server ports)
	dstAddr := session.RemoteAddrs[0]
	if len(session.RemoteAddrs) > 1 {
		dstAddr = session.RemoteAddrs[int(time.Now().UnixNano())%len(session.RemoteAddrs)]
	}

	e.udp.WriteTo(sealed, dstAddr)
}


func (e *Engine) udpToTUN(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-e.udp.Packets():
			if p.Raw != nil {
				e.handleHandshake(p.Raw, p.Addr)
				continue
			}

			session, ok := e.sm.GetByID(p.SessionID)
			if !ok || session.Cipher == nil {
				continue
			}
			e.sm.UpdateActivity(p.SessionID, p.Addr)

			// 1. Decrypt Payload
			decrypted, err := crypto.Decrypt(session.Cipher, p.Nonce, p.Payload, nil)
			if err != nil {
				continue
			}

			// 2. Forward or Local
			dstIP, err := GetDstIP(decrypted)
			if err != nil {
				continue
			}

			if dstIP == "10.0.0.1" || e.cfg == nil {
				e.tun.Write(decrypted)
			} else {
				e.handleOutbound(decrypted)
			}
		}
	}
}

func (e *Engine) handleHandshake(raw []byte, addr *net.UDPAddr) {
	if e.cfg == nil {
		return
	}
	cfg := e.cfg.Get()
	for _, peer := range cfg.Peers {
		pubB, _ := hex.DecodeString(peer.PublicKey)
		if transport.VerifyHandshake(raw, ed25519.PublicKey(pubB)) {
			sessionID := binary.BigEndian.Uint64(pubB[:8])
			
			// Use pubB as a simple key for ChaCha20-Poly1305 (32 bytes)
			cipher, _ := crypto.NewCipher(pubB)
			
			s := &transport.Session{
				ID:          sessionID,
				RemoteAddrs: []*net.UDPAddr{addr},
				Cipher:      cipher,
				LastSeen:    time.Now(),
				StaticIP:    peer.StaticIP,
				PublicKey:   pubB,
			}
			e.sm.Add(s)
			fmt.Printf("Handshake success from %s (StaticIP: %s)\n", addr.String(), peer.StaticIP)
			return
		}
	}
}
