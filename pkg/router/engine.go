package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
	"utun/pkg/config"
	"utun/pkg/crypto"
	"utun/pkg/transport"
	"utun/pkg/tun"
)

type RawWriter interface {
	Write(b []byte) (int, error)
}

type Engine struct {
	tun            tun.TUNDevice
	router         *Router
	sm             *transport.SessionManager
	cfg            *config.Manager
	udp            *transport.MultiPortListener
	privKey        ed25519.PrivateKey 
	serverPubKey   ed25519.PublicKey  
	OnHandshakeAck func(clientIP string, subnets []string)
	
	lanIfName      string
	lanRawDev      RawWriter
	lanMAC         net.HardwareAddr
	lanPrefix      *net.IPNet
}

func NewEngine(t tun.TUNDevice, r *Router, sm *transport.SessionManager, cfg *config.Manager) *Engine {
	return &Engine{
		tun:    t,
		router: r,
		sm:     sm,
		cfg:    cfg,
	}
}

func (e *Engine) SetLANSupport(ifName string, raw RawWriter, mac net.HardwareAddr) {
	e.lanIfName = ifName
	e.lanRawDev = raw
	e.lanMAC = mac
}

func (e *Engine) SetKeys(priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	e.privKey = priv
	e.serverPubKey = pub
}

func (e *Engine) SetListener(l *transport.MultiPortListener) {
	e.udp = l
}

func (e *Engine) SetTUNDevice(t tun.TUNDevice) {
	e.tun = t
}

func (e *Engine) Start(ctx context.Context) error {
	go e.tunToUDP(ctx)
	if e.udp != nil {
		go e.udpToTUN(ctx)
		go e.periodicRA(ctx)
	}
	return nil
}

func (e *Engine) periodicRA(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second) 
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C:
			if e.cfg != nil { e.sendRA(nil) }
			if e.lanRawDev != nil { e.sendRALAN() }
		}
	}
}

func (e *Engine) getLinkLocal(ifName string) net.IP {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil { return nil }
	addrs, _ := ifi.Addrs()
	for _, addr := range addrs {
		if ipn, ok := addr.(*net.IPNet); ok && ipn.IP.IsLinkLocalUnicast() {
			return ipn.IP.To16()
		}
	}
	return nil
}

func (e *Engine) sendRALAN() {
	prefix := e.lanPrefix
	if prefix == nil && e.tun != nil {
		ifi, err := net.InterfaceByName(e.tun.Name())
		if err == nil {
			addrs, _ := ifi.Addrs()
			for _, addr := range addrs {
				if ipn, ok := addr.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() && !ipn.IP.IsLoopback() {
					prefix = &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}
					break
				}
			}
		}
	}
	if prefix == nil { return }

	srcLL := e.getLinkLocal(e.lanIfName)
	if srcLL == nil { return }

	icmp := make([]byte, 56)
	icmp[0] = 134; icmp[4] = 64
	binary.BigEndian.PutUint16(icmp[6:8], 1800)
	pio := icmp[16:]
	pio[0] = 3; pio[1] = 4; pio[2] = 64; pio[3] = 0xc0
	binary.BigEndian.PutUint32(pio[4:8], 2592000)
	binary.BigEndian.PutUint32(pio[8:12], 604800)
	copy(pio[16:32], prefix.IP.To16())
	slla := icmp[48:]
	slla[0] = 1; slla[1] = 1
	copy(slla[2:8], e.lanMAC)

	ipHeader := make([]byte, 40)
	ipHeader[0] = 6<<4
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(len(icmp)))
	ipHeader[6] = 58; ipHeader[7] = 255
	copy(ipHeader[8:24], srcLL)
	copy(ipHeader[24:40], net.ParseIP("ff02::1"))

	csum := e.icmp6Checksum(append(ipHeader, icmp...), srcLL, net.ParseIP("ff02::1"))
	binary.BigEndian.PutUint16(icmp[2:4], csum)

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(eth[6:12], e.lanMAC)
	binary.BigEndian.PutUint16(eth[12:14], 0x86DD)

	e.lanRawDev.Write(append(eth, append(ipHeader, icmp...)...))
}

func (e *Engine) sendRA(targetSession *transport.Session) {
	cfg := e.cfg.Get()
	if cfg.TunIP6 == "" { return }
	_, ipnet, err := net.ParseCIDR(cfg.TunIP6)
	if err != nil { return }

	srcLL := e.getLinkLocal(e.tun.Name())
	if srcLL == nil { srcLL = net.ParseIP("fe80::1") }
	
	packet := make([]byte, 88) 
	packet[0] = 6<<4; packet[6] = 58; packet[7] = 255
	dstAll := net.ParseIP("ff02::1")
	copy(packet[8:24], srcLL); copy(packet[24:40], dstAll)
	binary.BigEndian.PutUint16(packet[4:6], uint16(48))

	icmp := packet[40:]
	icmp[0] = 134; icmp[4] = 64
	binary.BigEndian.PutUint16(icmp[6:8], 1800)
	pio := icmp[16:]
	pio[0] = 3; pio[1] = 4; pio[2] = 64; pio[3] = 0xc0
	binary.BigEndian.PutUint32(pio[4:8], 2592000)
	binary.BigEndian.PutUint32(pio[8:12], 604800)
	copy(pio[16:32], ipnet.IP.To16())

	csum := e.icmp6Checksum(packet, srcLL, dstAll)
	binary.BigEndian.PutUint16(icmp[2:4], csum)

	if targetSession != nil {
		e.sendPacketToSession(packet, targetSession)
	} else {
		for _, s := range e.sm.GetAll() {
			if s.Cipher != nil { e.sendPacketToSession(packet, s) }
		}
	}
}

func (e *Engine) icmp6Checksum(packet []byte, src, dst net.IP) uint16 {
	payload := packet[40:]
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i:i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i:i+2]))
	}
	sum += uint32(len(payload)) + 58
	for i := 0; i < len(payload); i += 2 {
		if i+1 < len(payload) {
			sum += uint32(binary.BigEndian.Uint16(payload[i:i+2]))
		} else {
			sum += uint32(payload[i]) << 8
		}
	}
	for sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
	return ^uint16(sum)
}

func (e *Engine) sendPacketToSession(packet []byte, session *transport.Session) {
	nonce := make([]byte, transport.NonceSize)
	rand.Read(nonce)
	encrypted := crypto.Encrypt(session.Cipher, nonce, packet, nil)
	sealed, err := transport.Seal(session.ID, nonce, encrypted)
	if err != nil { return }
	if len(session.RemoteAddrs) > 0 {
		e.udp.WriteTo(sealed, session.RemoteAddrs[0])
	}
}

func (e *Engine) tunToUDP(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done(): return
		default:
			if e.tun == nil { time.Sleep(100 * time.Millisecond); continue }
			n, err := e.tun.Read(buf)
			if err != nil { continue }
			packet := make([]byte, n)
			copy(packet, buf[:n])
			
			if e.cfg == nil && n >= 40 && (packet[0]>>4) == 6 {
				srcIP, _ := GetSrcIP(packet)
				if e.lanPrefix != nil && e.lanPrefix.Contains(net.ParseIP(srcIP)) {
					e.ensureKernelRoute(srcIP, e.lanIfName)
				}
			}
			e.handleOutbound(packet)
		}
	}
}

func (e *Engine) ensureKernelRoute(ip, ifName string) {
	if ip == "" || ifName == "" || strings.HasPrefix(ip, "fe80:") { return }
	exec.Command("ip", "-6", "route", "add", ip+"/128", "dev", ifName).Run()
}

func (e *Engine) handleOutbound(packet []byte) {
	dstIP, _ := GetDstIP(packet)
	if strings.HasPrefix(dstIP, "fe80:") || strings.HasPrefix(dstIP, "ff02::") { return }

	session, err := e.router.Route(packet)
	if err != nil || len(session.RemoteAddrs) == 0 || session.Cipher == nil {
		if !strings.HasPrefix(dstIP, "ff02::") && !strings.HasPrefix(dstIP, "224.") {
			fmt.Printf("OUTBOUND DROP: dst=%s, err=%v\n", dstIP, err)
		}
		return
	}
	e.sendPacketToSession(packet, session)
}

func (e *Engine) udpToTUN(ctx context.Context) {
	for {
		select {
		case <-ctx.Done(): return
		case p := <-e.udp.Packets():
			if p.Raw != nil {
				header := p.Raw[0]
				if header == transport.HeaderHandshake { e.handleHandshake(p.Raw, p.Addr)
				} else if header == transport.HeaderHandshakeAck { e.handleHandshakeAck(p.Raw) }
				continue
			}
			session, ok := e.sm.GetByID(p.SessionID)
			if !ok || session.Cipher == nil { continue }
			e.sm.UpdateActivity(p.SessionID, p.Addr)
			decrypted, err := crypto.Decrypt(session.Cipher, p.Nonce, p.Payload, nil)
			if err != nil { continue }

			srcIP, _ := GetSrcIP(decrypted)
			dstIP, _ := GetDstIP(decrypted)

			// IPv6 Learning
			if len(decrypted) >= 40 && (decrypted[0]>>4) == 6 {
				if !strings.HasPrefix(srcIP, "fe80:") && !e.router.HasRoute(net.ParseIP(srcIP)) {
					fmt.Printf("Learned IPv6 route: %s via session %d\n", srcIP, session.ID)
					e.router.AddSubnet(srcIP, session.ID)
					if e.cfg != nil {
						cfg := e.cfg.Get()
						exec.Command("ip", "-6", "route", "add", srcIP+"/128", "dev", cfg.TunName).Run()
					}
				}
			}

			isForSelf := false
			if strings.HasPrefix(dstIP, "fe80:") {
				isForSelf = true
			} else if e.tun != nil {
				ifi, err := net.InterfaceByName(e.tun.Name())
				if err == nil {
					addrs, _ := ifi.Addrs()
					for _, addr := range addrs {
						if ipn, ok := addr.(*net.IPNet); ok {
							if dstIP == ipn.IP.String() { isForSelf = true; break }
						}
					}
				}
			}
			
			if !isForSelf && e.cfg != nil {
				cfg := e.cfg.Get()
				if ip, _, err := net.ParseCIDR(cfg.TunIP); err == nil && dstIP == ip.String() { isForSelf = true }
				if !isForSelf && cfg.TunIP6 != "" {
					ip, _, err := net.ParseCIDR(cfg.TunIP6); if err == nil && dstIP == ip.String() { isForSelf = true }
				}
				if !isForSelf && cfg.TunIP6 != "" {
					_, ipnet, err := net.ParseCIDR(cfg.TunIP6); if err == nil && ipnet.Contains(net.ParseIP(dstIP)) {
						if !e.router.HasRoute(net.ParseIP(dstIP)) { isForSelf = true }
					}
				}
			}

			if isForSelf {
				if e.tun != nil { e.tun.Write(decrypted) }
			} else {
				if e.cfg == nil {
					if e.tun != nil { e.tun.Write(decrypted) } 
				} else {
					e.handleOutbound(decrypted)
				}
			}
		}
	}
}

func (e *Engine) handleHandshake(raw []byte, addr *net.UDPAddr) {
	if e.cfg == nil || e.privKey == nil { return }
	cfg := e.cfg.Get()
	for _, peer := range cfg.Peers {
		pubB, _ := hex.DecodeString(peer.PublicKey)
		if transport.VerifyHandshake(raw, ed25519.PublicKey(pubB)) {
			sessionID := binary.BigEndian.Uint64(pubB[:8])
			cipher, _ := crypto.NewCipher(pubB)
			s := &transport.Session{
				ID: sessionID, RemoteAddrs: []*net.UDPAddr{addr},
				Cipher: cipher, LastSeen: time.Now(),
				StaticIP: peer.StaticIP, PublicKey: pubB,
			}
			e.sm.Add(s)
			if peer.StaticIP != "" { e.router.AddSubnet(peer.StaticIP, s.ID) }
			for _, subnet := range peer.Subnets { e.router.AddSubnet(subnet, s.ID) }
			
			var respSubnets []string
			for _, p := range cfg.Peers {
				if p.StaticIP != "" { respSubnets = append(respSubnets, p.StaticIP) }
				respSubnets = append(respSubnets, p.Subnets...)
			}
			if cfg.TunIP6 != "" { respSubnets = append(respSubnets, cfg.TunIP6) }

			ack := transport.CreateHandshakeAck(e.privKey, peer.StaticIP, respSubnets)
			e.udp.WriteTo(ack, addr)
			fmt.Printf("Handshake success from %s\n", addr.String())
			go func() { time.Sleep(1 * time.Second); e.sendRA(s) }()
			return
		}
	}
}

func (e *Engine) handleHandshakeAck(raw []byte) {
	if e.serverPubKey == nil || e.OnHandshakeAck == nil { return }
	clientIP, subnets, err := transport.VerifyHandshakeAck(raw, e.serverPubKey)
	if err != nil { return }
	var v6Prefix *net.IPNet
	for _, sn := range subnets {
		if strings.Contains(sn, ":") {
			_, ipnet, err := net.ParseCIDR(sn)
			if err == nil {
				maskLen, _ := ipnet.Mask.Size()
				if maskLen == 64 { v6Prefix = ipnet; break }
			}
		}
	}
	if v6Prefix != nil { e.lanPrefix = v6Prefix }
	e.OnHandshakeAck(clientIP, subnets)
}
