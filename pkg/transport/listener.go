package transport

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// IncomingPacket represents a packet received on any of the listened ports.
type IncomingPacket struct {
	SessionID uint64
	Nonce     []byte
	Payload   []byte
	Addr      *net.UDPAddr
	Raw       []byte 
}

// MultiPortListener manages multiple UDP listeners.
type MultiPortListener struct {
	mu       sync.RWMutex
	conns    []*net.UDPConn
	stop     chan struct{}
	wg       sync.WaitGroup
	handler  func(p IncomingPacket) // Direct handler to avoid channel bottleneck
}

func NewMultiPortListener(ports []int) *MultiPortListener {
	l := &MultiPortListener{
		stop:     make(chan struct{}),
	}
	for _, p := range ports {
		addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", p))
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {
			conn.SetReadBuffer(8 * 1024 * 1024)
			conn.SetWriteBuffer(8 * 1024 * 1024)
			l.conns = append(l.conns, conn)
		}
	}
	return l
}

func (l *MultiPortListener) SetHandler(h func(p IncomingPacket)) {
	l.handler = h
}

func (l *MultiPortListener) Start() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, conn := range l.conns {
		l.wg.Add(1)
		go l.listen(conn)
	}
	return nil
}

func (l *MultiPortListener) listen(conn *net.UDPConn) {
	defer l.wg.Done()
	buf := make([]byte, 4096) 

	for {
		select {
		case <-l.stop:
			return
		default:
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil { return }
			if n < 1 || l.handler == nil { continue }

			if buf[0] == HeaderHandshake || buf[0] == HeaderHandshakeAck {
				raw := make([]byte, n)
				copy(raw, buf[:n])
				l.handler(IncomingPacket{Addr: addr, Raw: raw})
				continue
			}

			sessionID, nonce, payload, err := Unseal(buf[:n])
			if err != nil { continue }
			
			// Process immediately in serial to maintain order for fragments
			l.handler(IncomingPacket{
				SessionID: sessionID,
				Nonce:     nonce,
				Payload:   payload,
				Addr:      addr,
			})
		}
	}
}

func (l *MultiPortListener) WriteTo(data []byte, addr *net.UDPAddr) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.conns) == 0 {
		return fmt.Errorf("no active connections")
	}
	
	// Try to extract SessionID from data if it's a Data packet (HeaderData = 0x43)
	// data[0] is Header, data[1..9] is SessionID
	var idx int
	if len(data) >= 9 && data[0] == 0x43 {
		var sessionID uint64
		for i := 0; i < 8; i++ {
			sessionID |= uint64(data[1+i]) << (i * 8)
		}
		idx = int(sessionID % uint64(len(l.conns)))
	} else {
		idx = int(time.Now().UnixNano()) % len(l.conns)
	}
	
	_, err := l.conns[idx].WriteToUDP(data, addr)
	return err
}

func (l *MultiPortListener) RotateOne() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 { return nil }
	l.conns[0].Close()
	addr, _ := net.ResolveUDPAddr("udp", ":0")
	newConn, err := net.ListenUDP("udp", addr)
	if err != nil { return err }
	newConn.SetReadBuffer(8 * 1024 * 1024)
	newConn.SetWriteBuffer(8 * 1024 * 1024)
	l.wg.Add(1)
	go l.listen(newConn)
	l.conns = append(l.conns[1:], newConn)
	return nil
}

func (l *MultiPortListener) LocalAddr() *net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.conns) == 0 { return nil }
	return l.conns[0].LocalAddr().(*net.UDPAddr)
}

func (l *MultiPortListener) AllLocalAddrs() []*net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	addrs := make([]*net.UDPAddr, len(l.conns))
	for i, conn := range l.conns {
		addrs[i] = conn.LocalAddr().(*net.UDPAddr)
	}
	return addrs
}

func (l *MultiPortListener) Stop() {
	close(l.stop)
	l.mu.Lock()
	for _, conn := range l.conns { conn.Close() }
	l.mu.Unlock()
	l.wg.Wait()
}
