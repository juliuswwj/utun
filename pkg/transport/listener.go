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
	Raw       []byte // For handshake or other control packets
}

// MultiPortListener manages multiple UDP listeners with support for dynamic rotation.
type MultiPortListener struct {
	mu       sync.RWMutex
	conns    []*net.UDPConn
	packetCh chan IncomingPacket
	stop     chan struct{}
	wg       sync.WaitGroup
}

func NewMultiPortListener(ports []int) *MultiPortListener {
	l := &MultiPortListener{
		packetCh: make(chan IncomingPacket, 1024),
		stop:     make(chan struct{}),
	}
	for _, p := range ports {
		addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", p))
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {
			l.conns = append(l.conns, conn)
		}
	}
	return l
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
	buf := make([]byte, 2048)

	for {
		select {
		case <-l.stop:
			return
		default:
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // Connection closed or error
			}
			if n < 1 {
				continue
			}

			if buf[0] == HeaderHandshake || buf[0] == HeaderHandshakeAck {
				raw := make([]byte, n)
				copy(raw, buf[:n])
				l.packetCh <- IncomingPacket{Addr: addr, Raw: raw}
				continue
			}

			sessionID, nonce, payload, err := Unseal(buf[:n])
			if err != nil {
				continue
			}
			l.packetCh <- IncomingPacket{
				SessionID: sessionID,
				Nonce:     nonce,
				Payload:   payload,
				Addr:      addr,
			}
		}
	}
}

func (l *MultiPortListener) Packets() <-chan IncomingPacket {
	return l.packetCh
}

// WriteTo sends data using a random available connection.
func (l *MultiPortListener) WriteTo(data []byte, addr *net.UDPAddr) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.conns) == 0 {
		return fmt.Errorf("no active connections")
	}
	idx := int(time.Now().UnixNano()) % len(l.conns)
	_, err := l.conns[idx].WriteToUDP(data, addr)
	return err
}

// RotateOne closes the oldest connection and starts a new one on a random port.
func (l *MultiPortListener) RotateOne() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.conns) == 0 {
		return nil
	}

	// Close the oldest one (index 0)
	l.conns[0].Close()

	// Create a new random port connection
	addr, _ := net.ResolveUDPAddr("udp", ":0")
	newConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	// Start new listener
	l.wg.Add(1)
	go l.listen(newConn)

	// Update slice: move index 0 to end and replace with new
	l.conns = append(l.conns[1:], newConn)
	return nil
}

func (l *MultiPortListener) LocalAddr() *net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.conns) == 0 {
		return nil
	}
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
	for _, conn := range l.conns {
		conn.Close()
	}
	l.mu.Unlock()
	l.wg.Wait()
}
