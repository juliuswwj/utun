package tun

import (
	"io"
)

// MockDevice is a mock implementation of TUNDevice for testing.
type MockDevice struct {
	ReadChan  chan []byte
	WriteChan chan []byte
	Closed    bool
}

func NewMockDevice() *MockDevice {
	return &MockDevice{
		ReadChan:  make(chan []byte, 100),
		WriteChan: make(chan []byte, 100),
	}
}

func (m *MockDevice) Read(p []byte) (n int, err error) {
	data, ok := <-m.ReadChan
	if !ok {
		return 0, io.EOF
	}
	copy(p, data)
	return len(data), nil
}

func (m *MockDevice) Write(p []byte) (n int, err error) {
	data := make([]byte, len(p))
	copy(data, p)
	m.WriteChan <- data
	return len(p), nil
}

func (m *MockDevice) Close() error {
	if !m.Closed {
		close(m.ReadChan)
		close(m.WriteChan)
		m.Closed = true
	}
	return nil
}

func (m *MockDevice) Name() string {
	return "mock-tun"
}

func (m *MockDevice) Configure(ip, mask string, ip6 string, mtu int) error {
	return nil
}
