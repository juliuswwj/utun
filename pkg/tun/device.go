package tun

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TUNDevice is an interface for TUN device operations.
type TUNDevice interface {
	io.ReadWriteCloser
	Name() string
	Configure(ip, mask string, mtu int) error
}

// Device represents a Linux TUN device.
type Device struct {
	io.ReadWriteCloser
	name string
}

type ifreq struct {
	name  [16]byte
	flags uint16
}

// NewDevice creates a new TUN device with the given name.
func NewDevice(name string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	var ifr ifreq
	copy(ifr.name[:], name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create TUN device: %v", errno)
	}

	actualName := string(ifr.name[:]) // Null-terminated string handling might be needed if not fully filled
	// Trim null bytes
	for i, b := range ifr.name {
		if b == 0 {
			actualName = string(ifr.name[:i])
			break
		}
	}

	return &Device{
		ReadWriteCloser: os.NewFile(uintptr(fd), actualName),
		name:            actualName,
	}, nil
}

// Name returns the actual name of the TUN device.
func (d *Device) Name() string {
	return d.name
}

// Configure sets the IP address and MTU for the TUN device.
func (d *Device) Configure(ip, mask string, mtu int) error {
	// For simplicity and following the plan's mention of netlink, 
	// but using 'ip' command as a reliable wrapper for configuration.
	
	// Set MTU
	cmd := exec.Command("ip", "link", "set", "dev", d.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Set IP and mask
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ip, mask), "dev", d.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", d.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

// Read reads a packet from the TUN device.
func (d *Device) Read(p []byte) (n int, err error) {
	return d.ReadWriteCloser.Read(p)
}

// Write writes a packet to the TUN device.
func (d *Device) Write(p []byte) (n int, err error) {
	return d.ReadWriteCloser.Write(p)
}

// Close closes the TUN device.
func (d *Device) Close() error {
	return d.ReadWriteCloser.Close()
}
