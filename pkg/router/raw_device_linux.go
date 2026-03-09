package router

import (
	"net"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

// LinuxRawDevice implements EthernetDevice using AF_PACKET raw sockets.
type LinuxRawDevice struct {
	fd      int
	ifIndex int
}

// NewLinuxRawDevice creates a new raw socket device bound to the specified interface.
func NewLinuxRawDevice(ifaceName string) (*LinuxRawDevice, error) {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	// Use ETH_P_ALL to support both ARP and IPv6 (for RA/NDP)
	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return nil, err
	}

	sll := &unix.SockaddrLinklayer{
		Ifindex:  ifi.Index,
		Protocol: proto,
	}

	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &LinuxRawDevice{
		fd:      fd,
		ifIndex: ifi.Index,
	}, nil
}

func (d *LinuxRawDevice) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, 2048)
	n, _, err := unix.Recvfrom(d.fd, buf, 0)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return buf[:n], gopacket.CaptureInfo{
		CaptureLength: n,
		Length:        n,
	}, nil
}

func (d *LinuxRawDevice) WritePacketData(data []byte) error {
	sll := &unix.SockaddrLinklayer{
		Ifindex: d.ifIndex,
	}
	return unix.Sendto(d.fd, data, 0, sll)
}

func (d *LinuxRawDevice) Write(b []byte) (int, error) {
	err := d.WritePacketData(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (d *LinuxRawDevice) Close() {
	unix.Close(d.fd)
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
