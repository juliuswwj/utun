package router

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EthernetDevice is an interface to wrap raw socket or pcap handle.
type EthernetDevice interface {
	WritePacketData([]byte) error
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Close()
}

// ProxyARP manages ARP responses for a set of proxied subnets/peers from the Router.
type ProxyARP struct {
	ifaceName string
	hwAddr    net.HardwareAddr
	localIP   net.IP // The actual physical IP on this interface
	dev       EthernetDevice
	router    *Router
}

func NewProxyARP(ifaceName string, hwAddr net.HardwareAddr, localIP net.IP, dev EthernetDevice, r *Router) *ProxyARP {
	return &ProxyARP{
		ifaceName: ifaceName,
		hwAddr:    hwAddr,
		localIP:   localIP,
		dev:       dev,
		router:    r,
	}
}

// Run starts the ARP listener and responds to requests.
func (pa *ProxyARP) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			data, _, err := pa.dev.ReadPacketData()
			if err != nil {
				continue
			}

			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPRequest {
					if pa.shouldRespond(arp.DstProtAddress) {
						if err := pa.reply(arp); err != nil {
							fmt.Printf("failed to send ARP reply: %v\n", err)
						}
					}
				}
			}
		}
	}
}

// shouldRespond checks if the target IP is reachable via the utun router.
func (pa *ProxyARP) shouldRespond(targetIP []byte) bool {
	ip := net.IP(targetIP)
	
	// Never respond for the interface's own IP
	if ip.Equal(pa.localIP) {
		return false
	}

	// Respond if the router has a path to this IP (Server, other clients, or subnets)
	return pa.router.HasRoute(ip)
}

func (pa *ProxyARP) reply(req *layers.ARP) error {
	// Construct ARP Reply
	eth := &layers.Ethernet{
		SrcMAC:       pa.hwAddr,
		DstMAC:       req.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   pa.hwAddr,
		SourceProtAddress: req.DstProtAddress,
		DstHwAddress:      req.SourceHwAddress,
		DstProtAddress:    req.SourceProtAddress,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return err
	}

	return pa.dev.WritePacketData(buf.Bytes())
}
