package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"utun/pkg/config"
	"utun/pkg/crypto"
	"utun/pkg/router"
	"utun/pkg/transport"
	"utun/pkg/tun"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "gen-key":
		generateKeys()
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage: utun <command> [arguments]")
	fmt.Println("Commands:")
	fmt.Println("  gen-key    Generate a new Ed25519 key pair")
	fmt.Println("  server     Run in server mode")
	fmt.Println("  client     Run in client mode")
}

func generateKeys() {
	fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
	privPath := fs.String("o", "private.key", "Path to save private key")
	fs.Parse(os.Args[2:])

	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		return
	}

	pubHex := hex.EncodeToString(pub)

	fmt.Printf("Public Key: %s\n", pubHex)

	err = crypto.SaveKeyToFile(*privPath, priv)
	if err != nil {
		fmt.Printf("Failed to save private key: %v\n", err)
		return
	}
	fmt.Printf("Private key saved to %s\n", *privPath)
	fmt.Println("Keep your private key secret!")
}

func runServer() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: utun server <config_file>")
		return
	}
	configPath := os.Args[2]

	cfgMgr, err := config.NewManager(configPath)
	if err != nil {
		fmt.Printf("Config error: %v\n", err)
		return
	}
	cfg := cfgMgr.Get()

	// Server private key for signing HandshakeAcks
	keyPath := "private.key"
	privB, err := crypto.LoadKeyFromFile(keyPath)
	if err != nil {
		fmt.Printf("Failed to load server private key: %v\n", err)
		return
	}
	priv := ed25519.PrivateKey(privB)

	ip, ipnet, err := net.ParseCIDR(cfg.TunIP)
	if err != nil {
		fmt.Printf("Invalid IP/CIDR in config: %v\n", err)
		return
	}
	maskLen, _ := ipnet.Mask.Size()

	t, err := tun.NewDevice(cfg.TunName)
	if err != nil {
		fmt.Printf("TUN error: %v\n", err)
		return
	}
	t.Configure(ip.String(), strconv.Itoa(maskLen), 1400)

	sm := transport.NewSessionManager()
	r := router.NewRouter(sm)
	engine := router.NewEngine(t, r, sm, cfgMgr)
	engine.SetKeys(priv, nil)

	listener := transport.NewMultiPortListener(cfg.Ports)
	if err := listener.Start(); err != nil {
		fmt.Printf("Listener error: %v\n", err)
		return
	}
	engine.SetListener(listener)

	fmt.Printf("Server started with config: %s. Ports: %v, TUN: %s (%s)\n", 
		configPath, cfg.Ports, cfg.TunName, ip.String())
	engine.Start(context.Background())

	select {}
}

func runClient() {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddrStr := fs.String("s", "", "Server UDP addresses (comma separated, e.g., ip1:port,ip2:port)")
	serverPubHex := fs.String("spub", "", "Server public key (hex) for authentication")
	keyPath := fs.String("key", "private.key", "Path to private key")
	tunName := fs.String("tun", "utun1", "TUN interface name")
	numSockets := fs.Int("sockets", 2, "Number of local sockets (2-8)")
	proxyARP := fs.String("proxyarp", "", "Interface to enable Proxy ARP on (e.g., eth0)")
	fs.Parse(os.Args[2:])

	if *serverAddrStr == "" || *serverPubHex == "" {
		fmt.Println("Server addresses (-s) and Server public key (-spub) are required")
		return
	}

	serverPubB, err := hex.DecodeString(*serverPubHex)
	if err != nil || len(serverPubB) != ed25519.PublicKeySize {
		fmt.Printf("Invalid server public key: %v\n", err)
		return
	}
	serverPub := ed25519.PublicKey(serverPubB)

	privB, err := crypto.LoadKeyFromFile(*keyPath)
	if err != nil {
		fmt.Printf("Failed to load key: %v\n", err)
		return
	}
	priv := ed25519.PrivateKey(privB)
	pub := priv.Public().(ed25519.PublicKey)

	var serverAddrs []*net.UDPAddr
	for _, addr := range strings.Split(*serverAddrStr, ",") {
		sa, err := net.ResolveUDPAddr("udp", addr)
		if err == nil {
			serverAddrs = append(serverAddrs, sa)
		}
	}

	sm := transport.NewSessionManager()
	r := router.NewRouter(sm)
	
	ports := make([]int, *numSockets)
	for i := range ports {
		ports[i] = 0 
	}
	listener := transport.NewMultiPortListener(ports)
	listener.Start()
	
	sessionID := binary.BigEndian.Uint64(pub[:8])
	ciph, _ := crypto.NewCipher(pub)

	serverSession := &transport.Session{
		ID:          sessionID,
		RemoteAddrs: serverAddrs,
		Cipher:      ciph,
		LastSeen:    time.Now(),
		StaticIP:    "10.0.0.1",
	}
	sm.Add(serverSession)
	
	// Create engine without TUN device initially (it will be configured after handshake)
	engine := router.NewEngine(nil, r, sm, nil)
	engine.SetKeys(priv, serverPub) // Use server public key for ACK verification
	engine.SetListener(listener)

	var tunOnce sync.Once

	engine.OnHandshakeAck = func(clientIPCIDR string, subnets []string) {
		tunOnce.Do(func() {
			fmt.Printf("Received configuration: IP=%s, Subnets=%v\n", clientIPCIDR, subnets)
			ip, ipnet, err := net.ParseCIDR(clientIPCIDR)
			if err != nil {
				fmt.Printf("Invalid IP from server: %v\n", err)
				return
			}
			maskLen, _ := ipnet.Mask.Size()
			
			t, err := tun.NewDevice(*tunName)
			if err != nil {
				fmt.Printf("Failed to create TUN: %v\n", err)
				return
			}
			t.Configure(ip.String(), strconv.Itoa(maskLen), 1400)
			
			// Inject TUN into engine
			engine.SetTUNDevice(t)
			
			// Add routes to server
			r.AddSubnet(ipnet.String(), serverSession)
			for _, sn := range subnets {
				r.AddSubnet(sn, serverSession)
			}

			// Proxy ARP support
			if *proxyARP != "" {
				ifi, err := net.InterfaceByName(*proxyARP)
				if err != nil {
					fmt.Printf("Proxy ARP interface error: %v\n", err)
				} else {
					addrs, _ := ifi.Addrs()
					var localIP net.IP
					for _, addr := range addrs {
						if ipn, ok := addr.(*net.IPNet); ok {
							if ip4 := ipn.IP.To4(); ip4 != nil {
								localIP = ip4
								break
							}
						}
					}
					
					rawDev, err := router.NewLinuxRawDevice(*proxyARP)
					if err != nil {
						fmt.Printf("Failed to create raw device for Proxy ARP: %v\n", err)
					} else {
						pa := router.NewProxyARP(*proxyARP, ifi.HardwareAddr, localIP, rawDev, r)
						go pa.Run(context.Background())
						fmt.Printf("Proxy ARP enabled on %s\n", *proxyARP)
					}
				}
			}
		})
	}

	engine.Start(context.Background())

	// Randomized Handshake loop over multiple local sockets and remote ports
	go func() {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		for {
			// Rotate the oldest socket before sending heartbeat/handshake
			if err := listener.RotateOne(); err != nil {
				fmt.Printf("Socket rotation failed: %v\n", err)
			}
			
			handshake := transport.CreateHandshake(priv)
			// Randomly pick one server address to handshake
			dst := serverAddrs[rnd.Intn(len(serverAddrs))]
			listener.WriteTo(handshake, dst)
			
			delay := 5 + rnd.Intn(175)
			time.Sleep(time.Duration(delay) * time.Second)
		}
	}()

	fmt.Printf("Client started. Sockets: %d, Server Ports: %d, TUN: %s (waiting for config)\n", 
		*numSockets, len(serverAddrs), *tunName)
	select {}
}
