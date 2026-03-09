# utun (UDP + TUN VPN)

`utun` is a high-performance, secure private network tool written in Go. It uses TUN devices and obfuscated UDP tunnels to provide a seamless dual-stack L3 VPN experience.

## Features

- **Dual-Stack Support**: Full support for both IPv4 and IPv6 traffic.
- **IPv6 SLAAC**: Built-in Router Advertisement (RA) generator for Stateless Address Autoconfiguration.
- **Dynamic Routing**: Automatic learning of IPv6 client addresses and real-time injection of /128 kernel routes.
- **Proxy ARP & NDP**: Transparently bridges VPN networks with local Ethernet segments for both IPv4 and IPv6.
- **Ed25519 Authentication**: SSH-style public/private key authentication.
- **Strong Encryption**: All traffic is encrypted using ChaCha20-Poly1305.
- **UDP Obfuscation**:
    - Fake QUIC headers to bypass DPI.
    - Random padding (0-256 bytes) to hide traffic patterns.
    - Multi-port listening on the server.
    - Periodic socket rotation on the client.
- **Hot Reloading**: Server configuration (`server.cfg`) can be updated without restarting.

## Installation

Requires Go 1.21+

```bash
git clone https://github.com/your-username/utun.git
cd utun
go build ./cmd/utun
```

## Usage

### 1. Generate Keys

```bash
./utun gen-key -o server.key
./utun gen-key -o client.key
```

### 2. Configure Server

Create `server.cfg`:

```text
# server.cfg
ports=10000,10001
ip=10.0.0.1/24
ip6=2001:bb8:1:1::1/64
tun=utun0

# Client Mappings: <ClientIP>=<PublicKey>[,subnets...]
10.8.0.2=f0e1d2c3b4a5...
```

Run the server:
```bash
sudo ./utun server server.cfg -key server.key
```

### 3. Run Client

The client automatically receives configuration and performs SLAAC for IPv6.

```bash
sudo ./utun client -s <server_ip>:10000 -spub <server_public_key_hex> -key client.key -proxyarp eth0
```

## Automated Testing

A comprehensive test script is included for unit tests, building, deployment, and cluster-wide connectivity verification.

```bash
# Requires server.key and client.key to exist or be generated
./test.sh
```

## Command Options

### Server
- `utun server [options] <config_file>`
- `-key`: Path to the private key file (default: `private.key`).
- `-mock`: Use mock TUN device for testing.

### Client
- `-s`: Comma-separated server addresses (`ip:port`).
- `-spub`: Server public key (hex) for authentication.
- `-key`: Path to the private key file.
- `-sockets`: Number of local sockets for rotation (default: 2).
- `-tun`: TUN interface name (default: `utun1`).
- `-proxyarp`: Interface to enable Proxy ARP and Proxy NDP on.

## License

MIT
