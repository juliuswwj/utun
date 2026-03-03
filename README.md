# utun (UDP + TUN VPN)

`utun` is a high-performance, secure private network tool written in Go. It uses TUN devices and obfuscated UDP tunnels to provide a seamless L3 VPN experience.

## Features

- **L3 Routing**: Server-side routing for peer-to-peer communication between clients.
- **Ed25519 Authentication**: SSH-style public/private key authentication.
- **Strong Encryption**: All traffic is encrypted using ChaCha20-Poly1305.
- **UDP Obfuscation**:
    - Fake QUIC headers to bypass DPI.
    - Random padding (0-256 bytes) to hide traffic patterns.
    - Multi-port listening on the server.
    - Periodic socket rotation on the client.
- **Hot Reloading**: Server configuration (`server.cfg`) can be updated without restarting.
- **Static IP Management**: No DHCP, static IP to public key mapping for maximum predictability.
- **Proxy ARP**: Transparently proxy ARP requests for the VPN network on a local Ethernet interface.

## Installation

Requires Go 1.21+

```bash
git clone https://github.com/your-username/utun.git
cd utun
go build ./cmd/utun
```

## Usage

### 1. Generate Keys

Generate Ed25519 key pairs for both server and clients.

```bash
./utun gen-key -o server.key
./utun gen-key -o client.key
```

### 2. Configure Server

Create `server.cfg`. The format for client mappings is:
`<ClientIP>=<PublicKey>[,subnet1,subnet2...]`

```text
# server.cfg
ports=10000,10001
ip=10.0.0.1/24
tun=utun0

# Client Mappings: <ClientIP>=<PublicKey>[,subnets...]
10.8.0.2=f0e1d2c3b4a5...
10.8.0.32=778695a4b3c2...,10.8.0.32/27
```

Run the server (ensure `private.key` or the server's private key is in the current directory):
```bash
sudo ./utun server server.cfg
```

### 3. Run Client

The client will automatically receive its IP and subnet configuration from the server during handshake.

```bash
sudo ./utun client -s <server_ip>:10000 -key client.key
```

## Proxy ARP and Routing Modes

### 1. Routing Mode (Layer 3)
Used when the local physical subnet (e.g., `192.168.1.0/24`) and the VPN network (`10.8.0.0/24`) are **non-overlapping**.
-   **Server Config**: `10.8.0.2=<ClientPubKey>,192.168.1.0/24`
-   **Client**: Acts as an L3 router.

### 2. Proxy ARP Mode (Layer 2 Simulation)
Used when the local physical subnet is **part of the larger VPN network**.
-   **Scenario**:
    -   VPN Network: `10.8.0.0/24`.
    -   Physical Segment assigned range: `10.8.0.32/27`.
-   **Server Config**: `10.8.0.32=<ClientPubKey>,10.8.0.32/27` (The client IP is the base of the range).
-   **Client Configuration**:
    -   Gateway machine has `eth0` facing the physical wire and `utun1` facing the VPN.
    -   Gateway `eth0` IP: `10.8.0.33/27` (or any IP in the `/27` range).
    -   Gateway `utun1` IP: `10.8.0.32/24` (Configured automatically via server).
    -   **Crucial**: Other devices on the physical wire must be configured with the larger `/24` mask so they believe remote VPN peers (like `10.8.0.1`) are on-link.
-   **IP Allocation**: Use **dnsmasq** on the Gateway to assign IPs in the `10.8.0.32/27` range to physical devices.

#### Setup
```bash
sudo ./utun client -s <server_ip>:10000 -key client.key -proxyarp eth0
```

## Command Options

### Server
- `utun server <config_file>`: Run server with the specified configuration file.

### Client
- `-s`: Comma-separated server addresses (`ip:port`).
- `-key`: Path to the private key file.
- `-sockets`: Number of local sockets for rotation (default: 2).
- `-tun`: TUN interface name (default: `utun1`).
- `-proxyarp`: Interface to enable Proxy ARP on (e.g., `eth0`).

## License

MIT
