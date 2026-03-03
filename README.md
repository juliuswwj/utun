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

## Installation

Requires Go 1.21+

```bash
git clone https://github.com/your-username/utun.git
cd utun
go build ./cmd/utun
```

## Usage

### 1. Generate Keys

Generate an Ed25519 key pair. The command prints the public key and saves the private key to a file.

```bash
./utun gen-key -o client.key
```
**Output:**
```text
Public Key: <public_key_hex>
Private key saved to client.key
```

### 2. Configure Server

Create `server.cfg` on the server. It contains server settings and client mappings.

```text
# server.cfg
ports=10000,10001
ip=10.0.0.1/24
tun=utun0

# Client Mappings: <IP>=<Public Key>
10.0.0.2=f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f0
```

Run the server:
```bash
sudo ./utun server server.cfg
```

### 3. Run Client

Run the client using the generated private key.

```bash
sudo ./utun client -s <server_ip>:10000,<server_ip>:10001 -key client.key -ip 10.0.0.2/24
```

## Testing

You can run all unit and integration tests using the provided script:

```bash
./test.sh
```

## Command Options

### Server
- `utun server <config_file>`: Run server with the specified configuration file.

### Client
- `-s`: Comma-separated server addresses (`ip:port`).
- `-key`: Path to the private key file.
- `-ip`: TUN interface IP with CIDR.
- `-sockets`: Number of local sockets for rotation (default: 2, range 2-8).
- `-tun`: TUN interface name (default: `utun1`).

## License

MIT (or your preferred license)
