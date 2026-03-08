# UTUN VPN Test Plan

This document outlines the steps to build and test a VPN network between t1, t2, and t3 using `utun`.

## Network Topology
- **t1 (Server)**:
  - Local IP: `10.6.6.158`
  - VPN IP: `192.168.1.1/24`
  - Access: `ssh root@t1`
- **t2 (Client/Gateway)**:
  - Local IP (to t1): `10.6.6.173`
  - Local IP (to t3): `192.168.1.33/27` on `eth1`
  - VPN IP: `192.168.1.2/24`
  - Access: `ssh root@t2`
- **t3 (Behind t2)**:
  - Local IP (to t2): `192.168.1.34/24` on `eth0`
  - No direct connection to t1.
  - Access: `ssh root@t3` on t2

## Goal
- t3 (`192.168.1.34`) and t1 (`192.168.1.1`) can communicate via the VPN.

## Preparation
1. Build `utun` binary and distribute to t1 and t2.
2. Generate encryption keys:
   - Server: `b6dcf3a76dc948a9241bc5dcc8a393a934b41e8f2f2423660ee997d5f9a6d70e`
   - Client: `78e3794a3d8f451dfada11bc8968b2064bab8c175740c37a8b1946a3bdb16adc`

## Deployment Steps

### 1. Configure t1 (Server)
Create `server.cfg` on t1:
```ini
ports=10000
ip=192.168.1.1/24
# Peer t2: VPN IP 192.168.1.2, additionally routes t3 (192.168.1.34)
192.168.1.2=78e3794a3d8f451dfada11bc8968b2064bab8c175740c37a8b1946a3bdb16adc,192.168.1.34/32
```
Start server:
```bash
sudo ./utun server server.cfg -key server.key
```

### 2. Configure t2 (Client/Gateway)
Start client with 4 UDP sockets and Proxy ARP on `eth1`. Test duration should cover at least 2 socket rotations (~60s):
```bash
sudo ./utun client -s 10.6.6.201:10000 -spub d2f9846eabafab1cb07070870fabaf0573beb61ab3e28a0893bd991b6757c45b -key client.key -proxyarp eth1 -sockets 4
```

### 3. Verify t3 -> t1 Connectivity with Socket Rotation
On t3, run a long ping to ensure no packet loss during UDP socket rotations:
```bash
ping -c 60 192.168.1.1
```

### 4. Verify t1 -> t3 Connectivity
On t1:
```bash
ping -c 60 192.168.1.34
```


## Troubleshooting
- Check if IP forwarding is enabled on t2: `sysctl net.ipv4.ip_forward=1`
- Check firewall rules on t1 and t2.
