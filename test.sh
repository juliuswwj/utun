#!/bin/bash

# UTUN Automated Test Script
# Covers: Unit Tests, Build, Dynamic Key Gen, Deployment, and Cluster-wide Ping (v4/v6)

set -e

# Configuration (Physical Testbed IPs)
T1_IP="10.6.6.201"
T2_IP="10.6.6.202"
T3_IP="192.168.1.34"
T4_IP="10.6.6.204"

echo "=== Step 1: Running Unit Tests ==="
go test -v ./...

echo "=== Step 2: Building UTUN Binary ==="
go build -o utun cmd/utun/main.go

echo "=== Step 3: Generating Dynamic Keys ==="
SERVER_OUT=$(./utun gen-key -o server.key)
SERVER_PUB=$(echo "$SERVER_OUT" | grep "Public Key" | awk '{print $3}')
CLIENT_OUT=$(./utun gen-key -o client.key)
CLIENT_PUB=$(echo "$CLIENT_OUT" | grep "Public Key" | awk '{print $3}')
T4_OUT=$(./utun gen-key -o t4.key)
T4_PUB=$(echo "$T4_OUT" | grep "Public Key" | awk '{print $3}')

echo "Server Public Key: $SERVER_PUB"
echo "Client Public Key: $CLIENT_PUB"
echo "T4 Public Key: $T4_PUB"

echo "=== Step 4: Cleaning Environment on t1, t2, t3, t4 ==="
ssh root@$T1_IP "pkill -9 utun || true; ip -6 addr flush dev utun0 || true; ip -6 route flush dev utun0 || true"
ssh root@$T2_IP "pkill -9 utun || true; ip -6 addr flush dev utun1 || true; ip -6 neigh flush dev eth1 || true"
ssh root@$T2_IP "ssh root@t3 'ip -6 addr flush dev eth0 || true; ip -6 route flush dev eth0 || true'"
ssh root@$T4_IP "pkill -9 utun || true; ip -6 addr flush dev utun1 || true"

echo "=== Step 5: Distributing Binary and Configs ==="
scp utun root@$T1_IP:/root/utun
scp utun root@$T2_IP:/root/utun
scp utun root@$T4_IP:/root/utun
scp server.key root@$T1_IP:/root/private.key
scp client.key root@$T2_IP:/root/client.key
scp t4.key root@$T4_IP:/root/t4.key

ssh root@$T1_IP "cat <<EOF > /root/server.cfg
ports=10000
ip=192.168.1.1/24
ip6=2001:bb8:1:1::2/64
192.168.1.2/24=$CLIENT_PUB,192.168.1.34/32
192.168.1.4/24=$T4_PUB
EOF"

echo "=== Step 6: Starting UTUN Services ==="
ssh root@$T1_IP "nohup ./utun server server.cfg -key private.key > server.log 2>&1 &"
ssh root@$T2_IP "nohup ./utun client -s $T1_IP:10000 -spub $SERVER_PUB -key client.key -proxyarp eth1 -sockets 4 > client.log 2>&1 &"
ssh root@$T4_IP "nohup ./utun client -s $T1_IP:10000 -spub $SERVER_PUB -key t4.key -sockets 4 > client.log 2>&1 &"

echo "Waiting for interfaces and SLAAC (20s)..."
sleep 20

echo "=== Step 7: IPv4 Connectivity Tests ==="
echo -n "t2 -> t1 (192.168.1.1): "
ssh root@$T2_IP "ping -c 3 -W 2 192.168.1.1 > /dev/null" && echo "PASS" || echo "FAIL"

echo -n "t3 -> t1 (192.168.1.1): "
ssh root@$T2_IP "ssh root@t3 'ping -c 3 -W 2 192.168.1.1 > /dev/null'" && echo "PASS" || echo "FAIL"

echo -n "t3 -> t2 (192.168.1.2): "
ssh root@$T2_IP "ssh root@t3 'ping -c 3 -W 2 192.168.1.2 > /dev/null'" && echo "PASS" || echo "FAIL"

echo -n "t2 -> t4 (192.168.1.4) [Small Packet]: "
ssh root@$T2_IP "ping -c 3 -W 2 192.168.1.4 > /dev/null" && echo "PASS" || echo "FAIL"

echo -n "t2 -> t4 (192.168.1.4) [Large Packet 4000 bytes]: "
ssh root@$T2_IP "ping -c 3 -W 5 -s 4000 192.168.1.4 > /dev/null" && echo "PASS" || echo "FAIL"

echo "=== Step 8: IPv6 Connectivity Tests ==="
T2_V6=$(ssh root@$T2_IP "ip -6 addr show dev utun1 | grep global | awk '{print \$2}' | cut -d/ -f1 | head -n1")
T3_V6=$(ssh root@$T2_IP "ssh root@t3 \"ip -6 addr show dev eth0 | grep global | awk '{print \\\$2}' | cut -d/ -f1 | head -n1\"")
T4_V6=$(ssh root@$T4_IP "ip -6 addr show dev utun1 | grep global | awk '{print \$2}' | cut -d/ -f1 | head -n1")

echo "Detected T2 V6: $T2_V6"
echo "Detected T3 V6: $T3_V6"
echo "Detected T4 V6: $T4_V6"

echo -n "t2 -> t1 (2001:bb8:1:1::2): "
ssh root@$T2_IP "ping6 -c 3 -W 2 2001:bb8:1:1::2 > /dev/null" && echo "PASS" || echo "FAIL"

if [ ! -z "$T4_V6" ] && [ ! -z "$T2_V6" ]; then
    echo -n "t4 -> t2 ($T2_V6) [Large Packet 4000 bytes]: "
    ssh root@$T4_IP "ping6 -c 3 -W 5 -s 4000 $T2_V6 > /dev/null" && echo "PASS" || echo "FAIL"
fi

if [ ! -z "$T3_V6" ]; then
    echo -n "t3 -> t1 (2001:bb8:1:1::2): "
    ssh root@$T2_IP "ssh root@t3 'ping6 -c 3 -W 2 2001:bb8:1:1::2 > /dev/null'" && echo "PASS" || echo "FAIL"
    
    if [ ! -z "$T2_V6" ]; then
        echo -n "t3 -> t2 ($T2_V6): "
        ssh root@$T2_IP "ssh root@t3 'ping6 -c 3 -W 2 $T2_V6 > /dev/null'" && echo "PASS" || echo "FAIL"
    fi
else
    echo "t3 IPv6: SLAAC failed, skipping t3 IPv6 tests."
fi

echo "=== Test Summary ==="
ssh root@$T1_IP "grep 'Learned IPv6 route' server.log || echo 'No IPv6 routes learned yet'"
