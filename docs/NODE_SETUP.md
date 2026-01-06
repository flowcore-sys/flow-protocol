# FTC Node Setup Guide

Complete guide to running your own Flow Token Chain node and helping decentralize the network.

---

## Why Run a Node?

- **Support the network** — More nodes = more decentralization
- **Faster mining** — Direct connection, lower latency
- **Full validation** — Verify all transactions yourself
- **RPC access** — Your own API endpoint
- **Be a seed node** — Help others discover the network

---

## Quick Start (5 minutes)

### Download

Get the latest release from [GitHub Releases](https://github.com/flowcore-sys/flow-protocol/releases)

### Run

```bash
ftc-node.exe -datadir ./nodedata
```

That's it! Your node will:
1. Connect to DNS seeds (seed.flowprotocol.net)
2. Discover other peers
3. Download the blockchain
4. Start accepting connections

---

## System Requirements

### Minimum
| Resource | Requirement |
|----------|-------------|
| OS | Windows 10/11, Linux, macOS |
| CPU | 2 cores |
| RAM | 2 GB |
| Storage | 10 GB SSD |
| Network | 10 Mbps |

### Recommended (Seed Node)
| Resource | Requirement |
|----------|-------------|
| OS | Ubuntu 22.04 LTS |
| CPU | 4+ cores |
| RAM | 4+ GB |
| Storage | 50 GB SSD |
| Network | 100 Mbps, static IP |

---

## Installation

### Windows

1. Download `ftc-windows-v1.0.0.zip` from releases
2. Extract to any folder
3. Open Command Prompt in that folder
4. Run: `ftc-node.exe -datadir ./nodedata`

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake git libleveldb-dev

# Clone and build
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run node
./ftc-node -datadir ~/ftc-nodedata
```

### Linux (Pre-built)

```bash
# Download release
wget https://github.com/flowcore-sys/flow-protocol/releases/download/v1.0.0/ftc-linux-v1.0.0.tar.gz
tar -xzf ftc-linux-v1.0.0.tar.gz
cd ftc-linux

# Run
./ftc-node -datadir ~/ftc-nodedata
```

---

## Configuration

### Command Line Options

```
ftc-node [options]

Options:
  -datadir <path>     Data directory (default: ./nodedata)
  -port <port>        P2P port (default: 17317)
  -rpcport <port>     RPC port (default: 17318)
  -seed <host>        Add manual seed node
  -maxpeers <n>       Maximum peer connections (default: 125)
  -nowallet           Disable wallet functionality
```

### Examples

```bash
# Basic node
ftc-node -datadir /var/ftc/data

# Custom ports
ftc-node -datadir /var/ftc/data -port 17317 -rpcport 17318

# Add manual seed
ftc-node -datadir /var/ftc/data -seed 52.78.138.240

# High-performance node
ftc-node -datadir /var/ftc/data -maxpeers 200
```

---

## Port Configuration

### Required Ports

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 17317 | TCP | Inbound + Outbound | P2P network |
| 17318 | TCP | Inbound (optional) | RPC API |

### Firewall Setup

#### Linux (UFW)
```bash
sudo ufw allow 17317/tcp comment "FTC P2P"
sudo ufw allow 17318/tcp comment "FTC RPC"
sudo ufw reload
```

#### Linux (iptables)
```bash
sudo iptables -A INPUT -p tcp --dport 17317 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 17318 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables.rules
```

#### Windows Firewall
```powershell
# Run as Administrator
netsh advfirewall firewall add rule name="FTC P2P" dir=in action=allow protocol=TCP localport=17317
netsh advfirewall firewall add rule name="FTC RPC" dir=in action=allow protocol=TCP localport=17318
```

### Router Port Forwarding

1. Access your router (usually http://192.168.1.1)
2. Find "Port Forwarding" or "NAT"
3. Add rules:
   - External Port: 17317 → Internal Port: 17317 (TCP)
   - External Port: 17318 → Internal Port: 17318 (TCP)
4. Set destination to your computer's local IP

---

## Running as a Service

### Linux (systemd)

Create service file:
```bash
sudo nano /etc/systemd/system/ftc-node.service
```

Content:
```ini
[Unit]
Description=FTC Node
After=network.target

[Service]
Type=simple
User=ftc
ExecStart=/opt/ftc/ftc-node -datadir /var/ftc/data
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ftc-node
sudo systemctl start ftc-node

# Check status
sudo systemctl status ftc-node

# View logs
sudo journalctl -u ftc-node -f
```

### Windows (Task Scheduler)

1. Open Task Scheduler
2. Create Basic Task → "FTC Node"
3. Trigger: "When the computer starts"
4. Action: Start a program
   - Program: `C:\FTC\ftc-node.exe`
   - Arguments: `-datadir C:\FTC\nodedata`
5. Check "Run whether user is logged on or not"

---

## Becoming a Seed Node

Seed nodes help new users discover the network. Requirements:

### Prerequisites
- Static IP address or domain name
- 24/7 uptime
- Port 17317 open and accessible
- Stable internet connection

### Setup

1. **Get a VPS** (recommended providers)
   - AWS EC2
   - DigitalOcean
   - Vultr
   - Hetzner

2. **Configure firewall**
```bash
sudo ufw allow 17317/tcp
sudo ufw allow 17318/tcp
```

3. **Run node as service** (see above)

4. **Verify accessibility**
```bash
# From another machine
nc -zv YOUR_IP 17317
```

5. **Register your node**
   - Join [Telegram](https://t.me/flow_protocol_main)
   - Share your IP or domain
   - We'll add it to DNS seeds

### DNS Seed Registration

To add your node to `seed.flowprotocol.net`:

1. Ensure 99%+ uptime for 1 week
2. Contact admins in Telegram
3. Provide:
   - IP address or domain
   - Geographic location
   - Contact info

---

## Monitoring

### Check Node Status

```bash
# Get blockchain info
curl -s http://localhost:17318 -d '{"method":"getblockchaininfo"}' | jq

# Get peer count
curl -s http://localhost:17318 -d '{"method":"getpeerinfo"}' | jq '. | length'

# Get block height
curl -s http://localhost:17318 -d '{"method":"getblockcount"}'
```

### Health Check Script

```bash
#!/bin/bash
# save as check-node.sh

HEIGHT=$(curl -s http://localhost:17318 -d '{"method":"getblockcount"}' | jq -r '.result')
PEERS=$(curl -s http://localhost:17318 -d '{"method":"getpeerinfo"}' | jq '. | length')

echo "Block Height: $HEIGHT"
echo "Connected Peers: $PEERS"

if [ "$PEERS" -lt 3 ]; then
    echo "WARNING: Low peer count!"
fi
```

### Log Monitoring

```bash
# Follow logs (systemd)
journalctl -u ftc-node -f

# Filter errors
journalctl -u ftc-node | grep -i error
```

---

## Troubleshooting

### Node won't start

```bash
# Check if port is in use
netstat -tulpn | grep 17317

# Kill existing process
pkill ftc-node

# Check permissions
ls -la /var/ftc/data
```

### No peers connecting

1. **Check firewall**
```bash
sudo ufw status
```

2. **Test port externally**
   - Visit https://canyouseeme.org
   - Check port 17317

3. **Add manual seed**
```bash
ftc-node -seed 52.78.138.240
```

### Sync is slow

- Check internet speed
- Ensure SSD (not HDD)
- Increase max peers: `-maxpeers 200`

### High CPU/Memory

- Reduce max peers: `-maxpeers 50`
- Check for other processes
- Ensure adequate RAM

---

## Cloud Deployment

### AWS EC2

1. Launch instance:
   - AMI: Ubuntu 22.04 LTS
   - Type: t3.medium (or larger)
   - Storage: 50 GB gp3

2. Security Group:
   - Inbound: 17317 TCP, 17318 TCP, 22 TCP
   - Outbound: All

3. Connect and setup:
```bash
ssh -i key.pem ubuntu@YOUR_IP

# Install dependencies
sudo apt update && sudo apt install -y build-essential cmake git libleveldb-dev

# Build or download FTC
# ... (see installation section)

# Run
./ftc-node -datadir ~/nodedata
```

### DigitalOcean

1. Create Droplet:
   - Ubuntu 22.04
   - Basic: $12/mo (2GB RAM)
   - Datacenter: Choose closest

2. Configure firewall in DO console

3. SSH and install (same as above)

---

## Security Best Practices

1. **Don't expose RPC publicly** without authentication
2. **Use firewall** — only open necessary ports
3. **Keep system updated** — `apt update && apt upgrade`
4. **Use dedicated user** — don't run as root
5. **Monitor logs** — watch for suspicious activity
6. **Backup data** — regular backups of nodedata

### Create dedicated user

```bash
sudo useradd -r -s /bin/false ftc
sudo mkdir -p /var/ftc/data
sudo chown -R ftc:ftc /var/ftc
```

---

## Network Statistics

Check current network status:

```bash
# Your node's view
curl -s http://localhost:17318 -d '{"method":"getblockchaininfo"}'

# Public seed node
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getblockchaininfo"}'
```

---

## Getting Help

- **Telegram:** [@flow_protocol_main](https://t.me/flow_protocol_main)
- **GitHub Issues:** [Report bugs](https://github.com/flowcore-sys/flow-protocol/issues)
- **Documentation:** [README.md](https://github.com/flowcore-sys/flow-protocol)

---

## FAQ

**Q: How much storage does the blockchain need?**
A: Currently ~1 GB. Grows ~500 MB/month at full capacity.

**Q: Can I run node and miner together?**
A: Yes! Run node first, then point miner to localhost.

**Q: Do I earn rewards for running a node?**
A: No direct rewards, but lower latency for mining.

**Q: How do I update my node?**
A: Download new release, stop node, replace binary, start node.

**Q: Is my node helping the network?**
A: Yes! Every node strengthens decentralization and helps others sync.

---

**Thank you for supporting the FTC network!**
