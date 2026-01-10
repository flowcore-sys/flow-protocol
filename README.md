# Flow Token Chain (FTC)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/version-2.2.0-blue.svg)]()
[![Network](https://img.shields.io/badge/network-mainnet-green.svg)]()
[![Telegram](https://img.shields.io/badge/Telegram-Join%20Chat-blue.svg?logo=telegram)](https://t.me/flow_protocol_main)

```
    ███████╗██╗      ██████╗ ██╗    ██╗    ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗
    ██╔════╝██║     ██╔═══██╗██║    ██║    ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║
    █████╗  ██║     ██║   ██║██║ █╗ ██║       ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║
    ██╔══╝  ██║     ██║   ██║██║███╗██║       ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║
    ██║     ███████╗╚██████╔╝╚███╔███╔╝       ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║
    ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

**GPU-mineable cryptocurrency powered by Keccak-256 for decentralized AI compute payments.**

---

## What is FTC?

Flow Token Chain (FTC) brings GPU mining back to cryptocurrency. Built on the **Keccak-256** algorithm (SHA-3 family, double hash), FTC is designed to resist ASIC dominance and keep mining accessible to everyone with a graphics card.

- **Fair Launch** — No premine, no ICO, no VC allocation. 100% mined.
- **GPU Mining** — Optimized for NVIDIA GPUs (RTX 30/40/50 series supported)
- **ASIC Resistant** — Keccak-256 double hash keeps the network decentralized
- **Pool Mining** — Built-in Stratum server for efficient pool mining
- **P2P Network** — Decentralized node network with automatic peer discovery

---

## Specifications

| Parameter | Value |
|-----------|-------|
| **Name** | Flow Token Chain |
| **Ticker** | FTC |
| **Algorithm** | Keccak-256 (double hash) |
| **Consensus** | Proof of Work |
| **Model** | UTXO (Bitcoin-style) |
| **Max Supply** | 21,000,000 FTC |
| **Decimals** | 8 |
| **Block Time** | 60 seconds |
| **Initial Reward** | 50 FTC |
| **Halving** | Every 210,000 blocks (~4 years) |
| **P2P Port** | 17317 |
| **RPC Port** | 17318 |
| **Stratum Port** | 3333 |

---

## Quick Start

### Option 1: Start Mining (2 minutes)

1. **Download** the latest release from [GitHub Releases](https://github.com/flowcore-sys/flow-protocol/releases)

2. **Generate wallet** (or use existing address):
```bash
# Via RPC (remote)
curl http://seed.flowprotocol.net:17318/getnewaddress

# Or locally
ftc-node -genaddress
```

3. **Start mining**:
```bash
ftc-miner-gpu -address YOUR_ADDRESS -node seed.flowprotocol.net
```

That's it! You're mining FTC.

### Option 2: Run Your Own Node

Run a full node to support the network:

```bash
# Basic node
ftc-node -addnode seed.flowprotocol.net:17317

# Node with pool server (for miners to connect)
ftc-node -stratum -addnode seed.flowprotocol.net:17317

# Bootstrap blockchain from existing node (faster sync)
ftc-node -bootstrap http://seed.flowprotocol.net:17318/blocks.dat -addnode seed.flowprotocol.net:17317
```

---

## Downloads

| File | Platform | Description |
|------|----------|-------------|
| `ftc-node.exe` | Windows | Full node with RPC & Stratum pool |
| `ftc-node-linux` | Linux | Full node (x64) |
| `ftc-miner-gpu.exe` | Windows | CUDA GPU miner |
| `ftc-miner-gpu-linux` | Linux | CUDA GPU miner (requires CUDA) |

**Download:** [GitHub Releases](https://github.com/flowcore-sys/flow-protocol/releases/latest)

---

## Wallet

### Generate New Wallet

**Method 1: Via RPC (Remote)**
```bash
curl http://seed.flowprotocol.net:17318/getnewaddress
```

Response:
```json
{
  "result": {
    "address": "1HrDsG5xRfzUjaLjSDoWakVnmsxfhUL93f",
    "pubkey": "c630a43f14b335f57518649bf71fce9afd46488c183458437ea8e5b4e4e25a52",
    "privkey": "5JskzJqrNndFUKUatGJqqcgMJ1WmJSgT5sRhKSmPV2bNgXFbyAn"
  }
}
```

**Method 2: Local Generation**
```bash
ftc-node -genaddress
```

Output:
```
=== New FTC Address Generated ===

  Address:     1HrDsG5xRfzUjaLjSDoWakVnmsxfhUL93f
  Private Key: 5JskzJqrNndFUKUatGJqqcgMJ1WmJSgT5sRhKSmPV2bNgXFbyAn

IMPORTANT: Save your private key! It cannot be recovered.
```

> **WARNING:** Save your Private Key securely! It cannot be recovered if lost.

### Check Balance

```bash
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getbalance","params":["YOUR_ADDRESS"]}'
```

### Send FTC

```bash
curl -s http://seed.flowprotocol.net:17318 -d '{
  "method":"sendtoaddress",
  "params":["PRIVKEY", "PUBKEY", "TO_ADDRESS", 10.0, 0.001]
}'
```

---

## GPU Miner

### Basic Usage

```bash
ftc-miner-gpu -address YOUR_ADDRESS -node seed.flowprotocol.net
```

### All Options

```
ftc-miner-gpu [options]

Options:
  -address <addr>      Mining reward address (required)
  -node <host:port>    Node to connect (required)
  -intensity <1-100>   Mining intensity (default: 100)
  -devices <0,1,2>     GPU devices to use (default: all)
  -list                List available GPUs
  -help                Show help
```

### Examples

```bash
# Mine with all GPUs at full power
ftc-miner-gpu -address 1YourAddress -node seed.flowprotocol.net

# Laptop mode (50% intensity to reduce heat)
ftc-miner-gpu -address 1YourAddress -node seed.flowprotocol.net -intensity 50

# Use specific GPUs only
ftc-miner-gpu -address 1YourAddress -node seed.flowprotocol.net -devices 0,2
```

### Mining Display

```
  +=========================================================================+
  |  FTC GPU Miner v2.7.3                                           MINING  |
  +=========================================================================+
  |                                                                         |
  |  Hashrate:   1.25 GH/s    Uptime:   01:23:45   Share Rate:   12.5/min  |
  |  Accepted:   150          Rejected: 0          Efficiency:   100.0%    |
  |                                                                         |
  +-------------------------------------------------------------------------+
  |  Pool:       seed.flow   Online:   5          Pool HR:    3.50 GH/s    |
  |  Diff:       1024         Latency:  15   ms   Net Diff:   12345        |
  |  Height:     50000        Blocks:   127                                 |
  |                                                                         |
  +-------------------------------------------------------------------------+
  |  Wallet:     1YourAddressHere...                                        |
  |  Balance:    1234.5678     FTC  Payouts: 5                              |
  |                                                                         |
  +=========================================================================+

  [MINING] Job: abc123  Next: ~2:30 (avg 3m45s)  Found: 3
```

### Performance

| GPU | Hashrate | Power | Efficiency |
|-----|----------|-------|------------|
| RTX 3070 | 400-600 MH/s | ~130W | ~4 MH/W |
| RTX 3080 | 600-800 MH/s | ~220W | ~3.5 MH/W |
| RTX 3090 | 800-1000 MH/s | ~300W | ~3 MH/W |
| RTX 4070 | 600-800 MH/s | ~150W | ~5 MH/W |
| RTX 4080 | 1.0-1.3 GH/s | ~250W | ~4.5 MH/W |
| RTX 4090 | 1.5-2.0 GH/s | ~350W | ~5 MH/W |
| RTX 5080 | 1.0-1.2 GH/s | ~200W | ~5.5 MH/W |
| RTX 5090 | 2.0-3.0 GH/s | ~400W | ~6 MH/W |

---

## Node

### Basic Usage

```bash
ftc-node -addnode seed.flowprotocol.net:17317
```

### All Options

```
ftc-node [options]

Options:
  -rpcport <port>      RPC port (default: 17318)
  -stratum [port]      Enable Stratum pool server (default: 3333)
  -datadir <dir>       Data directory (default: ftcdata)
  -addnode <ip:port>   Add peer to connect (can use multiple)
  -peers <file>        Load peers from file
  -bootstrap <url>     Download blockchain from URL
  -genaddress          Generate wallet address and exit
  -nowallet            Disable wallet
  -recover             Recovery mode (skip validation)
  -help                Show help
```

### Run a Pool Server

To run your own mining pool:

```bash
# Start node with Stratum enabled
ftc-node -stratum -addnode seed.flowprotocol.net:17317

# Or with custom port
ftc-node -stratum 3334 -addnode seed.flowprotocol.net:17317
```

Miners connect to your pool:
```bash
ftc-miner-gpu -address MINER_ADDRESS -node YOUR_IP:17318
```

### Bootstrap (Fast Sync)

Download blockchain from existing node instead of syncing block-by-block:

```bash
ftc-node -bootstrap http://seed.flowprotocol.net:17318/blocks.dat -addnode seed.flowprotocol.net:17317
```

### Data Directory

Default locations:
- **Windows:** `ftcdata/` in current directory
- **Linux:** `ftcdata/` in current directory

Contents:
- `blocks.dat` — Blockchain data
- `wallet.dat` — Wallet keys (if enabled)

---

## P2P Network

FTC uses a decentralized P2P network for block propagation and synchronization.

### How It Works

1. Nodes connect to peers via `-addnode` or DNS seeds
2. New blocks are broadcast to all connected peers
3. Nodes automatically share peer lists
4. Multiple nodes can run Stratum servers for miners

### Seed Nodes

```
seed.flowprotocol.net:17317
seed1.flowprotocol.net:17317
```

### Run Multiple Nodes

You can run your own node to:
- Support network decentralization
- Run a mining pool for others
- Have faster block notifications
- Reduce latency

---

## RPC API

### Endpoint

```
http://seed.flowprotocol.net:17318
```

### Methods

| Method | Params | Description |
|--------|--------|-------------|
| `getinfo` | - | Network status |
| `getblockcount` | - | Current height |
| `getdifficulty` | - | Mining difficulty |
| `getpeercount` | - | Connected miners |
| `getbalance` | [address] | Address balance |
| `listunspent` | [address] | UTXOs |
| `getblock` | [height] | Block data |
| `getnewaddress` | - | Generate new wallet |
| `sendtoaddress` | [privkey, pubkey, to, amount, fee] | Send FTC |
| `getpoolstatus` | - | Pool statistics |
| `getstratumstats` | - | Stratum stats |

### Examples

```bash
# Network info
curl http://seed.flowprotocol.net:17318 -d '{"method":"getinfo"}'

# Generate wallet
curl http://seed.flowprotocol.net:17318/getnewaddress

# Check balance
curl http://seed.flowprotocol.net:17318 -d '{"method":"getbalance","params":["1YourAddress"]}'

# Pool status
curl http://seed.flowprotocol.net:17318 -d '{"method":"getpoolstatus"}'
```

---

## Building from Source

### Linux

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential git

# Clone
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol

# Build node
bash build_node_linux.sh

# Build GPU miner (requires CUDA Toolkit)
# Download CUDA: https://developer.nvidia.com/cuda-downloads
nvcc -O3 -o ftc-miner-gpu src/miner/keccak256_cuda.cu node/gpu_miner_main.c -lpthread
```

### Windows

```powershell
# Prerequisites:
# - Visual Studio 2022 with C++ workload
# - CUDA Toolkit 12.0+ (for GPU miner)

# Build node
build_node.bat

# Build GPU miner
build_miner.bat
```

---

## Roadmap

### Completed

- [x] Mainnet launch
- [x] GPU mining (CUDA)
- [x] Pool mining (Stratum protocol)
- [x] P2P network
- [x] RPC wallet generation
- [x] Bootstrap sync
- [x] Intensity control for laptops
- [x] Real-time balance display

### In Progress

- [ ] Block explorer
- [ ] Web wallet
- [ ] Exchange listings

### Planned

- [ ] OpenCL support (AMD GPUs)
- [ ] Mobile wallet
- [ ] AI compute marketplace

---

## Community

### Telegram

Join our community: **[@flow_protocol_main](https://t.me/flow_protocol_main)**

- Announcements & Updates
- Mining Support
- Development Discussion
- Community Chat

### GitHub

- [Source Code](https://github.com/flowcore-sys/flow-protocol)
- [Releases](https://github.com/flowcore-sys/flow-protocol/releases)
- [Issues](https://github.com/flowcore-sys/flow-protocol/issues)

---

## FAQ

**Q: What GPU do I need?**
A: Any NVIDIA GPU with CUDA support (GTX 10 series or newer). RTX 30/40/50 series recommended.

**Q: How do I check my balance?**
A: `curl http://seed.flowprotocol.net:17318 -d '{"method":"getbalance","params":["YOUR_ADDRESS"]}'`

**Q: When do I receive mining rewards?**
A: Rewards are paid instantly when you mine a block. Check your balance after seeing "Block Found" in the miner.

**Q: Can I run my own pool?**
A: Yes! Run `ftc-node -stratum` and miners can connect to your node.

**Q: Is there a minimum payout?**
A: No minimum. Rewards go directly to your address when a block is found.

**Q: My hashrate seems low, what's wrong?**
A: Try updating GPU drivers. Use `-intensity 100` for maximum performance. Reduce thermal throttling.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

**This software is provided "as is" without warranty of any kind.**

- Cryptocurrency involves significant risk
- You are solely responsible for your private keys
- Lost keys cannot be recovered
- This is experimental software

**Always do your own research.**

---

<p align="center">
  <b>GPU Mining is Back.</b><br>
  <a href="https://t.me/flow_protocol_main">Telegram</a> •
  <a href="https://github.com/flowcore-sys/flow-protocol">GitHub</a>
</p>
