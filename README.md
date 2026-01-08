# Flow Token Chain (FTC)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)]()
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
- **AI Compute Payments** — Native currency for decentralized AI compute marketplace

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
| **RPC Port** | 17318 |

---

## Network Infrastructure

FTC runs on a **high-availability centralized server** with **AWS Global Accelerator** for ultra-low latency worldwide.

### Global Low-Latency Network

- **Anycast routing** — Connect to the same DNS, get routed to your nearest AWS edge location
- **~3-5ms latency** — From most locations worldwide
- **Auto-recovery** — Server automatically restarts on crashes
- **Real-time saves** — Every block is saved immediately, no data loss
- **Dynamic difficulty** — Adjusts every 2016 blocks based on network hashrate

### DNS Seeds

The miner automatically discovers the server via DNS:
- `seed.flowprotocol.net`
- `seed1.flowprotocol.net`

---

## Quick Start

Get mining in 2 minutes:

### Prerequisites

- NVIDIA GPU (RTX 30/40/50 series)
- Windows 10/11 or Linux

### 1. Download

Get the latest release from [GitHub Releases](https://github.com/flowcore-sys/flow-protocol/releases)

### 2. Start Mining

```bash
ftc-miner-gpu -address YOUR_ADDRESS
```

That's it! The miner will automatically connect to the optimal server endpoint.

---

## Mining Performance

Real-world hashrates measured on mainnet:

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
| H100 | 5.0-8.0 GH/s | ~350W | ~18 MH/W |

> **Note:** Hashrates may vary based on driver version, memory speed, and thermal conditions.

---

## Building from Source

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake git

# Install CUDA Toolkit (for GPU mining)
# Download from: https://developer.nvidia.com/cuda-downloads

# Clone and build
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol
mkdir build && cd build

# GPU build (requires CUDA)
cmake -DFTC_BUILD_CUDA=ON ..
make -j$(nproc)
```

### Windows

```powershell
# Prerequisites:
# - Visual Studio 2022 with C++ workload
# - CMake (https://cmake.org/download/)
# - CUDA Toolkit 12.0+ (https://developer.nvidia.com/cuda-downloads)

# Clone repository
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol

# Build with batch script
build_gpu.bat

# Binary will be in release/
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `FTC_BUILD_CUDA` | OFF | Enable CUDA GPU mining support |
| `FTC_BUILD_TESTS` | ON | Build unit tests |

---

## Miner Options

```
ftc-miner-gpu [options]

Options:
  -address <addr>     Mining reward address (required)
  -node <host>        Manual node address (optional, auto-discovered via DNS)
  -devices <ids>      GPU device IDs to use, comma-separated (default: all)
```

### Examples

```bash
# Basic mining (auto-discovers best server)
ftc-miner-gpu -address 1YourAddressHere

# Specify server manually
ftc-miner-gpu -address 1YourAddressHere -node seed.flowprotocol.net

# Use specific GPUs (0 and 1)
ftc-miner-gpu -address 1YourAddressHere -devices 0,1
```

---

## RPC API

FTC provides a JSON-RPC API for querying the blockchain and sending transactions.

### Endpoint

```
http://seed.flowprotocol.net:17318
```

### RPC Methods

| Method | Params | Description |
|--------|--------|-------------|
| `getinfo` | - | Network status (blocks, difficulty, connections) |
| `getblockcount` | - | Current block height |
| `getdifficulty` | - | Current mining difficulty |
| `getpeercount` | - | Number of active miners |
| `getbalance` | [address] | Balance for address |
| `listunspent` | [address] | UTXOs for address |
| `getblock` | [height] | Block data by height |
| `sendtoaddress` | [privkey, pubkey, to, amount, fee] | Send FTC |

---

## Network Commands

### Linux/macOS (curl)

```bash
# Node Status
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getinfo"}'

# Check Balance
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getbalance","params":["YOUR_ADDRESS"]}'

# Block Height
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getblockcount"}'

# Peer Count (active miners)
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getpeercount"}'

# Difficulty
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getdifficulty"}'

# List Unspent (UTXOs)
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"listunspent","params":["YOUR_ADDRESS"]}'

# Get Block by Height
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getblock","params":[100]}'

# Send Transaction
curl -s http://seed.flowprotocol.net:17318 -d '{
  "method":"sendtoaddress",
  "params":[
    "YOUR_PRIVATE_KEY",
    "YOUR_PUBLIC_KEY",
    "RECIPIENT_ADDRESS",
    10.0,
    0.001
  ]
}'
```

### Windows PowerShell

```powershell
# Node Status
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body '{"method":"getinfo"}' -ContentType "application/json"

# Check Balance
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body '{"method":"getbalance","params":["YOUR_ADDRESS"]}' -ContentType "application/json"

# Block Height
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body '{"method":"getblockcount"}' -ContentType "application/json"

# Peer Count
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body '{"method":"getpeercount"}' -ContentType "application/json"

# Difficulty
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body '{"method":"getdifficulty"}' -ContentType "application/json"

# Send Transaction
$tx = @{
    method = "sendtoaddress"
    params = @("YOUR_PRIVATE_KEY", "YOUR_PUBLIC_KEY", "RECIPIENT_ADDRESS", 10.0, 0.001)
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://seed.flowprotocol.net:17318" -Method POST -Body $tx -ContentType "application/json"
```

---

## Wallet Commands

### Generate New Wallet

```bash
# Linux/macOS
./ftc-genaddr

# Windows
ftc-genaddr.exe
```

Output:
```
Private key: d33890038793f57450381fec47694f840170e284adc032dbce20a523d29fae18
Public key:  c630a43f14b335f57518649bf71fce9afd46488c183458437ea8e5b4e4e25a52
Address:     123NqWqRKWbaajfoFkbeJ2GYiiwt6zqZZs
```

> **IMPORTANT:** Save your Private Key securely! It cannot be recovered if lost.

### Check Balance

```bash
curl -s http://seed.flowprotocol.net:17318 -d '{"method":"getbalance","params":["YOUR_ADDRESS"]}'
```

Response:
```json
{"result":1234.56789012}
```

### Send FTC

To send FTC, you need your Private Key, Public Key, recipient address, amount, and fee:

```bash
curl -s http://seed.flowprotocol.net:17318 -d '{
  "method":"sendtoaddress",
  "params":[
    "YOUR_PRIVATE_KEY",
    "YOUR_PUBLIC_KEY",
    "RECIPIENT_ADDRESS",
    10.0,
    0.001
  ]
}'
```

Response:
```json
{"result":"transaction_id_here"}
```

**Parameters:**
- `YOUR_PRIVATE_KEY` — 64 hex characters (from ftc-genaddr)
- `YOUR_PUBLIC_KEY` — 64 hex characters (from ftc-genaddr)
- `RECIPIENT_ADDRESS` — FTC address starting with "1"
- `amount` — Amount to send (e.g., 10.0)
- `fee` — Transaction fee (recommended: 0.001)

---

## Roadmap

### Completed

- [x] Mainnet launch
- [x] GPU mining (CUDA) for RTX 30/40/50
- [x] DNS auto-discovery
- [x] RPC API for exchanges
- [x] UTXO model
- [x] Difficulty adjustment
- [x] Global low-latency infrastructure (AWS Global Accelerator)
- [x] Auto-recovery and real-time saves

### In Progress

- [ ] Block explorer
- [ ] Mining pool protocol
- [ ] Wallet GUI (Electron)

### Planned

- [ ] OpenCL support (AMD GPUs)
- [ ] Exchange listings
- [ ] Mobile wallet
- [ ] AI compute marketplace integration

---

## Community

### Telegram

Join our community: **[@flow_protocol_main](https://t.me/flow_protocol_main)**

- Announcements
- Mining support
- Development discussion
- Community chat

### Reporting Issues

Found a bug? Please [open an issue](https://github.com/flowcore-sys/flow-protocol/issues) with:
- Description of the problem
- Steps to reproduce
- System information (OS, GPU, driver version)
- Relevant logs

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Flow Protocol

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Disclaimer

**This software is provided "as is" without warranty of any kind.**

- Cryptocurrency mining and trading involves significant risk
- Past performance does not guarantee future results
- You are solely responsible for securing your private keys
- Lost private keys cannot be recovered
- This is experimental software - use at your own risk
- The developers are not responsible for any financial losses

**Always do your own research before participating in any cryptocurrency project.**

---

<p align="center">
  <b>GPU Mining is Back.</b><br>
  <a href="https://t.me/flow_protocol_main">Telegram</a> •
  <a href="https://github.com/flowcore-sys/flow-protocol">GitHub</a> •
  <a href="https://flowprotocol.net">Website</a>
</p>
