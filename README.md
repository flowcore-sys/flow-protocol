# Flow Token Chain (FTC)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]()
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
| **Database** | LevelDB |
| **Max Supply** | 21,000,000 FTC |
| **Decimals** | 8 |
| **Block Time** | 60 seconds |
| **Initial Reward** | 50 FTC |
| **Halving** | Every 210,000 blocks (~4 years) |
| **P2P Port** | 17317 |
| **RPC Port** | 17318 |

---

## Quick Start

Get mining in 5 minutes:

### Prerequisites

- NVIDIA GPU (RTX 30/40/50 series)
- [CUDA Toolkit 12.0+](https://developer.nvidia.com/cuda-downloads)
- CMake 3.16+
- C compiler (GCC, Clang, or MSVC)

### 1. Clone the repository

```bash
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol
```

### 2. Build

```bash
mkdir build && cd build
cmake -DFTC_BUILD_CUDA=ON ..
cmake --build . --config Release
```

### 3. Generate a wallet address

```bash
./ftc-genaddr
```

Save your private key securely! You'll see output like:
```
Address: 1A2B3C4D5E6F...
Private Key: abc123def456...
```

### 4. Start mining

```bash
./ftc-miner-gpu -address YOUR_ADDRESS_HERE
```

That's it! The miner will automatically discover peers via DNS and start mining.

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
sudo apt install -y build-essential cmake git libleveldb-dev

# Install CUDA Toolkit (for GPU mining)
# Download from: https://developer.nvidia.com/cuda-downloads

# Clone and build
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol
mkdir build && cd build

# CPU-only build
cmake ..
make -j$(nproc)

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

# Build with CMake
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 -DFTC_BUILD_CUDA=ON ..
cmake --build . --config Release

# Binaries will be in build/Release/
```

### macOS

```bash
# Install dependencies
brew install cmake leveldb

# Clone and build (CPU only, no CUDA on macOS)
git clone https://github.com/flowcore-sys/flow-protocol.git
cd flow-protocol
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `FTC_BUILD_CUDA` | OFF | Enable CUDA GPU mining support |
| `FTC_BUILD_TESTS` | ON | Build unit tests |
| `FTC_BUILD_TOOLS` | ON | Build utility tools |

---

## Running a Node

> **Detailed Guide:** See [docs/NODE_SETUP.md](docs/NODE_SETUP.md) for complete node setup instructions, including systemd service, cloud deployment, and becoming a seed node.

### Start a Full Node

```bash
./ftc-node -datadir /path/to/data
```

The node will:
- Automatically discover peers via DNS (flowprotocol.net)
- Sync the blockchain
- Start RPC server on port 17318
- Accept P2P connections on port 17317

### Configuration Options

```bash
./ftc-node [options]

Options:
  -datadir <path>     Data directory for blockchain storage
  -rpcport <port>     RPC port (default: 17318)
  -port <port>        P2P port (default: 17317)
  -seed <host>        Add seed node manually
  -nowallet           Disable wallet functionality
```

### Port Forwarding

To help the network, open these ports on your router:

| Port | Protocol | Purpose |
|------|----------|---------|
| 17317 | TCP | P2P connections |
| 17318 | TCP | RPC API (optional) |

---

## RPC API

FTC provides a JSON-RPC API compatible with standard cryptocurrency infrastructure.

### Basic Usage

```bash
curl -X POST http://localhost:17318 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}'
```

### Key Methods

| Method | Description |
|--------|-------------|
| `getinfo` | Get node status (blocks, peers, version) |
| `getblockcount` | Get current block height |
| `getbestblockhash` | Get latest block hash |
| `getdifficulty` | Get current mining difficulty |
| `getpeercount` | Get connected peer count |
| `getbalance` | Get address balance |
| `getblock` | Get block by hash or height |
| `gettransaction` | Get transaction details |
| `listunspent` | List UTXOs for address |
| `sendtoaddress` | Send FTC to address |
| `sendrawtransaction` | Broadcast signed transaction |
| `getblocktemplate` | Get mining template |
| `submitblock` | Submit mined block |

### Example: Check Balance

```bash
curl -X POST http://seed.flowprotocol.net:17318 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["YOUR_ADDRESS"],"id":1}'
```

Response:
```json
{"jsonrpc":"2.0","result":1234.56789012,"id":"1"}
```

---

## Network

### DNS Discovery

FTC uses DNS-based peer discovery. The miner and node automatically find peers through:

- `seed.flowprotocol.net`
- `seed1.flowprotocol.net`
- `seed2.flowprotocol.net`

### Manual Connection

To connect to a specific node:

```bash
./ftc-node -seed 52.78.138.240
./ftc-miner-gpu -node 52.78.138.240 -address YOUR_ADDRESS
```

### Network Status

- **Mainnet Status:** Live
- **Active Peers:** 35+
- **Block Height:** Growing
- **Network Hashrate:** Varies with miners

---

## Wallet Commands

### Generate New Address

```bash
./ftc-genaddr
```

Output:
```
Private Key: a1b2c3d4e5f6... (KEEP SECRET!)
Address: 1FTC2ABC3DEF...
```

### Check Balance via RPC

```bash
curl -s -X POST http://seed.flowprotocol.net:17318 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["YOUR_ADDRESS"],"id":1}'
```

### Send Transaction

```bash
curl -X POST http://localhost:17318 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"sendtoaddress",
    "params":["PRIVATE_KEY_HEX","RECIPIENT_ADDRESS",AMOUNT,FEE],
    "id":1
  }'
```

---

## Roadmap

### Completed

- [x] Mainnet launch
- [x] GPU mining (CUDA) for RTX 30/40/50
- [x] DNS auto-discovery
- [x] RPC API for exchanges
- [x] UTXO model
- [x] Difficulty adjustment
- [x] Transaction validation

### In Progress

- [ ] Block explorer
- [ ] Mining pool protocol
- [ ] Wallet GUI (Electron)

### Planned

- [ ] OpenCL support (AMD GPUs)
- [ ] Exchange listings
- [ ] Mobile wallet
- [ ] AI compute marketplace integration
- [ ] Smart contract layer (future)

---

## Contributing

We welcome contributions! Here's how to help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow existing code style
- Add tests for new features
- Update documentation
- Keep commits atomic and well-described

### Priority Areas

- Performance optimizations
- Additional GPU support (AMD/Intel)
- Network protocol improvements
- Documentation and guides

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

### Feature Requests

Have an idea? Open an issue with the `enhancement` label describing:
- The feature you'd like
- Why it would be useful
- Possible implementation approach

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
