Flow Token Chain (FTC) v2.0.0 - Windows Release
================================================

GPU-mineable cryptocurrency powered by Keccak-256

INCLUDED FILES:
- ftc-node.exe       Full blockchain node
- ftc-miner-gpu.exe  GPU miner (NVIDIA CUDA)
- ftc-genaddr.exe    Wallet address generator

REQUIREMENTS:
- Windows 10/11 64-bit
- NVIDIA GPU with CUDA support (RTX 30/40/50 series recommended)
- NVIDIA Driver 525+ installed

QUICK START:

1. Generate wallet address:
   ftc-genaddr.exe

   SAVE YOUR PRIVATE KEY! You need it to send coins.

2. Start mining:
   ftc-miner-gpu.exe -address YOUR_ADDRESS

   The miner auto-discovers peers via DNS.

3. Check balance:
   curl -X POST http://seed.flowprotocol.net:17318 -H "Content-Type: application/json" -d "{\"method\":\"getbalance\",\"params\":[\"YOUR_ADDRESS\"]}"

COMMANDS:

Mining:
  ftc-miner-gpu.exe -address 1ABC...     Start GPU mining
  ftc-miner-gpu.exe -list-devices        List available GPUs
  ftc-miner-gpu.exe -device 0            Use specific GPU

Node:
  ftc-node.exe -datadir ./data           Run full node
  ftc-node.exe -rpcport 17318            Custom RPC port

NETWORK:
- P2P Port: 17317
- RPC Port: 17318
- DNS: seed.flowprotocol.net

SUPPORT:
- Telegram: https://t.me/flow_protocol_main
- GitHub: https://github.com/flowcore-sys/flow-protocol

LICENSE: MIT
