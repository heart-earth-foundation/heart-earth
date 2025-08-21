# Heart Earth P2P Network - Quick Start

## Prerequisites
- Rust 1.75+ installed
- Git

## Get Started

### 1. Clone and Build
```bash
git clone https://github.com/AudioLedger/heart-earth.git
cd heart-earth
cargo build --release -p p2p --bin client
```

### 2. Create Your Wallet (First Time)
```bash
cargo run --release -p p2p --bin client create --name default
```
**Important**: Write down the 12-word mnemonic phrase! You'll need it to recover your wallet.

### 3. Join the Network
```bash
cargo run --release -p p2p --bin client login --name default
```

That's it! You'll connect to the bootstrap node and can start sending messages.

## What You'll See
- Your unique Peer ID (e.g., `12D3KooW...`)
- Your blockchain address (e.g., `artTL1jb55QE...`)
- Connection to the developer channel: `/art/dev/general/v1`

## Commands
- Type any message and press Enter to send
- Type `quit` to exit

## Network Details
- **Bootstrap Node**: `mainline.proxy.rlwy.net:49745`
- **Bootstrap Peer ID**: `12D3KooWJ9MqNT6eLDg2ZvtxqU1ZtUdedSvGunMeyZjdibjtNgzP`
- **Channel**: Developer General (`/art/dev/general/v1`)

## Troubleshooting
- If connection fails, the bootstrap node might be restarting
- Check that your firewall allows outbound connections on port 49745
- Environment variables are automatically loaded from `.env` file
