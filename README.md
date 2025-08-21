# Heart Earth - P2P Blockchain Network

A secure peer-to-peer blockchain network with HD wallet functionality built in Rust using libp2p.

## 🚀 Quick Start

### Join the Live Network (Public Bootstrap Node)

1. **Clone and Build**
   ```bash
   git clone https://github.com/AudioLedger/heart-earth.git
   cd heart-earth
   cargo build --release -p p2p --bin client
   ```

2. **Create Your Wallet** (First Time)
   ```bash
   cargo run --release -p p2p --bin client create --name default
   ```
   📝 **Important**: Save the 12-word mnemonic phrase!

3. **Join the Network**
   ```bash
   cargo run --release -p p2p --bin client login --name default
   ```

4. **Start Chatting**
   - Type any message and press Enter
   - Connect with other users on the `/art/dev/general/v1` channel
   - Type `quit` to exit

## 🌐 Network Details

**Live Bootstrap Node:**
- **Address**: `157.245.208.60:4001`
- **Peer ID**: `12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm`
- **Channel**: `/art/dev/general/v1`
- **Status**: 24/7 online

## 🔒 Security Features

- **End-to-End Encryption**: All connections use Noise Protocol (same as Signal/WhatsApp)
- **Ed25519 Authentication**: Each peer has cryptographic identity
- **Signed Messages**: All messages are signed and verified
- **HD Wallet**: Hierarchical deterministic wallet with seed phrase recovery

## 🏗️ Architecture

### Core Components
- **Wallet**: Secure HD wallet with secp256k1 (blockchain) and ed25519 (P2P) key derivation
- **Blockchain**: Account-based system with `art` address prefix  
- **P2P Network**: libp2p-based network with gossipsub messaging and Kademlia DHT

### Key Features
- **Shared Seed Derivation**: Blockchain accounts and P2P identities from same seed
- **Deterministic Addresses**: Same seed always generates same addresses
- **Multiple Transports**: TCP, WebSocket, and DNS support
- **Auto-Discovery**: Kademlia DHT for peer discovery

## 🖥️ What You'll See

```
Client starting...
Peer ID: 12D3KooWJD7NfLu726X6xMsGo7JFTj5s7iWb4tvobCTNsGXtQYNB
Blockchain address: artTL1jb55QE2YCXvKdiknQfwjd85Pa9gqRdU
Connected to developer channel: /art/dev/general/v1
Type messages to send, 'quit' to exit:
Connected to 12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm
hello world
```

## 🛠️ Development

### Local Development
```bash
# Run local bootstrap node
cargo run --release -p p2p --bin bootstrap

# In another terminal, connect client
cargo run --release -p p2p --bin client login --name default
```

### Testing
```bash
# Run all tests
cargo test

# Run P2P integration tests
cargo test -p p2p
```

### Project Structure
```
heart-earth/
├── wallet/          # HD wallet with secp256k1 + ed25519 derivation
├── blockchain/      # Account-based blockchain (placeholder)
├── p2p/            # libp2p network implementation
│   ├── src/bin/
│   │   ├── bootstrap.rs      # Bootstrap node
│   │   └── client.rs         # Client application
│   └── tests/       # Integration tests
└── docs/           # Documentation
```

## 📦 Dependencies

- **libp2p**: P2P networking (TCP, WebSocket, Noise, Yamux, Kademlia, GossipSub)
- **ed25519-dalek**: Ed25519 signatures for P2P identity
- **k256**: secp256k1 for blockchain accounts  
- **bip39**: Mnemonic phrase generation
- **argon2**: Password-based encryption for wallet storage

## 🚀 Deploy Your Own Bootstrap Node

See [DIGITALOCEAN_DEPLOYMENT.md](DIGITALOCEAN_DEPLOYMENT.md) for complete deployment guide.

**Quick Deploy on DigitalOcean:**
1. Create Ubuntu droplet ($6/month)
2. SSH in and install dependencies
3. Clone, build, and run the bootstrap node
4. **Keep it running 24/7**: `nohup ./target/release/bootstrap > bootstrap.log 2>&1 &`
5. Update your `.env` with the new bootstrap details

**Managing Your Bootstrap Node:**
- **Check if running**: `ps aux | grep bootstrap`
- **View logs**: `tail -f bootstrap.log`
- **Stop**: `pkill bootstrap`
- **Restart**: `nohup ./target/release/bootstrap > bootstrap.log 2>&1 &`

## 🔧 Configuration

Environment variables (automatically loaded from `.env`):
```bash
BOOTSTRAP_PEER_ID=12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm
BOOTSTRAP_ADDRESS=/ip4/157.245.208.60/tcp/4001
```

## 🐛 Troubleshooting

**Connection Issues:**
- Ensure firewall allows outbound connections on port 4001
- Check bootstrap node is online: `ping 157.245.208.60`
- Verify environment variables in `.env` file

**Wallet Issues:**
- Password incorrect: Re-enter your password
- Lost mnemonic: Cannot recover - create new wallet
- Permission denied: Check file permissions in wallet directory

**Build Issues:**
- Update Rust: `rustup update`
- Clear cache: `cargo clean`
- Check dependencies: `cargo check`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Follow code guidelines in `CLAUDE.md`
4. Add tests for new functionality
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🌟 Features Roadmap

- [x] HD Wallet with dual key derivation
- [x] P2P networking with libp2p
- [x] Bootstrap node deployment
- [x] Client application with messaging
- [ ] Blockchain transaction processing
- [ ] Web interface
- [ ] Mobile applications
- [ ] Advanced routing and NAT traversal

## 🔗 Links

- **Live Network**: Connect to `157.245.208.60:4001`
- **Documentation**: See `/docs` directory
- **Issues**: Report bugs via GitHub Issues
- **Deployment**: See `DIGITALOCEAN_DEPLOYMENT.md`

---

**Made with ❤️ using Rust and libp2p**

*Heart Earth - Connecting the world through decentralized P2P technology*