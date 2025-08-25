# Heart Earth Architecture

Heart Earth is a decentralized internet where node operators provide services in exchange for ART tokens. Services include private IPFS gateways, message relaying, content storage, and other infrastructure. Users discover services through the network, verify operator credentials, and pay through smart contracts.

## Network Architecture

Heart Earth runs on a single unified P2P network using libp2p, with different application layers distinguished by gossipsub topics:

### Heart Layer (Blockchain)
- `/heart/blocks/v1` - Block propagation and consensus
- `/heart/transactions/v1` - Transaction mempool
- Uses secp256k1 heart accounts for signing transactions and smart contracts

### Earth Layer (Services & Social)
- `/earth/services/v1` - Service discovery and credentials
- `/earth/social/v1` - Messaging and social interactions
- Uses ed25519 earth identities for peer authentication and service provision

Nodes choose which topics to subscribe to based on the services they want to provide. All nodes share the same P2P infrastructure for peer discovery and networking.

## Node Economics & Reputation

Validators earning block rewards from Heart Layer consensus are incentivized to reinvest in Earth Layer services, creating a positive feedback loop where blockchain security directly funds decentralized internet infrastructure.

Node operators maintain persistent dual identity - their Earth PeerID and Heart account are cryptographically linked through the same mnemonic derivation. This enables cross-layer reputation tracking:

- **Heart Layer reputation**: Validator performance, stake amount, slashing history
- **Earth Layer reputation**: Service uptime, response times, user satisfaction
- **Smart contracts**: Tied to Heart accounts, track service delivery and payments

The built-in validator reputation system (active/offline/suspended/slashed states) extends to service provision, creating accountability for operators across both blockchain validation and service delivery.

## Identity System

Heart Earth uses a unified account system where both blockchain and P2P identities are derived from the same mnemonic with shared indexing:

- **Heart Accounts**: `heart123abc...` addresses for blockchain transactions (secp256k1, path m/44'/0'/account'/0/index)
- **Earth Identities**: `12D3KooWxyz...` PeerIDs for P2P networking (ed25519, path m/44'/1'/account'/0/index)

This ensures the same index produces paired identities, enabling cryptographic proof that a blockchain account and P2P peer are controlled by the same person. Future plans include a `.earth` name service for human-readable identities that resolve to both address types.

**Dual Signing System**: Heart accounts use secp256k1 signing for blockchain transactions and smart contracts. Earth identities use ed25519 signing for P2P authentication and network operations. Both signing systems include structured data support and maintain complete cryptographic separation while deriving from the same mnemonic.

# Services

Node operators provide infrastructure services within the Earth Layer for ART token payments:

## Storage Services
- **IPFS Storage**: Node operators provide private IPFS gateways for blockchain-related content. Smart contracts store CIDs for token metadata, images, and files, which are pinned and served by node operators for ART token payments. This creates a self-sufficient ecosystem where all blockchain content is served directly from the Heart Earth network without relying on external services.
- **Profile Hosting**: Node operators serve user profile data network-wide. When users connect, their profile is served by their chosen hosting node, making it visible to all peers while online.

## Bandwidth Services  
- **Communication Relay**: Node operators provide relay services for direct P2P communications including message relay, audio relay, and video relay. Users pay ART tokens for relay bandwidth when direct peer-to-peer connection isn't possible.
- **Channel Services**: Node operators host public channels (community spaces discoverable through `/earth/social/v1`) and private channels (encrypted group chats and direct messages) as paid services.

## Discovery Services
- **Service Discovery**: Publishing and discovering available node operator services through `/earth/services/v1`
- **Network Bootstrap**: Helping new peers discover and connect to the Heart Earth P2P network

## Message History & Channel Federation

**Message History Sync**: When nodes connect, they discover peers with the most complete message history and sync through batch downloads. Nodes request specific time ranges and can cross-verify against multiple sources to ensure complete channel history.

**Channel Tiers**: 
- **Core Infrastructure Channels**: System announcements, network status, and main discussion channels are synced by all nodes
- **Public Community Channels**: Specialized channels (#music, #gaming, etc.) are hosted by specific node operators as paid services, discoverable through `/earth/services/v1`

**Channel Federation**: Multiple nodes can host the same public channel for redundancy. Users discover available channels and their hosting nodes through service discovery. Popular channels find multiple hosts naturally while inactive channels disappear when no operators choose to host them.

## Heart Earth Blockchain Implementation

The Heart Earth blockchain integrates Y Protocol's complete system with the existing P2P infrastructure:

### Consensus Mechanism
- **Proof-of-Stake (PoS)**: Validators selected based on stake and reputation, with immediate finality
- **Unified Network**: Validators use the same libp2p network for both blockchain consensus and service provision
- **Economic Alignment**: Block rewards fund infrastructure services, creating validator incentives for service quality
- **Reputation System**: Built-in slashing extends to service accountability (active/offline/suspended/slashed states)

### Smart Contract System  
- **WASM Virtual Machine**: Executes WebAssembly contracts with deterministic execution and gas metering
- **Service Integration**: Contracts can interact with infrastructure services (IPFS storage, messaging, relays)
- **Automated Payments**: Smart contracts handle ART token payments for node operator services
- **Persistent State**: Contract state stored with efficient key-value access

### Network Integration
- **Single P2P Stack**: Unified libp2p network handles blockchain consensus, service discovery, and social messaging
- **Dual Identity Support**: Heart accounts (secp256k1) for blockchain, peer identities (ed25519) for P2P networking
- **Cross-Layer Operations**: Blockchain transactions can trigger service requests and payments
- **Browser Compatibility**: WebSocket bridge enables full browser client participation

### Development Infrastructure
- **Rust Backend**: Wallet, P2P, and blockchain components share unified workspace dependencies
- **WASM Browser Support**: Complete browser compatibility for wallet functions and encrypted messaging  
- **React Frontend**: Web interface integrates blockchain operations with existing P2P chat functionality
- **Service Discovery**: Infrastructure services discoverable through `/earth/services/v1` gossipsub topic
