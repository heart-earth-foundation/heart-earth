# Heart Earth Web Integration Implementation Plan

## Overview
Enable web browsers to connect to the existing Heart Earth P2P network by adding WebSocket support to the bootstrap node and creating a real web frontend.

## Current Architecture
- **Digital Ocean Bootstrap**: `157.245.208.60:4001` (TCP only)
- **Peer ID**: `12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm`
- **Channel**: `/art/dev/general/v1`
- **Transport**: TCP + Noise + Yamux (libp2p 0.56)
- **Wallet**: HD derivation with secp256k1 + ed25519

## Implementation Path: WebSocket Bridge

### Phase 1: Bootstrap WebSocket Support (30 minutes)

#### Files to Modify:
1. `/p2p/src/bin/bootstrap.rs`
2. `/p2p/src/bin/bootstrap_railway.rs` (for Railway deployment)

#### Changes Required:

**A. Add WebSocket Listener**
```rust
// In bootstrap.rs, after TCP listener:
let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
swarm.listen_on(tcp_addr)?;

// ADD THIS:
let ws_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}/ws", p2p_port).parse()?;
swarm.listen_on(ws_addr)?;
```

**B. Update Connection Logging**
```rust
SwarmEvent::NewListenAddr { address, .. } => {
    println!("Listening on {address}");
    // Add WebSocket connection info for web clients
    if address.to_string().contains("/ws") {
        println!("Web clients can connect via: ws://157.245.208.60:4001/ws");
    }
}
```

#### Verification:
- Bootstrap logs show both TCP and WebSocket listeners
- `telnet 157.245.208.60 4001` works (TCP)
- WebSocket connection test passes

### Phase 2: Web Frontend Integration (2 hours)

#### Files to Create/Modify:
1. `/website/lib/p2p-client.ts` (new)
2. `/website/components/DashboardScreen.tsx` (modify)
3. `/website/lib/wallet.ts` (enhance)

#### A. Real P2P WebSocket Client

**Create `/website/lib/p2p-client.ts`:**
```typescript
import { WalletData } from '@/app/page'

export class HeartEarthP2PClient {
  private ws: WebSocket | null = null
  private peerId: string
  private onMessage: (message: any) => void
  
  constructor(walletData: WalletData, onMessage: (message: any) => void) {
    this.peerId = walletData.peerAddress
    this.onMessage = onMessage
  }
  
  async connect(): Promise<void> {
    const wsUrl = `ws://157.245.208.60:4001/ws/p2p/${this.peerId}`
    this.ws = new WebSocket(wsUrl)
    
    this.ws.onopen = () => {
      console.log('Connected to Heart Earth network')
      this.subscribeToChannel('/art/dev/general/v1')
    }
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      this.onMessage(data)
    }
  }
  
  sendMessage(channel: string, content: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'publish',
        channel,
        content
      }))
    }
  }
  
  private subscribeToChannel(channel: string): void {
    this.ws?.send(JSON.stringify({
      type: 'subscribe',
      channel
    }))
  }
}
```

#### B. Integration with Dashboard

**Modify DashboardScreen.tsx:**
- Replace mock connection with real P2PClient
- Handle real messages from network
- Display actual connected peers
- Real message sending functionality

#### C. Enhanced Wallet Integration

**Enhance `/website/lib/wallet.ts`:**
- Use actual BIP32 derivation paths
- Match exact derivation logic from Rust wallet
- Implement proper address generation
- Add validation against known test vectors

### Phase 3: Digital Ocean Deployment (15 minutes)

#### Deployment Steps:
```bash
# 1. SSH to Digital Ocean
ssh root@157.245.208.60

# 2. Update code
cd heart-earth
git pull origin main

# 3. Rebuild bootstrap
cargo build --release -p p2p --bin bootstrap

# 4. Stop current bootstrap
pkill bootstrap

# 5. Start with WebSocket support
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &

# 6. Verify both transports
tail -f bootstrap.log
# Should show: "Listening on /ip4/0.0.0.0/tcp/4001"
# Should show: "Listening on /ip4/0.0.0.0/tcp/4001/ws"
```

#### Verification Commands:
```bash
# Test TCP (existing clients)
echo "test" | nc 157.245.208.60 4001

# Test WebSocket (new web clients)
# Use browser dev tools or wscat
```

### Phase 4: Testing & Validation (30 minutes)

#### Test Cases:
1. **CLI to CLI**: Existing functionality unchanged
2. **Web to CLI**: Browser user sends message, CLI receives
3. **CLI to Web**: CLI user sends message, browser receives  
4. **Web to Web**: Multiple browser users communicate
5. **Network Discovery**: Web client sees CLI peers in user list

#### Success Criteria:
- [ ] Bootstrap accepts both TCP and WebSocket connections
- [ ] Web frontend connects to live network (not demo)
- [ ] Real message exchange between web and CLI clients
- [ ] Wallet generation uses actual BIP39/BIP32 (not mock)
- [ ] Addresses match Rust derivation exactly
- [ ] No security regressions

## Technical Specifications

### WebSocket Protocol
- **Endpoint**: `ws://157.245.208.60:4001/ws`
- **Protocol**: libp2p WebSocket transport
- **Security**: Noise encryption (same as TCP)
- **Multiplexing**: Yamux (same as TCP)

### Message Format
```json
{
  "type": "gossipsub_message",
  "channel": "/art/dev/general/v1", 
  "sender": "12D3KooWJD7NfLu726X6xMsGo7JFTj5s7iWb4tvobCTNsGXtQYNB",
  "content": "Hello from web!",
  "timestamp": 1703123456
}
```

### Security Considerations
- Same Noise encryption as CLI clients
- Web Crypto API for entropy (not Math.random)
- Mnemonic never sent over network
- Private keys stay in browser memory only
- CSP headers prevent XSS attacks

## Rollback Plan
If WebSocket implementation fails:
1. Revert bootstrap.rs changes
2. Rebuild and restart: `pkill bootstrap && nohup ./target/release/bootstrap > bootstrap.log 2>&1 &`
3. TCP-only operation restored
4. No impact on existing CLI clients

## Future Enhancements (Post-MVP)
1. **WASM Wallet**: Compile wallet crate to WebAssembly
2. **WebRTC Support**: Direct peer-to-peer in browsers
3. **Mobile App**: React Native with same backend
4. **Browser Extension**: Deep integration with web3 sites

---

**Estimated Total Time**: 3-4 hours
**Risk Level**: Low (additive changes, no breaking modifications)
**Dependencies**: None (all required libraries already in Cargo.toml)