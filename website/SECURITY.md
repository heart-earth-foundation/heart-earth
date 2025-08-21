# Heart Earth Web Security Model

## 🔒 Security Overview (2025 Standards)

Your wallet security follows industry best practices. Here's exactly what happens:

### ✅ What's SECURE

**Mnemonic Generation:**
- Uses `@scure/bip39` library (audited, industry standard)
- 128 bits of cryptographically secure entropy
- Browser's `Web Crypto API` for randomness (NOT Math.random)
- Generates true BIP39-compliant 12-word phrases

**Local Storage:**
- Mnemonic stays in YOUR browser memory only
- NEVER sent to any server
- NEVER stored permanently in browser storage
- Only exists while you're actively using the app

**Network Security:**
- Security headers prevent clickjacking, XSS attacks
- Content Security Policy blocks malicious scripts
- No external connections except to your P2P bootstrap node

### 🏠 Where Your Data Lives

**Your Computer Only:**
```
Mnemonic → Browser Memory → Deleted when you close tab
Private Keys → Derived locally → Never stored anywhere
Addresses → Generated deterministically → Safe to display
```

**NOT on our servers:**
- We have no servers storing wallet data
- We cannot see your mnemonic or private keys
- We cannot recover your wallet if you lose it

### 🚫 What We DON'T Do

- ❌ Store mnemonics on servers
- ❌ Send private keys over internet
- ❌ Use cloud storage for wallet data
- ❌ Track your wallet addresses
- ❌ Have backdoors or master keys

### 🔐 Your Responsibilities

**CRITICAL - You Must:**
1. **Write down your mnemonic on paper** (not digital!)
2. **Store paper backup safely** (fireproof, offline)
3. **Never share mnemonic with anyone**
4. **Never store mnemonic in cloud/email/photos**

**If you lose your mnemonic:**
- Your wallet is gone forever
- We cannot recover it
- No one can recover it

### 🌐 P2P Network Security

**What's Secure:**
- All P2P connections use libp2p Noise encryption
- Messages are cryptographically signed
- Your peer ID is derived from your wallet seed
- Bootstrap node only routes messages, can't read them

**Network Data:**
- Bootstrap node sees: Your peer ID, connection time
- Other peers see: Your peer ID, messages you send
- Network does NOT see: Your mnemonic, private keys, blockchain address

### 🛡️ Security Libraries Used

**Cryptography:**
- `@scure/bip39`: BIP39 mnemonic standard
- `@noble/hashes`: Audited hash functions  
- `@scure/bip32`: HD wallet derivation
- Browser Web Crypto API for entropy

**Framework:**
- Next.js 14.2.32 (latest security patches)
- Security headers preventing common attacks
- TypeScript for type safety

### ⚠️ Current Limitations (Demo Mode)

This is a **DEMONSTRATION** frontend. For production:

1. **Real Wallet Integration**: Connect to your Rust wallet backend
2. **Proper Key Derivation**: Use full BIP32/SLIP10 paths
3. **Encrypted Storage**: Add local encryption for saved wallets
4. **Hardware Wallet Support**: Integrate Ledger/Trezor
5. **Audit**: Third-party security audit required

### 🚨 Red Flags - Never Trust If:

- App asks to "backup to cloud"
- App sends mnemonic to server "for safety"
- App requires email/phone verification
- App promises to "recover lost wallets"
- App runs on HTTP (not HTTPS)

### 📱 Mobile/Production Considerations

For real mobile/production deployment:

1. **Use HTTPS only** (never HTTP)
2. **Pin TLS certificates**
3. **Disable dev tools in production**
4. **Add biometric authentication**
5. **Use secure enclave on mobile**

---

**Bottom Line:** Your mnemonic never leaves your device. We built this following 2025 security standards, but YOU must protect your recovery phrase.