# Authentication Research - Heart Earth Wallet

## Project Requirements
- Adapt EIP-712 + EIP-4361 (SIWE) for Heart Earth wallet
- Support WebAuthn biometric unlock alongside password
- Use existing Ed25519 keys for message signing
- Work with current HD wallet structure (UnifiedAccount)
- Support WASM browser environment

## Current Wallet Architecture Analysis

### From wallet/src/account.rs:
- `UnifiedAccount` structure with shared index for blockchain + P2P keys
- Ed25519 signing keys available via `ed25519_signing_key()`
- Address format: 'art' prefix (from address.rs)
- HD derivation paths: blockchain (m/44'/0'/account'/0/index), P2P (m/44'/1'/account'/0/index)

### From wallet/src/storage.rs:
- Password-based encryption with Argon2 + AES-GCM
- Mnemonic storage protection
- ASCII-only password validation

## Official Specifications Research

### EIP-712: Typed Structured Data Hashing and Signing
**Source**: https://eips.ethereum.org/EIPS/eip-712

**Key Components**:
- Domain separator prevents signature collision
- Structured data types (atomic, dynamic, reference)
- `hashStruct` function for deterministic encoding
- JSON-RPC method: `eth_signTypedData`

**Domain Separator Fields**:
- name: signing domain name
- version: domain version  
- chainId: EIP-155 chain ID
- verifyingContract: contract address (optional)
- salt: disambiguation (optional)

### EIP-4361: Sign-In with Ethereum (SIWE)
**Source**: https://eips.ethereum.org/EIPS/eip-4361

**Required Message Fields**:
- domain: requesting domain
- address: Ethereum address (ERC-55 checksum)
- uri: RFC 3986 URI
- version: "1"
- chain-id: EIP-155 Chain ID
- nonce: minimum 8 alphanumeric characters
- issued-at: RFC 3339 datetime

**Optional Fields**:
- scheme: URI scheme
- statement: human-readable text
- expiration-time: message expiry
- not-before: message validity start
- request-id: system identifier
- resources: related URIs list

## Dependencies Research Status

### Current Dependencies (confirmed in Cargo.toml):
- ✅ `rand` 0.8 - OsRng for secure random generation
- ✅ `ed25519-dalek` 2.1 - Ed25519 signing/verification
- ✅ `serde/serde_json` - message serialization
- ✅ `uuid` - needs v4 feature for session IDs

### Dependencies Needed (research completed):
- ✅ `chrono` - RFC 3339 timestamp generation via `.to_rfc3339()`
- ✅ `webauthn-rs` - passkey/biometric auth with WebauthnBuilder
- ✅ `base64` - URL-safe encoding for credentials (URL_SAFE_NO_PAD)

## Detailed Dependency Research

### chrono (for SIWE timestamps)
**Source**: https://docs.rs/chrono/latest/chrono/
- **RFC 3339 Format**: Use `DateTime<Utc>::now().to_rfc3339()` 
- **Example Output**: "2017-07-14T02:40:00+00:00"
- **SIWE Compliance**: Meets EIP-4361 requirement for issued-at field

### webauthn-rs (for biometric authentication)
**Source**: https://docs.rs/webauthn-rs/latest/webauthn_rs/
- **Configuration**: WebauthnBuilder with RP identity and origin
- **Workflow**: start_passkey_registration → finish_passkey_registration
- **Integration**: Can work alongside existing password encryption
- **Security**: Prevents replay attacks, enforces user verification

### base64 (for credential encoding)
**Source**: https://docs.rs/base64/latest/base64/
- **WebAuthn Requirements**: URL-safe encoding without padding
- **Configuration**: `base64::engine::general_purpose::URL_SAFE_NO_PAD`
- **Use Cases**: Encode WebAuthn credentials, challenge responses

## Outstanding Research Questions

1. **EIP-712 Adaptation**: Replace keccak256 with blake3/sha256 for Ed25519 compatibility
2. **SIWE Address Format**: Modify message format to accept 'art' prefixed addresses  
3. **Chain ID**: Define custom chain ID for Heart Earth network (non-Ethereum)
4. **Domain Separator**: Configure for Heart Earth instead of Ethereum
5. **WASM Compatibility**: Verify all dependencies work in browser environment

## EIP-712 Adaptation for Ed25519

### hashStruct Function Analysis
**Source**: https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct
- **Original**: `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`
- **Heart Earth Adaptation**: Replace keccak256 with blake3 or sha256
- **Type Safety**: Maintain typeHash generation for struct disambiguation
- **Encoding**: Keep 32-byte zero-padding for atomic types

### SIWE Reference Implementation Analysis  
**Source**: https://github.com/spruceid/siwe/blob/main/packages/siwe/lib/client.ts
- **Message Construction**: Standard format with domain, address, URI, nonce
- **Address Validation**: Currently validates Ethereum addresses
- **Signature Verification**: Supports both EOA and contract wallet signatures
- **Security**: Implements nonce-based replay protection

## Heart Earth Adaptations Required

### Message Format Modifications
1. **Address Field**: Accept 'art' prefixed addresses instead of Ethereum 0x format
2. **Chain ID**: Define custom Heart Earth chain ID (suggest: 4361 for SIWE reference)
3. **Domain Separator**: Configure for heart-earth.network domain
4. **Signature Algorithm**: Use Ed25519 instead of secp256k1

### Integration with Current Wallet
1. **Signing Keys**: Use existing `UnifiedAccount.ed25519_signing_key()`
2. **Address Format**: Use existing `Address.to_string()` ('art' prefix)
3. **Storage**: Add WebAuthn credentials alongside encrypted mnemonic
4. **WASM Compatibility**: Verify all dependencies support WASM target

## Implementation Planning Status
✅ **RESEARCH COMPLETE** - Ready for implementation planning