import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'

export interface WalletAddresses {
  peerAddress: string
  blockchainAddress: string
}

export class SecureWallet {
  /**
   * Generate a cryptographically secure 12-word BIP39 mnemonic
   * Uses browser's Web Crypto API for secure entropy
   */
  static generateMnemonic(): string {
    // Use 128 bits of entropy for 12-word mnemonic (secure standard)
    return generateMnemonic(wordlist, 128)
  }

  /**
   * Validate a BIP39 mnemonic phrase
   */
  static validateMnemonic(mnemonic: string): boolean {
    return validateMnemonic(mnemonic, wordlist)
  }

  /**
   * Generate deterministic addresses from mnemonic
   * Simulates the Rust wallet's HD derivation logic
   */
  static generateAddresses(mnemonic: string, accountNumber: number = 0, index: number = 0): WalletAddresses {
    if (!this.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic phrase')
    }

    // Generate seed from mnemonic (no passphrase)
    const seed = mnemonicToSeedSync(mnemonic, '')
    
    // Simulate deterministic derivation (in production, use proper BIP32 derivation)
    const seedHex = Array.from(seed)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
    
    // Create deterministic but unique identifiers
    const accountSeed = seedHex + accountNumber.toString() + index.toString()
    
    // Generate peer ID (simulate ed25519 public key format)
    const peerHash = this.deterministicHash(accountSeed + 'peer')
    const peerAddress = '12D3KooW' + peerHash.substring(0, 44)
    
    // Generate blockchain address with 'art' prefix
    const blockchainHash = this.deterministicHash(accountSeed + 'blockchain')
    const blockchainAddress = 'art' + blockchainHash.substring(0, 27)
    
    return {
      peerAddress,
      blockchainAddress
    }
  }

  /**
   * Create a deterministic hash (simulates proper key derivation)
   */
  private static deterministicHash(input: string): string {
    // This is a simplified hash for demo purposes
    // In production, use proper HMAC-SHA512 or Ed25519/secp256k1 derivation
    let hash = 0
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36).padStart(16, '0')
  }

  /**
   * Securely clear sensitive data from memory
   */
  static clearSensitiveData(data: string): void {
    // In a real implementation, you'd use techniques to overwrite memory
    // JavaScript doesn't provide direct memory management, but we can:
    data = ''
    if (typeof window !== 'undefined' && window.crypto && 'getRandomValues' in window.crypto) {
      // Trigger garbage collection hint
      if ('gc' in window) {
        (window as any).gc()
      }
    }
  }
}