import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Wallet, Key, Network, Shield, Code, Users, Globe, ArrowRight } from "lucide-react"

export default function WalletPage() {
  return (
    <div className="container mx-auto px-6 py-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="text-center space-y-4">
          <Wallet className="h-16 w-16 text-primary mx-auto" />
          <h1 className="text-4xl font-bold">Heart Earth Unified Wallet</h1>
          <p className="text-xl text-muted-foreground">
            Single 12-word mnemonic generates Heart blockchain accounts and Earth P2P identities
          </p>
          <p className="text-sm text-muted-foreground">
            Heart accounts hold ART tokens and execute blockchain transactions • Earth identities provide P2P network authentication and messaging
          </p>
          <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md text-sm">
            Same seed index produces linked Heart address and Earth peer ID for unified identity management
          </div>
        </div>

        <Card className="border-2 border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ArrowRight className="h-5 w-5" />
              <span>Unified Account Architecture</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4 items-center">
              <div className="text-center">
                <div className="font-mono text-sm bg-yellow-100 dark:bg-yellow-900/20 p-2 rounded mb-2">
                  12-word mnemonic
                </div>
                <div className="text-xs text-muted-foreground">Single backup phrase</div>
              </div>
              <ArrowRight className="h-6 w-6 text-primary mx-auto" />
              <div className="text-center space-y-2">
                <div className="font-mono text-xs bg-red-100 dark:bg-red-900/20 p-1 rounded">
                  heart_123abc...
                </div>
                <div className="font-mono text-xs bg-green-100 dark:bg-green-900/20 p-1 rounded">
                  12D3KooWxyz...
                </div>
                <div className="text-xs text-muted-foreground">Linked accounts from same index</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Key className="h-5 w-5 text-red-500" />
                <span>Heart Account (Blockchain)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="font-mono text-sm bg-gray-100 dark:bg-gray-800 p-2 rounded">
                heart_abc123...
              </div>
              <ul className="space-y-1 text-sm">
                <li>• Derivation: BIP44 path m/44'/0'/account/0/index</li>
                <li>• Cryptography: secp256k1 elliptic curve</li>
                <li>• Purpose: ART token transactions and smart contracts</li>
                <li>• Address format: Custom heart_ prefix with base58 encoding</li>
                <li>• Token compatibility: Holds and transfers ART tokens</li>
              </ul>
              <div className="mt-2 text-xs text-muted-foreground">
                Rebranded from art_ prefix to align with Heart Earth project branding
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Network className="h-5 w-5 text-green-500" />
                <span>Earth Identity (P2P Network)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="font-mono text-sm bg-gray-100 dark:bg-gray-800 p-2 rounded">
                12D3KooWxyz...
              </div>
              <ul className="space-y-1 text-sm">
                <li>• Derivation: Ed25519 path m/44'/1'/account/0/index</li>
                <li>• Cryptography: Ed25519 signature scheme</li>
                <li>• Purpose: P2P network participation and messaging</li>
                <li>• Format: Standard libp2p CIDv0 multihash</li>
                <li>• Network role: Peer discovery and gossipsub communication</li>
              </ul>
              <div className="mt-2 text-xs text-muted-foreground">
                Uses standard libp2p format for network compatibility
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Code className="h-5 w-5" />
              <span>Complete Signing Matrix - Both Accounts Support Both Methods</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3 text-red-600">Heart Account Signing Powers</h4>
                <div className="space-y-3">
                  <div>
                    <div className="font-medium text-sm">AccountAuthSigner</div>
                    <ul className="space-y-1 text-xs text-muted-foreground ml-2">
                      <li>• SIWE-style authentication messages</li>
                      <li>• Transaction authorization</li>
                      <li>• Blockchain app login</li>
                      <li>• Context: heart-earth-auth-account</li>
                    </ul>
                  </div>
                  <div>
                    <div className="font-medium text-sm">AccountStructuredSigner</div>
                    <ul className="space-y-1 text-xs text-muted-foreground ml-2">
                      <li>• EIP-712 style typed data</li>
                      <li>• Transfer request signing</li>
                      <li>• Smart contract interactions</li>
                      <li>• Context: heart-earth-account</li>
                    </ul>
                  </div>
                </div>
              </div>
              <div>
                <h4 className="font-semibold mb-3 text-green-600">Earth Identity Signing Powers</h4>
                <div className="space-y-3">
                  <div>
                    <div className="font-medium text-sm">P2PAuthSigner</div>
                    <ul className="space-y-1 text-xs text-muted-foreground ml-2">
                      <li>• P2P network authentication</li>
                      <li>• Peer identity verification</li>
                      <li>• Message authentication</li>
                      <li>• Context: heart-earth-auth-p2p</li>
                    </ul>
                  </div>
                  <div>
                    <div className="font-medium text-sm">P2PStructuredSigner</div>
                    <ul className="space-y-1 text-xs text-muted-foreground ml-2">
                      <li>• P2P protocol data signing</li>
                      <li>• Service authorization requests</li>
                      <li>• Cross-platform identity proof</li>
                      <li>• Context: heart-earth-p2p</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
            <div className="mt-4 bg-orange-50 dark:bg-orange-900/20 p-3 rounded-md">
              <div className="font-medium text-sm mb-1">Domain Separation Security</div>
              <div className="text-xs text-muted-foreground">
                Different cryptographic contexts prevent signature reuse attacks. Heart signatures cannot be used for Earth operations and vice versa.
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Users className="h-5 w-5" />
              <span>Name Service Integration</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2">.earth Domain System</h4>
              <p className="text-sm text-muted-foreground mb-3">
                Register human-readable names that resolve to both your Heart blockchain address and Earth peer ID.
              </p>
              <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-md font-mono text-sm">
                <div className="mb-2">username.earth resolves to:</div>
                <div className="ml-4 space-y-1 text-xs">
                  <div>• Heart: heart_abc123... (ART tokens)</div>
                  <div>• Earth: 12D3KooWxyz... (P2P network)</div>
                </div>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Unified Identity Display</h4>
              <ul className="space-y-1 text-sm text-muted-foreground">
                <li>• P2P chat shows "alice.earth" instead of peer ID</li>
                <li>• Blockchain transactions resolve to readable names</li>
                <li>• Cross-platform identity without revealing technical addresses</li>
                <li>• Fallback to raw addresses when names unavailable</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Shield className="h-5 w-5" />
              <span>Security Architecture</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2">Storage Encryption</h4>
                <ul className="space-y-1 text-sm">
                  <li>• AES-256-GCM symmetric encryption</li>
                  <li>• Argon2 key derivation function</li>
                  <li>• WebAuthn biometric authentication</li>
                  <li>• IndexedDB browser storage</li>
                  <li>• Cross-platform compatibility (CLI/WASM)</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Cryptographic Features</h4>
                <ul className="space-y-1 text-sm">
                  <li>• BLAKE3 hashing for structured data</li>
                  <li>• Nonce-based replay protection</li>
                  <li>• Domain-isolated signature contexts</li>
                  <li>• RFC 4086 compliant randomness</li>
                  <li>• Memory-safe key handling</li>
                </ul>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Network Security</h4>
              <ul className="space-y-1 text-sm">
                <li>• Noise protocol transport encryption</li>
                <li>• Ed25519 peer authentication</li>
                <li>• Gossipsub message validation</li>
                <li>• Rate limiting and connection limits</li>
                <li>• TLS/WSS for production deployment</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Globe className="h-5 w-5" />
              <span>Live Network Status</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2">P2P Network</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Bootstrap: 157.245.208.60:4001 (TCP)</li>
                  <li>• WebSocket: ws://157.245.208.60:4001/ws</li>
                  <li>• Channel: /art/dev/general/v1</li>
                  <li>• Status: Live and accepting connections</li>
                  <li>• Protocol: libp2p with gossipsub messaging</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Browser Integration</h4>
                <ul className="space-y-1 text-sm">
                  <li>• WASM wallet with CLI compatibility</li>
                  <li>• Secure IndexedDB storage</li>
                  <li>• WebAuthn biometric unlock</li>
                  <li>• Real-time P2P messaging</li>
                  <li>• Cross-browser compatibility</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Token Economics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div>
                <div className="font-semibold text-sm mb-1">ART Token Distribution</div>
                <ul className="space-y-1 text-sm text-muted-foreground">
                  <li>• Heart accounts: Hold and transfer ART tokens</li>
                  <li>• Earth identities: Network participation only (no token balance required)</li>
                  <li>• Unified ownership: Same mnemonic controls both account types</li>
                </ul>
              </div>
              <div>
                <div className="font-semibold text-sm mb-1">Cross-Account Design Rationale</div>
                <ul className="space-y-1 text-sm text-muted-foreground">
                  <li>• Simplified architecture: Single mnemonic backup</li>
                  <li>• Clear separation: Financial vs network identity</li>
                  <li>• Future compatibility: .earth names unify both roles</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>
    </div>
  )
}