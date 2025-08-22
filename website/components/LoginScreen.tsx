'use client'

import { useState } from 'react'
import { WalletData } from '@/app/page'
import { SecureWallet } from '@/lib/wallet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

interface LoginScreenProps {
  onLogin: (data: WalletData) => void
  onBack: () => void
}

export default function LoginScreen({ onLogin, onBack }: LoginScreenProps) {
  const [walletName, setWalletName] = useState('default')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const generateAddresses = (mnemonic: string) => {
    // Use deterministic address generation
    return SecureWallet.generateAddresses(mnemonic, 0, 0)
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      // Simulate wallet loading delay
      await new Promise(resolve => setTimeout(resolve, 1000))

      // Simulate checking wallet existence and password validation
      if (Math.random() > 0.7) {
        setError('Wallet not found or invalid password')
        setLoading(false)
        return
      }

      // In production, decrypt and load the actual mnemonic from storage
      const simulatedMnemonic = 'abandon ability able about above absent absorb abstract absurd abuse access accident'
      const addresses = generateAddresses(simulatedMnemonic)

      onLogin({
        name: walletName,
        mnemonic: simulatedMnemonic,
        password,
        peerAddress: addresses.peerAddress,
        blockchainAddress: addresses.blockchainAddress
      })
    } catch (err) {
      setError('Failed to load wallet')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container mx-auto px-6 py-8">
      <div className="min-h-[80vh] flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Login</CardTitle>
            <CardDescription>Access your existing wallet</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="wallet-name">Wallet Name</Label>
                <Input
                  id="wallet-name"
                  type="text"
                  value={walletName}
                  onChange={(e) => setWalletName(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="flex gap-3">
                <Button 
                  type="button" 
                  variant="outline"
                  onClick={onBack} 
                  className="flex-1"
                  disabled={loading}
                >
                  Back
                </Button>
                <Button 
                  type="submit" 
                  className="flex-1"
                  disabled={loading}
                >
                  {loading ? 'Loading...' : 'Login'}
                </Button>
              </div>
            </form>
          </CardContent>
          <CardFooter className="justify-center">
            <p className="text-sm text-muted-foreground text-center">
              Wallet stored in: <span className="font-mono">~/.config/heart-earth/wallets/</span>
            </p>
          </CardFooter>
        </Card>
      </div>
    </div>
  )
}