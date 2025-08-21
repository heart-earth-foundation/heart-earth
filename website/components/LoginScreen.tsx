'use client'

import { useState } from 'react'
import { WalletData } from '@/app/page'
import { SecureWallet } from '@/lib/wallet'

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
    <div className="min-h-screen flex items-center justify-center">
      <div className="card max-w-md mx-auto">
      <h2 className="text-2xl font-bold text-center mb-6 text-heart-earth-500">
        Login
      </h2>

      <form onSubmit={handleLogin} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Wallet Name</label>
          <input
            type="text"
            value={walletName}
            onChange={(e) => setWalletName(e.target.value)}
            className="w-full input-field"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full input-field"
            required
          />
        </div>

        {error && (
          <div className="text-red-500 text-sm text-center">
            {error}
          </div>
        )}

        <div className="flex space-x-3">
          <button 
            type="button" 
            onClick={onBack} 
            className="flex-1 btn-secondary"
            disabled={loading}
          >
            Back
          </button>
          <button 
            type="submit" 
            className="flex-1 btn-primary"
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Login'}
          </button>
        </div>
      </form>

      <div className="mt-6 text-center text-sm text-gray-400">
        <p>Wallet stored in: <span className="font-mono">~/.config/heart-earth/wallets/</span></p>
      </div>
      </div>
    </div>
  )
}