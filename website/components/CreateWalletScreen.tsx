'use client'

import { useState } from 'react'
import { WalletData } from '@/app/page'
import { SecureWallet } from '@/lib/wallet'

interface CreateWalletScreenProps {
  onWalletCreated: (data: WalletData) => void
  onBack: () => void
}

export default function CreateWalletScreen({ onWalletCreated, onBack }: CreateWalletScreenProps) {
  const [step, setStep] = useState<'password' | 'mnemonic' | 'confirm'>('password')
  const [walletName, setWalletName] = useState('default')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [mnemonic, setMnemonic] = useState('')
  const [savedMnemonic, setSavedMnemonic] = useState(false)
  const [error, setError] = useState('')

  const generateMnemonic = () => {
    // Use cryptographically secure mnemonic generation
    return SecureWallet.generateMnemonic()
  }

  const generateAddresses = (mnemonic: string) => {
    // Use deterministic address generation from mnemonic
    return SecureWallet.generateAddresses(mnemonic, 0, 0)
  }

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (password.length < 8) {
      setError('Password must be at least 8 characters long')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (!password.match(/^[\x20-\x7E]*$/)) {
      setError('Password must contain only ASCII characters')
      return
    }

    const generated = generateMnemonic()
    setMnemonic(generated)
    setStep('mnemonic')
  }

  const handleMnemonicConfirm = () => {
    if (!savedMnemonic) {
      setError('Please confirm you have saved your mnemonic phrase')
      return
    }
    
    const addresses = generateAddresses(mnemonic)
    onWalletCreated({
      name: walletName,
      mnemonic,
      password,
      peerAddress: addresses.peerAddress,
      blockchainAddress: addresses.blockchainAddress
    })
  }

  const renderPasswordStep = () => (
    <div className="min-h-screen flex items-center justify-center">
      <div className="card max-w-md mx-auto">
        <h2 className="text-2xl font-bold text-center mb-6 text-heart-earth-500">
          Create New Wallet
        </h2>

      <form onSubmit={handlePasswordSubmit} className="space-y-4">
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
          <label className="block text-sm font-medium mb-1">Password (ASCII only)</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full input-field"
            minLength={8}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Confirm Password</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
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
          <button type="button" onClick={onBack} className="flex-1 btn-secondary">
            Back
          </button>
          <button type="submit" className="flex-1 btn-primary">
            Generate Wallet
          </button>
        </div>
      </form>
      </div>
    </div>
  )

  const renderMnemonicStep = () => (
    <div className="min-h-screen flex items-center justify-center">
      <div className="card max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold text-center mb-6 text-red-500">
        ⚠️ SAVE YOUR RECOVERY PHRASE
      </h2>

      <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
        <p className="text-red-400 font-bold text-center mb-2">
          This phrase will ONLY be shown ONCE!
        </p>
        <p className="text-red-300 text-center">
          Write it down and keep it safe!
        </p>
      </div>

      <div className="bg-gray-900 border border-heart-earth-500 rounded-lg p-6 mb-6">
        <p className="text-heart-earth-500 font-mono text-lg text-center leading-relaxed">
          {mnemonic}
        </p>
      </div>

      <div className="mb-6">
        <label className="flex items-center space-x-3 cursor-pointer">
          <input
            type="checkbox"
            checked={savedMnemonic}
            onChange={(e) => setSavedMnemonic(e.target.checked)}
            className="w-4 h-4 text-heart-earth-500 rounded"
          />
          <span className="text-sm">I have saved my recovery phrase</span>
        </label>
      </div>

      {error && (
        <div className="text-red-500 text-sm text-center mb-4">
          {error}
        </div>
      )}

      <div className="flex space-x-3">
        <button onClick={onBack} className="flex-1 btn-secondary">
          Go Back
        </button>
        <button 
          onClick={handleMnemonicConfirm}
          className={`flex-1 ${savedMnemonic ? 'btn-primary' : 'bg-gray-600 text-gray-400 cursor-not-allowed'}`}
          disabled={!savedMnemonic}
        >
          Create Wallet
        </button>
      </div>
      </div>
    </div>
  )

  switch (step) {
    case 'password':
      return renderPasswordStep()
    case 'mnemonic':
      return renderMnemonicStep()
    default:
      return renderPasswordStep()
  }
}