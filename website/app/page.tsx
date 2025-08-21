'use client'

import { useState } from 'react'
import WelcomeScreen from '@/components/WelcomeScreen'
import CreateWalletScreen from '@/components/CreateWalletScreen'
import LoginScreen from '@/components/LoginScreen'
import DashboardScreen from '@/components/DashboardScreen'

export type Screen = 'welcome' | 'create' | 'login' | 'dashboard'

export interface WalletData {
  name: string
  mnemonic: string
  password: string
  peerAddress: string
  blockchainAddress: string
}

export default function Home() {
  const [currentScreen, setCurrentScreen] = useState<Screen>('welcome')
  const [walletData, setWalletData] = useState<WalletData | null>(null)

  const handleScreenChange = (screen: Screen) => {
    setCurrentScreen(screen)
  }

  const handleWalletCreated = (data: WalletData) => {
    setWalletData(data)
    setCurrentScreen('dashboard')
  }

  const handleLogin = (data: WalletData) => {
    setWalletData(data)
    setCurrentScreen('dashboard')
  }

  const renderScreen = () => {
    switch (currentScreen) {
      case 'welcome':
        return <WelcomeScreen onScreenChange={handleScreenChange} />
      case 'create':
        return <CreateWalletScreen onWalletCreated={handleWalletCreated} onBack={() => handleScreenChange('welcome')} />
      case 'login':
        return <LoginScreen onLogin={handleLogin} onBack={() => handleScreenChange('welcome')} />
      case 'dashboard':
        return <DashboardScreen walletData={walletData} onLogout={() => handleScreenChange('welcome')} />
      default:
        return <WelcomeScreen onScreenChange={handleScreenChange} />
    }
  }

  return (
    <main className="min-h-screen bg-gray-900">
      <div className="w-full">
        {renderScreen()}
      </div>
    </main>
  )
}