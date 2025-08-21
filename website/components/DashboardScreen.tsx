'use client'

import { useState, useEffect } from 'react'
import { WalletData } from '@/app/page'

interface DashboardScreenProps {
  walletData: WalletData | null
  onLogout: () => void
}

interface Message {
  id: string
  sender: string
  content: string
  timestamp: number
}

export default function DashboardScreen({ walletData, onLogout }: DashboardScreenProps) {
  const [activeTab, setActiveTab] = useState<'account' | 'gossip' | 'settings'>('account')
  const [messages, setMessages] = useState<Message[]>([])
  const [messageInput, setMessageInput] = useState('')
  const [connectedPeers, setConnectedPeers] = useState<string[]>([])
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')

  useEffect(() => {
    // Simulate connection process
    const timer = setTimeout(() => {
      setConnectionStatus('connected')
      setConnectedPeers(['12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm'])
      
      // Add some demo messages
      setMessages([
        {
          id: '1',
          sender: 'artTL1jb55QE2YCXvKdiknQfwjd85Pa9gqRdU',
          content: 'Welcome to Heart Earth network!',
          timestamp: Date.now() - 120000
        },
        {
          id: '2', 
          sender: 'Bootstrap',
          content: 'Connected to developer channel',
          timestamp: Date.now() - 60000
        }
      ])
    }, 2000)

    return () => clearTimeout(timer)
  }, [])

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault()
    if (!messageInput.trim()) return

    const newMessage: Message = {
      id: Date.now().toString(),
      sender: walletData?.blockchainAddress || 'You',
      content: messageInput,
      timestamp: Date.now()
    }

    setMessages(prev => [...prev, newMessage])
    setMessageInput('')
  }

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  const renderAccountTab = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">Wallet Info</h3>
          <div className="space-y-3">
            <div>
              <label className="text-sm text-gray-400">Wallet Name</label>
              <p className="font-mono text-white">{walletData?.name}</p>
            </div>
            <div>
              <label className="text-sm text-gray-400">Blockchain Address</label>
              <p className="font-mono text-sm text-heart-earth-500 break-all">
                {walletData?.blockchainAddress}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">P2P Identity</h3>
          <div className="space-y-3">
            <div>
              <label className="text-sm text-gray-400">Peer ID</label>
              <p className="font-mono text-sm text-heart-earth-500 break-all">
                {walletData?.peerAddress}
              </p>
            </div>
            <div>
              <label className="text-sm text-gray-400">Status</label>
              <p className={`font-semibold ${connectionStatus === 'connected' ? 'text-green-500' : 'text-yellow-500'}`}>
                {connectionStatus === 'connected' ? '🟢 Connected' : '🟡 Connecting...'}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">Network Info</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-gray-400">Bootstrap Node</label>
            <p className="font-mono text-sm">157.245.208.60:4001</p>
          </div>
          <div>
            <label className="text-sm text-gray-400">Channel</label>
            <p className="font-mono text-sm">/art/dev/general/v1</p>
          </div>
          <div>
            <label className="text-sm text-gray-400">Connected Peers</label>
            <p className="text-sm">{connectedPeers.length}</p>
          </div>
          <div>
            <label className="text-sm text-gray-400">Protocol</label>
            <p className="text-sm">libp2p (TCP + Gossipsub)</p>
          </div>
        </div>
      </div>
    </div>
  )

  const renderGossipTab = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-4">
          <div className="card">
            <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">#general</h3>
            <div className="space-y-2 h-64 overflow-y-auto border border-gray-700 rounded p-3 bg-gray-900">
              {messages.map((msg) => (
                <div key={msg.id} className="text-sm">
                  <span className="text-gray-400">[{formatTime(msg.timestamp)}]</span>
                  <span className="text-heart-earth-500 ml-2">&lt;{msg.sender}&gt;</span>
                  <span className="ml-2">{msg.content}</span>
                </div>
              ))}
            </div>
          </div>

          <form onSubmit={handleSendMessage} className="flex space-x-2">
            <input
              type="text"
              value={messageInput}
              onChange={(e) => setMessageInput(e.target.value)}
              placeholder="Type message here..."
              className="flex-1 input-field"
              disabled={connectionStatus !== 'connected'}
            />
            <button 
              type="submit"
              className="btn-primary"
              disabled={connectionStatus !== 'connected'}
            >
              Send
            </button>
          </form>
        </div>

        <div className="space-y-4">
          <div className="card">
            <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">Channels</h3>
            <div className="space-y-2">
              <div className="text-sm bg-heart-earth-600 px-2 py-1 rounded"># general</div>
            </div>
          </div>

          <div className="card">
            <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">Users</h3>
            <div className="space-y-2">
              <div className="text-sm">🟢 You</div>
              {connectedPeers.map((peer, i) => (
                <div key={i} className="text-sm">🟢 {peer.slice(0, 8)}...</div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )

  const renderSettingsTab = () => (
    <div className="space-y-6">
      <div className="card max-w-2xl">
        <h3 className="text-lg font-semibold text-heart-earth-500 mb-4">Settings</h3>
        <div className="space-y-4">
          <div>
            <label className="text-sm text-gray-400">Theme</label>
            <select className="w-full input-field mt-1">
              <option>Dark</option>
              <option>Light</option>
            </select>
          </div>
          
          <div className="pt-4 border-t border-gray-700">
            <button className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded transition-colors">
              Delete Wallet
            </button>
            <p className="text-xs text-gray-500 mt-2">
              This will permanently delete your wallet from this device
            </p>
          </div>
        </div>
      </div>
    </div>
  )

  const tabs = [
    { id: 'account' as const, label: 'Account', render: renderAccountTab },
    { id: 'gossip' as const, label: 'Gossip', render: renderGossipTab },
    { id: 'settings' as const, label: 'Settings', render: renderSettingsTab },
  ]

  return (
    <div className="min-h-screen bg-gray-900 p-4">
      <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-heart-earth-500">Heart Earth Dashboard</h1>
        <button onClick={onLogout} className="btn-secondary">
          Logout
        </button>
      </div>

      <div className="flex space-x-1 bg-gray-800 p-1 rounded-lg">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-heart-earth-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div>
        {tabs.find(tab => tab.id === activeTab)?.render()}
      </div>
      </div>
    </div>
  )
}