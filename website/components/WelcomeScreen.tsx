import { Screen } from '@/app/page'

interface WelcomeScreenProps {
  onScreenChange: (screen: Screen) => void
}

export default function WelcomeScreen({ onScreenChange }: WelcomeScreenProps) {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-12 max-w-2xl mx-auto px-4">
        <div className="space-y-6">
          <h1 className="text-6xl md:text-7xl font-bold text-heart-earth-500">
            Heart Earth
          </h1>
          <p className="text-2xl text-gray-300">
            Secure P2P Blockchain Network
          </p>
          <p className="text-lg text-gray-400 max-w-xl mx-auto leading-relaxed">
            Connect to the decentralized network with HD wallet functionality. 
            Create a new wallet or login to join the live network.
          </p>
        </div>

        <div className="space-y-4 max-w-sm mx-auto">
          <button 
            onClick={() => onScreenChange('create')}
            className="w-full btn-primary text-lg py-4 font-semibold"
          >
            Create New Wallet
          </button>
          
          <button 
            onClick={() => onScreenChange('login')}
            className="w-full btn-secondary text-lg py-4 font-semibold"
          >
            Login to Existing Wallet
          </button>
        </div>

        <div className="text-sm text-gray-500 space-y-2 border-t border-gray-700 pt-6">
          <p>Live Network: <span className="text-heart-earth-500 font-mono">157.245.208.60:4001</span></p>
          <p>Channel: <span className="text-heart-earth-500 font-mono">/art/dev/general/v1</span></p>
        </div>
      </div>
    </div>
  )
}