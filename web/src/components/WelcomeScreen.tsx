import { Screen } from '@/app/page'
import { Button } from '@/components/ui/button'

interface WelcomeScreenProps {
  onScreenChange: (screen: Screen) => void
}

export default function WelcomeScreen({ onScreenChange }: WelcomeScreenProps) {
  return (
    <div className="container mx-auto px-6 py-8">
      <div className="min-h-[80vh] flex items-center justify-center">
        <div className="text-center space-y-12 max-w-2xl mx-auto">
        <div className="space-y-6">
          <h1 className="text-6xl md:text-7xl font-bold">
            Heart Earth
          </h1>
          <p className="text-2xl text-muted-foreground">
            A Decentralized Internet
          </p>
          <p className="text-lg text-muted-foreground max-w-xl mx-auto leading-relaxed">
            Create a new wallet or login to participate in the network.
          </p>
        </div>

        <div className="space-y-4 max-w-sm mx-auto">
          <Button 
            onClick={() => onScreenChange('create')}
            className="w-full"
            size="lg"
          >
            Create New Wallet
          </Button>
          
          <Button 
            onClick={() => onScreenChange('login')}
            variant="secondary"
            className="w-full"
            size="lg"
          >
            Login to Existing Wallet
          </Button>
        </div>

        <div className="text-sm text-muted-foreground space-y-2 border-t pt-6">
          <p>Live Network: <span className="font-mono">157.245.208.60:4001</span></p>
          <p>Channel: <span className="font-mono">/art/dev/general/v1</span></p>
        </div>
        </div>
      </div>
    </div>
  )
}