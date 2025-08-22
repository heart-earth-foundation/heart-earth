import Link from "next/link"
import { Github } from "lucide-react"

export function Footer() {
  return (
    <footer className="border-t bg-background">
      <div className="container mx-auto px-6 py-8">
        <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-8">
          {/* Left - Brand */}
          <div className="flex-1 text-center md:text-left">
            <span className="text-lg font-bold">Heart Earth</span>
            <p className="text-sm text-muted-foreground mt-2">
              A Decentralized Internet
            </p>
          </div>

          {/* Center - Navigation */}
          <div className="flex-1 text-center">
            <h4 className="text-sm font-semibold mb-3">Navigation</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>
                <Link href="/wallet" className="hover:text-foreground transition-colors">
                  Wallet
                </Link>
              </li>
              <li>
                <Link href="/p2p" className="hover:text-foreground transition-colors">
                  P2P
                </Link>
              </li>
            </ul>
          </div>

          {/* Right - Links */}
          <div className="flex-1 text-center md:text-right">
            <h4 className="text-sm font-semibold mb-3">Links</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li className="flex justify-center md:justify-end">
                <Link 
                  href="https://github.com/AudioLedger/heart-earth" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-foreground transition-colors flex items-center"
                >
                  <Github className="h-4 w-4 mr-2" />
                  GitHub
                </Link>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </footer>
  )
}