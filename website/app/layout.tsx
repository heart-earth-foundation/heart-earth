import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Heart Earth - P2P Blockchain Network',
  description: 'Secure peer-to-peer blockchain network with HD wallet functionality',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-900 text-white">
        {children}
      </body>
    </html>
  )
}