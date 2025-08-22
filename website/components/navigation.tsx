"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { ThemeToggle } from "@/components/theme-toggle"
import { Menu, Github } from "lucide-react"
import { cn } from "@/lib/utils"

export function Navigation() {
  const pathname = usePathname()

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto px-6 py-0">
        <div className="flex h-16 items-center justify-between">
          {/* Left - Brand */}
          <div className="flex items-center">
            <Link href="/" className="flex items-center">
              <span className="text-xl font-bold">Heart Earth</span>
            </Link>
          </div>

          {/* Center - Navigation */}
          <nav className="hidden md:flex items-center space-x-8">
            <Link
              href="/wallet"
              className={cn(
                "text-sm font-medium transition-colors hover:text-primary",
                pathname === "/wallet"
                  ? "text-foreground"
                  : "text-muted-foreground"
              )}
            >
              Wallet
            </Link>
            <Link
              href="/p2p"
              className={cn(
                "text-sm font-medium transition-colors hover:text-primary",
                pathname === "/p2p"
                  ? "text-foreground"
                  : "text-muted-foreground"
              )}
            >
              P2P
            </Link>
          </nav>

          {/* Right - Actions */}
          <div className="flex items-center space-x-2">
            <Button variant="ghost" size="sm" asChild className="hidden md:flex">
              <Link
                href="https://github.com/AudioLedger/heart-earth"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Github className="h-4 w-4 mr-2" />
                Source
              </Link>
            </Button>
            <ThemeToggle />

            {/* Mobile Navigation */}
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="sm" className="md:hidden">
                  <Menu className="h-5 w-5" />
                  <span className="sr-only">Toggle menu</span>
                </Button>
              </SheetTrigger>
              <SheetContent side="right">
                <div className="grid gap-6 py-6">
                  <Link
                    href="/wallet"
                    className={cn(
                      "text-sm font-medium transition-colors hover:text-primary",
                      pathname === "/wallet"
                        ? "text-foreground"
                        : "text-muted-foreground"
                    )}
                  >
                    Wallet
                  </Link>
                  <Link
                    href="/p2p"
                    className={cn(
                      "text-sm font-medium transition-colors hover:text-primary",
                      pathname === "/p2p"
                        ? "text-foreground"
                        : "text-muted-foreground"
                    )}
                  >
                    P2P
                  </Link>
                  <Link
                    href="https://github.com/AudioLedger/heart-earth"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-muted-foreground transition-colors hover:text-primary"
                  >
                    Source
                  </Link>
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </header>
  )
}