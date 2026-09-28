import { useState, type ReactElement, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useDisclosure } from '../hooks/useDisclosure'
import { BottomSheet } from './BottomSheet'
import { buttonClasses } from '../lib/buttonStyles'
import { createAccount, loadWallet } from '../lib/wallet'

interface EnterDemoProps {
  children: ReactNode
  className: string
}

/**
 * The way into the demo. A browser that already holds a demo account goes
 * straight in; otherwise the sheet creates one with a passkey first.
 */
export function EnterDemo({ children, className }: EnterDemoProps): ReactElement {
  const sheet = useDisclosure()

  if (loadWallet()) {
    return (
      <Link to="/app" className={className}>
        {children}
      </Link>
    )
  }

  return (
    <>
      <button type="button" onClick={sheet.show} aria-haspopup="dialog" aria-expanded={sheet.open} className={className}>
        {children}
      </button>

      <BottomSheet open={sheet.open} onClose={sheet.hide} title="Enter the C-Sign demo">
        <div className="space-y-5 pb-2">
          <p className="text-sm leading-relaxed text-neutral-400">
            A passkey on this device becomes the only signer of a new smart account on testnet. Signing in with it
            never sends a transaction.
          </p>
          <PasskeyCreate />
        </div>
      </BottomSheet>
    </>
  )
}

/** Creates the passkey account and enters the demo. Also used inside the app when no account exists yet. */
export function PasskeyCreate({ onCreated }: { onCreated?: () => void }): ReactElement {
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const supported = typeof window !== 'undefined' && 'PublicKeyCredential' in window

  async function create(): Promise<void> {
    setBusy(true)
    setError(null)
    try {
      await createAccount('C-Sign demo')
      if (onCreated) onCreated()
      else navigate('/app')
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e)
      if (!/NotAllowedError|cancel|abort/i.test(text)) setError(text)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col items-center gap-3">
      <button
        type="button"
        onClick={() => void create()}
        disabled={busy || !supported}
        aria-busy={busy}
        className={buttonClasses({ variant: 'positive', size: 'lg', full: true })}
      >
        {busy ? 'Creating your account…' : 'Create a passkey account'}
      </button>
      <p className="max-w-sm text-center text-xs leading-relaxed text-neutral-500">
        No extension, no seed phrase, nothing to buy. The account lives on this device only, and the demo pays the
        deployment fee. <strong className="font-medium text-neutral-400">Testnet only.</strong>
      </p>
      {!supported && (
        <p role="status" className="max-w-sm text-center text-xs text-warning-300">
          This browser has no passkey support.
        </p>
      )}
      {error && (
        <p role="alert" className="max-w-sm text-center text-xs text-negative-300">
          {error}
        </p>
      )}
    </div>
  )
}
