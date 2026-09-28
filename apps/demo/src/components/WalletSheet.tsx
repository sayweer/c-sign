import { useEffect, useState, type ReactElement } from 'react'
import { toDisplayText, type SignedMessage } from 'c-sign'
import { verifierIsPinned } from '../lib/wallet'
import { buttonClasses } from '../lib/buttonStyles'
import { BottomSheet } from './BottomSheet'
import { short } from './ui'

export interface WalletRequest {
  account: string
  message: SignedMessage
  verifierId: string
  signers: ('passkey' | 'recovery')[]
}

const SIGNER_LABEL = { passkey: 'Passkey', recovery: 'Recovery key (Ed25519)' }

/**
 * The wallet's side of the exchange. The sheet is the wallet; the message it
 * is about to sign sits inside it on paper, decoded by the wallet itself.
 */
export function WalletSheet({
  request,
  onApprove,
  onReject,
}: {
  request: WalletRequest | null
  onApprove: () => void
  onReject: () => void
}): ReactElement {
  const [pinned, setPinned] = useState<boolean | null>(null)

  useEffect(() => {
    if (!request) return
    let live = true
    setPinned(null)
    void verifierIsPinned(request.verifierId).then((ok) => live && setPinned(ok))
    return () => {
      live = false
    }
  }, [request])

  const m = request?.message
  return (
    <BottomSheet open={!!request} onClose={onReject} title="Signature request">
      {request && m && (
        <div className="space-y-5 pb-2">
          <p className="text-sm leading-relaxed text-neutral-400">
            <span className="font-mono text-neutral-100">{m.domain}</span> asks your smart account{' '}
            <span className="font-mono text-neutral-100">{short(request.account, 4)}</span> to sign in. This is a
            message, not a transaction: nothing is submitted and nothing is paid.
          </p>

          <div className="surface-site rounded-2xl p-5 text-neutral-950">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-600">Message</p>
            <p className="mt-3 text-xl font-medium tracking-[-0.03em]">{m.statement}</p>
            <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 border-t border-neutral-950/10 pt-4 text-sm">
              <dt className="text-neutral-600">Domain</dt>
              <dd className="font-mono text-[13px]">
                {m.domain} <span className="text-neutral-600">(from this page's origin)</span>
              </dd>
              <dt className="text-neutral-600">Nonce</dt>
              <dd className="font-mono text-[13px]">{m.nonce}</dd>
              <dt className="text-neutral-600">Issued</dt>
              <dd className="font-mono text-[13px]">{new Date(m.issuedAt * 1000).toLocaleTimeString()}</dd>
              <dt className="text-neutral-600">Verifier</dt>
              <dd className="font-mono text-[13px]">
                {short(request.verifierId, 4)}{' '}
                {pinned === null && <span className="text-neutral-600">checking Wasm…</span>}
                {pinned === true && <span className="text-positive-300">reference Wasm ✓</span>}
                {pinned === false && <span className="text-negative-400">unknown Wasm, do not sign</span>}
              </dd>
              <dt className="text-neutral-600">Signs with</dt>
              <dd>{request.signers.map((s) => SIGNER_LABEL[s]).join(' + ')}</dd>
            </dl>
            <details className="mt-3 text-sm">
              <summary className="cursor-pointer text-neutral-600">Exact text</summary>
              <pre className="mt-2 whitespace-pre-wrap rounded-xl border border-neutral-950/10 p-3 font-mono text-xs leading-relaxed">
                {toDisplayText(m, request.account)}
              </pre>
            </details>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <button type="button" onClick={onReject} className={buttonClasses({ variant: 'secondary', size: 'lg', full: true })}>
              Reject
            </button>
            <button
              type="button"
              autoFocus
              disabled={pinned === false}
              onClick={onApprove}
              className={buttonClasses({ variant: 'positive', size: 'lg', full: true })}
            >
              Sign
            </button>
          </div>
        </div>
      )}
    </BottomSheet>
  )
}
