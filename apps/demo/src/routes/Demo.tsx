import { useCallback, useEffect, useRef, useState, type ReactElement, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import type { SignedMessage } from 'c-sign'
import { getChallenge, getSession, signOut, verify } from '../lib/api'
import { REPO_URL, VERIFIER_ID } from '../lib/config'
import {
  activeSigners,
  addRecoveryKey,
  forgetWallet,
  loadWallet,
  removePasskey,
  signMessage,
  type WalletState,
} from '../lib/wallet'
import { buttonClasses } from '../lib/buttonStyles'
import { cardClasses } from '../lib/cardClasses'
import { useSurface } from '../hooks/useSurface'
import { BrandMark } from '../components/BrandMark'
import { PasskeyCreate } from '../components/EnterDemo'
import { Inspector, type InspectorState } from '../components/Inspector'
import { WalletSheet, type WalletRequest } from '../components/WalletSheet'
import { CheckIcon } from '../components/icons'
import { Eyebrow, IdLink } from '../components/ui'

const LAST_SIGN_IN = 'c-sign-demo.last-sign-in'

type Pending = { request: WalletRequest; resolve: (ok: boolean) => void }

export function Demo(): ReactElement {
  useSurface('app')
  const navigate = useNavigate()
  const [wallet, setWallet] = useState<WalletState | null>(() => loadWallet())
  const [session, setSession] = useState<string | null>(null)
  const [firstSignature, setFirstSignature] = useState<string | null>(() => localStorage.getItem(LAST_SIGN_IN))
  const [inspector, setInspector] = useState<InspectorState | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [txs, setTxs] = useState<{ label: string; hash: string }[]>([])
  const [pasted, setPasted] = useState('')
  const inspectorRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    document.title = 'C-Sign demo'
    void getSession().then((s) => setSession(s.account)).catch(() => undefined)
  }, [])

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label)
    setError(null)
    try {
      await fn()
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e)
      if (!/NotAllowedError|cancel|abort/i.test(text)) setError(text)
    } finally {
      setBusy(null)
    }
  }

  /** Opens the wallet sheet and resolves when the user approves or rejects. */
  const askWallet = (request: WalletRequest) => new Promise<boolean>((resolve) => setPending({ request, resolve }))
  const approve = useCallback(() => setPending((p) => (p?.resolve(true), null)), [])
  const reject = useCallback(() => setPending((p) => (p?.resolve(false), null)), [])

  const showInInspector = (state: InspectorState) => {
    setInspector(state)
    if (window.matchMedia('(max-width: 1023px)').matches) inspectorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const onSignIn = () =>
    run('Waiting for the wallet…', async () => {
      if (!wallet) return
      const challenge = await getChallenge()
      // The wallet, not the site, writes the domain: it comes from the page origin.
      const message: SignedMessage = {
        version: '1',
        domain: location.host,
        statement: challenge.statement,
        nonce: challenge.nonce,
        issuedAt: challenge.issuedAt,
      }
      const signers = activeSigners(wallet)
      if (!(await askWallet({ account: wallet.account, message, verifierId: VERIFIER_ID, signers }))) return
      setBusy(signers.includes('passkey') ? 'Confirm with your passkey…' : 'Signing with the recovery key…')
      const signature = await signMessage(wallet, message, VERIFIER_ID)
      setBusy('Verifying…')
      const subtitle = 'Full relying-party check: domain, one-time nonce, age.'
      showInInspector({ title: 'Sign-in', subtitle, running: true, signature })
      const result = await verify(signature, 'signin', challenge.token)
      showInInspector({ title: 'Sign-in', subtitle, running: false, result, signature })
      if (result.status === 'valid') {
        setSession(result.account ?? null)
        if (!firstSignature) {
          localStorage.setItem(LAST_SIGN_IN, signature)
          setFirstSignature(signature)
        }
      }
    })

  const onRecheck = () =>
    run('Checking again…', async () => {
      if (!firstSignature) return
      const subtitle = "Same bytes as your first sign-in, checked against the account's rules as they are now."
      showInInspector({ title: 'First signature, checked again', subtitle, running: true, signature: firstSignature })
      const result = await verify(firstSignature, 'recheck')
      showInInspector({ title: 'First signature, checked again', subtitle, running: false, result, signature: firstSignature })
    })

  const onAddRecovery = () =>
    run('Confirm with your passkey to add the recovery key…', async () => {
      if (!wallet) return
      const { state, hash } = await addRecoveryKey(wallet)
      setWallet(state)
      if (hash) setTxs((t) => [...t, { label: 'Recovery key added', hash }])
    })

  const onRemovePasskey = () =>
    run('Confirm with your passkey one last time…', async () => {
      if (!wallet) return
      const { state, hash } = await removePasskey(wallet)
      setWallet(state)
      if (hash) setTxs((t) => [...t, { label: 'Passkey removed', hash }])
    })

  const onInspect = () =>
    run('Verifying…', async () => {
      const signature = pasted.trim()
      if (!signature) return
      const subtitle = 'Any C-Sign signature. The domain is shown, not enforced.'
      showInInspector({ title: 'Inspect a signature', subtitle, running: true, signature })
      const result = await verify(signature, 'inspect')
      showInInspector({ title: 'Inspect a signature', subtitle, running: false, result, signature })
    })

  const onReset = () =>
    run('Signing out…', async () => {
      await signOut()
      forgetWallet()
      localStorage.removeItem(LAST_SIGN_IN)
      navigate('/')
    })

  const signedIn = !!wallet && session === wallet.account
  const step = !wallet ? 1 : !signedIn && !firstSignature ? 2 : 3
  const idle = busy !== null

  return (
    <div className="min-h-dvh">
      <AppHeader />

      <main key={wallet ? 'account' : 'none'} className="mx-auto grid max-w-7xl gap-8 px-5 pb-24 pt-10 motion-safe:animate-rise-in sm:px-8 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-12 lg:px-10 lg:pt-14">
        <div className="min-w-0">
          <Eyebrow>Signed messages for contract accounts</Eyebrow>
          <h1 className="mt-4 max-w-xl text-[clamp(2.25rem,5vw,3.5rem)] font-medium leading-[0.92] tracking-[-0.055em]">
            Sign in with your smart account<span className="text-positive-300">.</span>
          </h1>

          {error && (
            <p role="alert" className="mt-8 rounded-2xl border border-negative-300/30 bg-negative-300/[0.06] px-4 py-3 text-sm text-negative-300">
              {error}
            </p>
          )}
          {busy && (
            <p className="mt-8 flex items-center gap-2 text-sm text-neutral-400" aria-live="polite">
              <span className="size-1.5 rounded-full bg-neutral-100 animate-pulse-dot" /> {busy}
            </p>
          )}

          <ol className="mt-10 space-y-3">
            <Step n={1} title="Smart account" active={step === 1} done={!!wallet}>
              {!wallet ? (
                <div className="max-w-sm">
                  <PasskeyCreate onCreated={() => setWallet(loadWallet())} />
                </div>
              ) : (
                <AccountRow wallet={wallet} onReset={onReset} disabled={idle} />
              )}
            </Step>

            <Step n={2} title="Sign in, without a transaction" active={step === 2} done={!!firstSignature} locked={!wallet}>
              <p className="text-sm leading-relaxed text-neutral-400">
                The site sends a statement and a one-time nonce. The wallet adds the domain, and the account signs one call,{' '}
                <code className="font-mono text-[13px] text-neutral-100">verify_message(account, msg)</code>, which can never
                succeed on-chain. The site checks it by simulation.
              </p>
              <div className="mt-5 flex flex-wrap items-center gap-3">
                <button type="button" onClick={onSignIn} disabled={idle || !wallet} className={buttonClasses({ variant: 'positive', size: 'lg' })}>
                  {signedIn ? 'Sign in again' : 'Sign in with smart account'}
                </button>
                {signedIn && <span className="font-mono text-xs text-positive-300">● signed in</span>}
              </div>
            </Step>

            <Step n={3} title="Rotate a key, watch the old signature fail" active={step === 3} locked={!firstSignature}>
              <p className="text-sm leading-relaxed text-neutral-400">
                A C-Sign signature is checked against the account's <em>current</em> rules, like ERC-1271 on Ethereum. Lose
                the device, rotate the key, and what the old key signed stops verifying.
              </p>
              <ol className="mt-5 divide-y divide-hairline overflow-hidden rounded-xl border border-hairline bg-neutral-950/40">
                <LabRow label="Check your first signature now" hint="Expected: valid" onClick={onRecheck} action="Check" disabled={!firstSignature || idle} />
                <LabRow
                  label="Add a recovery key"
                  hint="An Ed25519 key, generated in this browser, joins the passkey. This rule needs every signer, so even this changes what verifies."
                  done={!!wallet?.recoverySecret}
                  onClick={onAddRecovery}
                  action="Add"
                  disabled={!firstSignature || !!wallet?.recoverySecret || idle}
                />
                <LabRow
                  label="Remove the passkey"
                  hint="Both keys sign the change. Afterwards only the recovery key remains."
                  done={!!wallet?.passkeyRemoved}
                  onClick={onRemovePasskey}
                  action="Remove"
                  disabled={!wallet?.recoverySecret || !!wallet?.passkeyRemoved || idle}
                />
                <LabRow label="Check your first signature again" hint="Same bytes as before. Expected: invalid" onClick={onRecheck} action="Check" disabled={!wallet?.passkeyRemoved || idle} />
                <LabRow label="Sign in with the recovery key" hint="Expected: valid" onClick={onSignIn} action="Sign in" disabled={!wallet?.passkeyRemoved || idle} />
              </ol>
              {txs.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-neutral-400">
                  {txs.map((t) => (
                    <li key={t.hash}>
                      {t.label}: <IdLink id={t.hash} kind="tx" />
                    </li>
                  ))}
                </ul>
              )}
            </Step>
          </ol>

          <section className={`mt-10 ${cardClasses()}`}>
            <Eyebrow>Tool</Eyebrow>
            <h2 className="mt-3 text-xl font-medium tracking-[-0.04em]">Verify any signature</h2>
            <p className="mt-2 text-sm leading-relaxed text-neutral-400">
              Paste a base64 <code className="font-mono text-[13px] text-neutral-100">SorobanAuthorizationEntry</code> produced by any
              C-Sign wallet on testnet.
            </p>
            <label className="sr-only" htmlFor="signature">Signature</label>
            <textarea
              id="signature"
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder="AAAAA…"
              className="mt-4 w-full resize-y rounded-xl border border-boundary/50 bg-neutral-950/40 p-3 font-mono text-xs leading-relaxed text-neutral-100 placeholder:text-neutral-600 focus:border-neutral-300 focus:outline-none"
            />
            <button type="button" className={`mt-3 ${buttonClasses({ variant: 'secondary' })}`} onClick={onInspect} disabled={!pasted.trim() || idle}>
              Verify
            </button>
          </section>
        </div>

        <aside ref={inspectorRef} className="min-w-0 scroll-mt-24 lg:sticky lg:top-24 lg:max-h-[calc(100dvh-7rem)] lg:self-start lg:overflow-y-auto">
          <Inspector state={inspector} />
          <Facts />
        </aside>
      </main>

      <WalletSheet request={pending?.request ?? null} onApprove={approve} onReject={reject} />
    </div>
  )
}

function AppHeader(): ReactElement {
  return (
    <header className="sticky top-0 z-40 border-b border-hairline bg-neutral-950/95 backdrop-blur-md">
      <div className="mx-auto flex h-[4.5rem] w-full max-w-7xl items-center justify-between gap-6 px-5 sm:px-8 lg:px-10">
        <Link to="/" className="flex min-h-11 items-center gap-2.5 rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-300">
          <BrandMark className="h-6 w-6 text-accent-500" />
          <span className="text-base font-medium tracking-[-0.025em]">C-Sign</span>
          <span className="rounded-full border border-boundary/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-neutral-400">
            testnet
          </span>
        </Link>
        <nav className="flex items-center gap-6 text-sm text-neutral-400">
          <a className="hidden transition-colors duration-100 hover:text-neutral-100 sm:inline" href={`${REPO_URL}/blob/main/docs/SPEC.md`} target="_blank" rel="noreferrer">Spec</a>
          <a className="hidden transition-colors duration-100 hover:text-neutral-100 sm:inline" href={`${REPO_URL}/blob/main/docs/EXPERIMENTS.md`} target="_blank" rel="noreferrer">Experiments</a>
          <a className="transition-colors duration-100 hover:text-neutral-100" href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
        </nav>
      </div>
    </header>
  )
}

function Step({
  n,
  title,
  active,
  done,
  locked,
  children,
}: {
  n: number
  title: string
  active: boolean
  done?: boolean
  locked?: boolean
  children: ReactNode
}): ReactElement {
  return (
    <li
      className={`rounded-2xl border p-5 transition-[border-color,opacity] duration-200 sm:p-6 ${
        active ? 'border-boundary/60 bg-neutral-900' : 'border-hairline'
      } ${locked ? 'opacity-45' : ''}`}
      aria-disabled={locked}
    >
      <div className="flex items-center gap-3">
        <span
          className={`grid size-6 place-items-center rounded-full font-mono text-[11px] ${
            done ? 'bg-positive-400 text-onPositive' : 'border border-boundary/60 text-neutral-400'
          }`}
        >
          {done ? <CheckIcon className="h-3.5 w-3.5" /> : n}
        </span>
        <h2 className="text-lg font-medium tracking-[-0.03em]">{title}</h2>
      </div>
      <div className="mt-4 sm:pl-9">{children}</div>
    </li>
  )
}

function LabRow({
  label,
  hint,
  action,
  onClick,
  disabled,
  done,
}: {
  label: string
  hint: string
  action: string
  onClick: () => void
  disabled: boolean
  done?: boolean
}): ReactElement {
  return (
    <li className="flex items-center justify-between gap-4 px-4 py-3.5">
      <div className="min-w-0">
        <p className="text-sm text-neutral-100">
          {done && <CheckIcon className="mr-1.5 inline h-3.5 w-3.5 text-positive-300" />}
          {label}
        </p>
        <p className="mt-0.5 text-xs leading-relaxed text-neutral-500">{hint}</p>
      </div>
      <button type="button" onClick={onClick} disabled={disabled} className={`shrink-0 ${buttonClasses({ variant: 'secondary', size: 'sm' })}`}>
        {action}
      </button>
    </li>
  )
}

function AccountRow({ wallet, onReset, disabled }: { wallet: WalletState; onReset: () => void; disabled: boolean }): ReactElement {
  const signers = activeSigners(wallet).map((s) => (s === 'passkey' ? 'passkey' : 'recovery key')).join(' + ')
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="text-sm">
        <IdLink id={wallet.account} n={8} />
        <p className="mt-1 text-xs text-neutral-500">OpenZeppelin smart account · signers: {signers}</p>
      </div>
      <button type="button" onClick={onReset} disabled={disabled} className={buttonClasses({ variant: 'ghost', size: 'sm' })}>
        Start over
      </button>
    </div>
  )
}

function Facts(): ReactElement {
  return (
    <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 px-1 text-xs text-neutral-400">
      <dt>Verifier</dt>
      <dd>
        <IdLink id={VERIFIER_ID} /> <span className="text-neutral-600">· no admin, no storage, always reverts</span>
      </dd>
      <dt>Pinned Wasm</dt>
      <dd className="font-mono">2a5004a7…c299</dd>
      <dt>Evidence</dt>
      <dd>
        <a className="underline decoration-boundary underline-offset-4 transition-colors duration-100 hover:text-neutral-100" href={`${REPO_URL}/blob/main/docs/EXPERIMENTS.md`} target="_blank" rel="noreferrer">
          15 testnet experiments
        </a>{' '}
        · nonce is not burned on-chain
      </dd>
    </dl>
  )
}
