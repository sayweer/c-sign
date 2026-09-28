/** Landing route: a scroll-driven introduction to C-Sign. */
import { useEffect, useRef, type ReactElement, type ReactNode } from 'react'
import { BrandMark } from '../components/BrandMark'
import { EnterDemo } from '../components/EnterDemo'
import { SiteCta, SiteFooter, SiteHeader, siteNavItemClass } from '../components/SiteChrome'
import { OpeningScene } from '../components/OpeningScene'
import { PixelText } from '../components/PixelText'
import { SignJourney } from '../components/SignJourney'
import { SceneParallax } from '../components/scroll/SceneParallax'
import { ScrollScene } from '../components/scroll/ScrollScene'
import { ScrollStage } from '../components/scroll/ScrollStage'
import type { StageApi } from '../components/scroll/stageContext'
import { useSurface } from '../hooks/useSurface'
import { ArrowRightIcon, CheckIcon, LayersIcon, LockIcon, RefreshIcon, XIcon } from '../components/icons'
import { REPO_URL } from '../lib/config'

/* ─────────────────────────────────────────────────────────
 * LANDING STORYBOARD
 *
 *    0ms   the quiet hero is on screen; header and hero actions are live
 * scroll   each chapter rises over the last one as an inset card,
 *          then expands to full bleed while the layer beneath recedes
 *
 * Under reduced motion the same scenes render as ordinary stacked sections.
 * Scene indices are referenced by the header nav — keep NAV_SCENES in sync
 * with the order of <ScrollScene> children below.
 * ───────────────────────────────────────────────────────── */

const NAV_SCENES = { how: 1, evidence: 3, security: 7 } as const

const SPEC_URL = `${REPO_URL}/blob/main/docs/SPEC.md`
const EXPERIMENTS_URL = `${REPO_URL}/blob/main/docs/EXPERIMENTS.md`
const NONCE_TX = '30ffa685b9f21ff13380c43ec23ed428131e55031b52170b00f3b41deaf41de7'

const facts = [
  { value: '0', label: 'Transactions to sign in', note: 'NO FEE, NO SUBMISSION' },
  { value: '0', label: 'Nonces burned on replay', note: 'PROVEN ON TESTNET' },
  { value: '15/15', label: 'Testnet experiments passed', note: 'WITH TX LINKS' },
  { value: '0.7 s', label: 'Median verification', note: 'PUBLIC TESTNET RPC' },
]

export function Landing(): ReactElement {
  useSurface('site')
  useEffect(() => {
    document.title = 'C-Sign — smart accounts can sign in'
  }, [])

  const stage = useRef<StageApi | null>(null)

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-950">
      <div id="landing-content">
        <a
          href="#landing-main"
          className="fixed left-4 top-4 z-50 -translate-y-24 rounded-full bg-neutral-950 px-4 py-3 text-sm font-medium text-neutral-50 transition-transform focus:translate-y-0 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:ring-offset-2 focus:ring-offset-neutral-50 motion-reduce:transition-none"
        >
          Skip to main content
        </a>
        <SiteHeader nav={<LandingNav onNavigate={(scene) => stage.current?.scrollToScene(scene)} />} />

        <main id="landing-main" tabIndex={-1}>
          <ScrollStage apiRef={stage}>
            <ScrollScene custom length={3.8} className="bg-neutral-50 text-neutral-950" label="C-Sign">
              <OpeningScene
                stats={facts}
                headline={
                  <h1 className="mx-auto w-full max-w-[96rem] px-5 text-center text-[clamp(2.75rem,9.2vw,9rem)] font-normal leading-[0.88] tracking-[-0.065em] sm:px-8 lg:whitespace-nowrap lg:px-10">
                    Smart accounts can sign in<span className="text-positive-300">.</span>
                  </h1>
                }
              >
                <SceneBody className="max-w-[96rem] text-center">
                  <p className="mt-12 text-xl font-medium tracking-[-0.02em] text-neutral-950 sm:mt-14 sm:text-3xl">
                    <PixelText>Signed messages for contract accounts</PixelText>
                  </p>
                  <p className="mx-auto mt-4 max-w-3xl text-xl leading-relaxed text-neutral-950 sm:text-3xl">
                    <PixelText delay={160}>No transaction. No fee. The account's own rules decide.</PixelText>
                  </p>
                  <div className="mx-auto mt-10 grid w-full max-w-xs gap-3 sm:flex sm:max-w-none sm:flex-wrap sm:items-center sm:justify-center">
                    <SiteCta>Launch demo</SiteCta>
                    <button
                      type="button"
                      onClick={() => stage.current?.scrollToScene(NAV_SCENES.how)}
                      className="inline-flex min-h-12 w-full items-center justify-center rounded-full bg-neutral-950 px-6 py-3 text-sm font-medium text-neutral-50 [touch-action:manipulation] [-webkit-tap-highlight-color:transparent] transition-transform duration-100 ease-spring motion-safe:hover:scale-[1.04] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-neutral-950 motion-reduce:transform-none sm:w-auto"
                    >
                      See how it works
                    </button>
                  </div>
                </SceneBody>
              </OpeningScene>
            </ScrollScene>

            <ScrollScene id="how" className="surface-ink bg-neutral-950 text-neutral-50">
              <SceneBody className="text-center">
                <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent-300">The missing primitive</p>
                <h2 className="mx-auto mt-7 max-w-5xl text-[clamp(3.25rem,7vw,7rem)] font-medium leading-[0.88] tracking-[-0.06em]">
                  Contract accounts can't sign a message.
                </h2>
                <p className="mx-auto mt-8 max-w-2xl text-lg leading-relaxed text-neutral-300">
                  SEP-53 covers G… keys. Passkey wallets, multisig and agent wallets are C… contracts, and signMessage
                  fails for them today. C-Sign closes that gap in three steps.
                </p>
                <SceneLink href={SPEC_URL} tone="dark" className="mt-6 justify-center sm:mt-8">
                  Read the draft SEP
                </SceneLink>
              </SceneBody>
            </ScrollScene>

            <ScrollScene className="surface-ink bg-neutral-950 text-neutral-50" label="How a signature is made" length={2.5}>
              <SignJourney />
            </ScrollScene>

            <ScrollScene id="evidence" className="bg-accent-500 text-neutral-50">
              <SceneBody className="grid items-center gap-6 sm:gap-14 lg:grid-cols-[0.92fr_1.08fr]">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-neutral-50/90">Nonce</p>
                  <h2 className="mt-4 max-w-3xl text-[2.5rem] font-medium leading-[0.87] tracking-[-0.06em] sm:mt-7 sm:text-[clamp(3rem,6vw,6rem)]">
                    Submit it. Nothing burns.
                  </h2>
                  <p className="mt-5 max-w-xl text-[0.9375rem] leading-relaxed text-neutral-50/80 sm:mt-8 sm:text-lg">
                    The verifier always reverts, so a signature someone sends on-chain fails and the host rolls its nonce
                    back. The same signature still verifies afterwards.
                  </p>
                  <SceneLink href={EXPERIMENTS_URL} tone="dark" className="mt-4 sm:mt-7">
                    See the testnet experiments
                  </SceneLink>
                </div>
                <SceneParallax>
                  <NonceVisual />
                </SceneParallax>
              </SceneBody>
            </ScrollScene>

            <ScrollScene className="bg-neutral-50 text-neutral-950">
              <SceneBody className="grid items-center gap-7 sm:gap-14 lg:grid-cols-[1.08fr_0.92fr]">
                <SceneParallax className="order-2 lg:order-1">
                  <PinVisual />
                </SceneParallax>
                <div className="lg:order-2">
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-positive-300">Pinning</p>
                  <h2 className="mt-4 max-w-3xl text-[2.5rem] font-medium leading-[0.87] tracking-[-0.06em] sm:mt-7 sm:text-[clamp(3rem,6vw,6rem)]">
                    Pin the code, not an address.
                  </h2>
                  <p className="mt-5 max-w-xl text-[0.9375rem] leading-relaxed text-neutral-600 sm:mt-8 sm:text-lg">
                    Anyone can deploy the verifier. Wallets and sites trust an instance only if it runs the published
                    Wasm hash, which stops a fake verifier from answering "authorized".
                  </p>
                </div>
              </SceneBody>
            </ScrollScene>

            <ScrollScene className="bg-neutral-200 text-neutral-950">
              <SceneBody className="grid items-center gap-7 sm:gap-14 lg:grid-cols-2">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-neutral-600">Rotation</p>
                  <h2 className="mt-4 max-w-3xl text-[2.5rem] font-medium leading-[0.87] tracking-[-0.06em] sm:mt-7 sm:text-[clamp(3rem,6vw,6rem)]">
                    Rotate a key, old signatures stop.
                  </h2>
                  <p className="mt-5 max-w-xl text-[0.9375rem] leading-relaxed text-neutral-600 sm:mt-8 sm:text-lg">
                    Validity follows the account's current rules, like ERC-1271. Remove a signer and what it signed no
                    longer verifies; the new key's signature does.
                  </p>
                </div>
                <SceneParallax>
                  <RotationVisual />
                </SceneParallax>
              </SceneBody>
            </ScrollScene>

            <ScrollScene className="surface-ink bg-neutral-950 text-neutral-50">
              <SceneBody className="grid items-center gap-7 sm:gap-16 lg:grid-cols-2">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent-300">Accounts</p>
                  <h2 className="mt-4 text-[2.5rem] font-medium leading-[0.87] tracking-[-0.06em] sm:mt-7 sm:text-[clamp(3rem,6vw,6rem)]">
                    Works with accounts that exist.
                  </h2>
                  <p className="mt-5 max-w-xl text-[0.9375rem] leading-relaxed text-neutral-300 sm:mt-8 sm:text-lg">
                    C-Sign asks nothing new of the account. Whatever its __check_auth accepts for a transaction, it
                    accepts for a message.
                  </p>
                </div>
                <div className="grid gap-px overflow-hidden rounded-2xl bg-neutral-50/15 sm:grid-cols-2">
                  <AccountTile
                    label="OPENZEPPELIN · PASSKEY"
                    title="WebAuthn signer"
                    body="The demo's account: a passkey on this device, checked on-chain by the OpenZeppelin WebAuthn verifier."
                  />
                  <AccountTile
                    label="OPENZEPPELIN · ED25519"
                    title="Key and multisig signers"
                    body="One Ed25519 key or several. The account's rule decides how many have to sign."
                  />
                </div>
              </SceneBody>
            </ScrollScene>

            <ScrollScene id="security" className="bg-neutral-50 text-neutral-950">
              <SceneBody>
                <div className="grid gap-5 sm:gap-12 lg:grid-cols-[1.15fr_0.85fr] lg:items-end">
                  <div>
                    <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-positive-300">Security</p>
                    <h2 className="mt-4 max-w-5xl text-[2.5rem] font-medium leading-[0.87] tracking-[-0.06em] sm:mt-7 sm:text-[clamp(3rem,6vw,6rem)]">
                      The wallet writes the domain.
                    </h2>
                  </div>
                  <p className="max-w-xl text-[0.9375rem] leading-relaxed text-neutral-600 sm:text-lg">
                    Signing happens in the wallet, which fills in the site's domain itself. The verifier is recognised by
                    its code, never trusted for its address.
                  </p>
                </div>

                <div className="mt-5 grid border-y border-neutral-950/10 sm:mt-16 sm:grid-cols-3">
                  <Assurance number="01" title="Domain from origin" body="A phishing site cannot collect a signature that names another site." />
                  <Assurance number="02" title="Pinned verifier" body="Relying parties check that the instance runs the published Wasm hash." />
                  <Assurance number="03" title="No admin, no storage" body="One function in 1,475 bytes. It always reverts." />
                </div>

                <SceneLink href={`${SPEC_URL}#security-concerns`} tone="light" className="mt-4 sm:mt-7">
                  Read the security notes
                </SceneLink>
              </SceneBody>
            </ScrollScene>

            <ScrollScene className="bg-accent-500 text-neutral-50">
              <SceneBody>
                <BrandMark className="h-12 w-12 text-neutral-50" />
                <h2 className="mt-14 max-w-6xl text-[clamp(3.25rem,7.5vw,7.5rem)] font-medium leading-[0.84] tracking-[-0.065em]">
                  Sign in with your smart account.
                </h2>
                <div className="mt-10 flex flex-wrap items-center gap-4">
                  <EnterDemo className="group inline-flex min-h-12 items-center gap-2 rounded-full bg-neutral-50 px-7 py-3 text-sm font-medium text-neutral-950 transition-transform duration-100 hover:-translate-y-0.5 active:translate-y-0 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-neutral-50 motion-reduce:transform-none">
                    Launch demo
                    <ArrowRightIcon className="h-4 w-4 transition-transform duration-100 group-hover:translate-x-1 motion-reduce:transform-none" />
                  </EnterDemo>
                  <span className="text-sm text-neutral-50/90">Testnet. Nothing to install, nothing to pay.</span>
                </div>
              </SceneBody>
            </ScrollScene>
          </ScrollStage>
        </main>

        <SiteFooter />
      </div>
    </div>
  )
}

/** Shared inner container for a scene: horizontal rhythm only, the stage centres vertically. */
function SceneBody({ children, className = '' }: { children: ReactNode; className?: string }): ReactElement {
  return <div className={`mx-auto w-full max-w-7xl px-5 sm:px-8 lg:px-10 ${className}`}>{children}</div>
}

/** Link from a scene to the specification or the testnet evidence. */
function SceneLink({
  href,
  tone,
  children,
  className = '',
}: {
  href: string
  tone: 'light' | 'dark'
  children: ReactNode
  className?: string
}): ReactElement {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className={`group inline-flex min-h-11 items-center gap-2 text-sm font-medium no-underline underline-offset-4 transition-colors duration-100 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 ${
        tone === 'dark'
          ? 'text-neutral-50/90 hover:text-neutral-50 focus-visible:outline-neutral-50'
          : 'text-accent-500 hover:text-neutral-950 focus-visible:outline-accent-500'
      } ${className}`}
    >
      {children}
      <ArrowRightIcon className="h-4 w-4 transition-transform duration-100 group-hover:translate-x-1 motion-reduce:transform-none" />
    </a>
  )
}

function LandingNav({ onNavigate }: { onNavigate: (scene: number) => void }): ReactElement {
  return (
    <nav aria-label="Primary navigation" className="hidden items-center gap-8 md:flex">
      {(
        [
          ['How it works', NAV_SCENES.how],
          ['Evidence', NAV_SCENES.evidence],
          ['Security', NAV_SCENES.security],
        ] as const
      ).map(([label, scene]) => (
        <button key={label} type="button" onClick={() => onNavigate(scene)} className={siteNavItemClass}>
          {label}
        </button>
      ))}
      <a href={REPO_URL} target="_blank" rel="noreferrer" className={siteNavItemClass}>
        GitHub
      </a>
    </nav>
  )
}

/** Scene 3: the on-chain submission that fails without burning the nonce. */
function NonceVisual(): ReactElement {
  return (
    <div className="rounded-3xl bg-neutral-50 p-4 text-neutral-950 shadow-2xl shadow-neutral-950/15 sm:p-8">
      <div className="flex items-center justify-between gap-4 border-b border-neutral-950/10 pb-4 sm:pb-6">
        <a
          href={`https://stellar.expert/explorer/testnet/tx/${NONCE_TX}`}
          target="_blank"
          rel="noreferrer"
          className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-600 underline-offset-4 hover:underline"
        >
          Testnet tx {NONCE_TX.slice(0, 8)}…
        </a>
        <LockIcon className="h-5 w-5 text-figure-ochre" />
      </div>
      <div className="grid gap-4 py-5 sm:grid-cols-2 sm:gap-8 sm:py-10">
        <Metric label="Nonce consumed" value="No" />
        <Metric label="Still verifies" value="Yes" />
      </div>
      <div className="relative h-px bg-neutral-950/15">
        <span className="absolute -top-1 left-0 h-2 w-2 rounded-full bg-accent-500" />
        <span className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rounded-full bg-negative-400" />
        <span className="absolute -top-1 right-0 h-2 w-2 rounded-full bg-positive-400" />
      </div>
      <div className="mt-3 flex justify-between font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-600 sm:mt-4">
        <span>Submitted</span>
        <span>Error(Contract, #1)</span>
        <span>Re-verified</span>
      </div>
    </div>
  )
}

/** Scene 4: two instances pass the hash pin, the fake verifier does not. */
function PinVisual(): ReactElement {
  return (
    <div className="surface-ink order-2 rounded-3xl bg-neutral-950 p-5 text-neutral-50 shadow-2xl shadow-neutral-950/15 sm:p-8 lg:order-1">
      <div className="flex items-center justify-between gap-4 border-b border-neutral-50/15 pb-4 sm:pb-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-400">Pinned Wasm hash</p>
        <LayersIcon className="h-5 w-5 text-figure-verdigris" />
      </div>
      <div className="py-6 sm:py-10">
        <p className="font-mono text-[2.75rem] font-medium leading-none tracking-[-0.04em] text-accent-400 sm:text-[clamp(3.5rem,7vw,5.5rem)]">
          2a5004a7
        </p>
        <p className="mt-3 max-w-md text-[0.9375rem] leading-relaxed text-neutral-300 sm:mt-5 sm:text-lg">
          The reference verifier builds to the same hash on macOS and on Linux CI.
        </p>
      </div>
      <ul className="divide-y divide-neutral-50/10 border-t border-neutral-50/10 text-sm">
        <PinRow id="CCL5EDN2…NFD5" name="Instance A" ok />
        <PinRow id="CDWCB2Z3…XKJS" name="Instance B" ok />
        <PinRow id="CBMSJ7WO…IIYQ" name="Fake verifier" ok={false} />
      </ul>
    </div>
  )
}

function PinRow({ id, name, ok }: { id: string; name: string; ok: boolean }): ReactElement {
  return (
    <li className="flex items-center justify-between gap-4 py-2.5">
      <span>
        {name} <span className="font-mono text-xs text-neutral-400">{id}</span>
      </span>
      {ok ? <CheckIcon className="h-4 w-4 text-positive-300" /> : <XIcon className="h-4 w-4 text-negative-300" />}
    </li>
  )
}

/** Scene 5: the same signature before and after a key rotation. */
function RotationVisual(): ReactElement {
  return (
    <div className="rounded-3xl bg-neutral-50 p-5 shadow-2xl shadow-neutral-950/10 sm:p-8">
      <div className="flex items-center justify-between gap-4 border-b border-neutral-950/10 pb-4 sm:pb-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-600">One signature, two answers</p>
        <RefreshIcon className="h-5 w-5 text-figure-mulberry" />
      </div>
      <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2 py-5 sm:gap-3 sm:py-8">
        <StateTile label="Valid" value="Passkey is a signer" tone="positive" />
        <ArrowRightIcon className="mx-auto h-5 w-5 text-neutral-600 sm:h-6 sm:w-6" />
        <StateTile label="Invalid" value="Passkey removed" tone="negative" />
      </div>
      <div className="flex items-baseline justify-between gap-4 rounded-2xl bg-neutral-200 px-4 py-3 sm:px-5 sm:py-4">
        <span className="text-sm text-neutral-600">New key signs in</span>
        <span className="text-2xl font-medium tracking-[-0.04em] text-positive-300 sm:text-3xl">Valid</span>
      </div>
    </div>
  )
}

function StateTile({ label, value, tone }: { label: string; value: string; tone: 'positive' | 'negative' }): ReactElement {
  return (
    <div className={`rounded-2xl p-3.5 text-onPositive sm:p-5 ${tone === 'positive' ? 'bg-positive-500' : 'bg-negative-500'}`}>
      <p className="text-xl font-medium tracking-[-0.045em] sm:text-4xl">{label}</p>
      <p className="mt-1 text-[0.6875rem] leading-tight opacity-90 sm:mt-2 sm:text-xs">{value}</p>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }): ReactElement {
  return (
    <div>
      <p className="text-sm text-neutral-600">{label}</p>
      <p className="mt-2 text-3xl font-medium tracking-[-0.045em] tabular-nums sm:mt-3 sm:text-5xl">{value}</p>
    </div>
  )
}

function AccountTile({ label, title, body }: { label: string; title: string; body: string }): ReactElement {
  return (
    <article className="surface-ink flex flex-col justify-between gap-3.5 bg-neutral-900 p-5 sm:min-h-80 sm:gap-0 sm:p-8">
      <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-accent-300">{label}</p>
      <div>
        <h3 className="text-xl font-medium tracking-[-0.04em] sm:text-3xl">{title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-neutral-300 sm:mt-4 sm:text-base">{body}</p>
      </div>
    </article>
  )
}

function Assurance({ number, title, body }: { number: string; title: string; body: string }): ReactElement {
  return (
    <article className="border-b border-neutral-950/10 py-2.5 last:border-b-0 sm:border-b-0 sm:border-r sm:px-8 sm:py-8 sm:first:pl-0 sm:last:border-r-0 sm:last:pr-0">
      <p className="font-mono text-[10px] tracking-[0.18em] text-accent-500">{number}</p>
      <h3 className="mt-1.5 text-base font-medium tracking-[-0.025em] sm:mt-8 sm:text-xl">{title}</h3>
      <p className="mt-1 text-sm leading-snug text-neutral-600 sm:mt-3 sm:max-w-xs sm:text-base sm:leading-relaxed">{body}</p>
    </article>
  )
}
