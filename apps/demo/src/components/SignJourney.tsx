import type { ReactElement } from 'react'
import { CheckCircleIcon, LockIcon, MessageIcon } from './icons'
import { useSceneStep, useStage } from './scroll/stageContext'

const JOURNEY_STEPS = [
  {
    eyebrow: '01 · REQUEST',
    title: 'The site asks.',
    body: 'A statement and a one-time nonce. The wallet adds the domain from the page origin, so no site can collect a signature meant for another.',
    icon: <MessageIcon className="h-5 w-5 text-figure-ember" />,
  },
  {
    eyebrow: '02 · AUTHORIZE',
    title: 'The account signs one call.',
    body: 'verify_message(account, msg) on a verifier whose Wasm hash is pinned. Address-bound credentials, no sub-calls. Existing accounts need no upgrade.',
    icon: <LockIcon className="h-5 w-5 text-figure-ochre" />,
  },
  {
    eyebrow: '03 · DECIDE',
    title: '__check_auth decides.',
    body: "The site simulates the call in enforcing mode and the account's own rules run. Error(Contract, #1) from the verifier means authorized. Nothing is submitted, nothing is paid.",
    icon: <CheckCircleIcon className="h-5 w-5 text-figure-verdigris" />,
  },
] as const

/**
 * The three-step story of a signature. Inside a pinned `ScrollScene` the steps
 * are driven by scroll progress and the copy cross-fades in place; in the
 * stacked fallback every step is listed and the diagram shows its end state.
 */
export function SignJourney(): ReactElement {
  const pinned = useStage()?.pinned ?? false
  const scrubbedStep = useSceneStep(JOURNEY_STEPS.length)
  const activeStep = pinned ? scrubbedStep : JOURNEY_STEPS.length - 1

  return (
    <div className="mx-auto grid w-full max-w-7xl gap-6 px-5 sm:gap-10 sm:px-8 lg:grid-cols-[0.92fr_1.08fr] lg:gap-20 lg:px-10">
      <JourneyVisual activeStep={activeStep} />

      {pinned ? (
        <div className="grid items-center">
          {JOURNEY_STEPS.map((step, index) => (
            <div
              key={step.eyebrow}
              className={`col-start-1 row-start-1 transition-opacity duration-300 ${
                activeStep === index ? 'opacity-100' : 'opacity-0'
              }`}
            >
              <JourneyCopy step={step} isActive={activeStep === index} />
            </div>
          ))}
        </div>
      ) : (
        <div className="flex flex-col justify-center gap-14">
          {JOURNEY_STEPS.map((step) => (
            <JourneyCopy key={step.eyebrow} step={step} isActive />
          ))}
        </div>
      )}
    </div>
  )
}

function JourneyCopy({
  step,
  isActive,
}: {
  step: (typeof JOURNEY_STEPS)[number]
  isActive: boolean
}): ReactElement {
  return (
    <div className={`journey-copy ${isActive ? 'is-active' : ''}`}>
      <div className="flex items-center justify-between gap-6 text-neutral-400">
        <p className="font-mono text-[11px] uppercase tracking-[0.2em]">{step.eyebrow}</p>
        <span aria-hidden="true">{step.icon}</span>
      </div>
      <h3 className="mt-4 text-[2rem] font-medium leading-[0.9] tracking-[-0.055em] sm:mt-6 sm:text-[clamp(2.25rem,4.6vw,4.25rem)]">
        {step.title}
      </h3>
      <p className="mt-4 max-w-lg text-base leading-relaxed text-neutral-300 sm:mt-6 sm:text-lg">{step.body}</p>
    </div>
  )
}

function JourneyVisual({ activeStep }: { activeStep: number }): ReactElement {
  return (
    <div
      aria-hidden="true"
      className="relative mx-auto aspect-square w-full max-w-[16rem] self-center overflow-hidden rounded-3xl border border-neutral-50/15 bg-neutral-900 p-5 sm:max-w-md sm:p-8 lg:mx-0"
    >
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-400">
        <span>Signature architecture</span>
        <span>0{activeStep + 1} / 03</span>
      </div>

      <div className="absolute inset-x-5 bottom-5 top-16 sm:inset-x-8 sm:bottom-8 sm:top-20">
        <div className={`journey-source ${activeStep >= 1 ? 'is-separated' : ''}`}>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-400">Message</p>
          <p className="mt-3 text-4xl font-medium tracking-[-0.05em] sm:mt-4 sm:text-6xl">Sign in</p>
          <div className="mt-auto flex items-end justify-between gap-4">
            <div>
              <p className="text-xl font-medium">demo.c-sign.dev</p>
              <p className="mt-1 font-mono text-xs text-neutral-400">nonce 2ba9a80f…</p>
            </div>
            <MessageIcon className="h-8 w-8 text-figure-ember" />
          </div>
        </div>

        <div className={`journey-positions ${activeStep >= 1 ? 'is-visible' : ''}`}>
          <PositionCard
            className="bg-neutral-50 text-neutral-950"
            label="CALL"
            amount="verify_message"
            note={activeStep >= 2 ? 'Simulated, never sent' : 'One call, no sub-calls'}
          />
          <PositionCard
            className="bg-accent-500 text-onAccent"
            label="SIGNED BY"
            amount="C…POWL"
            note={activeStep >= 2 ? 'Its __check_auth ran' : 'Address-bound (V2)'}
          />
        </div>

        <div className={`journey-choice ${activeStep >= 2 ? 'is-visible' : ''}`}>
          <span>ERROR(CONTRACT, #1)</span>
          <span className="text-positive-300">VALID</span>
        </div>
      </div>
    </div>
  )
}

function PositionCard({
  className,
  label,
  amount,
  note,
}: {
  className: string
  label: string
  amount: string
  note: string
}): ReactElement {
  return (
    <div className={`flex min-h-32 flex-col rounded-2xl p-4 pb-12 sm:min-h-48 sm:p-6 sm:pb-14 ${className}`}>
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] opacity-90">{label}</p>
      <p className="mt-auto font-mono text-sm font-medium tracking-[-0.02em] sm:text-lg">{amount}</p>
      <p className="mt-1 text-[0.6875rem] leading-tight opacity-90 sm:text-xs">{note}</p>
    </div>
  )
}
